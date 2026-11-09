package cln_iap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	authCookie = "__Secure-cln-iap-auth"
	flowCookie = "__Host-cln-iap-flow"
	jwtHeader  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"HS256","typ":"JWT"}
	flowTTL    = 5 * time.Minute
	maxToken   = 3500 // Leave room for the cookie name, domain and attributes within 4 KiB.
)

var b64 = base64.RawURLEncoding.Strict()
var errInvalid = errors.New("invalid authentication data")

type config struct {
	cas, domain string
	hosts       map[string]bool
	logins      map[string]bool
	secret      []byte
	ttl         time.Duration
	logLevel    slog.Level
}

func dnsName(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func httpsURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(s, "#") ||
		!dnsName(u.Host) || strings.ContainsAny(s, "\\\r\n\t ") {
		return nil, errInvalid
	}
	return u, nil
}

const configPath = "/etc/traefik/cln-iap.json"
const callbackPath = "/__cln_iap/callback"

type Config struct {
	AllowedLogins string `json:"allowedLogins,omitempty"`
}

type adminConfig struct {
	CASURL        string   `json:"casUrl"`
	CookieDomain  string   `json:"cookieDomain"`
	AllowedHosts  []string `json:"allowedHosts"`
	JWTSecret     string   `json:"jwtSecret"`
	JWTSecretFile string   `json:"jwtSecretFile"`
	JWTTTL        string   `json:"jwtTtl"`
	LogLevel      string   `json:"logLevel"`
}

func CreateConfig() *Config { return &Config{} }

func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return newMiddleware(next, cfg, configPath)
}

func newMiddleware(next http.Handler, cfg *Config, path string) (http.Handler, error) {
	if cfg == nil || next == nil {
		return nil, errors.New("missing middleware configuration or handler")
	}
	c, err := loadConfig(path, cfg)
	if err != nil {
		return nil, err
	}
	a := newApp(c, newLogger(os.Stdout, c.logLevel))
	a.next = next
	return a, nil
}

func loadConfig(path string, local *Config) (config, error) {
	c := config{hosts: map[string]bool{}, logins: map[string]bool{}, ttl: 4 * time.Hour}
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot open administrator configuration")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return c, errors.New("invalid administrator configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var global adminConfig
	if decoder.Decode(&global) != nil {
		return c, errors.New("invalid administrator configuration")
	}
	var trailing interface{}
	if decoder.Decode(&trailing) != io.EOF {
		return c, errors.New("invalid administrator configuration")
	}
	return configure(global, local)
}

func configure(global adminConfig, local *Config) (config, error) {
	c := config{cas: global.CASURL, domain: global.CookieDomain, hosts: map[string]bool{}, logins: map[string]bool{}, ttl: 4 * time.Hour}
	if local == nil {
		return c, errors.New("missing middleware configuration")
	}
	level, err := parseLogLevel(global.LogLevel)
	if err != nil {
		return c, err
	}
	c.logLevel = level
	cas, err := httpsURL(c.cas)
	if err != nil || strings.Contains(cas.Path, "//") {
		return c, errors.New("invalid casUrl")
	}
	c.cas = strings.TrimRight(c.cas, "/")
	if !dnsName(c.domain) {
		return c, errors.New("invalid cookieDomain")
	}
	within := func(host string) bool { return host == c.domain || strings.HasSuffix(host, "."+c.domain) }
	if len(global.AllowedHosts) == 0 {
		return c, errors.New("allowedHosts must not be empty")
	}
	for _, host := range global.AllowedHosts {
		host = strings.TrimSpace(host)
		base := strings.TrimPrefix(host, "*.")
		if !dnsName(base) || !within(base) {
			return c, errors.New("invalid allowedHosts")
		}
		c.hosts[host] = true
	}
	if strings.TrimSpace(local.AllowedLogins) != "" {
		for _, login := range strings.Split(local.AllowedLogins, ",") {
			login = strings.TrimSpace(login)
			if login == "" {
				return c, errors.New("allowedLogins contains an empty login")
			}
			c.logins[login] = true
		}
	}
	if global.JWTTTL != "" {
		c.ttl, err = time.ParseDuration(global.JWTTTL)
		if err != nil || c.ttl < time.Second || c.ttl%time.Second != 0 {
			return c, errors.New("jwtTtl must be positive whole seconds")
		}
	}
	if (global.JWTSecret == "") == (global.JWTSecretFile == "") {
		return c, errors.New("set exactly one of jwtSecret and jwtSecretFile")
	}
	c.secret = []byte(global.JWTSecret)
	if global.JWTSecretFile != "" {
		c.secret, err = os.ReadFile(global.JWTSecretFile)
		if err != nil {
			return c, errors.New("cannot read jwtSecretFile")
		}
	}
	if len(c.secret) < 32 {
		return c, errors.New("JWT secret must contain at least 32 random bytes")
	}
	return c, nil
}

func parseLogLevel(value string) (slog.Level, error) {
	switch value {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, errors.New("logLevel must be debug, info, warn or error")
	}
}

func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

type app struct {
	next http.Handler
	config
	flowKey []byte
	client  *http.Client
	logger  *slog.Logger
	random  io.Reader
}

func newApp(c config, logger *slog.Logger) *app {
	return &app{config: c, logger: logger, random: rand.Reader, flowKey: mac(c.secret, "cln-iap/flow/v1"), client: &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func mac(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}

func sign(key []byte, prefix string, value any) string {
	payload, _ := json.Marshal(value)
	message := prefix + b64.EncodeToString(payload)
	return message + "." + b64.EncodeToString(mac(key, message))
}

func unsign(key []byte, prefix, token string, value any) error {
	if len(token) > maxToken || !strings.HasPrefix(token, prefix) {
		return errInvalid
	}
	parts := strings.Split(strings.TrimPrefix(token, prefix), ".")
	if len(parts) != 2 {
		return errInvalid
	}
	sig, err := b64.DecodeString(parts[1])
	if err != nil || !hmac.Equal(sig, mac(key, prefix+parts[0])) {
		return errInvalid
	}
	payload, err := b64.DecodeString(parts[0])
	if err != nil || !utf8.Valid(payload) || json.Unmarshal(payload, value) != nil {
		return errInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, payload) {
		return errInvalid
	}
	return nil
}

type claims struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Issued   int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

func (a *app) audience() string { return "cln-iap:" + a.domain }

func (a *app) session(token string) (claims, bool) {
	var c claims
	now := time.Now().Unix()
	valid := unsign(a.secret, jwtHeader+".", token, &c) == nil && strings.TrimSpace(c.Subject) != "" &&
		c.Issuer == a.cas && c.Audience == a.audience() && c.Issued > 0 && c.Issued <= now &&
		c.Expires > now && c.Expires > c.Issued && c.Expires-c.Issued <= int64(a.ttl/time.Second)
	return c, valid
}

func (a *app) allowedLogin(login string) bool { return len(a.logins) == 0 || a.logins[login] }

type flow struct {
	Return  string `json:"return"`
	State   string `json:"state"`
	Expires int64  `json:"exp"`
}

func (a *app) allowedHost(host string) bool {
	if !dnsName(host) {
		return false
	}
	if a.hosts[host] {
		return true
	}
	for pattern := range a.hosts {
		if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) {
			return true
		}
	}
	return false
}

func (a *app) validReturn(raw string) bool {
	if len(raw) > 2048 || strings.ContainsAny(raw, "\\\r\n\t ") || strings.Contains(raw, "#") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Opaque == "" && u.User == nil && a.allowedHost(u.Host)
}

func oneCookie(r *http.Request, name string) string {
	var value string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			value = cookie.Value
			count++
		}
	}
	if count != 1 {
		return ""
	}
	return value
}

func query(r *http.Request, names ...string) (url.Values, bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != len(names) {
		return nil, false
	}
	for _, name := range names {
		if len(q[name]) != 1 || q.Get(name) == "" {
			return nil, false
		}
	}
	return q, true
}

func setCookie(w http.ResponseWriter, name, value, domain string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Domain: domain, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: maxAge})
}

func (a *app) reject(w http.ResponseWriter, code int, level slog.Level, reason string) {
	privateResponse(w)
	a.logger.Log(context.Background(), level, "request_rejected", "reason", reason, "status", code)
	http.Error(w, http.StatusText(code), code)
}

func privateResponse(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || !a.allowedHost(r.Host) {
		a.reject(w, 400, slog.LevelDebug, "invalid_request_origin")
		return
	}
	if r.URL.Path == "/__cln_iap" || strings.HasPrefix(r.URL.Path, "/__cln_iap/") {
		privateResponse(w)
		if r.URL.Path != callbackPath {
			a.reject(w, 404, slog.LevelDebug, "unknown_endpoint")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.reject(w, 405, slog.LevelDebug, "method_not_allowed")
			return
		}
		a.callback(w, r)
		return
	}
	c, valid := a.session(oneCookie(r, authCookie))
	if valid {
		if !a.allowedLogin(c.Subject) {
			a.reject(w, 403, slog.LevelWarn, "login_not_allowed")
			return
		}
		a.next.ServeHTTP(w, r)
		return
	}
	privateResponse(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		a.reject(w, 401, slog.LevelDebug, "authentication_required")
		return
	}
	if oneCookie(r, authCookie) != "" {
		a.logger.Debug("cookie_rejected", "reason", "invalid_auth_cookie", "status", 303)
	}
	a.login(w, r)
}

func (a *app) service(host, state string) string {
	return "https://" + host + callbackPath + "?" + url.Values{"state": {state}}.Encode()
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.RequestURI()
	target := "https://" + r.Host + uri
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") || !a.validReturn(target) {
		a.reject(w, 400, slog.LevelDebug, "invalid_return")
		return
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(a.random, nonce); err != nil {
		a.reject(w, 500, slog.LevelError, "random_generation_failed")
		return
	}
	expires := time.Now().Add(flowTTL)
	f := flow{target, b64.EncodeToString(nonce), expires.Unix()}
	token := sign(a.flowKey, "", f)
	if len(token) > maxToken {
		a.reject(w, 400, slog.LevelDebug, "flow_too_large")
		return
	}
	setCookie(w, flowCookie, token, "", expires, int(flowTTL/time.Second))
	http.Redirect(w, r, a.cas+"/login?"+url.Values{"service": {a.service(r.Host, f.State)}}.Encode(), 303)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	q, ok := query(r, "state", "ticket")
	var f flow
	now := time.Now().Unix()
	if !ok || unsign(a.flowKey, "", oneCookie(r, flowCookie), &f) != nil ||
		f.Expires <= now || f.Expires > now+int64(flowTTL/time.Second) ||
		!hmac.Equal([]byte(f.State), []byte(q.Get("state"))) || !a.validReturn(f.Return) || !strings.HasPrefix(f.Return, "https://"+r.Host+"/") {
		a.reject(w, 400, slog.LevelWarn, "invalid_or_expired_flow")
		return
	}
	nonce, err := b64.DecodeString(f.State)
	if err != nil || len(nonce) != 32 || !strings.HasPrefix(q.Get("ticket"), "ST-") || len(q.Get("ticket")) > 4096 {
		a.reject(w, 400, slog.LevelWarn, "invalid_callback_parameters")
		return
	}
	started := time.Now()
	subject, err := a.validateTicket(r.Context(), q.Get("ticket"), a.service(r.Host, f.State))
	if err != nil {
		level := slog.LevelError
		reason, upstreamStatus := "invalid_response", 0
		if failure, ok := err.(*casError); ok {
			reason, upstreamStatus = failure.reason, failure.status
		}
		if reason == "ticket_rejected" {
			level = slog.LevelWarn
		}
		a.logger.Log(r.Context(), level, "cas_validation_failed", "reason", reason, "status", 502, "cas_status", upstreamStatus, "duration_ms", time.Since(started).Milliseconds())
		http.Error(w, http.StatusText(502), 502)
		return
	}
	if !a.allowedLogin(subject) {
		setCookie(w, flowCookie, "", "", time.Unix(1, 0), -1)
		a.reject(w, 403, slog.LevelWarn, "login_not_allowed")
		return
	}
	now = time.Now().Unix()
	c := claims{subject, a.cas, a.audience(), now, now + int64(a.ttl/time.Second)}
	token := sign(a.secret, jwtHeader+".", c)
	if len(token) > maxToken {
		a.reject(w, 502, slog.LevelError, "jwt_too_large")
		return
	}
	setCookie(w, authCookie, token, a.domain, time.Unix(c.Expires, 0), int(a.ttl/time.Second))
	setCookie(w, flowCookie, "", "", time.Unix(1, 0), -1)
	a.logger.Info("authentication_succeeded", "status", 303, "duration_ms", time.Since(started).Milliseconds())
	http.Redirect(w, r, f.Return, 303)
}
