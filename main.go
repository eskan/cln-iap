// CAS ForwardAuth. Terminate HTTPS at Traefik; expose only /login and /callback
// on IAP_URL, without ForwardAuth. Keep /verify and application ports private.
// Use trustForwardHeader=false and run ForwardAuth before path rewriting.
package main

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
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	authCookie = "__Secure-cas-auth"
	flowCookie = "__Host-cas-flow"
	jwtHeader  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"HS256","typ":"JWT"}
	flowTTL    = 5 * time.Minute
	maxToken   = 3500 // Leave room for the cookie name, domain and attributes within 4 KiB.
)

var b64 = base64.RawURLEncoding.Strict()
var errInvalid = errors.New("invalid authentication data")

type config struct {
	cas, auth, domain string
	hosts             map[string]bool
	secret            []byte
	ttl               time.Duration
	logLevel          slog.Level
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

func loadConfig() (config, error) {
	c := config{cas: os.Getenv("CAS_URL"), auth: os.Getenv("IAP_URL"),
		domain: os.Getenv("COOKIE_DOMAIN"), hosts: map[string]bool{}, ttl: 4 * time.Hour}
	level, err := parseLogLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		return c, err
	}
	c.logLevel = level
	cas, err := httpsURL(c.cas)
	if err != nil || strings.Contains(cas.Path, "//") {
		return c, errors.New("invalid CAS_URL")
	}
	c.cas = strings.TrimRight(c.cas, "/")
	auth, err := httpsURL(c.auth)
	if err != nil || auth.Path != "" && auth.Path != "/" {
		return c, errors.New("IAP_URL must be an HTTPS origin")
	}
	c.auth = strings.TrimSuffix(c.auth, "/")
	within := func(host string) bool { return host == c.domain || strings.HasSuffix(host, "."+c.domain) }
	if !dnsName(c.domain) || !within(auth.Host) {
		return c, errors.New("invalid COOKIE_DOMAIN or IAP_URL outside domain")
	}
	for _, host := range strings.Split(os.Getenv("ALLOWED_HOSTS"), ",") {
		host = strings.TrimSpace(host)
		base := strings.TrimPrefix(host, "*.")
		if !dnsName(base) || !within(base) || host == auth.Host {
			return c, errors.New("invalid ALLOWED_HOSTS")
		}
		c.hosts[host] = true
	}
	if value := os.Getenv("JWT_TTL"); value != "" {
		c.ttl, err = time.ParseDuration(value)
		if err != nil || c.ttl < time.Second || c.ttl%time.Second != 0 {
			return c, errors.New("JWT_TTL must be a positive whole number of seconds")
		}
	}
	secret, file := os.Getenv("JWT_SECRET"), os.Getenv("JWT_SECRET_FILE")
	if (secret == "") == (file == "") {
		return c, errors.New("set exactly one of JWT_SECRET and JWT_SECRET_FILE")
	}
	c.secret = []byte(secret)
	if file != "" {
		c.secret, err = os.ReadFile(file)
		if err != nil {
			return c, errors.New("cannot read JWT_SECRET_FILE")
		}
	}
	// Secret files are read verbatim; use the same bytes on every replica.
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
		return slog.LevelInfo, errors.New("LOG_LEVEL must be debug, info, warn or error")
	}
}

func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// net/http diagnostics can contain request data or panic values; never forward them raw.
type serverLogWriter struct{ logger *slog.Logger }

func (w serverLogWriter) Write(p []byte) (int, error) {
	w.logger.Error("http_server_error", "reason", "internal_http_error")
	return len(p), nil
}

type app struct {
	config
	flowKey []byte
	client  *http.Client
	logger  *slog.Logger
}

func newApp(c config, logger *slog.Logger) *app {
	return &app{config: c, logger: logger, flowKey: mac(c.secret, "cas-forwardauth/flow/v1"), client: &http.Client{
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
	payload, _ := json.Marshal(value) // Only concrete structs with strings and integers.
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
	// Accept only our own canonical encoding: no duplicate/unknown fields,
	// alternate claim types, missing fields, or ambiguous JSON representations.
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

func (a *app) audience() string { return "cas-forwardauth:" + a.domain }

func (a *app) validJWT(token string) bool {
	var c claims
	now := time.Now().Unix()
	return unsign(a.secret, jwtHeader+".", token, &c) == nil && strings.TrimSpace(c.Subject) != "" &&
		c.Issuer == a.auth && c.Audience == a.audience() && c.Issued > 0 && c.Issued <= now &&
		c.Expires > now && c.Expires > c.Issued && c.Expires-c.Issued <= int64(a.ttl/time.Second)
}

type flow struct {
	Return  string `json:"return"`
	State   string `json:"state"`
	Expires int64  `json:"exp"`
}

func (a *app) allowedHost(host string) bool {
	if !dnsName(host) || host == strings.TrimPrefix(a.auth, "https://") {
		return false
	}
	if a.hosts[host] {
		return true
	}
	for pattern := range a.hosts {
		// The leading dot enforces a label boundary and excludes the base domain.
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

func oneHeader(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
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
	a.logger.Log(context.Background(), level, "request_rejected", "reason", reason, "status", code)
	http.Error(w, http.StatusText(code), code)
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		a.reject(w, 405, slog.LevelDebug, "method_not_allowed")
		return
	}
	if r.URL.Path == "/verify" {
		a.verify(w, r)
		return
	}
	if r.Host != strings.TrimPrefix(a.auth, "https://") {
		a.reject(w, 400, slog.LevelDebug, "invalid_auth_host")
		return
	}
	switch r.URL.Path {
	case "/login":
		a.login(w, r)
	case "/callback":
		a.callback(w, r)
	default:
		a.reject(w, 404, slog.LevelDebug, "unknown_endpoint")
	}
}

func (a *app) verify(w http.ResponseWriter, r *http.Request) {
	host, uri := oneHeader(r, "X-Forwarded-Host"), oneHeader(r, "X-Forwarded-Uri")
	target := "https://" + host + uri
	if oneHeader(r, "X-Forwarded-Proto") != "https" || !a.allowedHost(host) ||
		!strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") || !a.validReturn(target) {
		a.reject(w, 400, slog.LevelDebug, "invalid_forwarded_request")
		return
	}
	if a.validJWT(oneCookie(r, authCookie)) {
		w.WriteHeader(200)
		return
	}
	method := oneHeader(r, "X-Forwarded-Method")
	if method != http.MethodGet && method != http.MethodHead {
		a.reject(w, 401, slog.LevelDebug, "authentication_required")
		return
	}
	if len(r.Cookies()) > 0 {
		for _, cookie := range r.Cookies() {
			if cookie.Name == authCookie {
				a.logger.Debug("cookie_rejected", "reason", "invalid_auth_cookie", "status", 303)
				break
			}
		}
	}
	http.Redirect(w, r, a.auth+"/login?"+url.Values{"return": {target}}.Encode(), 303)
}

func (a *app) service(state string) string {
	return a.auth + "/callback?" + url.Values{"state": {state}}.Encode()
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	q, ok := query(r, "return")
	if !ok || !a.validReturn(q.Get("return")) {
		a.reject(w, 400, slog.LevelDebug, "invalid_return")
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		a.reject(w, 500, slog.LevelError, "random_generation_failed")
		return
	}
	expires := time.Now().Add(flowTTL)
	f := flow{q.Get("return"), b64.EncodeToString(nonce), expires.Unix()}
	token := sign(a.flowKey, "", f)
	if len(token) > maxToken {
		a.reject(w, 400, slog.LevelDebug, "flow_too_large")
		return
	}
	setCookie(w, flowCookie, token, "", expires, int(flowTTL/time.Second))
	http.Redirect(w, r, a.cas+"/login?"+url.Values{"service": {a.service(f.State)}}.Encode(), 303)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	q, ok := query(r, "state", "ticket")
	var f flow
	now := time.Now().Unix()
	if !ok || unsign(a.flowKey, "", oneCookie(r, flowCookie), &f) != nil ||
		f.Expires <= now || f.Expires > now+int64(flowTTL/time.Second) ||
		!hmac.Equal([]byte(f.State), []byte(q.Get("state"))) || !a.validReturn(f.Return) {
		a.reject(w, 400, slog.LevelWarn, "invalid_or_expired_flow")
		return
	}
	nonce, err := b64.DecodeString(f.State)
	if err != nil || len(nonce) != 32 || !strings.HasPrefix(q.Get("ticket"), "ST-") || len(q.Get("ticket")) > 4096 {
		a.reject(w, 400, slog.LevelWarn, "invalid_callback_parameters")
		return
	}
	started := time.Now()
	subject, err := a.validateTicket(r.Context(), q.Get("ticket"), a.service(f.State))
	if err != nil {
		level := slog.LevelError
		reason, upstreamStatus := "invalid_response", 0
		var failure *casError
		if errors.As(err, &failure) {
			reason, upstreamStatus = failure.reason, failure.status
		}
		if reason == "ticket_rejected" {
			level = slog.LevelWarn
		}
		a.logger.Log(r.Context(), level, "cas_validation_failed", "reason", reason, "status", 502, "cas_status", upstreamStatus, "duration_ms", time.Since(started).Milliseconds())
		http.Error(w, http.StatusText(502), 502)
		return
	}
	now = time.Now().Unix()
	c := claims{subject, a.auth, a.audience(), now, now + int64(a.ttl/time.Second)}
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

func main() {
	logger := newLogger(os.Stdout, slog.LevelInfo)
	c, err := loadConfig()
	if err != nil {
		logger.Error("configuration_invalid", "reason", err.Error())
		os.Exit(1)
	}
	logger = newLogger(os.Stdout, c.logLevel)
	server := &http.Server{Addr: ":8080", Handler: newApp(c, logger), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(serverLogWriter{logger}, "", 0)}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.Error("server_failed", "reason", "listen_failed")
		os.Exit(1)
	}
	logger.Info("server_started", "address", server.Addr)
	if err := server.Serve(listener); err != nil {
		logger.Error("server_failed", "reason", "serve_failed")
		os.Exit(1)
	}
}
