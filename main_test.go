package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testApp() *app {
	return newApp(config{cas: "https://cas.example.net/cas", auth: "https://auth.example.org",
		domain: "example.org", hosts: map[string]bool{"app1.example.org": true, "app2.example.org": true},
		secret: []byte(strings.Repeat("s", 32)), ttl: 4 * time.Hour}, newLogger(io.Discard, slog.LevelInfo))
}

func request(a *app, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", a.auth+path, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func verifyRequest(host, uri, method string) *http.Request {
	r := httptest.NewRequest("GET", "http://internal/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", uri)
	r.Header.Set("X-Forwarded-Method", method)
	return r
}

func begin(t *testing.T, a *app) (string, *http.Cookie) {
	t.Helper()
	w := request(a, "/login?"+url.Values{"return": {"https://app1.example.org/a%2Fb?x=1&x=2"}}.Encode())
	if w.Code != 303 {
		t.Fatalf("login: %d", w.Code)
	}
	location, _ := url.Parse(w.Header().Get("Location"))
	service := location.Query().Get("service")
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing flow cookie")
	}
	c := cookies[0]
	if c.Name != flowCookie || c.Domain != "" || c.Path != "/" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe flow cookie")
	}
	return service, c
}

func successXML(user string) string {
	return `<cas:serviceResponse xmlns:cas="` + casNamespace + `"><cas:authenticationSuccess><cas:user>` + user + `</cas:user></cas:authenticationSuccess></cas:serviceResponse>`
}

func TestFlow(t *testing.T) {
	for _, wildcard := range []bool{false, true} {
		t.Run(fmt.Sprintf("wildcard=%t", wildcard), func(t *testing.T) {
			a := testApp()
			if wildcard {
				a.hosts = map[string]bool{"*.example.org": true}
			}
			testFlow(t, a)
		})
	}
}

func testFlow(t *testing.T, a *app) {
	service, flowCookieValue := begin(t, a)
	var attempts atomic.Int32
	cas := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/serviceValidate" || r.URL.Query().Get("service") != service || r.URL.Query().Get("ticket") != "ST-once" {
			t.Error("incorrect CAS request")
			w.WriteHeader(400)
			return
		}
		if attempts.Add(1) != 1 {
			fmt.Fprint(w, `<serviceResponse xmlns="`+casNamespace+`"><authenticationFailure/></serviceResponse>`)
			return
		}
		fmt.Fprint(w, successXML("alice"))
	}))
	defer cas.Close()
	a.cas, a.client = cas.URL, cas.Client()
	u, _ := url.Parse(service)
	callback := u.RequestURI() + "&ticket=ST-once"
	w := request(a, callback, flowCookieValue)
	if w.Code != 303 || w.Header().Get("Location") != "https://app1.example.org/a%2Fb?x=1&x=2" {
		t.Fatalf("callback: %d %s", w.Code, w.Header().Get("Location"))
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatal("expected JWT and flow deletion")
	}
	c := cookies[0]
	if c.Name != authCookie || c.Domain != a.domain || !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 14400 || !a.validJWT(c.Value) {
		t.Fatal("unsafe or invalid JWT cookie")
	}
	if cookies[1].Name != flowCookie || cookies[1].MaxAge != -1 || cookies[1].Domain != "" {
		t.Fatal("flow not deleted")
	}
	for _, host := range []string{"app1.example.org", "app2.example.org"} {
		r := verifyRequest(host, "/a%2Fb?x=1&x=2", "POST")
		r.AddCookie(c)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("valid session on %s: %d", host, w.Code)
		}
	}
	if w := request(a, callback, flowCookieValue); w.Code != 502 || len(w.Result().Cookies()) != 0 {
		t.Fatal("ticket reuse accepted")
	}
}

func TestWildcardHosts(t *testing.T) {
	a := testApp()
	a.hosts = map[string]bool{"*.dev.example.org": true, "app1.example.org": true}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"app1.example.org", true},
		{"app.dev.example.org", true},
		{"app.team.dev.example.org", true},
		{"dev.example.org", false},
		{"example.org", false},
		{"app2.example.org", false},
		{"evildev.example.org", false},
		{"app.dev.example.org.evil.org", false},
		{"app.dev.example.org:443", false},
		{"App.dev.example.org", false},
		{".dev.example.org", false},
		{"app..dev.example.org", false},
		{"-app.dev.example.org", false},
		{"app.dev.example.org.", false},
		{"*.dev.example.org", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			if got := a.allowedHost(tc.host); got != tc.want {
				t.Fatalf("allowedHost = %t, want %t", got, tc.want)
			}
			target := "https://" + tc.host + "/path?x=1"
			want := 400
			if tc.want {
				want = 303
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, verifyRequest(tc.host, "/path?x=1", "GET"))
			if w.Code != want {
				t.Errorf("verify = %d, want %d", w.Code, want)
			}
			if w := request(a, "/login?"+url.Values{"return": {target}}.Encode()); w.Code != want {
				t.Errorf("login = %d, want %d", w.Code, want)
			}
			if !tc.want {
				f := flow{target, b64.EncodeToString(make([]byte, 32)), time.Now().Add(time.Minute).Unix()}
				cookie := &http.Cookie{Name: flowCookie, Value: sign(a.flowKey, "", f)}
				if w := request(a, "/callback?state="+f.State+"&ticket=ST-test", cookie); w.Code != 400 {
					t.Errorf("callback accepted forbidden return: %d", w.Code)
				}
			}
		})
	}
	a.hosts = map[string]bool{"*.example.org": true}
	if a.allowedHost("example.org") || a.allowedHost("auth.example.org") {
		t.Fatal("wildcard allowed base domain or authentication host")
	}
	a.hosts["example.org"] = true
	if !a.allowedHost("example.org") {
		t.Fatal("explicit base domain rejected")
	}
	for _, target := range []string{"https://auth.example.org/", "http://app.example.org/", "https://user@app.example.org/", "https://app.example.org:443/"} {
		if a.validReturn(target) {
			t.Errorf("unsafe wildcard return accepted: %s", target)
		}
	}
}

func TestJWT(t *testing.T) {
	a := testApp()
	now := time.Now().Unix()
	valid := claims{"alice", a.auth, a.audience(), now, now + 3600}
	token := sign(a.secret, jwtHeader+".", valid)
	if !a.validJWT(token) {
		t.Fatal("valid token rejected")
	}
	for name, mutate := range map[string]func(*claims){
		"subject": func(c *claims) { c.Subject = " " }, "issuer": func(c *claims) { c.Issuer = "other" },
		"audience": func(c *claims) { c.Audience = "other" }, "future": func(c *claims) { c.Issued = now + 60 },
		"expired": func(c *claims) { c.Expires = now }, "zero iat": func(c *claims) { c.Issued = 0 },
		"duration": func(c *claims) { c.Expires = now + 20000 },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			mutate(&c)
			if a.validJWT(sign(a.secret, jwtHeader+".", c)) {
				t.Fatal("accepted")
			}
		})
	}
	for _, bad := range []string{token + "x", "", "x.y.z", strings.Replace(token, jwtHeader, b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)), 1), token + ".extra"} {
		if a.validJWT(bad) {
			t.Fatal("invalid JWT accepted")
		}
	}
	for _, payload := range []string{
		fmt.Sprintf(`{"sub":"alice","sub":"bob","iss":%q,"aud":%q,"iat":%d,"exp":%d}`, a.auth, a.audience(), now, now+3600),
		fmt.Sprintf(`{"sub":"alice","iss":%q,"aud":%q,"iat":"%d","exp":%d}`, a.auth, a.audience(), now, now+3600),
		`{"sub":"alice"}`, `null`,
	} {
		message := jwtHeader + "." + b64.EncodeToString([]byte(payload))
		if a.validJWT(message + "." + b64.EncodeToString(mac(a.secret, message))) {
			t.Fatal("ambiguous claims accepted")
		}
	}
	a.secret = []byte(strings.Repeat("r", 32))
	if a.validJWT(token) {
		t.Fatal("old secret accepted")
	}
}

func TestCookieSize(t *testing.T) {
	w := httptest.NewRecorder()
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	setCookie(w, authCookie, strings.Repeat("x", maxToken), domain, time.Now().Add(4*time.Hour), 14400)
	if len(w.Header().Get("Set-Cookie")) > 4096 {
		t.Fatal("cookie exceeds browser limit")
	}
	if testApp().validJWT(strings.Repeat("x", maxToken+1)) {
		t.Fatal("oversized token accepted")
	}
}

func TestRedirectsAndHeaders(t *testing.T) {
	a := testApp()
	for _, target := range []string{"https://evil.org/", "//evil.org/", "http://app1.example.org/", "https://app1.example.org.evil.org/", "https://app1.example.org:443/", "https://user@app1.example.org/", "https://auth.example.org/", "https://app1.example.org/#x", "https://app1.example.org\\@evil.org/", "https://app1.example.org/\r\n"} {
		if w := request(a, "/login?"+url.Values{"return": {target}}.Encode()); w.Code != 400 || len(w.Result().Cookies()) != 0 {
			t.Errorf("unsafe return accepted: %q", target)
		}
	}
	for _, path := range []string{"/login?return=x&return=y", "/login?return=%zz", "/login", "/callback?state=a&state=b&ticket=ST-x"} {
		if w := request(a, path); w.Code != 400 {
			t.Errorf("bad query accepted: %s", path)
		}
	}
	for name, mutate := range map[string]func(*http.Request){
		"proto":     func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") },
		"host":      func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "evil.org") },
		"duplicate": func(r *http.Request) { r.Header.Add("X-Forwarded-Host", "app2.example.org") },
		"list":      func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "app1.example.org, evil.org") },
		"uri":       func(r *http.Request) { r.Header.Set("X-Forwarded-Uri", "//evil.org/") },
		"absolute":  func(r *http.Request) { r.Header.Set("X-Forwarded-Uri", "https://evil.org/") },
	} {
		t.Run(name, func(t *testing.T) {
			r := verifyRequest("app1.example.org", "/", "GET")
			mutate(r)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatal(w.Code)
			}
		})
	}
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "", "GET, POST"} {
		r := verifyRequest("app1.example.org", "/a%2Fb?x=1&x=2", method)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		expected := 401
		if method == "GET" || method == "HEAD" {
			expected = 303
		}
		if w.Code != expected {
			t.Fatalf("%s: %d", method, w.Code)
		}
		if expected == 303 {
			u, _ := url.Parse(w.Header().Get("Location"))
			if u.Query().Get("return") != "https://app1.example.org/a%2Fb?x=1&x=2" {
				t.Fatal("return changed")
			}
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("missing privacy headers")
		}
	}
	now := time.Now().Unix()
	c := &http.Cookie{Name: authCookie, Value: sign(a.secret, jwtHeader+".", claims{"alice", a.auth, a.audience(), now, now + 3600})}
	r := verifyRequest("app1.example.org", "/", "GET")
	r.AddCookie(c)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatal("duplicate JWT cookies accepted")
	}
}

func TestFlowFailures(t *testing.T) {
	a := testApp()
	service, cookie := begin(t, a)
	u, _ := url.Parse(service)
	var f flow
	if err := unsign(a.flowKey, "", cookie.Value, &f); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*flow){
		"expired": func(f *flow) { f.Expires = time.Now().Unix() },
		"future":  func(f *flow) { f.Expires += 3600 },
		"state":   func(f *flow) { f.State = "wrong" },
		"return":  func(f *flow) { f.Return = "https://evil.org/" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := f
			change(&bad)
			c := &http.Cookie{Name: flowCookie, Value: sign(a.flowKey, "", bad)}
			w := request(a, u.RequestURI()+"&ticket=ST-x", c)
			if w.Code != 400 || len(w.Result().Cookies()) != 0 {
				t.Fatal("bad flow accepted")
			}
		})
	}
	_, replacement := begin(t, a)
	for _, cookies := range [][]*http.Cookie{nil, {cookie, cookie}, {{Name: flowCookie, Value: cookie.Value + "x"}}, {replacement}} {
		if w := request(a, u.RequestURI()+"&ticket=ST-x", cookies...); w.Code != 400 {
			t.Fatal("invalid flow accepted")
		}
	}
	a.flowKey = mac([]byte(strings.Repeat("r", 32)), "cas-forwardauth/flow/v1")
	if w := request(a, u.RequestURI()+"&ticket=ST-x", cookie); w.Code != 400 {
		t.Fatal("old flow secret accepted")
	}
}

func TestCASResponses(t *testing.T) {
	valid := successXML("alice")
	cases := []struct {
		name, body string
		status     int
		valid      bool
	}{
		{"success", valid, 200, true},
		{"attributes", strings.Replace(valid, "</cas:authenticationSuccess>", "<cas:attributes><cas:role>ignored</cas:role></cas:attributes></cas:authenticationSuccess>", 1), 200, true},
		{"empty user", successXML(" "), 200, false},
		{"nested user", successXML("<cas:name>alice</cas:name>"), 200, false},
		{"duplicate user", strings.Replace(valid, "</cas:user>", "</cas:user><cas:user>bob</cas:user>", 1), 200, false},
		{"failure", strings.Replace(valid, "</cas:serviceResponse>", "<cas:authenticationFailure/></cas:serviceResponse>", 1), 200, false},
		{"duplicate success", strings.Replace(valid, "</cas:serviceResponse>", "<cas:authenticationSuccess><cas:user>bob</cas:user></cas:authenticationSuccess></cas:serviceResponse>", 1), 200, false},
		{"namespace", strings.ReplaceAll(valid, casNamespace, "https://evil.org"), 200, false},
		{"trailing", valid + valid, 200, false},
		{"malformed", "<", 200, false},
		{"large", valid + strings.Repeat(" ", 64<<10), 200, false},
		{"status", valid, 500, false},
		{"redirect", valid, 302, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := testApp()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/other")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			a.cas = server.URL
			a.client.Transport = server.Client().Transport
			user, err := a.validateTicket(context.Background(), "ST-x", a.service("state"))
			if tc.valid && (err != nil || user != "alice") || !tc.valid && err == nil {
				t.Fatalf("user=%q err=%v", user, err)
			}
		})
	}
	a := testApp()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	a.cas = server.URL
	a.client.Transport = server.Client().Transport
	a.client.Timeout = 20 * time.Millisecond
	if _, err := a.validateTicket(context.Background(), "ST-x", "service"); err == nil || err.Error() != "timeout" {
		t.Fatalf("timeout classification: %v", err)
	}
	a.client = newApp(a.config, a.logger).client // No trust for the test server's certificate.
	if _, err := a.validateTicket(context.Background(), "ST-x", "service"); err == nil || err.Error() != "tls_error" {
		t.Fatalf("TLS classification: %v", err)
	}
	server.Close()
	if _, err := a.validateTicket(context.Background(), "ST-x", "service"); err == nil || err.Error() != "network_error" {
		t.Fatalf("network classification: %v", err)
	}
}

func TestConfig(t *testing.T) {
	baseline := map[string]string{"CAS_URL": "https://cas.example.net/cas", "AUTH_URL": "https://auth.example.org", "COOKIE_DOMAIN": "example.org", "ALLOWED_HOSTS": "app1.example.org,app2.example.org", "JWT_SECRET": strings.Repeat("s", 32), "JWT_SECRET_FILE": "", "JWT_TTL": "", "LOG_LEVEL": ""}
	for key, value := range baseline {
		t.Setenv(key, value)
	}
	if c, err := loadConfig(); err != nil || c.ttl != 4*time.Hour {
		t.Fatalf("default: %v", err)
	}
	for key, values := range map[string][]string{
		"CAS_URL":       {"http://cas.example.net", "https://user@cas.example.net", "https://cas.example.net?x=1"},
		"AUTH_URL":      {"https://auth.example.org/path", "https://evil.org"},
		"COOKIE_DOMAIN": {"org", "other.org", ".example.org"},
		"ALLOWED_HOSTS": {"", "*", "*example.org", "app.*.example.org", "*.*.example.org", "*.other.org", "*.org", "*.example.org.evil.org", "*.example.org:443", "*.Example.org", "*.example.org,", "app.example.org.evil.org", "auth.example.org", "app.example.org:443"},
		"JWT_SECRET":    {"", "short"}, "JWT_SECRET_FILE": {"/missing"}, "JWT_TTL": {"0s", "-1h", "1.5s", "invalid"},
	} {
		for _, value := range values {
			t.Run(key+"="+value, func(t *testing.T) {
				t.Setenv(key, value)
				if _, err := loadConfig(); err == nil {
					t.Fatal("invalid config accepted")
				}
			})
		}
	}
	for _, value := range []string{"*.example.org", "*.dev.example.org, app1.example.org", "example.org,*.example.org", "*.auth.example.org"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ALLOWED_HOSTS", value)
			c, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if !newApp(c, newLogger(io.Discard, slog.LevelInfo)).allowedHost("app.dev.example.org") && value != "*.auth.example.org" {
				t.Fatal("wildcard configuration did not allow nested host")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(strings.Repeat("f", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SECRET", "")
	t.Setenv("JWT_SECRET_FILE", path)
	if c, err := loadConfig(); err != nil || string(c.secret) != strings.Repeat("f", 32) {
		t.Fatal("secret file failed")
	}
}

// RUN_TRAEFIK_TEST=1 go test -run TestTraefik -v
// Uses Docker Desktop's host.docker.internal to reach temporary Go test servers.
// No production service or Docker socket is exposed to the Traefik container.
func TestTraefik(t *testing.T) {
	if os.Getenv("RUN_TRAEFIK_TEST") != "1" {
		t.Skip("set RUN_TRAEFIK_TEST=1 with Docker Desktop to test Traefik v2.11")
	}
	listen := func(handler http.Handler) *httptest.Server {
		s := httptest.NewUnstartedServer(handler)
		s.Listener.Close()
		var err error
		s.Listener, err = net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		s.Start()
		t.Cleanup(s.Close)
		return s
	}
	a := testApp()
	var calls atomic.Int32
	backend := listen(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, r.Host+r.URL.RequestURI()) }))
	var lock sync.Mutex
	tickets := map[string]string{}
	cas := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		service := r.URL.Query().Get("service")
		if r.URL.Path == "/login" {
			ticket := fmt.Sprintf("ST-%d", time.Now().UnixNano())
			tickets[ticket] = service
			http.Redirect(w, r, service+"&ticket="+ticket, 303)
			return
		}
		ticket := r.URL.Query().Get("ticket")
		stored, ok := tickets[ticket]
		delete(tickets, ticket)
		if !ok || service != stored {
			w.WriteHeader(400)
			return
		}
		fmt.Fprint(w, successXML("alice"))
	}))
	defer cas.Close()
	a.cas, a.client = cas.URL, cas.Client()
	auth := listen(a)
	internalURL := func(s *httptest.Server) string {
		_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
		return "http://host.docker.internal:" + port
	}
	dynamic := fmt.Sprintf(`http:
  routers:
    apps:
      rule: "Host(`+"`app1.example.org`"+`) || Host(`+"`app2.example.org`"+`)"
      service: app
      middlewares: [auth]
      tls: {}
    login:
      rule: "Host(`+"`auth.example.org`"+`) && (Path(`+"`/login`"+`) || Path(`+"`/callback`"+`))"
      service: auth
      tls: {}
  middlewares:
    auth:
      forwardAuth:
        address: %s/verify
        trustForwardHeader: false
        authRequestHeaders: [Cookie]
  services:
    auth:
      loadBalancer:
        servers:
          - url: %s
    app:
      loadBalancer:
        servers:
          - url: %s
`, internalURL(auth), internalURL(auth), internalURL(backend))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dynamic.yml"), []byte(dynamic), 0600); err != nil {
		t.Fatal(err)
	}
	docker := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", args...).Output()
		if err != nil {
			t.Fatalf("docker %s: %s: %v", args[0], out, err)
		}
		return strings.TrimSpace(string(out))
	}
	container := docker("run", "-d", "--rm", "-p", "127.0.0.1::443", "-v", dir+":/config:ro", "traefik:v2.11", "--entrypoints.websecure.address=:443", "--providers.file.filename=/config/dynamic.yml")
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", container).Run() })
	addr := docker("port", container, "443/tcp")
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 10 * time.Second, Jar: jar, Transport: &http.Transport{
		// Only Traefik's disposable test certificate is untrusted here.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if strings.HasPrefix(address, "127.0.0.1:") {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	defer client.CloseIdleConnections()
	// Docker may publish the port before Traefik has loaded its routers.
	deadline := time.Now().Add(15 * time.Second)
	for {
		res, err := client.Get("https://auth.example.org/login")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 400 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Traefik did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(c *http.Client, method, target string, forged bool) (int, string, string) {
		t.Helper()
		r, _ := http.NewRequest(method, target, nil)
		if forged {
			r.Header.Set("X-Forwarded-Host", "evil.org")
			r.Header.Set("X-Forwarded-Proto", "http")
			r.Header.Set("X-Forwarded-Uri", "//evil.org/")
			r.Header.Set("X-Forwarded-Method", "POST")
		}
		res, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body), res.Header.Get("Location")
	}
	code, _, location := get(&noRedirect, "GET", "https://app1.example.org/a%2Fb?x=1&x=2", true)
	if code != 303 || calls.Load() != 0 {
		t.Fatalf("unauthenticated access: %d, calls=%d", code, calls.Load())
	}
	u, _ := url.Parse(location)
	if u.Query().Get("return") != "https://app1.example.org/a%2Fb?x=1&x=2" {
		t.Fatal("forged forwarded headers trusted")
	}
	if code, _, _ := get(&noRedirect, "POST", "https://app1.example.org/", false); code != 401 || calls.Load() != 0 {
		t.Fatal("unauthenticated POST passed")
	}
	if code, _, _ := get(&noRedirect, "GET", "https://auth.example.org/verify", false); code != 404 {
		t.Fatal("verify publicly routed")
	}
	code, body, _ := get(client, "GET", "https://app1.example.org/a%2Fb?x=1&x=2", false)
	if code != 200 || body != "app1.example.org/a%2Fb?x=1&x=2" || calls.Load() != 1 {
		t.Fatalf("full flow: %d %q calls=%d", code, body, calls.Load())
	}
	code, body, _ = get(&noRedirect, "GET", "https://app2.example.org/second", false)
	if code != 200 || body != "app2.example.org/second" || calls.Load() != 2 {
		t.Fatal("shared cookie failed")
	}
	t.Log("Traefik v2.11: full CAS flow, shared cookie, spoofed headers, private verify and fail-closed access passed")
}
