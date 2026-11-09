package cln_iap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testGlobal() adminConfig {
	return adminConfig{CASURL: "https://cas.example.net/cas", CookieDomain: "example.org", AllowedHosts: []string{"app1.example.org", "app2.example.org"}, JWTSecret: strings.Repeat("s", 32)}
}
func testApp() *app {
	c, err := configure(testGlobal(), CreateConfig())
	if err != nil {
		panic(err)
	}
	a := newApp(c, newLogger(io.Discard, slog.LevelInfo))
	a.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	return a
}
func (a *app) validJWT(token string) bool { _, ok := a.session(token); return ok }
func request(a *app, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://app1.example.org"+path, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func verifyRequest(host, uri, method string) *http.Request {
	return httptest.NewRequest(method, "https://"+host+uri, nil)
}
func begin(t *testing.T, a *app) (string, *http.Cookie) {
	t.Helper()
	w := request(a, "/a%2Fb?x=1&x=2")
	if w.Code != 303 {
		t.Fatalf("start: %d", w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	cs := w.Result().Cookies()
	if len(cs) != 1 || cs[0].Name != flowCookie || cs[0].Domain != "" || !cs[0].Secure || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe flow cookie")
	}
	return u.Query().Get("service"), cs[0]
}
func successXML(user string) string {
	return `<cas:serviceResponse xmlns:cas="` + casNamespace + `"><cas:authenticationSuccess><cas:user>` + user + `</cas:user></cas:authenticationSuccess></cas:serviceResponse>`
}
func authToken(a *app, user string) *http.Cookie {
	now := time.Now().Unix()
	return &http.Cookie{Name: authCookie, Value: sign(a.secret, jwtHeader+".", claims{user, a.cas, a.audience(), now, now + 3600})}
}
func TestJWT(t *testing.T) {
	a := testApp()
	now := time.Now().Unix()
	valid := claims{"alice", a.cas, a.audience(), now, now + 3600}
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
		fmt.Sprintf(`{"sub":"alice","sub":"bob","iss":%q,"aud":%q,"iat":%d,"exp":%d}`, a.cas, a.audience(), now, now+3600),
		fmt.Sprintf(`{"sub":"alice","iss":%q,"aud":%q,"iat":"%d","exp":%d}`, a.cas, a.audience(), now, now+3600),
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
	a.flowKey = mac([]byte(strings.Repeat("r", 32)), "cln-iap/flow/v1")
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
			user, err := a.validateTicket(context.Background(), "ST-x", a.service("app1.example.org", "state"))
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
	for _, value := range []string{"", " ", "alice", " alice, bob,alice "} {
		c, e := configure(testGlobal(), &Config{AllowedLogins: value})
		if e != nil {
			t.Fatal(e)
		}
		a := newApp(c, newLogger(io.Discard, slog.LevelInfo))
		if !a.allowedLogin("alice") {
			t.Fatal("alice denied")
		}
		if strings.TrimSpace(value) != "" && a.allowedLogin("Alice") {
			t.Fatal("case folded")
		}
	}
	for _, v := range []string{",", "alice,", ",alice", "alice, ,bob"} {
		if _, e := configure(testGlobal(), &Config{AllowedLogins: v}); e == nil {
			t.Fatal("empty login accepted")
		}
	}
	for name, change := range map[string]func(*adminConfig){
		"cas":      func(c *adminConfig) { c.CASURL = "http://cas.example.net" },
		"domain":   func(c *adminConfig) { c.CookieDomain = "org" },
		"hosts":    func(c *adminConfig) { c.AllowedHosts = nil },
		"outside":  func(c *adminConfig) { c.AllowedHosts = []string{"*.evil.org"} },
		"wildcard": func(c *adminConfig) { c.AllowedHosts = []string{"*example.org"} },
		"ttl":      func(c *adminConfig) { c.JWTTTL = "1.5s" },
		"secret":   func(c *adminConfig) { c.JWTSecret = "short" },
		"both":     func(c *adminConfig) { c.JWTSecretFile = "/missing" },
		"file":     func(c *adminConfig) { c.JWTSecret = ""; c.JWTSecretFile = "/missing" },
		"level":    func(c *adminConfig) { c.LogLevel = "trace" },
	} {
		t.Run(name, func(t *testing.T) {
			c := testGlobal()
			change(&c)
			if _, e := configure(c, CreateConfig()); e == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte(strings.Repeat("x", 32)), 0600)
	g := testGlobal()
	g.JWTSecret = ""
	g.JWTSecretFile = secret
	if c, e := configure(g, CreateConfig()); e != nil || string(c.secret) != strings.Repeat("x", 32) {
		t.Fatal("file secret", e)
	}
	file := filepath.Join(dir, "config.json")
	for _, value := range []string{`{}`, `{"allowedLogins":"alice"}`, `{} {}`, `null`, `{"casUrl":42}`} {
		os.WriteFile(file, []byte(value), 0600)
		if _, e := loadConfig(file, CreateConfig()); e == nil {
			t.Fatal("invalid global config accepted")
		}
	}
	if _, e := New(context.Background(), nil, CreateConfig(), "test"); e == nil {
		t.Fatal("nil next accepted")
	}
}

func TestHostsAndOrigins(t *testing.T) {
	a := testApp()
	a.hosts = map[string]bool{"*.example.org": true}
	for _, host := range []string{"app.example.org", "nested.app.example.org"} {
		if !a.allowedHost(host) {
			t.Fatal(host)
		}
	}
	for _, host := range []string{"example.org", "evil.org", "example.org.evil.org", "app.example.org:443", "APP.example.org"} {
		if a.allowedHost(host) {
			t.Fatal(host)
		}
	}
	for _, target := range []string{"http://app.example.org/", "https://user@app.example.org/", "https://evil.org/", "https://app.example.org/#x", "https://app.example.org\\@evil.org/"} {
		if a.validReturn(target) {
			t.Fatal(target)
		}
	}
	r := verifyRequest("app.example.org", "/", "GET")
	r.TLS = nil
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("insecure origin")
	}
	r = verifyRequest("app.example.org", "/", "GET")
	r.Header.Set("X-Forwarded-Host", "evil.org")
	r.Header.Set("X-Forwarded-Uri", "//evil.org/")
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	u, _ := url.Parse(w.Header().Get("Location"))
	if !strings.HasPrefix(u.Query().Get("service"), "https://app.example.org/__cln_iap/callback?") {
		t.Fatal("spoofed origin")
	}
}

func TestAuthorizationAndPassthrough(t *testing.T) {
	a := testApp()
	cookie := authToken(a, "alice")
	a.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(201)
		fmt.Fprintf(w, "%s:%s:%s", r.Method, r.URL.RequestURI(), body)
	})
	r := httptest.NewRequest("POST", "https://app1.example.org/a%2Fb?x=1&x=2", strings.NewReader("body"))
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 201 || w.Body.String() != "POST:/a%2Fb?x=1&x=2:body" || w.Header().Get("Referrer-Policy") != "" || w.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Fatal("changed request or response", w)
	}
	restricted := testApp()
	restricted.logins = map[string]bool{"bob": true}
	if w = request(restricted, "/", cookie); w.Code != 403 || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 {
		t.Fatal("restricted session", w.Code)
	}
	restricted.logins = map[string]bool{"alice": true}
	if request(restricted, "/", cookie).Code != 200 {
		t.Fatal("allowed session")
	}
	restricted.logins = map[string]bool{"bob": true}
	if request(restricted, "/", cookie).Code != 403 {
		t.Fatal("removed login")
	}
	if request(testApp(), "/", cookie).Code != 200 {
		t.Fatal("shared session lost")
	}
	if request(testApp(), "/", cookie, cookie).Code != 303 {
		t.Fatal("duplicate cookie")
	}
	for _, path := range []string{"/__cln_iap", "/__cln_iap/", "/__cln_iap/unknown"} {
		if request(testApp(), path, cookie).Code != 404 {
			t.Fatal(path)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
		w := httptest.NewRecorder()
		testApp().ServeHTTP(w, verifyRequest("app1.example.org", "/", method))
		if w.Code != 401 {
			t.Fatal(method)
		}
	}
}

func TestFlow(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			a := testApp()
			if !allowed {
				a.logins = map[string]bool{"bob": true}
			}
			service, cookie := begin(t, a)
			a.client.Transport = logTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Query().Get("service") != service || r.URL.Query().Get("ticket") != "ST-once" {
					t.Error("CAS service mismatch")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(successXML("alice"))), Header: make(http.Header)}, nil
			})
			u, _ := url.Parse(service)
			r := verifyRequest("app2.example.org", u.RequestURI()+"&ticket=ST-once", "GET")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatal("cross-host callback")
			}
			w = request(a, u.RequestURI()+"&ticket=ST-once", cookie)
			if !allowed {
				if w.Code != 403 {
					t.Fatal(w.Code)
				}
				for _, c := range w.Result().Cookies() {
					if c.Name == authCookie {
						t.Fatal("issued unauthorized cookie")
					}
				}
				return
			}
			if w.Code != 303 || w.Header().Get("Location") != "https://app1.example.org/a%2Fb?x=1&x=2" {
				t.Fatal("callback", w)
			}
			cs := w.Result().Cookies()
			if len(cs) != 2 || cs[0].Domain != "example.org" || !cs[0].Secure || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteLaxMode || cs[1].MaxAge != -1 {
				t.Fatal("cookies")
			}
			if request(a, "/", cs[0]).Code != 200 {
				t.Fatal("session")
			}
		})
	}
}

func TestAdministratorFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cln-iap.json")
	valid := `{"casUrl":"https://cas.example.net/cas","cookieDomain":"example.org","allowedHosts":["app1.example.org"],"jwtSecret":"ssssssssssssssssssssssssssssssss"}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path, &Config{AllowedLogins: "alice"})
	if err != nil || !c.logins["alice"] || c.cas != "https://cas.example.net/cas" {
		t.Fatal("global and local configuration", err)
	}
	for _, input := range []string{valid + ` {}`, strings.Replace(valid, `"casUrl"`, `"allowedLogins":"bob","casUrl"`, 1), valid + strings.Repeat(" ", 65536)} {
		os.WriteFile(path, []byte(input), 0600)
		if _, err := loadConfig(path, CreateConfig()); err == nil {
			t.Fatal("invalid administrator file accepted")
		}
	}
	if _, err := loadConfig(path+".missing", CreateConfig()); err == nil {
		t.Fatal("missing administrator file accepted")
	}
}

func TestCallbackParameters(t *testing.T) {
	a := testApp()
	service, cookie := begin(t, a)
	u, _ := url.Parse(service)
	for _, query := range []string{"", "state=a&state=b&ticket=ST-x", "state=%zz&ticket=ST-x", u.RawQuery + "&ticket=bad", u.RawQuery + "&ticket=" + strings.Repeat("x", 4097), u.RawQuery + "&ticket=ST-x&extra=x"} {
		if w := request(a, callbackPath+"?"+query, cookie); w.Code != 400 {
			t.Fatal("invalid callback", w.Code)
		}
	}
	r := verifyRequest("app1.example.org", callbackPath, "POST")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatal("callback method")
	}
}
