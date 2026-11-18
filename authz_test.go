package cln_iap

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func authorizationApp(t *testing.T) (*app, <-chan string) {
	t.Helper()
	settings, lookups := ldapFixture(t, 1, 0)
	a := testApp()
	a.name = "staff@file"
	a.ldap = settings
	a.ldapAttribute = "eduPersonAffiliation"
	a.ldapValues = map[string]bool{"staff": true}
	a.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("application"))
	})
	return a, lookups
}

func authorizationFrom(t *testing.T, a *app, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == a.authorizationCookie() && cookie.MaxAge > 0 {
			return cookie
		}
	}
	t.Fatalf("missing authorization cookie: status=%d headers=%v", w.Code, w.Header())
	return nil
}

func expectLookup(t *testing.T, lookups <-chan string, subject string) {
	t.Helper()
	select {
	case got := <-lookups:
		if got != subject {
			t.Fatalf("LDAP identity %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing LDAP lookup")
	}
}

func expectNoLookup(t *testing.T, lookups <-chan string) {
	t.Helper()
	select {
	case <-lookups:
		t.Fatal("unexpected LDAP lookup")
	default:
	}
}

func TestAuthorizationCookieReuse(t *testing.T) {
	a, lookups := authorizationApp(t)
	cas := authToken(a, "alice")
	first := request(a, "/", cas)
	if first.Code != 200 || first.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatal("unprotected authorization response")
	}
	authz := authorizationFrom(t, a, first)
	expectLookup(t, lookups, "alice")
	if !authz.Secure || !authz.HttpOnly || authz.SameSite != http.SameSiteLaxMode || authz.Path != "/" || authz.Domain != "" || authz.MaxAge > 300 {
		t.Fatalf("unsafe authorization cookie: %+v", authz)
	}
	var c authorizationClaims
	if err := unsign(a.authorizationKey(), jwtHeader+".", authz.Value, &c); err != nil {
		t.Fatal(err)
	}
	session, _ := a.session(cas.Value)
	if c.Subject != "alice" || c.Session != fingerprint(cas.Value) || c.Expires > session.Expires {
		t.Fatal("authorization not bound to CAS")
	}
	for _, private := range []string{"staff", "eduPersonAffiliation", "reader", "dc=example", "127.0.0.1"} {
		payload := strings.Split(authz.Value, ".")[1]
		decoded, _ := b64.DecodeString(payload)
		if strings.Contains(string(decoded), private) {
			t.Fatalf("private authorization data: %s", private)
		}
	}
	a.ldap.tlsConfig = &tls.Config{}
	for _, path := range []string{"/", "/style.css", "/image.png"} {
		w := request(a, path, cas, authz)
		if w.Code != 200 || len(w.Result().Cookies()) != 0 || w.Result().Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("cached authorization: %d", w.Code)
		}
	}
	expectNoLookup(t, lookups)
	if w := request(a, "/", authz); w.Code != 303 {
		t.Fatal("authorization replaced CAS authentication")
	}
	var expired authorizationClaims
	unsign(a.authorizationKey(), jwtHeader+".", authz.Value, &expired)
	expired.Issued = time.Now().Unix() - 301
	expired.Expires = time.Now().Unix() - 1
	stale := &http.Cookie{Name: authz.Name, Value: sign(a.authorizationKey(), jwtHeader+".", expired)}
	w := request(a, "/", cas, stale)
	if w.Code != 503 {
		t.Fatalf("expired authorization bypassed unavailable LDAP: %d", w.Code)
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == authz.Name && cookie.MaxAge >= 0 {
			t.Fatal("failed renewal retained authorization")
		}
	}
}

func TestAuthorizationInvalidation(t *testing.T) {
	for _, reason := range []string{"signature", "session", "identity", "middleware", "host", "attribute", "values", "logins", "directory", "secret", "expired", "duplicate"} {
		t.Run(reason, func(t *testing.T) {
			a, lookups := authorizationApp(t)
			cas := authToken(a, "alice")
			first := request(a, "/", cas)
			authz := authorizationFrom(t, a, first)
			expectLookup(t, lookups, "alice")
			cookie := *authz
			host := "app1.example.org"
			switch reason {
			case "signature":
				cookie.Value += "x"
			case "session":
				c, _ := a.session(cas.Value)
				c.Issued--
				cas.Value = sign(a.secret, jwtHeader+".", c)
			case "identity":
				cas = authToken(a, "bob")
			case "middleware":
				a.name = "other@file"
				cookie.Name = a.authorizationCookie()
			case "host":
				host = "app2.example.org"
			case "attribute":
				a.ldapAttribute = "departmentNumber"
			case "values":
				a.ldapValues = map[string]bool{"faculty": true}
			case "logins":
				a.logins = map[string]bool{"alice": true}
			case "directory":
				a.ldap.BaseDN = "ou=people,dc=example,dc=org"
			case "secret":
				a.secret = []byte(strings.Repeat("r", 32))
				cas = authToken(a, "alice")
			case "expired":
				var c authorizationClaims
				unsign(a.authorizationKey(), jwtHeader+".", cookie.Value, &c)
				c.Expires = time.Now().Unix() - 1
				cookie.Value = sign(a.authorizationKey(), jwtHeader+".", c)
			}
			r := verifyRequest(host, "/", "GET")
			r.AddCookie(cas)
			r.AddCookie(&cookie)
			if reason == "duplicate" {
				r.AddCookie(&cookie)
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			want := 200
			if reason == "values" || reason == "attribute" {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("status=%d want=%d", w.Code, want)
			}
			subject := "alice"
			if reason == "identity" {
				subject = "bob"
			}
			expectLookup(t, lookups, subject)
			if want == 200 {
				authorizationFrom(t, a, w)
			}
		})
	}
}

func TestAuthorizationClaimsValidation(t *testing.T) {
	a, _ := authorizationApp(t)
	cas := authToken(a, "alice")
	session, _ := a.session(cas.Value)
	w := request(a, "/", cas)
	cookie := authorizationFrom(t, a, w)
	var valid authorizationClaims
	if err := unsign(a.authorizationKey(), jwtHeader+".", cookie.Value, &valid); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*authorizationClaims)
	}{
		{"subject", func(c *authorizationClaims) { c.Subject = "bob" }},
		{"session", func(c *authorizationClaims) { c.Session = "other" }},
		{"audience", func(c *authorizationClaims) { c.Audience = "other" }},
		{"policy", func(c *authorizationClaims) { c.Policy = "other" }},
		{"future", func(c *authorizationClaims) { c.Issued = time.Now().Unix() + 60 }},
		{"zero issued", func(c *authorizationClaims) { c.Issued = 0 }},
		{"before session", func(c *authorizationClaims) { c.Issued = session.Issued - 1 }},
		{"expired", func(c *authorizationClaims) { c.Expires = time.Now().Unix() }},
		{"inverted", func(c *authorizationClaims) { c.Expires = c.Issued }},
		{"longer than session", func(c *authorizationClaims) { c.Expires = session.Expires + 1 }},
		{"longer than policy", func(c *authorizationClaims) { c.Expires = c.Issued + 301 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.mutate(&c)
			if a.validAuthorization(sign(a.authorizationKey(), jwtHeader+".", c), session, cas.Value, "app1.example.org") {
				t.Fatal("invalid authorization accepted")
			}
		})
	}
	if a.validJWT(cookie.Value) {
		t.Fatal("authorization accepted as CAS session")
	}
	if a.validAuthorization(cas.Value, session, cas.Value, "app1.example.org") {
		t.Fatal("CAS session accepted as authorization")
	}
}

func TestAuthorizationExpiryLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		subject string
		expires int64
		want    int
	}{
		{"limited by session", "alice", time.Now().Unix() + 30, 200},
		{"session expired during LDAP", "alice", time.Now().Unix() - 1, 401},
		{"oversized authorization", strings.Repeat("x", 3000), time.Now().Unix() + 300, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := authorizationApp(t)
			c := claims{tc.subject, a.cas, a.audience(), time.Now().Unix() - 1, tc.expires}
			w := httptest.NewRecorder()
			a.authorizeLDAP(w, verifyRequest("app1.example.org", "/", "GET"), c, sign(a.secret, jwtHeader+".", c))
			if w.Code != tc.want {
				t.Fatalf("status %d", w.Code)
			}
			if tc.want == 200 {
				cookie := authorizationFrom(t, a, w)
				if cookie.Expires.Unix() != c.Expires || cookie.MaxAge > 30 {
					t.Fatal("authorization outlives session")
				}
			}
		})
	}
}

func TestAuthorizationOptional(t *testing.T) {
	a := testApp()
	a.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	w := request(a, "/", authToken(a, "alice"))
	if w.Code != 204 || len(w.Result().Cookies()) != 0 {
		t.Fatal("optional LDAP affected CAS-only middleware")
	}
}

func TestAuthorizationResponseController(t *testing.T) {
	recorder := httptest.NewRecorder()
	wrapped := &authorizationResponse{ResponseWriter: recorder}
	if err := http.NewResponseController(wrapped).Flush(); err != nil || !recorder.Flushed {
		t.Fatalf("response controller: %v", err)
	}
}
