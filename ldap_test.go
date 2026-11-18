package cln_iap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func ldapFixture(t testing.TB, entries int, bindCode int64) (*ldapSettings, <-chan string) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	listener, err := tls.Listen("tcp", "0.0.0.0:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	filters := make(chan string, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				for {
					packet, err := ber.ReadPacket(conn)
					if err != nil {
						return
					}
					id := packet.Children[0].Value.(int64)
					op := packet.Children[1]
					send := func(tag ber.Tag, children ...*ber.Packet) {
						response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
						body := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
						for _, child := range children {
							body.AppendChild(child)
						}
						response.AppendChild(body)
						conn.Write(response.Bytes())
					}
					status := func(tag ber.Tag, code int64) {
						send(tag, ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""), ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""), ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					}
					if op.Tag == 0 {
						status(1, bindCode)
						continue
					}
					if op.Tag != 3 {
						return
					}
					select {
					case filters <- string(op.Children[6].Children[1].Data.Bytes()):
					default:
					}
					for i := 0; i < entries; i++ {
						attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "eduPersonAffiliation", ""))
						values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
						for _, v := range []string{"student", "staff", "cn=team,ou=groups,dc=example,dc=org"} {
							values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
						}
						attr.AppendChild(values)
						attrs.AppendChild(attr)
						send(4, ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=alice,dc=example,dc=org", ""), attrs)
					}
					if entries == -1 {
						<-time.After(1500 * time.Millisecond)
						return
					}
					if entries == -2 {
						status(5, 50)
						continue
					}
					status(5, 0)
				}
			}(conn)
		}
	}()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	return &ldapSettings{CAFile: caFile, URL: "ldaps://127.0.0.1:" + port, BindDN: "cn=reader,dc=example,dc=org", BaseDN: "dc=example,dc=org", LoginAttribute: "uid", password: "secret", timeout: time.Second, authorizationTTL: 5 * time.Minute, tlsConfig: &tls.Config{RootCAs: certServer.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}}, filters
}

func TestLDAPAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries int
		bind    int64
		value   string
		want    int
	}{
		{"multiple values", 1, 0, "staff", 200},
		{"value containing commas", 1, 0, "cn=team,ou=groups,dc=example,dc=org", 200}, {"missing value", 1, 0, "faculty", 403}, {"missing user", 0, 0, "staff", 403}, {"ambiguous user", 2, 0, "staff", 403}, {"bind failure", 1, 49, "staff", 503}, {"search failure", -2, 0, "staff", 503}, {"timeout", -1, 0, "staff", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings, filters := ldapFixture(t, tc.entries, tc.bind)
			a := testApp()
			a.ldap = settings
			a.ldapAttribute = "eduPersonAffiliation"
			a.ldapValues = map[string]bool{tc.value: true}
			subject := "alice*)(uid=*)"
			r := verifyRequest("app1.example.org", "/", "GET")
			r.AddCookie(authToken(a, subject))
			a.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d want %d", w.Code, tc.want)
			}
			if tc.bind == 0 {
				if got := <-filters; got != subject {
					t.Fatalf("identity changed: %q", got)
				}
			}
			unauthenticated := httptest.NewRecorder()
			a.ServeHTTP(unauthenticated, verifyRequest("app1.example.org", "/", "POST"))
			if unauthenticated.Code != 401 {
				t.Fatal("unvalidated identity accepted")
			}
		})
	}
}

func TestLDAPConfiguration(t *testing.T) {
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	os.WriteFile(password, []byte("secret"), 0600)
	valid := ldapSettings{URL: "ldaps://directory.example.org", BindDN: "cn=reader,dc=example,dc=org", BaseDN: "dc=example,dc=org", LoginAttribute: "uid", AllowedAttributes: []string{"eduPersonAffiliation"}, PasswordFile: password}
	for _, tc := range []struct {
		name   string
		mutate func(*ldapSettings, *Config)
		ok     bool
	}{
		{"valid", func(*ldapSettings, *Config) {}, true},
		{"valid authorization TTL", func(s *ldapSettings, c *Config) { s.AuthorizationTTL = "30s" }, true},
		{"invalid authorization TTL", func(s *ldapSettings, c *Config) { s.AuthorizationTTL = "invalid" }, false},
		{"zero authorization TTL", func(s *ldapSettings, c *Config) { s.AuthorizationTTL = "0s" }, false},
		{"long authorization TTL", func(s *ldapSettings, c *Config) { s.AuthorizationTTL = "2h" }, false},
		{"fractional authorization TTL", func(s *ldapSettings, c *Config) { s.AuthorizationTTL = "1.5s" }, false},
		{"missing login attribute", func(s *ldapSettings, c *Config) { s.LoginAttribute = "" }, false},
		{"invalid bind DN", func(s *ldapSettings, c *Config) { s.BindDN = "invalid" }, false},
		{"invalid base DN", func(s *ldapSettings, c *Config) { s.BaseDN = "invalid" }, false},
		{"invalid allowlist", func(s *ldapSettings, c *Config) { s.AllowedAttributes = []string{"bad;binary"} }, false},
		{"missing CA", func(s *ldapSettings, c *Config) { s.CAFile = "missing" }, false},
		{"valid CA", func(s *ldapSettings, c *Config) {
			fixture, _ := ldapFixture(t, 1, 0)
			s.CAFile = fixture.CAFile
			s.Timeout = "1s"
		}, true},
		{"plaintext", func(s *ldapSettings, c *Config) { s.URL = "ldap://directory.example.org" }, false},
		{"unapproved", func(s *ldapSettings, c *Config) { c.LDAPAttribute = "userPassword" }, false},
		{"attribute injection", func(s *ldapSettings, c *Config) { c.LDAPAttribute = "uid)(objectClass=*" }, false},
		{"empty values", func(s *ldapSettings, c *Config) { c.LDAPAllowedValues = nil }, false},
		{"blank value", func(s *ldapSettings, c *Config) { c.LDAPAllowedValues = []string{""} }, false},
		{"missing password", func(s *ldapSettings, c *Config) { s.PasswordFile = "missing" }, false},
		{"invalid timeout", func(s *ldapSettings, c *Config) { s.Timeout = "0s" }, false},
		{"invalid CA", func(s *ldapSettings, c *Config) { s.CAFile = password }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := valid
			local := &Config{LDAPAttribute: "eduPersonAffiliation", LDAPAllowedValues: []string{"staff"}}
			tc.mutate(&s, local)
			data, _ := json.Marshal(s)
			path := filepath.Join(dir, "ldap.json")
			os.WriteFile(path, data, 0600)
			global := testGlobal()
			global.LDAPFile = path
			_, err := configure(global, local)
			if (err == nil) != tc.ok {
				t.Fatalf("configuration: %v", err)
			}
		})
	}
	cfg := &Config{LDAPAttribute: "uid", LDAPAllowedValues: []string{"alice"}}
	if _, err := configure(testGlobal(), cfg); err == nil {
		t.Fatal("missing private configuration accepted")
	}
	data, _ := json.Marshal(cfg)
	if strings.Contains(string(data), "password") {
		t.Fatal("private configuration exposed")
	}
}

func TestLDAPCancellationAndTLS(t *testing.T) {
	settings, _ := ldapFixture(t, 1, 0)
	a := testApp()
	a.ldap = settings
	a.ldapAttribute = "eduPersonAffiliation"
	a.ldapValues = map[string]bool{"staff": true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ldapAllowed(ctx, "alice"); err == nil {
		t.Fatal("canceled request accepted")
	}
	settings.tlsConfig = &tls.Config{}
	if _, err := a.ldapAllowed(context.Background(), "alice"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestLDAPInvalidPrivateFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ldap.json")
	local := &Config{LDAPAttribute: "uid", LDAPAllowedValues: []string{"alice"}}
	global := testGlobal()
	global.LDAPFile = path
	if _, err := configure(global, local); err == nil {
		t.Fatal("missing file accepted")
	}
	for _, data := range []string{"{", `{"unexpected":true}`, `{} {}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := configure(global, local); err == nil {
			t.Fatal("invalid file accepted")
		}
	}
}

func TestLDAPInvalidEndpoint(t *testing.T) {
	a := testApp()
	a.ldap = &ldapSettings{URL: "ldaps://%", timeout: time.Second}
	if _, err := a.ldapAllowed(context.Background(), "alice"); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
	a.ldap.URL = "ldaps://directory.example.org"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ldapAllowed(ctx, "alice"); err == nil {
		t.Fatal("canceled connection accepted")
	}
}

func TestLDAPCallback(t *testing.T) {
	for _, value := range []string{"faculty", "staff"} {
		t.Run(value, func(t *testing.T) {
			settings, identities := ldapFixture(t, 1, 0)
			a := testApp()
			a.ldap = settings
			a.ldapAttribute = "eduPersonAffiliation"
			a.ldapValues = map[string]bool{value: true}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, successXML("alice")) }))
			defer server.Close()
			a.cas = server.URL
			a.client.Transport = server.Client().Transport
			service, cookie := begin(t, a)
			u, _ := url.Parse(service)
			w := request(a, u.RequestURI()+"&ticket=ST-valid", cookie)
			want := 403
			if value == "staff" {
				want = 303
			}
			if w.Code != want {
				t.Fatalf("callback status %d", w.Code)
			}
			if got := <-identities; got != "alice" {
				t.Fatalf("CAS identity %q", got)
			}
			var casCookie *http.Cookie
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == authCookie {
					casCookie = cookie
				}
			}
			if casCookie == nil || !a.validJWT(casCookie.Value) {
				t.Fatal("LDAP decision lost global CAS authentication")
			}
			if want == 303 {
				authz := authorizationFrom(t, a, w)
				a.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
				if next := request(a, "/", casCookie, authz); next.Code != 200 {
					t.Fatalf("callback authorization not reusable: %d", next.Code)
				}
				expectNoLookup(t, identities)
			}
			if want == 403 {
				for _, cookie := range w.Result().Cookies() {
					if cookie.Name == a.authorizationCookie() && cookie.MaxAge > 0 {
						t.Fatal("denied callback issued authorization")
					}
				}
			}
		})
	}
}

func TestLDAPAndLoginRestrictions(t *testing.T) {
	settings, identities := ldapFixture(t, 1, 0)
	a := testApp()
	a.ldap = settings
	a.ldapAttribute = "eduPersonAffiliation"
	a.ldapValues = map[string]bool{"staff": true}
	a.logins = map[string]bool{"bob": true}
	a.next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("denied request reached application") })
	r := verifyRequest("app1.example.org", "/", "GET")
	r.AddCookie(authToken(a, "alice"))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
	select {
	case <-identities:
		t.Fatal("login restriction did not precede LDAP")
	default:
	}
	a.logins = map[string]bool{"alice": true}
	a.ldapValues = map[string]bool{"faculty": true}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("LDAP restriction bypassed: %d", w.Code)
	}
}
