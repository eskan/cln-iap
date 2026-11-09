package cln_iap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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

type integration struct {
	client    *http.Client
	calls     atomic.Int32
	logins    atomic.Int32
	configDir string
	container string
	docker    func(...string) string
}

func startTraefik(t testing.TB) *integration {
	t.Helper()
	f := &integration{}
	f.docker = func(args ...string) string {
		t.Helper()
		cmd := exec.Command("docker", args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", args[0], err, stderr.String())
		}
		return strings.TrimSpace(string(out))
	}
	dir := t.TempDir()
	f.configDir = dir
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cln-iap test"}, DNSNames: []string{"cas.example.net", "app1.example.org", "app2.example.org", "baseline.example.org", "evil.example.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	write("cert.pem", certPEM)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	var mu sync.Mutex
	tickets := map[string]string{}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			n := f.logins.Add(1)
			ticket := fmt.Sprintf("ST-%d", n)
			service := r.URL.Query().Get("service")
			mu.Lock()
			tickets[ticket] = service
			mu.Unlock()
			http.Redirect(w, r, service+"&ticket="+ticket, 303)
			return
		}
		if r.URL.Path == "/serviceValidate" {
			ticket := r.URL.Query().Get("ticket")
			mu.Lock()
			service, ok := tickets[ticket]
			delete(tickets, ticket)
			mu.Unlock()
			if !ok || service != r.URL.Query().Get("service") {
				fmt.Fprint(w, `<serviceResponse xmlns="`+casNamespace+`"><authenticationFailure/></serviceResponse>`)
				return
			}
			fmt.Fprint(w, successXML("alice"))
			return
		}
		f.calls.Add(1)
		if r.URL.Path == "/asset" {
			fmt.Fprint(w, strings.Repeat("x", 100*1024))
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprint(w, r.Method+":"+r.Host+r.URL.RequestURI()+":"+string(body))
	}))
	backend.Listener.Close()
	backend.Listener, err = net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	backend.Start()
	t.Cleanup(backend.Close)
	_, port, _ := net.SplitHostPort(backend.Listener.Addr().String())
	global := testGlobal()
	global.CASURL = "https://cas.example.net"
	global.JWTSecret = ""
	global.JWTSecretFile = "/etc/traefik/secret"
	global.LogLevel = "debug"
	data, _ := json.Marshal(global)
	write("cln-iap.json", data)
	write("secret", []byte(strings.Repeat("s", 32)))
	router := func(rule, middleware string) map[string]interface{} {
		r := map[string]interface{}{"rule": rule, "service": "app", "tls": map[string]interface{}{}}
		if middleware != "" {
			r["middlewares"] = []string{middleware}
		}
		return r
	}
	middleware := func(logins string) interface{} {
		return map[string]interface{}{"plugin": map[string]interface{}{"cln-iap": map[string]string{"allowedLogins": logins}}}
	}
	dynamic := map[string]interface{}{
		"tls": map[string]interface{}{"certificates": []interface{}{map[string]string{"certFile": "/etc/traefik/cert.pem", "keyFile": "/etc/traefik/key.pem"}}},
		"http": map[string]interface{}{
			"routers": map[string]interface{}{
				"app1":     router("Host(`app1.example.org`)", "open"),
				"private":  router("Host(`app1.example.org`) && PathPrefix(`/private`)", "restricted"),
				"app2":     router("Host(`app2.example.org`) && (PathPrefix(`/tools`) || PathPrefix(`/__cln_iap`))", "allowed"),
				"cas":      router("Host(`cas.example.net`)", ""),
				"baseline": router("Host(`baseline.example.org`)", ""),
				"evil":     router("Host(`evil.example.org`)", "open"),
			},
			"middlewares": map[string]interface{}{"open": middleware(""), "allowed": middleware("alice,bob"), "restricted": middleware("bob")},
			"services":    map[string]interface{}{"app": map[string]interface{}{"loadBalancer": map[string]interface{}{"servers": []interface{}{map[string]string{"url": "http://host.docker.internal:" + port}}}}},
		}}
	data, _ = json.Marshal(dynamic)
	write("dynamic.yml", data)
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	f.container = f.docker("run", "-d", "--rm", "--add-host", "host.docker.internal:host-gateway", "--add-host", "cas.example.net:127.0.0.1", "-p", "127.0.0.1::443", "-v", dir+":/etc/traefik:ro", "-v", root+":/plugins-local/src/github.com/eskan/cln-iap:ro", "-e", "SSL_CERT_FILE=/etc/traefik/cert.pem", "traefik:v3.7.17", "--entrypoints.websecure.address=:443", "--providers.file.filename=/etc/traefik/dynamic.yml", "--experimental.localplugins.cln-iap.modulename=github.com/eskan/cln-iap")
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", f.container).CombinedOutput()
			t.Log(string(out))
		}
		exec.Command("docker", "rm", "-f", f.container).Run()
	})
	addr := f.docker("port", f.container, "443/tcp")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	jar, _ := cookiejar.New(nil)
	f.client = &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}}
	t.Cleanup(f.client.CloseIdleConnections)
	deadline := time.Now().Add(30 * time.Second)
	for {
		r, err := f.client.Get("https://app1.example.org/__cln_iap/callback")
		if err == nil {
			r.Body.Close()
			if r.StatusCode == 400 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Traefik plugin did not become ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return f
}

func TestTraefik(t *testing.T) {
	if os.Getenv("RUN_TRAEFIK_TEST") != "1" {
		t.Skip("RUN_TRAEFIK_TEST=1 requires Docker")
	}
	f := startTraefik(t)
	noRedirect := *f.client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(c *http.Client, method, target, body string) (int, string, http.Header) {
		t.Helper()
		r, _ := http.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("X-Forwarded-Host", "evil.org")
		r.Header.Set("X-Forwarded-Proto", "http")
		res, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b), res.Header
	}
	code, _, h := get(&noRedirect, "GET", "https://app1.example.org/a%2Fb?x=1&x=2", "")
	u, _ := url.Parse(h.Get("Location"))
	if code != 303 || !strings.HasPrefix(u.Query().Get("service"), "https://app1.example.org/__cln_iap/callback?") || f.calls.Load() != 0 {
		t.Fatal("anonymous or forged request passed", code, h)
	}
	if code, _, _ = get(&noRedirect, "POST", "https://app1.example.org/", ""); code != 401 {
		t.Fatal("anonymous POST", code)
	}
	if code, _, _ = get(&noRedirect, "GET", "https://evil.example.org/", ""); code != 400 {
		t.Fatal("host allowlist", code)
	}
	rejected := noRedirect
	rejected.Jar, _ = cookiejar.New(nil)
	_, _, rejectedHeaders := get(&rejected, "GET", "https://app1.example.org/", "")
	rejectedLogin, _ := url.Parse(rejectedHeaders.Get("Location"))
	rejectedCallback := rejectedLogin.Query().Get("service") + "&ticket=ST-invalid"
	if code, _, _ := get(&rejected, "GET", rejectedCallback, ""); code != 502 {
		t.Fatal("invalid CAS ticket", code)
	}
	code, body, h := get(f.client, "GET", "https://app1.example.org/a%2Fb?x=1&x=2", "")
	if code != 200 || body != "GET:app1.example.org/a%2Fb?x=1&x=2:" || h.Get("Cache-Control") != "public, max-age=60" {
		t.Fatal("CAS flow", code, body)
	}
	n := f.logins.Load()
	if code, body, _ = get(&noRedirect, "GET", "https://app2.example.org/tools/second", ""); code != 200 || body != "GET:app2.example.org/tools/second:" || f.logins.Load() != n {
		t.Fatal("shared session", code, body)
	}
	if code, _, h = get(&noRedirect, "GET", "https://app1.example.org/private", ""); code != 403 || h.Get("Set-Cookie") != "" {
		t.Fatal("local authorization", code)
	}
	if code, body, _ = get(&noRedirect, "POST", "https://app1.example.org/send", "payload"); code != 200 || body != "POST:app1.example.org/send:payload" {
		t.Fatal("POST body", code, body)
	}
	if code, _, _ = get(&noRedirect, "GET", "https://app1.example.org/__cln_iap/unknown", ""); code != 404 {
		t.Fatal("reserved path", code)
	}
	fresh := *f.client
	fresh.Jar, _ = cookiejar.New(nil)
	if code, _, _ = get(&fresh, "GET", "https://app2.example.org/tools/start", ""); code != 200 {
		t.Fatal("prefix callback", code)
	}
	dynamicPath := filepath.Join(f.configDir, "dynamic.yml")
	data, err := os.ReadFile(dynamicPath)
	if err != nil {
		t.Fatal(err)
	}
	var dynamic map[string]interface{}
	if err := json.Unmarshal(data, &dynamic); err != nil {
		t.Fatal(err)
	}
	middlewares := dynamic["http"].(map[string]interface{})["middlewares"].(map[string]interface{})
	middlewares["allowed"].(map[string]interface{})["plugin"].(map[string]interface{})["cln-iap"].(map[string]interface{})["allowedLogins"] = "bob"
	data, err = json.Marshal(dynamic)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dynamicPath+".tmp", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dynamicPath+".tmp", dynamicPath); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, _, _ = get(&noRedirect, "GET", "https://app2.example.org/tools/second", "")
		if code == 403 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("login removal not applied to existing session", code)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code, _, _ = get(&noRedirect, "GET", "https://app1.example.org/", ""); code != 200 {
		t.Fatal("shared session deleted")
	}

	logs := f.docker("logs", f.container)
	for _, s := range []string{"ST-1", "ST-2", "\"alice\"", strings.Repeat("s", 32)} {
		if strings.Contains(logs, s) {
			t.Fatal("sensitive plugin log")
		}
	}
}
