package cln_iap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestMiddlewareInitialization(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
	for _, tc := range []struct {
		name string
		next http.Handler
		cfg  *Config
	}{
		{"missing handler", nil, CreateConfig()},
		{"missing configuration", next, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if handler, err := New(context.Background(), tc.next, tc.cfg, "test"); err == nil || handler != nil {
				t.Fatalf("handler=%v error=%v", handler, err)
			}
		})
	}
	setAdministratorEnv(t)
	t.Setenv("CLN_IAP_CAS_URL", "")
	if handler, err := New(context.Background(), next, CreateConfig(), "test"); err == nil || handler != nil {
		t.Fatalf("missing environment: handler=%v error=%v", handler, err)
	}
	t.Setenv("CLN_IAP_CAS_URL", "https://cas.example.net/cas")
	handler, err := New(context.Background(), next, &Config{AllowedLogins: "alice"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	a := handler.(*app)
	if !a.allowedLogin("alice") || a.allowedLogin("bob") {
		t.Fatal("local restrictions lost")
	}
	w := request(a, "/", authToken(a, "alice"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("downstream status=%d", w.Code)
	}
}

func TestInvalidDNSLabels(t *testing.T) {
	for _, host := range []string{".example.org", "app..example.org", "app.example.org.", "-app.example.org", "app-.example.org", strings.Repeat("a", 64) + ".org"} {
		t.Run(host, func(t *testing.T) {
			if dnsName(host) {
				t.Fatal("invalid DNS label accepted")
			}
		})
	}
	if _, err := configure(testGlobal(), nil); err == nil {
		t.Fatal("missing local configuration accepted")
	}
}

func TestLoginFailures(t *testing.T) {
	for _, tc := range []struct {
		name, path, query string
		random            io.Reader
		status            int
	}{
		{name: "invalid return", path: "//evil.org/", status: 400},
		{name: "random unavailable", path: "/", random: failingReader{}, status: 500},
		{name: "oversized flow", path: "/", query: strings.Repeat(`"`, 1800), status: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testApp()
			if tc.random != nil {
				a.random = tc.random
			}
			r := verifyRequest("app1.example.org", "/", "GET")
			r.URL.Path, r.URL.RawQuery = tc.path, tc.query
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != tc.status || len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" {
				t.Fatalf("status=%d headers=%v", w.Code, w.Header())
			}
		})
	}
}

func TestCASAdditionalFailures(t *testing.T) {
	for _, tc := range []struct {
		name, cas, body, reason string
		readFailure             bool
		canceled                bool
	}{
		{name: "invalid endpoint", cas: "://invalid", reason: "invalid_response"},
		{name: "canceled", canceled: true, reason: "request_canceled"},
		{name: "body interrupted", readFailure: true, reason: "network_error"},
		{name: "truncated trailing XML", body: successXML("alice") + "<", reason: "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testApp()
			if tc.cas != "" {
				a.cas = tc.cas
			}
			a.client.Transport = logTransport(func(r *http.Request) (*http.Response, error) {
				if tc.canceled {
					return nil, r.Context().Err()
				}
				var body io.ReadCloser = io.NopCloser(strings.NewReader(tc.body))
				if tc.readFailure {
					body = io.NopCloser(failingReader{})
				}
				return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			user, err := a.validateTicket(ctx, "ST-test", "https://app1.example.org/")
			var failure *casError
			if user != "" || !errors.As(err, &failure) || failure.reason != tc.reason {
				t.Fatalf("user=%q error=%v", user, err)
			}
		})
	}
}
