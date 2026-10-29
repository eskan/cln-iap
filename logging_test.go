package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type logTransport func(*http.Request) (*http.Response, error)

func (f logTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func logRecords(t *testing.T, b *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if _, err := time.Parse(time.RFC3339Nano, record["time"].(string)); err != nil {
			t.Fatal(err)
		}
		if record["msg"] == nil || record["level"] == nil {
			t.Fatal("missing event or level")
		}
		records = append(records, record)
	}
	return records
}

func TestLogLevels(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  slog.Level
		count int
	}{
		{"", slog.LevelInfo, 3}, {"debug", slog.LevelDebug, 4}, {"info", slog.LevelInfo, 3},
		{"warn", slog.LevelWarn, 2}, {"error", slog.LevelError, 1},
	} {
		t.Run(tc.value, func(t *testing.T) {
			level, err := parseLogLevel(tc.value)
			if err != nil || level != tc.want {
				t.Fatalf("level=%v err=%v", level, err)
			}
			var b bytes.Buffer
			logger := newLogger(&b, level)
			logger.Debug("debug_event")
			logger.Info("info_event")
			logger.Warn("warn_event")
			logger.Error("error_event")
			if got := len(logRecords(t, &b)); got != tc.count {
				t.Fatalf("got %d events", got)
			}
		})
	}
	for _, value := range []string{"trace", "INFO", " info", "sensitive-invalid-level"} {
		t.Setenv("LOG_LEVEL", value)
		_, err := loadConfig()
		if err == nil || err.Error() != "LOG_LEVEL must be debug, info, warn or error" {
			t.Fatalf("invalid level: %v", err)
		}
	}
}

func TestCASDiagnosticLogs(t *testing.T) {
	failure := `<cas:serviceResponse xmlns:cas="` + casNamespace + `"><cas:authenticationFailure code="INVALID_TICKET">sensitive-cas-body</cas:authenticationFailure></cas:serviceResponse>`
	for _, tc := range []struct {
		name, body, reason, level string
		upstream                  int
		err                       error
	}{
		{name: "success", body: successXML("sensitive-user"), level: "INFO", upstream: 200},
		{name: "refusal", body: failure, reason: "ticket_rejected", level: "WARN", upstream: 200},
		{name: "mixed", body: strings.Replace(successXML("sensitive-user"), "</cas:serviceResponse>", "<cas:authenticationFailure/></cas:serviceResponse>", 1), reason: "invalid_response", level: "ERROR", upstream: 200},
		{name: "duplicate refusal", body: strings.Replace(failure, "</cas:serviceResponse>", "<cas:authenticationFailure/></cas:serviceResponse>", 1), reason: "invalid_response", level: "ERROR", upstream: 200},
		{name: "nested refusal", body: strings.Replace(failure, "sensitive-cas-body", "<unexpected/>", 1), reason: "invalid_response", level: "ERROR", upstream: 200},
		{name: "trailing", body: failure + failure, reason: "invalid_response", level: "ERROR", upstream: 200},
		{name: "malformed", body: "sensitive-cas-body", reason: "invalid_response", level: "ERROR", upstream: 200},
		{name: "large", body: strings.Repeat("sensitive-cas-body", 5000), reason: "response_too_large", level: "ERROR", upstream: 200},
		{name: "status", body: "sensitive-cas-body", reason: "http_status", level: "ERROR", upstream: 503},
		{name: "network", err: errors.New("sensitive-network-error"), reason: "network_error", level: "ERROR"},
		{name: "timeout", err: context.DeadlineExceeded, reason: "timeout", level: "ERROR"},
		{name: "tls", err: &tls.CertificateVerificationError{Err: errors.New("sensitive-certificate")}, reason: "tls_error", level: "ERROR"},
		{name: "oversize jwt", body: successXML(strings.Repeat("sensitive-user", 300)), reason: "jwt_too_large", level: "ERROR", upstream: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testApp()
			var b bytes.Buffer
			a.logger = newLogger(&b, slog.LevelDebug)
			service, cookie := begin(t, a)
			u, _ := url.Parse(service)
			a.client.Transport = logTransport(func(r *http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, &url.Error{Op: "Get", URL: r.URL.String(), Err: tc.err}
				}
				return &http.Response{StatusCode: tc.upstream, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})
			w := request(a, u.RequestURI()+"&ticket=ST-sensitive-ticket", cookie)
			wantStatus := 502
			if tc.name == "success" {
				wantStatus = 303
			}
			if w.Code != wantStatus {
				t.Fatalf("status %d", w.Code)
			}
			records := logRecords(t, &b)
			if len(records) != 1 {
				t.Fatalf("expected one event, got %d", len(records))
			}
			record := records[0]
			if record["level"] != tc.level || record["status"] != float64(wantStatus) {
				t.Fatalf("bad event: %v", record)
			}
			if tc.reason != "" && record["reason"] != tc.reason {
				t.Fatalf("wrong reason: %v", record)
			}
			if tc.name != "oversize jwt" && record["duration_ms"] == nil {
				t.Fatal("missing CAS duration")
			}
			if tc.reason == "http_status" && record["cas_status"] != float64(tc.upstream) {
				t.Fatal("missing upstream status")
			}
			for _, sensitive := range []string{"sensitive-", service, cookie.Value, u.Query().Get("state"), string(a.secret), "https://"} {
				if strings.Contains(b.String(), sensitive) {
					t.Fatalf("sensitive data leaked: %q", sensitive)
				}
			}
			if tc.name == "success" {
				if record["msg"] != "authentication_succeeded" {
					t.Fatal(record)
				}
				jwt := w.Result().Cookies()[0]
				if strings.Contains(b.String(), jwt.Value) {
					t.Fatal("JWT leaked")
				}
				b.Reset()
				r := verifyRequest("app1.example.org", "/", "POST")
				r.AddCookie(jwt)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 || b.Len() != 0 {
					t.Fatal("valid JWT must be silent")
				}
			}
		})
	}
}

func TestRequestDiagnosticLogs(t *testing.T) {
	a := testApp()
	var b bytes.Buffer
	a.logger = newLogger(&b, slog.LevelDebug)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, verifyRequest("app1.example.org", "/", "GET"))
	if w.Code != 303 || b.Len() != 0 {
		t.Fatal("normal redirect must be silent")
	}
	r := verifyRequest("app1.example.org", "/", "GET")
	r.AddCookie(&http.Cookie{Name: authCookie, Value: "sensitive-cookie"})
	a.ServeHTTP(httptest.NewRecorder(), r)
	records := logRecords(t, &b)
	if len(records) != 1 || records[0]["level"] != "DEBUG" {
		t.Fatal(records)
	}
	if strings.Contains(b.String(), "sensitive-cookie") {
		t.Fatal("cookie leaked")
	}
	b.Reset()
	request(a, "/callback?state=sensitive-state&ticket=ST-sensitive-ticket")
	records = logRecords(t, &b)
	if len(records) != 1 || records[0]["level"] != "WARN" || strings.Contains(b.String(), "sensitive-") {
		t.Fatal(records)
	}
	b.Reset()
	f := flow{"https://app1.example.org/", b64.EncodeToString(make([]byte, 32)), time.Now().Add(-time.Minute).Unix()}
	cookie := &http.Cookie{Name: flowCookie, Value: sign(a.flowKey, "", f)}
	request(a, "/callback?state="+f.State+"&ticket=ST-sensitive-ticket", cookie)
	records = logRecords(t, &b)
	if len(records) != 1 || records[0]["level"] != "WARN" {
		t.Fatal(records)
	}
	b.Reset()
	a.logger = newLogger(&b, slog.LevelInfo)
	a.ServeHTTP(httptest.NewRecorder(), r)
	request(a, "/login?return=sensitive-invalid-return")
	if b.Len() != 0 {
		t.Fatal("debug logs emitted at info")
	}
	writer := serverLogWriter{a.logger}
	writer.Write([]byte("panic containing sensitive-cookie"))
	records = logRecords(t, &b)
	if len(records) != 1 || records[0]["level"] != "ERROR" || strings.Contains(b.String(), "sensitive-") {
		t.Fatal(records)
	}
}
