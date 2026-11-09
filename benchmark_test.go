package cln_iap

import (
	"io"
	"net/http"
	"os"
	"testing"
)

func BenchmarkTraefik(b *testing.B) {
	if os.Getenv("RUN_TRAEFIK_BENCH") != "1" {
		b.Skip("RUN_TRAEFIK_BENCH=1 requires Docker")
	}
	f := startTraefik(b)
	response, err := f.client.Get("https://app1.example.org/asset")
	if err != nil {
		b.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		b.Fatal(response.StatusCode)
	}
	n := f.logins.Load()
	for _, tc := range []struct{ name, url string }{
		{"without_plugin", "https://baseline.example.org/asset"},
		{"with_plugin", "https://app1.example.org/asset"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			c := *f.client
			c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			b.SetBytes(100 * 1024)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r, e := c.Get(tc.url)
				if e != nil {
					b.Fatal(e)
				}
				size, e := io.Copy(io.Discard, r.Body)
				r.Body.Close()
				if e != nil || r.StatusCode != 200 || size != 100*1024 {
					b.Fatal("asset response", r.StatusCode, size, e)
				}
			}
			b.StopTimer()
			if f.logins.Load() != n {
				b.Fatal("unexpected CAS login")
			}
		})
	}
}
