package server

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/zzusec/ip-lookup/web"
)

// The initial IP must be usable before JavaScript or any lookup data finishes.
// No lookup service is configured: serving the page must not need it.
func TestPageIncludesIPWithoutLookup(t *testing.T) {
	s := &Server{Web: web.FS, TrustProxy: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, remote, realIP, want string }{
		{"/", "127.0.0.1:5000", "192.0.2.7", "192.0.2.7"},
		{"/", "127.0.0.1:5000", "fe80::1%<svg/onload=alert(1)>", "fe80::1"},
		{"/", "192.0.2.9:5000", "198.51.100.7", "192.0.2.9"},
		{"/8.8.8.8", "127.0.0.1:5000", "192.0.2.7", "8.8.8.8"},
		{"/2001:db8::1", "127.0.0.1:5000", "192.0.2.7", "2001:db8::1"},
	} {
		r := httptest.NewRequest("GET", c.path, nil)
		r.RemoteAddr = c.remote
		r.Header.Set("Accept", "text/html")
		r.Header.Set("X-Real-IP", c.realIP)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `<h1 id="ipAddress">`+c.want+`</h1>`) {
			t.Errorf("%s: IP %s not in initial HTML (status %d)", c.path, c.want, w.Code)
		}
		if strings.Contains(w.Body.String(), "__IP_ADDRESS__") {
			t.Error("unresolved address placeholder")
		}
		if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
			t.Errorf("personalized HTML cache policy: %s", got)
		}
	}
	if !strings.Contains(string(s.index), "__IP_ADDRESS__") {
		t.Error("per-request rendering mutated the shared page")
	}
}

func TestVersioned(t *testing.T) {
	static := fstest.MapFS{"app.js": {Data: []byte("x")}}
	page, err := versioned([]byte(`<script src="/static/app.js"></script><img src="/static/app.js">`), static, "app.js")
	if err != nil {
		t.Fatal(err)
	}
	// The first four bytes of sha256("x").
	if want := `<script src="/static/app.js?v=2d711642"></script><img src="/static/app.js?v=2d711642">`; string(page) != want {
		t.Errorf("got %s", page)
	}
	if _, err := versioned(page, static, "gone.js"); err == nil {
		t.Error("missing file accepted")
	}
}

// Every static file the page loads must carry a version, or browsers keep
// running the previous release for a day after an update.
func TestPageAssetsVersioned(t *testing.T) {
	s := &Server{Web: web.FS}
	if _, err := s.Handler(); err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`"/static/[^"?]*"`).Find(s.index); m != nil {
		t.Errorf("unversioned asset %s", m)
	}
}

func TestClientIP(t *testing.T) {
	s := &Server{TrustProxy: true}
	cases := []struct {
		remote, realIP, xff, want string
	}{
		{"127.0.0.1:5000", "203.0.113.7", "", "203.0.113.7"},
		{"127.0.0.1:5000", "", "198.51.100.1, 203.0.113.8", "203.0.113.8"},
		{"[::1]:5000", "2001:db8::1", "", "2001:db8::1"},
		{"192.0.2.10:5000", "203.0.113.7", "", "192.0.2.10"}, // not from the local proxy
		{"127.0.0.1:5000", "garbage", "", "127.0.0.1"},
		{"[::ffff:192.0.2.1]:80", "", "", "192.0.2.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.realIP != "" {
			r.Header.Set("X-Real-IP", c.realIP)
		}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientIP(r); got != netip.MustParseAddr(c.want) {
			t.Errorf("%+v: got %s", c, got)
		}
	}
}

func TestIsBrowser(t *testing.T) {
	for ua, want := range map[string]bool{
		"curl/8.7.1": false, "Wget/1.21": false, "HTTPie/3.2": false,
		"Mozilla/5.0 (Macintosh) AppleWebKit Chrome/140": true,
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", ua)
		if got := isBrowser(r); got != want {
			t.Errorf("isBrowser(%q) = %v", ua, got)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(2, 60e9)
	a, b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	if ok, _ := l.allow(a); !ok {
		t.Fatal("first request refused")
	}
	if ok, _ := l.allow(b); !ok {
		t.Fatal("second request refused")
	}
	if ok, retry := l.allow(a); ok || retry <= 0 {
		t.Fatal("same /64 should share the budget")
	}
	if ok, _ := l.allow(netip.MustParseAddr("2001:db8:1::1")); !ok {
		t.Fatal("other /64 refused")
	}
}
