package server

import (
	"net/http/httptest"
	"net/netip"
	"regexp"
	"testing"
	"testing/fstest"

	"github.com/zzusec/ip-lookup/web"
)

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
