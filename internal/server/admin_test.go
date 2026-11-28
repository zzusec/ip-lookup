package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzusec/ip-lookup/internal/datasets"
	"github.com/zzusec/ip-lookup/internal/lookup"
	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/internal/sources"
	"github.com/zzusec/ip-lookup/web"
)

func TestAdminConfiguration(t *testing.T) {
	dir := t.TempDir()
	if panel, err := NewAdminPanel("", dir); panel != nil || err != nil {
		t.Fatal("unconfigured admin must remain disabled")
	}
	if _, err := os.Stat(filepath.Join(dir, "site-usage.json")); !os.IsNotExist(err) {
		t.Fatal("disabled admin must not create usage data")
	}
	password := rand.Text() + rand.Text()
	for _, tc := range []struct {
		name string
		data string
		mode os.FileMode
	}{
		{"permissive", password, 0644}, {"weak", "short", 0600},
		{"single-byte", strings.Repeat("a", 40), 0600}, {"multiple-lines", password + "\nsecond", 0600},
		{"oversized", strings.Repeat(password, 8), 0600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte(tc.data), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			if panel, err := NewAdminPanel(path, dir); panel != nil || err == nil {
				t.Error("unsafe configuration accepted")
			}
		})
	}
	path := filepath.Join(dir, "protected")
	if err := os.WriteFile(path, []byte(password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAdminPanel(link, dir); err == nil {
		t.Error("symbolic link accepted as private password file")
	}
}

type adminFixture struct {
	panel   *AdminPanel
	handler http.Handler
	login   string
	logs    *bytes.Buffer
}

func newAdminFixture(t *testing.T, enabled bool) adminFixture {
	t.Helper()
	dir := t.TempDir()
	password := rand.Text() + rand.Text()
	path := ""
	if enabled {
		path = filepath.Join(dir, "password")
		if err := os.WriteFile(path, []byte(password+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	panel, err := NewAdminPanel(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	logs := new(bytes.Buffer)
	logger := slog.New(slog.NewTextHandler(logs, nil))
	app := Server{Admin: panel, Web: web.FS, Log: logger, TrustProxy: true, Lookup: &lookup.Service{
		Data: datasets.NewManager(dir, "test", logger), Online: sources.NewSet(nil, []*sources.Provider{{Name: "test-provider"}}),
	}}
	handler, err := app.Handler()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"password": password})
	return adminFixture{panel, handler, string(body), logs}
}

func (f adminFixture) request(method, target, body, origin string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, r)
	return out
}

const adminTestOrigin = "https://ip.example.test"

func (f adminFixture) signIn(t *testing.T) *http.Cookie {
	t.Helper()
	out := f.request("POST", adminTestOrigin+"/admin/api/login", f.login, adminTestOrigin, nil, nil)
	if out.Code != http.StatusNoContent || out.Body.Len() != 0 {
		t.Fatalf("valid login: status %d, %d response bytes", out.Code, out.Body.Len())
	}
	cookies := out.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/admin" || cookies[0].Domain != "" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].MaxAge <= 0 || !cookies[0].Expires.After(time.Now()) {
		t.Fatal("login did not set one limited, protected, expiring session cookie")
	}
	return cookies[0]
}

func TestAdminLifecycle(t *testing.T) {
	f := newAdminFixture(t, true)
	for _, path := range []string{"/admin", "/admin/"} {
		out := f.request("GET", adminTestOrigin+path, "", "", nil, nil)
		if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "/static/admin.js?v=") || out.Header().Get("Cache-Control") != "no-store" || !strings.Contains(out.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("wrong private page at %s: status %d", path, out.Code)
		}
	}
	endpoint := adminTestOrigin + "/admin/api/overview"
	if out := f.request("GET", endpoint, "", "", nil, nil); out.Code != http.StatusUnauthorized || strings.Contains(out.Body.String(), "datasets") {
		t.Fatalf("overview without session: %d", out.Code)
	}
	f.panel.usage.record("view")
	cookie := f.signIn(t)
	out := f.request("GET", endpoint, "", "", cookie, nil)
	var report struct {
		Usage   usageReport         `json:"usage"`
		Sources model.SourcesReport `json:"sources"`
	}
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &report) != nil || report.Usage.Schema != 1 || report.Usage.Site != "ip" || len(report.Usage.Days) != 1 || report.Usage.Days[0].PageViews != 1 || len(report.Sources.Online) != 1 || report.Sources.Online[0].Name != "test-provider" {
		t.Fatal("authenticated overview must combine local aggregate usage and the existing provider report")
	}
	logout := adminTestOrigin + "/admin/api/logout"
	if out := f.request("POST", logout, "{}", "https://other.example.test", cookie, nil); out.Code != http.StatusForbidden {
		t.Errorf("cross-origin logout: %d", out.Code)
	}
	if out := f.request("GET", endpoint, "", "", cookie, nil); out.Code != http.StatusOK {
		t.Fatal("a rejected request modified the session")
	}
	out = f.request("POST", logout, "{}", adminTestOrigin, cookie, nil)
	if out.Code != http.StatusNoContent || len(out.Result().Cookies()) != 1 || out.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("logout did not clear the cookie: %d", out.Code)
	}
	if out := f.request("GET", endpoint, "", "", cookie, nil); out.Code != http.StatusUnauthorized {
		t.Fatal("logged-out session remained valid")
	}
	cookie = f.signIn(t)
	f.panel.mu.Lock()
	for key := range f.panel.sessions {
		f.panel.sessions[key] = time.Now().Add(-time.Minute)
	}
	f.panel.mu.Unlock()
	if out := f.request("GET", endpoint, "", "", cookie, nil); out.Code != http.StatusUnauthorized {
		t.Fatal("expired session remained valid")
	}
	if strings.Contains(f.logs.String(), "admin") || strings.Contains(f.logs.String(), f.login) || strings.Contains(f.logs.String(), cookie.Value) {
		t.Fatal("private requests must not enter public HTTP logs")
	}
}

func TestAdminPostBoundaryAndLoginBudget(t *testing.T) {
	f := newAdminFixture(t, true)
	login := adminTestOrigin + "/admin/api/login"
	for _, tc := range []struct {
		origin, body, content, fetch string
		code                         int
	}{
		{"", f.login, "application/json", "", 403}, {"https://other.example.test", f.login, "application/json", "", 403},
		{adminTestOrigin, f.login, "application/json", "cross-site", 403}, {adminTestOrigin, f.login, "text/plain", "", 415},
		{adminTestOrigin, "{}{}", "application/json", "", 400}, {adminTestOrigin, "null", "application/json", "", 400},
		{adminTestOrigin, strings.Repeat("x", 3000), "application/json", "", 413},
	} {
		out := f.request("POST", login, tc.body, tc.origin, nil, map[string]string{"Content-Type": tc.content, "Sec-Fetch-Site": tc.fetch})
		if out.Code != tc.code || len(out.Result().Cookies()) != 0 || out.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("boundary: got %d, want %d", out.Code, tc.code)
		}
	}
	for attempt := 0; attempt < 8; attempt++ {
		if out := f.request("POST", login, `{"password":"incorrect"}`, adminTestOrigin, nil, nil); out.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d: %d", attempt+1, out.Code)
		}
	}
	if out := f.request("POST", login, f.login, adminTestOrigin, nil, nil); out.Code != http.StatusTooManyRequests || out.Header().Get("Retry-After") == "" {
		t.Fatalf("rate-limited login: %d", out.Code)
	}
}

func TestAdminTransportAndDisabled(t *testing.T) {
	disabled := newAdminFixture(t, false)
	for _, path := range []string{"/admin", "/admin/", "/admin/api/overview", "/admin/api/login"} {
		for _, method := range []string{"GET", "POST"} {
			out := disabled.request(method, adminTestOrigin+path, "", "", nil, nil)
			if out.Code != http.StatusNotFound || out.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("disabled %s %s: %d", method, path, out.Code)
			}
		}
	}
	f := newAdminFixture(t, true)
	for _, tc := range []struct {
		remote, host, proto string
		code                int
	}{
		{"192.0.2.12:4000", "ip.example.test", "https", 403}, {"127.0.0.1:4000", "ip.example.test", "https", 200},
		{"127.0.0.1:4000", "ip.example.test", "http", 403}, {"127.0.0.1:4000", "localhost:9000", "", 200},
		{"[::1]:4000", "[::1]:9000", "", 200}, {"192.0.2.12:4000", "localhost:9000", "", 403},
	} {
		r := httptest.NewRequest("GET", "http://"+tc.host+"/admin", nil)
		r.RemoteAddr = tc.remote
		if tc.proto != "" {
			r.Header.Set("X-Forwarded-Proto", tc.proto)
		}
		out := httptest.NewRecorder()
		f.handler.ServeHTTP(out, r)
		if out.Code != tc.code {
			t.Errorf("transport remote=%s host=%s XFP=%s: %d", tc.remote, tc.host, tc.proto, out.Code)
		}
	}
}

func TestAdminStealthGateRotatePasswordAndTelemetry(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "admin.creds")
	initGate := rand.Text()[:16]
	initPass := rand.Text()
	nextPass := rand.Text()
	seed := "gate_key: " + initGate + "\nusername: operator\npassword: " + initPass + "\n"
	if err := os.WriteFile(credPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	panel, err := NewAdminPanel(credPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	logs := new(bytes.Buffer)
	logger := slog.New(slog.NewTextHandler(logs, nil))
	app := Server{Admin: panel, Web: web.FS, Log: logger, TrustProxy: true, Lookup: &lookup.Service{
		Data: datasets.NewManager(dir, "test", logger), Online: sources.NewSet(nil, []*sources.Provider{{Name: "test-provider"}}),
	}}
	handler, err := app.Handler()
	if err != nil {
		t.Fatal(err)
	}

	req := func(method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, adminTestOrigin+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:4444"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Real-IP", "198.51.100.42")
		if method == "POST" {
			r.Header.Set("Origin", adminTestOrigin)
			r.Header.Set("Content-Type", "application/json")
		}
		for _, c := range cookies {
			if c != nil {
				r.AddCookie(c)
			}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	// 1. Stealth 404 without ?k= or with wrong ?k=
	if out := req("GET", "/admin", ""); out.Code != http.StatusNotFound {
		t.Fatalf("expected 404 without ?k=, got %d", out.Code)
	}
	if out := req("GET", "/admin?k=wrong", ""); out.Code != http.StatusNotFound {
		t.Fatalf("expected 404 with wrong ?k=, got %d", out.Code)
	}
	if out := req("POST", "/admin/api/login", `{"username":"operator","password":"`+initPass+`"}`); out.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on login without gate, got %d", out.Code)
	}

	// 2. Valid ?k= unlocks gate and sets gate cookie
	gateOut := req("GET", "/admin?k="+initGate, "")
	if gateOut.Code != http.StatusOK || len(gateOut.Result().Cookies()) == 0 {
		t.Fatalf("expected 200 and gate cookie, got %d", gateOut.Code)
	}
	gateCookie := gateOut.Result().Cookies()[0]

	// 3. Progressive 3-strike brute-force lock + unblock
	for range 3 {
		if out := req("POST", "/admin/api/login", `{"username":"operator","password":"wrong"}`, gateCookie); out.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on wrong password, got %d", out.Code)
		}
	}
	if out := req("POST", "/admin/api/login", `{"username":"operator","password":"`+initPass+`"}`, gateCookie); out.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after 3 strikes in gated mode, got %d", out.Code)
	}
	panel.live.unblockIP("198.51.100.42")

	// 4. Login with username + password
	loginOut := req("POST", "/admin/api/login", `{"username":"operator","password":"`+initPass+`"}`, gateCookie)
	if loginOut.Code != http.StatusNoContent {
		t.Fatalf("expected 204 login, got %d", loginOut.Code)
	}
	sessCookie := loginOut.Result().Cookies()[0]

	// 5. Generate public traffic with iOS 27.2 frozen UA and verify /admin/api/visits + /admin/api/visitor
	pubReq := httptest.NewRequest("GET", "https://ip.example.test/", nil)
	pubReq.RemoteAddr = "127.0.0.1:5000"
	pubReq.Header.Set("X-Forwarded-Proto", "https")
	pubReq.Header.Set("X-Real-IP", "203.0.113.88")
	pubReq.Header.Set("Accept", "text/html")
	pubReq.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1")
	pubRec := httptest.NewRecorder()
	handler.ServeHTTP(pubRec, pubReq)
	if pubRec.Code != http.StatusOK {
		t.Fatalf("public page failed: %d", pubRec.Code)
	}

	vOut := req("GET", "/admin/api/visits?page=1&size=10", "", sessCookie)
	if vOut.Code != http.StatusOK || !strings.Contains(vOut.Body.String(), "iOS 27.2") || !strings.Contains(vOut.Body.String(), "Safari 27.2") {
		t.Fatalf("visits did not capture iOS 27.2 frozen UA resolution: %s", vOut.Body.String())
	}
	if emptyDay := req("GET", "/admin/api/visits?day=1999-01-01", "", sessCookie); emptyDay.Code != http.StatusOK || !strings.Contains(emptyDay.Body.String(), `"total":0`) {
		t.Fatalf("visits day filter failed: %d %s", emptyDay.Code, emptyDay.Body.String())
	}
	ovOut := req("GET", "/admin/api/overview", "", sessCookie)
	if ovOut.Code != http.StatusOK || !strings.Contains(ovOut.Body.String(), `"topIps":[`) || !strings.Contains(ovOut.Body.String(), "203.0.113.88") {
		t.Fatalf("overview did not include aggregated topIps: %d %s", ovOut.Code, ovOut.Body.String())
	}
	dOut := req("GET", "/admin/api/visitor?ip=203.0.113.88", "", sessCookie)
	if dOut.Code != http.StatusOK || !strings.Contains(dOut.Body.String(), "203.0.113.88") {
		t.Fatalf("visitor detail failed: %d %s", dOut.Code, dOut.Body.String())
	}

	// 6. Rotate ?k= token and change password, then verify persistence across restart
	rotOut := req("POST", "/admin/api/rotate-url-token", `{"password":"`+initPass+`"}`, sessCookie)
	if rotOut.Code != http.StatusOK {
		t.Fatalf("rotate token failed: %d %s", rotOut.Code, rotOut.Body.String())
	}
	var rotResp struct {
		URLToken string `json:"url_token"`
	}
	if err := json.Unmarshal(rotOut.Body.Bytes(), &rotResp); err != nil || len(rotResp.URLToken) != 16 {
		t.Fatalf("unexpected rotated token: %+v (%v)", rotResp, err)
	}
	if out := req("GET", "/admin?k="+initGate, ""); out.Code != http.StatusNotFound {
		t.Fatalf("old ?k= must return 404 immediately after rotation, got %d", out.Code)
	}

	pwOut := req("POST", "/admin/api/change-password", `{"username":"admin2","old_password":"`+initPass+`","new_password":"`+nextPass+`"}`, sessCookie)
	if pwOut.Code != http.StatusOK {
		t.Fatalf("change password failed: %d %s", pwOut.Code, pwOut.Body.String())
	}

	reloaded, err := NewAdminPanel(credPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.mu.Lock()
	persistedOK := reloaded.gateKey == rotResp.URLToken && reloaded.username == "admin2" && reloaded.verifyPasswordLocked(nextPass)
	reloaded.mu.Unlock()
	if !persistedOK {
		t.Fatal("rotated ?k= token and changed password did not persist across restart")
	}
}
