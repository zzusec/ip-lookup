package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zzusec/ip-lookup/internal/lookup"
	"github.com/zzusec/ip-lookup/web"
)

func TestSiteUsageCountsResponsesWithoutRequestIdentifiers(t *testing.T) {
	var logs bytes.Buffer
	dir := t.TempDir()
	passwordPath := filepath.Join(dir, "admin-test-password")
	if err := os.WriteFile(passwordPath, []byte(rand.Text()+rand.Text()), 0o600); err != nil {
		t.Fatal(err)
	}
	panel, err := NewAdminPanel(passwordPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Admin: panel, Web: web.FS, Lookup: &lookup.Service{Timeout: time.Second}, TrustProxy: true, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	handler, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, ua, proto string
		status                  int
	}{
		{"GET", "/", "Mozilla/5.0", "https", 200},
		{"GET", "/192.0.2.77", "Mozilla/5.0", "https", 200},
		{"GET", "/api/lookup?ip=192.0.2.77&mode=fast", "curl/1", "https", 200},
		{"GET", "/api/lookup?ip=192.0.2.77&mode=full", "curl/1", "https", 200},
		{"GET", "/json", "curl/1", "https", 200},
		{"GET", "/json/192.0.2.77", "curl/1", "https", 200},
		{"GET", "/", "curl/1", "https", 200},
		{"GET", "/192.0.2.77", "curl/1", "https", 200},
		{"GET", "/?ip=invalid-query-marker", "curl/1", "https", 400},
		{"GET", "/json/invalid-query-marker", "curl/1", "https", 400},
		{"GET", "/api/lookup?ip=invalid-query-marker", "curl/1", "https", 400},
		{"GET", "/not-a-query-marker", "curl/1", "https", 404},
		{"GET", "/unknown/path", "Mozilla/5.0", "https", 404},
		{"HEAD", "/api/lookup?ip=192.0.2.77", "curl/1", "https", 200},
		{"HEAD", "/", "Mozilla/5.0", "https", 200},
		{"POST", "/json", "curl/1", "https", 405},
		{"GET", "/", "Mozilla/5.0", "http", 301},
		{"GET", "/api/ip", "curl/1", "https", 200},
		{"GET", "/static/favicon.svg", "Mozilla/5.0", "https", 200},
		{"GET", "/healthz", "curl/1", "https", 200},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("X-Real-IP", "198.51.100.93")
		req.Header.Set("X-Forwarded-Proto", tc.proto)
		req.Header.Set("User-Agent", tc.ua+" secret-ua-marker")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != tc.status {
			t.Errorf("%s %s: got %d, want %d", tc.method, tc.path, recorder.Code, tc.status)
		}
	}
	if err := panel.Flush(); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "site-usage.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"192.0.2.77", "198.51.100.93", "invalid-query-marker", "not-a-query-marker", "secret-ua-marker"} {
		if strings.Contains(logs.String(), raw) || bytes.Contains(stored, []byte(raw)) {
			t.Errorf("unexpected request identifier in storage or access log: %q", raw)
		}
	}
	actual := panel.usage.snapshot()
	if len(actual.Days) != 1 || actual.Days[0].PageViews != 2 || actual.Days[0].Lookups != 6 || actual.Days[0].Errors != 3 {
		t.Errorf("unexpected request totals: %+v", actual)
	}
	reopened, err := openSiteUsage(dir)
	if err != nil {
		t.Fatal(err)
	}
	if restored := reopened.snapshot(); !reflect.DeepEqual(restored, actual) {
		t.Errorf("restart changed totals: %+v vs %+v", restored, actual)
	}
	info, err := os.Stat(filepath.Join(dir, "site-usage.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected snapshot permissions: %v, %v", info, err)
	}
}

func TestUsageDayBoundaryAndRetention(t *testing.T) {
	usage := SiteUsage{report: usageReport{Days: []usageDay{}}}
	boundary := time.Date(2025, 3, 1, 16, 0, 0, 0, time.UTC)
	for offset := -30; offset < 0; offset++ {
		usage.recordLocked(boundary.AddDate(0, 0, offset), "view")
	}
	usage.recordLocked(boundary.Add(-time.Second), "error")
	usage.recordLocked(boundary, "lookup")
	days := usage.report.Days
	if len(days) != 30 || days[0].Date != "2025-02-01" || days[28].Date != "2025-03-01" || days[28].Errors != 1 || days[29] != (usageDay{Date: "2025-03-02", Lookups: 1}) {
		t.Fatalf("unexpected retained days at UTC+8 midnight: %+v", days)
	}
}

func TestUsageWriteRetryPreservesConcurrentCounts(t *testing.T) {
	dir := t.TempDir()
	usage, err := openSiteUsage(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := usage.path
	usage.path = filepath.Join(dir, "missing", "state")
	usage.record("error")
	if err := usage.Flush(); err == nil {
		t.Fatal("state write failure was hidden")
	}
	usage.path = path
	var wait sync.WaitGroup
	for range 6 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 30 {
				usage.record("lookup")
			}
			if err := usage.Flush(); err != nil {
				t.Error(err)
			}
		}()
	}
	wait.Wait()
	if err := usage.Flush(); err != nil {
		t.Fatal(err)
	}
	other, err := openSiteUsage(dir)
	if err != nil {
		t.Fatal(err)
	}
	report := other.snapshot()
	if len(report.Days) != 1 || report.Days[0].Lookups != 180 || report.Days[0].Errors != 1 {
		t.Errorf("lost failed or concurrent writes: %+v", report)
	}
}

func TestUsageDoesNotReplaceUnreadableState(t *testing.T) {
	for _, content := range []string{"{bad", `{"schema":2}`, `{"schema":1,"site":"ip","startedAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z","days":[{"date":"bad"}]}`} {
		dir := t.TempDir()
		path := filepath.Join(dir, "site-usage.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openSiteUsage(dir); err == nil {
			t.Fatal("invalid usage state was accepted")
		}
		stored, err := os.ReadFile(path)
		if err != nil || string(stored) != content {
			t.Error("invalid state was overwritten")
		}
	}
	contents, err := json.Marshal((&SiteUsage{report: usageReport{Days: []usageDay{}}}).snapshot())
	if err != nil || !bytes.Contains(contents, []byte(`"days":[]`)) {
		t.Errorf("empty state has non-array days: %s (%v)", contents, err)
	}
}
