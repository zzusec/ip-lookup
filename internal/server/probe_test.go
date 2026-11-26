package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/web"
)

func TestInspectRequestProbe(t *testing.T) {
	s := &Server{TrustProxy: true}

	// 1. Standard browser over HTTPS with matching Client Hints and Fetch Metadata
	bReq := httptest.NewRequest("GET", "/api/lookup", nil)
	bReq.Header.Set("X-Forwarded-Proto", "https")
	bReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")
	bReq.Header.Set("Sec-Fetch-Site", "same-origin")
	bReq.Header.Set("Sec-Fetch-Mode", "cors")
	bReq.Header.Set("Sec-CH-UA", `"Chromium";v="136", "Google Chrome";v="136"`)
	bReq.Header.Set("Sec-CH-UA-Platform", `"macOS"`)
	bReq.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	bReq.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	bp := s.inspectRequestProbe(bReq)
	if bp.Verdict != "human_browser" || bp.HumanShare < 90 {
		t.Fatalf("browser probe = %+v", bp)
	}

	// 2. CLI tool (curl)
	cReq := httptest.NewRequest("GET", "/", nil)
	cReq.Header.Set("User-Agent", "curl/8.7.1")
	cp := s.inspectRequestProbe(cReq)
	if cp.Verdict != "cli_tool" || cp.AutomationShare < 80 || cp.ClientFamily != "curl" {
		t.Fatalf("curl probe = %+v", cp)
	}

	// 3. HeadlessChrome automation
	hReq := httptest.NewRequest("GET", "/api/lookup", nil)
	hReq.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/136.0.0.0 Safari/537.36")
	hp := s.inspectRequestProbe(hReq)
	if hp.Verdict != "automated_client" || hp.AutomationShare < 85 {
		t.Fatalf("headless probe = %+v", hp)
	}

	// 4. Spoofed Chrome UA over HTTPS missing Sec-Fetch and Sec-CH-UA + OS mismatch
	sReq := httptest.NewRequest("GET", "/api/lookup", nil)
	sReq.Header.Set("X-Forwarded-Proto", "https")
	sReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36")
	sReq.Header.Set("Sec-CH-UA", `"Chromium";v="136"`)
	sReq.Header.Set("Sec-CH-UA-Platform", `"Linux"`)
	sp := s.inspectRequestProbe(sReq)
	if sp.Verdict != "suspect_automation" || sp.AutomationShare < 50 {
		t.Fatalf("spoofed probe = %+v", sp)
	}
}

func TestMatchBaitBrand(t *testing.T) {
	if brand, hit := matchBaitBrand("www.microsoft.com", 20473); !hit || brand != "Microsoft / Bing" {
		t.Fatalf("expected Reality hit on Vultr ASN, got %q %v", brand, hit)
	}
	if _, hit := matchBaitBrand("www.microsoft.com", 8075); hit {
		t.Fatal("legitimate Microsoft ASN 8075 must not be flagged as Reality")
	}
}

func TestAPIProbeSkipsPrivateAndReturnsJSON(t *testing.T) {
	s := &Server{Web: web.FS, TrustProxy: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/probe", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-Real-IP", "198.51.100.7") // TEST-NET-2 reserved address -> skipped without network I/O
	r.Header.Set("User-Agent", "curl/8.7.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var got model.ActiveProbe
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.IP != "198.51.100.7" || got.RequestProbe == nil || got.RequestProbe.Verdict != "cli_tool" {
		t.Fatalf("unexpected ActiveProbe: %+v", got)
	}
	if got.TLS443 == nil || got.TLS443.Verdict != "skipped" {
		t.Fatalf("reserved address should skip public 443 dial, got %+v", got.TLS443)
	}
}

func TestTextIncludesTrafficAndAudit(t *testing.T) {
	desk, mob := 70.0, 30.0
	r := &model.Result{
		IP:      "203.0.113.8",
		Verdict: model.Verdict{Label: "机房 · 租赁网段", Confidence: "high"},
		Score:   model.Score{Value: 62, Level: "良好", DataStatus: "complete"},
		Native:  model.Native{Label: "原生 IP", Detail: "US"},
		Traffic: &model.Traffic{
			Mode: "radar", Source: "Cloudflare Radar", Window: "7d",
			HumanPct: 35.5, BotPct: 64.5, DesktopPct: &desk, MobilePct: &mob, Level: "机器偏多", Tone: "poor",
			RequestProbe: &model.RequestProbe{Label: "命令行 / 程序化客户端", HumanShare: 15, AutomationShare: 85, ClientFamily: "curl"},
		},
		Audit: &model.NetworkAudit{
			Neighbor: &model.NeighborDensity{Prefix: "203.0.113.0/24", Flagged: 18, Total: 256, DensityPct: 7.0, Level: "中度污染"},
			Lease:    &model.LeaseCheck{Leased: true, Broker: "IPXO"},
		},
	}
	txt := Text(r, "ip.example.com")
	for _, want := range []string{"人机流量", "真人 35.5% / 机器 64.5%", "设备分布", "当前请求", "同段邻居", "IPXO"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in text output:\n%s", want, txt)
		}
	}
}
