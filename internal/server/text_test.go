package server

import (
	"strings"
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

func TestTextReputationAvailability(t *testing.T) {
	for _, c := range []struct{ status, want string }{
		{"unavailable", "未知 · 信誉数据不足"},
		{"limited", "100 分 · 极度纯净（数据有限）"},
		{"complete", "100 分 · 极度纯净"},
	} {
		r := &model.Result{IP: "192.0.2.1", Score: model.Score{Value: 100, Level: "极度纯净", DataStatus: c.status}}
		report := Text(r, "ip.example.com")
		if !strings.Contains(report, c.want) {
			t.Errorf("%s: missing %q in %s", c.status, c.want, report)
		}
		if c.status == "unavailable" && strings.Contains(report, "100 分") {
			t.Error("a numeric baseline was presented as a measured clean rating")
		}
	}
}

func TestTextDNSSeparatesUnavailableEvidence(t *testing.T) {
	result := &model.Result{Network: model.Network{RDNS: []string{"mail.example"}, FCrDNSChecks: []model.FCrDNSCheck{{Name: "mail.example", Status: "error"}}}, DNSBL: []model.DNSBL{{Zone: "a", Listed: true}, {Zone: "b"}, {Zone: "c", Error: "refused"}}}
	text := Text(result, "ip.example.com")
	for _, want := range []string{"正反解未能确定", "mail.example：查询失败", "1/2 命中，另有 1 个查询失败"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	result.DNSBL = result.DNSBL[2:]
	if text := Text(result, "ip.example.com"); !strings.Contains(text, "未知 · 1 个查询均失败") || strings.Contains(text, "0/1 命中") {
		t.Errorf("absent DNSBL answers presented as evidence: %s", text)
	}
}
