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
