package classify

import (
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

func TestReputationCoverage(t *testing.T) {
	provider := func(name, status string, actual bool) model.Source {
		return model.Source{Name: name, Kind: "online", Status: status, ReputationSource: true, Reputation: actual}
	}
	for _, c := range []struct {
		name                   string
		result                 model.Result
		status                 string
		received, total, value int
	}{
		{"geography is not a clean reputation check", model.Result{Mode: "full", Sources: []model.Source{
			{Name: "ipwho.is", Status: "ok"}, {Name: "Merged-IP", Kind: "offline", Status: "ok"},
			{Name: "DNSBL", Kind: "dns", Status: "ok"}, provider("proxycheck.io", "timeout", false),
		}, DNSBL: []model.DNSBL{{Zone: "example.test", Error: "timeout"}}}, "unavailable", 0, 1, 100},
		{"missing privacy is not a clean check", model.Result{Mode: "full", Sources: []model.Source{
			provider("ipinfo.io", "ok", false),
		}}, "unavailable", 0, 1, 100},
		{"an explicit zero is data", model.Result{Mode: "full", Risk: []model.Risk{{Source: "proxycheck.io", Value: 0}},
			Sources: []model.Source{provider("proxycheck.io", "ok", true), provider("ipyou.net", "quota", false)}}, "limited", 1, 2, 100},
		{"one answer is limited even if the only configured source", model.Result{Mode: "full", Sources: []model.Source{
			provider("ip-api.com", "ok", true),
		}}, "limited", 1, 1, 100},
		{"all relevant providers answered", model.Result{Mode: "full", Sources: []model.Source{
			provider("ip-api.com", "ok", true), provider("ipapi.is", "ok", true), provider("ip-api.com", "ok", true),
		}}, "complete", 2, 2, 100},
		{"failed provider cannot claim an answer", model.Result{Mode: "full", Sources: []model.Source{
			provider("ip-api.com", "error", true),
		}}, "unavailable", 0, 1, 100},
		{"known offline risk remains a limited estimate", model.Result{Mode: "full", Flags: model.Flags{Tor: true}}, "limited", 0, 0, 40},
		{"offline network classification remains limited", model.Result{Mode: "full", Flags: model.Flags{Hosting: true}}, "limited", 0, 0, 75},
		{"nested data is not a second provider", model.Result{Mode: "full", Risk: []model.Risk{
			{Source: "ipyou.net", Value: 0}, {Source: "IP2Proxy 欺诈分（经 ipyou.net）", Value: 0},
		}}, "limited", 1, 1, 100},
		{"fast response cannot be complete", model.Result{Mode: "fast", Sources: []model.Source{
			provider("ip-api.com", "ok", true), provider("ipapi.is", "ok", true),
		}}, "limited", 2, 2, 100},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := Score(&c.result)
			if s.Value != c.value || s.DataStatus != c.status || s.Coverage.Received != c.received || s.Coverage.Total != c.total {
				t.Errorf("got %+v / %+v", s, s.Coverage)
			}
		})
	}
}
