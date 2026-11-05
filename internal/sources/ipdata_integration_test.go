package sources

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

func TestIPDataOptionalRegistration(t *testing.T) {
	for _, key := range []string{"", "fixture-ipdata-key"} {
		count := 0
		for _, p := range All(Keys{IPData: key}) {
			if p.Name == "ipdata.co" {
				count++
			}
		}
		want := 0
		if key != "" {
			want = 1
		}
		if count != want {
			t.Errorf("configured=%t: providers=%d, want %d", key != "", count, want)
		}
	}
}

func TestIPDataReputationCoverageAndExactCache(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	for _, c := range []struct {
		name, raw string
		valid     bool
	}{
		{"geo only", `{"ip":"8.8.8.8","country_code":"US"}`, false},
		{"explicit negative", `{"ip":"8.8.8.8","threat":{"is_proxy":false}}`, true},
		{"trust zero is a readout", `{"ip":"8.8.8.8","threat":{"scores":{"trust_score":0}}}`, true},
		{"trust one hundred is a readout", `{"ip":"8.8.8.8","threat":{"scores":{"trust_score":100}}}`, true},
		{"missing security", `{"ip":"8.8.8.8","country_code":"US","threat":{"is_tor":null,"scores":{"trust_score":null}}}`, false},
		{"out of range", `{"ip":"8.8.8.8","country_code":"US","threat":{"scores":{"trust_score":101}}}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			client := ipdataClient(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/8.8.8.8" {
					t.Errorf("unexpected lookup path %s", r.URL.Path)
				}
				return ipdataReply(200, c.raw), nil
			})
			p := ipdata("fixture-ipdata-key")
			set := NewSet(client, []*Provider{p})
			for i := range 2 {
				o := &Out{Res: &model.Result{}}
				source := set.one(context.Background(), p, q, o)
				if source.Status != "ok" || !source.ReputationSource || source.Reputation != c.valid || source.Cached != (i == 1) {
					t.Fatalf("source=%+v", source)
				}
			}
			if used, _ := p.Limit.State(); calls != 1 || used != 1 {
				t.Errorf("cache reuse: upstream calls=%d, budget=%d", calls, used)
			}
		})
	}
	if reputationData("ipdata.co", []byte(`{"ip":"8.8.4.4","threat":{"is_proxy":false}}`), q.Addr) {
		t.Error("another IP's response must not count as reputation evidence")
	}
}
