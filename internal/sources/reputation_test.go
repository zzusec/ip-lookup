package sources

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

func TestRiskProviderScores(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	proxyRaw := func(body string) string { return fmt.Sprintf(`{"status":"ok","%s":%s}`, q.Addr, body) }
	cases := []struct {
		name      string
		provider  func() *Provider
		raw       string
		want      []int
		wantError bool
	}{
		{"proxy geo only", func() *Provider { return proxycheck("") }, proxyRaw(`{"location":{"country_name":"United States"}}`), nil, false},
		{"proxy empty detections", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{}}`), nil, false},
		{"proxy null risk", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":null}}`), nil, false},
		{"proxy true zero", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":0}}`), []int{0}, false},
		{"proxy upper bound", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":100}}`), []int{100}, false},
		{"proxy real risk", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":72}}`), []int{72}, false},
		{"proxy negative risk", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":-1}}`), nil, false},
		{"proxy above bound", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":101}}`), nil, false},
		{"proxy string risk", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":"0"}}`), nil, true},
		{"proxy fractional risk", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":0.5}}`), nil, true},
		{"proxy overflow risk", func() *Provider { return proxycheck("") }, proxyRaw(`{"detections":{"risk":1e309}}`), nil, true},
		{"ipyou geo only", ipyou, `{"geo":{"country":"United States"}}`, nil, false},
		{"ipyou empty score", ipyou, `{"ip_score":{}}`, nil, false},
		{"ipyou null score", ipyou, `{"ip_score":{"score":null}}`, nil, false},
		{"ipyou true zero", ipyou, `{"ip_score":{"score":0}}`, []int{0}, false},
		{"ipyou upper bound", ipyou, `{"ip_score":{"score":100}}`, []int{100}, false},
		{"ipyou real score", ipyou, `{"ip_score":{"score":27}}`, []int{27}, false},
		{"ipyou negative score", ipyou, `{"ip_score":{"score":-1}}`, nil, false},
		{"ipyou above bound", ipyou, `{"ip_score":{"score":101}}`, nil, false},
		{"ipyou string score", ipyou, `{"ip_score":{"score":"0"}}`, nil, true},
		{"ipyou fractional score", ipyou, `{"ip_score":{"score":0.5}}`, nil, true},
		{"ipyou overflow score", ipyou, `{"ip_score":{"score":1e309}}`, nil, true},
		{"fraud missing score", ipyou, `{"proxy_info":{"found":true}}`, nil, false},
		{"fraud null score", ipyou, `{"proxy_info":{"found":true,"fraud_score":null}}`, nil, false},
		{"fraud true zero", ipyou, `{"proxy_info":{"found":true,"fraud_score":0}}`, []int{0}, false},
		{"fraud upper bound", ipyou, `{"proxy_info":{"found":true,"fraud_score":100}}`, []int{100}, false},
		{"fraud negative score", ipyou, `{"proxy_info":{"found":true,"fraud_score":-1}}`, nil, false},
		{"fraud above bound", ipyou, `{"proxy_info":{"found":true,"fraud_score":101}}`, nil, false},
		{"fraud string score", ipyou, `{"proxy_info":{"found":true,"fraud_score":"0"}}`, nil, true},
		{"fraud fractional score", ipyou, `{"proxy_info":{"found":true,"fraud_score":0.5}}`, nil, true},
		{"fraud without match", ipyou, `{"proxy_info":{"found":false,"fraud_score":18}}`, nil, false},
		{"both real scores", ipyou, `{"ip_score":{"score":0},"proxy_info":{"found":true,"fraud_score":18}}`, []int{0, 18}, false},
		{"greynoise malicious", func() *Provider { return greynoise("") }, `{"noise":true,"classification":"malicious"}`, []int{90}, false},
		{"greynoise unknown", func() *Provider { return greynoise("") }, `{"noise":true,"classification":"unknown"}`, []int{50}, false},
		{"greynoise benign", func() *Provider { return greynoise("") }, `{"noise":true,"classification":"benign"}`, []int{10}, false},
		{"greynoise missing classification", func() *Provider { return greynoise("") }, `{"noise":true}`, nil, false},
		{"greynoise unexpected classification", func() *Provider { return greynoise("") }, `{"noise":true,"classification":"unclassified"}`, nil, false},
		{"greynoise riot", func() *Provider { return greynoise("") }, `{"riot":true}`, nil, false},
		{"greynoise no match", func() *Provider { return greynoise("") }, `{"noise":false,"riot":false}`, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := &Out{Res: &model.Result{}}
			err := c.provider().Apply(o, q, []byte(c.raw))
			if (err != nil) != c.wantError {
				t.Fatalf("Apply error = %v, wantError %v", err, c.wantError)
			}
			var got []int
			for _, risk := range o.Res.Risk {
				got = append(got, risk.Value)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Risk values = %v, want %v", got, c.want)
			}
		})
	}
}

func TestReputationSource(t *testing.T) {
	for _, name := range []string{"ip-api.com", "ipapi.is", "ipinfo.io", "proxycheck.io", "ipyou.net", "GreyNoise"} {
		if !reputationSource(name) {
			t.Errorf("reputationSource(%q) = false", name)
		}
	}
	for _, name := range []string{"", "ipwho.is", "ip.sb", "ipapi.co", "RDAP", "greynoise", "unknown-provider"} {
		if reputationSource(name) {
			t.Errorf("reputationSource(%q) = true", name)
		}
	}
}

func TestReputationDataBooleanFields(t *testing.T) {
	addr := netip.MustParseAddr("8.8.8.8")
	cases := []struct {
		name   string
		fields []string
		wrap   func(string) string
		geo    string
	}{
		{"ip-api.com", []string{"proxy", "hosting"}, func(s string) string { return `{` + s + `}` }, `{"status":"success","country":"United States","as":"AS15169 Google LLC"}`},
		{"ipapi.is", []string{"is_vpn", "is_proxy", "is_tor", "is_abuser", "is_datacenter", "is_crawler"}, func(s string) string { return `{` + s + `}` }, `{"country":"United States","asn":"AS15169 Google LLC"}`},
		{"ipinfo.io", []string{"vpn", "proxy", "tor", "relay", "hosting"}, func(s string) string { return `{"privacy":{` + s + `}}` }, `{"country":"US","org":"AS15169 Google LLC"}`},
		{"proxycheck.io", []string{"proxy", "vpn", "tor", "hosting", "compromised", "scraper", "anonymous"}, func(s string) string { return `{"8.8.8.8":{"detections":{` + s + `}}}` }, `{"status":"ok","8.8.8.8":{"network":{"asn":"AS15169"},"location":{"country_name":"United States"}}}`},
		{"ipyou.net", []string{"is_proxy", "is_vpn", "is_tor", "is_bot", "is_hosting", "is_abuser"}, func(s string) string { return `{"intel_summary":{` + s + `}}` }, `{"geo":{"country":"United States"},"usage_inferred":{"label":"residential"}}`},
		{"GreyNoise", []string{"noise", "riot"}, func(s string) string { return `{"classification":"benign",` + s + `}` }, `{"ip":"8.8.8.8","name":"Some service"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, field := range c.fields {
				for _, value := range []string{"true", "false"} {
					t.Run(field+"="+value, func(t *testing.T) {
						raw := c.wrap(fmt.Sprintf(`%q:%s`, field, value))
						if !reputationData(c.name, []byte(raw), addr) {
							t.Errorf("reputationData(%s) = false", raw)
						}
					})
				}
				for _, value := range []string{"null", "0", `"false"`, `""`, "{}", "[]"} {
					t.Run(field+"="+value, func(t *testing.T) {
						raw := c.wrap(fmt.Sprintf(`%q:%s`, field, value))
						if reputationData(c.name, []byte(raw), addr) {
							t.Errorf("reputationData(%s) = true", raw)
						}
					})
				}
			}
			for _, raw := range []string{c.geo, `{}`, `{"status":"ok"}`, `null`, `[]`, `true`, `"success"`, `{"proxy":`} {
				if reputationData(c.name, []byte(raw), addr) {
					t.Errorf("reputationData(%s) = true without reputation fields", raw)
				}
			}
		})
	}
}

func TestReputationDataRiskScores(t *testing.T) {
	addr := netip.MustParseAddr("8.8.8.8")
	for _, c := range []struct {
		name string
		wrap func(string) string
	}{
		{"proxycheck.io", func(s string) string { return `{"8.8.8.8":{"detections":{"risk":` + s + `}}}` }},
		{"ipyou.net", func(s string) string { return `{"ip_score":{"score":` + s + `}}` }},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, score := range []string{"0", "25", "100"} {
				if raw := c.wrap(score); !reputationData(c.name, []byte(raw), addr) {
					t.Errorf("reputationData(%s) = false", raw)
				}
			}
			for _, score := range []string{"null", `"0"`, "false", "{}", "[]", "-1", "101", "0.5", "1e309", "NaN", "Infinity"} {
				if raw := c.wrap(score); reputationData(c.name, []byte(raw), addr) {
					t.Errorf("reputationData(%s) = true", raw)
				}
			}
		})
	}
}

func TestReputationDataScope(t *testing.T) {
	addr := netip.MustParseAddr("8.8.8.8")
	cases := []struct {
		name, raw string
		want      bool
	}{
		{"ip-api.com", `{"mobile":false}`, false},
		{"ipapi.is", `{"is_mobile":false,"is_bogon":false}`, false},
		{"ipinfo.io", `{"privacy":{}}`, false},
		{"ipinfo.io", `{"privacy":null}`, false},
		{"ipinfo.io", `{"privacy":[]}`, false},
		{"ipinfo.io", `{"proxy":false,"asn":{"type":"hosting"}}`, false},
		{"proxycheck.io", `{"8.8.8.8":{"detections":{}}}`, false},
		{"proxycheck.io", `{"8.8.8.8":{"detections":null}}`, false},
		{"proxycheck.io", `{"8.8.8.8":{"detections":[]}}`, false},
		{"proxycheck.io", `{"8.8.4.4":{"detections":{"proxy":false,"risk":0}}}`, false},
		{"proxycheck.io", `{"proxy":false,"risk":0}`, false},
		{"ipyou.net", `{"intel_summary":{},"ip_score":{}}`, false},
		{"ipyou.net", `{"intel_summary":null,"ip_score":null}`, false},
		{"ipyou.net", `{"intel_summary":[],"ip_score":[]}`, false},
		{"ipyou.net", `{"is_proxy":false,"score":0,"blocklisted":false}`, false},
		{"GreyNoise", `{"noise":false}`, false},
		{"GreyNoise", `{"noise":true,"classification":"unexpected"}`, false},
		{"GreyNoise", `{"noise":false,"riot":false,"classification":"unexpected"}`, false},
		{"GreyNoise", `{"noise":true,"classification":null}`, false},
		{"GreyNoise", `{"classification":"benign"}`, false},
		{"GreyNoise", `{"riot":true}`, true},
		{"GreyNoise", `{"riot":true,"classification":"unexpected"}`, true},
		{"GreyNoise", `{"noise":true,"classification":"malicious"}`, true},
		{"GreyNoise", `{"noise":false,"classification":"unknown"}`, true},
		{"unknown-provider", `{"proxy":false,"noise":true,"classification":"malicious","privacy":{"proxy":false},"intel_summary":{"is_proxy":false},"ip_score":{"score":0}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name+"/"+c.raw, func(t *testing.T) {
			if got := reputationData(c.name, []byte(c.raw), addr); got != c.want {
				t.Errorf("reputationData = %v, want %v", got, c.want)
			}
		})
	}
	if reputationData("proxycheck.io", []byte(`{"8.8.8.8":{"detections":{"risk":0}}}`), netip.MustParseAddr("8.8.4.4")) {
		t.Error("proxycheck reputation belongs to a different address")
	}
	if !reputationData("proxycheck.io", []byte(`{"2001:4860:4860::8888":{"detections":{"risk":0}}}`), netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Error("proxycheck IPv6 reputation was ignored")
	}
}

func TestRiskProviderKeepsOtherEvidence(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	for _, c := range []struct {
		name     string
		provider *Provider
		raw      string
		kinds    []string
	}{
		{"proxycheck.io", proxycheck(""), `{"8.8.8.8":{"network":{"range":"8.8.8.0/24"},"detections":{"proxy":true,"hosting":true},"operator":{"name":"Some VPN"}}}`, []string{"proxy", "hosting", "vpn"}},
		{"ipyou.net", ipyou(), `{"intel_summary":{"is_proxy":true,"is_abuser":true},"proxy_info":{"found":true,"proxy_label":"VPN","usage_type":"DCH","usage_label":"Data center"},"blocklisted":true}`, []string{"hosting", "proxy", "proxy", "abuser", "abuser"}},
		{"GreyNoise", greynoise(""), `{"noise":true,"riot":true,"classification":"unexpected","name":"Some service"}`, []string{"public_service"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := &Out{Res: &model.Result{}}
			if err := c.provider.Apply(o, q, []byte(c.raw)); err != nil {
				t.Fatal(err)
			}
			var kinds []string
			for _, sig := range o.Sig {
				kinds = append(kinds, sig.Kind)
			}
			if !reflect.DeepEqual(kinds, c.kinds) {
				t.Errorf("signal kinds = %v, want %v", kinds, c.kinds)
			}
			if len(o.Res.Risk) != 0 {
				t.Errorf("missing or unknown score produced Risk: %+v", o.Res.Risk)
			}
			if c.name == "proxycheck.io" && o.Res.Network.Prefix != "8.8.8.0/24" {
				t.Errorf("prefix = %q", o.Res.Network.Prefix)
			}
		})
	}
}

func TestIPAPIISSecuritySignals(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	for _, c := range []struct {
		field      string
		kind       string
		weight     int
		reputation bool
	}{
		{"is_bogon", "", 0, false},
		{"is_mobile", "mobile", 60, false},
		{"is_datacenter", "hosting", 60, true},
		{"is_tor", "tor", 80, true},
		{"is_proxy", "proxy", 50, true},
		{"is_vpn", "vpn", 50, true},
		{"is_abuser", "abuser", 40, true},
		{"is_crawler", "crawler", 60, true},
	} {
		for _, on := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s=%t", c.field, on), func(t *testing.T) {
				raw := []byte(fmt.Sprintf(`{"country":"United States","asn":"AS15169 Google LLC",%q:%t}`, c.field, on))
				o := &Out{Res: &model.Result{}}
				if err := ipapiIs("").Apply(o, q, raw); err != nil {
					t.Fatal(err)
				}
				var want []model.Signal
				if on && c.kind != "" {
					want = []model.Signal{{Kind: c.kind, Source: "ipapi.is", Detail: c.field, Weight: c.weight}}
				}
				if !reflect.DeepEqual(o.Sig, want) {
					t.Errorf("signals = %+v, want %+v", o.Sig, want)
				}
				if got := reputationData("ipapi.is", raw, q.Addr); got != c.reputation {
					t.Errorf("reputationData = %v, want %v", got, c.reputation)
				}
				if len(o.Res.GeoSources) != 1 || o.Res.GeoSources[0].Country != "United States" || o.Res.GeoSources[0].ASN != 15169 {
					t.Errorf("geographic/ASN evidence changed: %+v", o.Res.GeoSources)
				}
			})
		}
	}

	t.Run("all false", func(t *testing.T) {
		raw := []byte(`{"country":"United States","asn":"AS15169 Google LLC","is_bogon":false,"is_mobile":false,"is_datacenter":false,"is_tor":false,"is_proxy":false,"is_vpn":false,"is_abuser":false,"is_crawler":false}`)
		o := &Out{Res: &model.Result{}}
		if err := ipapiIs("").Apply(o, q, raw); err != nil {
			t.Fatal(err)
		}
		if len(o.Sig) != 0 {
			t.Errorf("false fields produced signals: %+v", o.Sig)
		}
		if !reputationData("ipapi.is", raw, q.Addr) {
			t.Error("explicit negative security fields should count as reputation data")
		}
	})
}
