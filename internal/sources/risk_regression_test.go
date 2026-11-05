package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
)

func fixtureProvider(p *Provider, raw string) *Provider {
	p.Fetch = func(context.Context, *Client, Query) ([]byte, error) {
		return []byte(raw), nil
	}
	return p
}

func TestMobileUnknownObservationDoesNotDeduct(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("192.0.2.1")}
	o := &Out{Res: &model.Result{Mode: "full"}}
	s := NewSet(nil, []*Provider{
		fixtureProvider(proxycheck(""), `{"192.0.2.1":{"detections":{"risk":0}}}`),
		fixtureProvider(ipyou(), `{"usage_inferred":{"label":"mobile","confidence":1},"ip_score":{"score":15,"level":"low"}}`),
		fixtureProvider(greynoise(""), `{"noise":true,"riot":false,"classification":"unknown","name":"unknown","last_seen":"2026-01-01"}`),
	})
	o.Res.Sources = s.Run(context.Background(), q, o, false)
	o.Res.Verdict, o.Res.Flags = classify.Decide(o.Sig)
	score := classify.Score(o.Res)
	if !o.Res.Flags.Mobile || score.Value != 100 || len(score.Factors) != 0 {
		t.Fatalf("mobile score = %+v, flags = %+v, risk = %+v", score, o.Res.Flags, o.Res.Risk)
	}
	if len(o.Res.Risk) != 2 {
		t.Fatalf("risk = %+v, want original proxycheck and ipyou readings only", o.Res.Risk)
	}
	for _, risk := range o.Res.Risk {
		if risk.Source == "ipyou.net" && (risk.Value != 15 || risk.EffectiveValue == nil || *risk.EffectiveValue != 0 || risk.ScoringNote == "") {
			t.Fatalf("original ipyou reading or scoring explanation lost: %+v", risk)
		}
	}
	for _, source := range o.Res.Sources {
		if source.Name == "GreyNoise" && (source.Status != "ok" || source.Reputation || !strings.Contains(source.Note, "未知")) {
			t.Fatalf("unknown GreyNoise observation = %+v", source)
		}
	}
}

func TestGreyNoiseUnknownOnlyIsUnavailable(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("192.0.2.1")}
	o := &Out{Res: &model.Result{Mode: "full"}}
	s := NewSet(nil, []*Provider{
		fixtureProvider(greynoise(""), `{"noise":true,"riot":false,"classification":"unknown"}`),
	})
	o.Res.Sources = s.Run(context.Background(), q, o, false)
	score := classify.Score(o.Res)
	if score.DataStatus != "unavailable" || score.Coverage.Received != 0 || len(o.Res.Risk) != 0 {
		t.Fatalf("unknown-only score = %+v, risk = %+v", score, o.Res.Risk)
	}
}

func TestIPYouLowRiskPolicyKeepsOriginalAndOtherRisks(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("192.0.2.1")}
	for _, value := range []int{0, 15, 19, 20, 27, 100} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			o := &Out{Res: &model.Result{}}
			raw := fmt.Sprintf(`{"ip_score":{"score":%d,"level":"low"},"proxy_info":{"found":true,"fraud_score":15}}`, value)
			if err := ipyou().Apply(o, q, []byte(raw)); err != nil {
				t.Fatal(err)
			}
			if len(o.Res.Risk) != 2 || o.Res.Risk[0].Value != value {
				t.Fatalf("readings = %+v, original score changed", o.Res.Risk)
			}
			risk, fraud := o.Res.Risk[0], o.Res.Risk[1]
			if value < 20 {
				if risk.EffectiveValue == nil || *risk.EffectiveValue != 0 || risk.ScoringNote == "" {
					t.Fatalf("lowest-risk range was not explained: %+v", risk)
				}
			} else if risk.EffectiveValue != nil || risk.ScoringNote != "" {
				t.Fatalf("threshold leaked into higher risk: %+v", risk)
			}
			if fraud.Value != 15 || fraud.EffectiveValue != nil || fraud.ScoringNote != "" {
				t.Fatalf("ipyou normal range policy leaked into IP2Proxy fraud: %+v", fraud)
			}
			if value >= 20 {
				o.Res.Risk = []model.Risk{risk}
				if score := classify.Score(o.Res); score.Value != 100-value/4 {
					t.Fatalf("higher score arithmetic changed: %+v", score)
				}
			}
		})
	}
}

func TestGreyNoiseClassificationEvidence(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("192.0.2.1")}
	for _, c := range []struct {
		name, raw, status string
		reputation, note  bool
		abuser, public    bool
		riskCount, score  int
	}{
		{"unknown", `{"noise":true,"riot":false,"classification":"unknown"}`, "ok", false, true, false, false, 0, 100},
		{"unrecognised", `{"noise":true,"classification":"unclassified"}`, "ok", false, true, false, false, 0, 100},
		{"benign", `{"noise":true,"classification":"benign","name":"Research scanner"}`, "ok", true, true, false, false, 0, 100},
		{"malicious", `{"noise":true,"classification":"malicious"}`, "ok", true, false, true, false, 1, 53},
		{"riot", `{"riot":true}`, "ok", true, true, false, true, 0, 100},
		{"riot with unknown", `{"noise":true,"riot":true,"classification":"unknown"}`, "ok", true, true, false, true, 0, 100},
		{"riot does not erase malicious", `{"noise":true,"riot":true,"classification":"malicious"}`, "ok", true, true, true, true, 1, 53},
		{"no match remains empty", `{"noise":false,"riot":false,"classification":"unknown"}`, "empty", false, false, false, false, 0, 100},
		{"invalid response remains error", `{"noise":"yes"}`, "error", false, false, false, false, 0, 100},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := NewSet(nil, []*Provider{fixtureProvider(greynoise(""), c.raw)})
			for pass := 0; pass < 2; pass++ {
				o := &Out{Res: &model.Result{Mode: "full"}}
				o.Res.Sources = s.Run(context.Background(), q, o, false)
				if len(o.Res.Sources) != 1 {
					t.Fatalf("sources = %+v", o.Res.Sources)
				}
				st := o.Res.Sources[0]
				if st.Status != c.status || st.Reputation != c.reputation || (st.Note != "") != c.note {
					t.Fatalf("source = %+v, want status %s / reputation %t / note %t", st, c.status, c.reputation, c.note)
				}
				if pass == 1 && !st.Cached {
					t.Fatal("fixture was not served from cache on second run")
				}
				o.Res.Verdict, o.Res.Flags = classify.Decide(o.Sig)
				if o.Res.Flags.Abuser != c.abuser || o.Res.Flags.PublicService != c.public || len(o.Res.Risk) != c.riskCount {
					t.Fatalf("flags = %+v, risks = %+v", o.Res.Flags, o.Res.Risk)
				}
				if c.abuser && o.Res.Risk[0].Value != 90 {
					t.Fatalf("confirmed malicious risk changed: %+v", o.Res.Risk)
				}
				if score := classify.Score(o.Res); score.Value != c.score {
					t.Fatalf("score = %+v, want %d", score, c.score)
				}
			}
		})
	}
}

func TestRiskPolicyJSONKeepsRawAndOptionalExplanation(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("192.0.2.1")}
	o := &Out{Res: &model.Result{}}
	if err := ipyou().Apply(o, q, []byte(`{"ip_score":{"score":15}}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(o.Res.Risk[0])
	if err != nil {
		t.Fatal(err)
	}
	var encoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &encoded); err != nil {
		t.Fatal(err)
	}
	if string(encoded["value"]) != "15" || string(encoded["effective_value"]) != "0" || len(encoded["scoring_note"]) == 0 {
		t.Fatalf("JSON lost original value or policy explanation: %s", raw)
	}
	raw, err = json.Marshal(model.Risk{Source: "other", Value: 15})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "effective_value") || strings.Contains(string(raw), "scoring_note") {
		t.Fatalf("optional risk fields changed an unadjusted reading: %s", raw)
	}
	raw, err = json.Marshal(model.Source{Name: "GreyNoise", Note: "来源分类未知"})
	if err != nil || !strings.Contains(string(raw), `"note":"来源分类未知"`) {
		t.Fatalf("source explanation missing from JSON: %s / %v", raw, err)
	}
}
