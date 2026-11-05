package classify

import (
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

// This records the original arithmetic independently of provider parsing.
// Unknown observations must no longer be turned into the synthetic 50 below.
func TestLegacyUnknownObservationProduced95(t *testing.T) {
	r := &model.Result{Flags: model.Flags{Mobile: true}, Risk: []model.Risk{
		{Source: "proxycheck.io", Value: 0},
		{Source: "ipyou.net", Value: 15, Detail: "等级 low"},
		{Source: "GreyNoise", Value: 50, Detail: "unknown unknown 2026-01-01"},
	}}
	s := Score(r)
	if s.Value != 95 || len(s.Factors) != 1 || s.Factors[0].Delta != -5 {
		t.Fatalf("legacy input score = %+v, want one deduction of 5", s)
	}
}

func TestScoreEffectiveRiskValue(t *testing.T) {
	zero, invalidLow, invalidHigh := 0, -1, 101
	for _, c := range []struct {
		name string
		risk model.Risk
		want int
	}{
		{"effective zero preserves raw reading", model.Risk{Value: 15, EffectiveValue: &zero}, 100},
		{"raw reading without adjustment", model.Risk{Value: 15}, 97},
		{"negative effective reading falls back", model.Risk{Value: 80, EffectiveValue: &invalidLow}, 80},
		{"oversized effective reading falls back", model.Risk{Value: 80, EffectiveValue: &invalidHigh}, 80},
		{"high risk on mobile still deducts", model.Risk{Value: 90}, 78},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &model.Result{Flags: model.Flags{Mobile: true}, Risk: []model.Risk{c.risk}}
			if s := Score(r); s.Value != c.want {
				t.Fatalf("score = %+v, want %d", s, c.want)
			}
		})
	}
	for _, c := range []struct {
		name  string
		flags model.Flags
		dnsbl []model.DNSBL
		want  int
	}{
		{"mobile proxy remains a deduction", model.Flags{Mobile: true, Proxy: true}, nil, 60},
		{"DNSBL remains a deduction", model.Flags{Mobile: true}, []model.DNSBL{{Listed: true}}, 95},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &model.Result{Flags: c.flags, DNSBL: c.dnsbl, Risk: []model.Risk{{Value: 15, EffectiveValue: &zero}}}
			if s := Score(r); s.Value != c.want {
				t.Fatalf("score = %+v, want %d", s, c.want)
			}
		})
	}
}
