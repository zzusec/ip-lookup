package lookup

import (
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/internal/sources"
)

// 纯真 and 百度 put notes such as IDC机房 or 阿里云 next to the operator; they
// must not vote on the type the way other providers' ISP names do.
func TestFinishSkipsChineseNotes(t *testing.T) {
	r := &model.Result{GeoSources: []model.GeoSource{
		{Source: "纯真 (zxinc)", ISP: "电信/IDC机房"},
		{Source: "百度 IP", ISP: "阿里云"},
		{Source: "ip-api.com", ISP: "Example Broadband"},
	}}
	(&Service{}).finish(&sources.Out{Res: r})
	var got []string
	for _, s := range r.Verdict.Evidence {
		if s.Source == "名称关键词" {
			got = append(got, s.Kind+":"+s.Detail)
		}
	}
	if want := "residential:Example Broadband"; len(got) != 1 || got[0] != want {
		t.Errorf("name keyword signals = %v, want [%s]", got, want)
	}
}

func TestFillConsensusGeo(t *testing.T) {
	r := &model.Result{
		Geo: model.Geo{Country: "泰国", CountryCode: "TH"},
		GeoSources: []model.GeoSource{
			{Source: "Merged-IP", Country: "泰国", CountryCode: "TH"},
			{Source: "DB-IP City Lite", Country: "泰国", CountryCode: "TH", Region: "Uttaradit", City: "Tron"},
			{Source: "IP2Location.io", Country: "泰国", CountryCode: "TH", Region: "Phetchabun", City: "Si Thep"},
			{Source: "ipinfo.io", Country: "泰国", CountryCode: "TH", Region: "Chiang Mai", City: "Wiang Haeng"},
			{Source: "ip-api.com", Country: "泰国", CountryCode: "TH", Region: "程逸府", City: "Tron"},
		},
	}
	fillConsensusGeo(r)
	if r.Geo.Region != "程逸府" || r.Geo.City != "Tron" {
		t.Fatalf("got region=%q city=%q, want 程逸府 / Tron", r.Geo.Region, r.Geo.City)
	}
}
