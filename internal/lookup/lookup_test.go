package lookup

import (
	"context"
	"net/netip"
	"testing"

	"github.com/zzusec/ip-lookup/internal/dnsq"
	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/internal/sources"
)

func TestRPKIRequiresOriginAndPrefixFromSameObservation(t *testing.T) {
	query := sources.Query{Addr: netip.MustParseAddr("192.0.2.10"), ASN: 64500, Prefix: netip.MustParsePrefix("192.0.2.8/30")}
	incomplete := map[string]string{"bgp_prefix:ripe": "192.0.2.0/24", "origin_asn:cymru": "64501"}
	if got := observedRouteQuery(query, incomplete); got.Prefix.IsValid() || got.ASN != 64500 {
		t.Fatalf("mixed observations or offline route: %+v", got)
	}
	incomplete["origin_asn:ripe"] = "64502"
	incomplete["bgp_prefix:cymru"] = "198.51.100.0/24"
	got := observedRouteQuery(query, incomplete)
	if got.ASN != 64502 || got.Prefix.String() != "192.0.2.0/24" {
		t.Fatalf("wrong observed pair: %+v", got)
	}
}

func TestCanceledDNSBLIsNotSuccessfulSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service := Service{DNS: dnsq.New([]string{"127.0.0.1:0"})}
	out := &sources.Out{Res: &model.Result{}}
	statuses := service.dnsChecks(ctx, out, netip.MustParseAddr("192.0.2.2"))
	listed, checked := model.SummarizeDNSBL(out.Res.DNSBL)
	if listed != 0 || checked != 0 || len(out.Res.DNSBL) != len(dnsq.Zones) || len(out.Sig) != 0 {
		t.Fatalf("invalid DNSBL results: %+v; signals %+v", out.Res.DNSBL, out.Sig)
	}
	for _, source := range statuses {
		if source.Name == "DNSBL" {
			if source.Status != "error" || source.Error == "" {
				t.Fatalf("all failed but source was %+v", source)
			}
			return
		}
	}
	t.Fatal("missing DNSBL source")
}

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
