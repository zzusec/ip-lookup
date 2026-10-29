package classify

import (
	"slices"
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

func sig(kind, src string, w int) model.Signal { return Sig(kind, src, "", w) }

func TestDecide(t *testing.T) {
	cases := []struct {
		name  string
		sig   []model.Signal
		typ   string
		conf  string
		usage []string
	}{
		{"hosting with weak vpn tag", []model.Signal{
			sig("hosting", "a", 60), sig("hosting", "b", 60), sig("hosting", "c", 50), sig("vpn", "bgp.tools", 20),
			sig("business", "d", 40),
		}, "hosting", "high", nil},
		{"residential", []model.Signal{
			sig("residential", "a", 60), sig("residential", "b", 50), sig("residential", "c", 40),
		}, "residential", "high", nil},
		{"mobile beats weak residential", []model.Signal{
			sig("mobile", "a", 70), sig("mobile", "b", 60), sig("residential", "c", 50),
		}, "mobile", "high", nil},
		{"cdn refines hosting", []model.Signal{
			sig("hosting", "a", 60), sig("hosting", "b", 60), sig("hosting", "c", 50),
			sig("cdn", "list", 90), sig("cdn", "c", 50), sig("business", "d", 40),
		}, "cdn", "high", nil},
		{"weak cdn stays hosting", []model.Signal{
			sig("hosting", "a", 60), sig("hosting", "b", 60), sig("cdn", "c", 50), sig("cdn", "d", 50),
		}, "hosting", "high", nil},
		{"tor exit", []model.Signal{
			sig("hosting", "a", 60), sig("tor", "list", 100), sig("tor", "b", 80), sig("vpn", "c", 30),
		}, "hosting", "medium", []string{"tor"}},
		{"usage ordered by weight", []model.Signal{
			sig("hosting", "a", 60), sig("proxy", "x", 60), sig("vpn", "y", 70), sig("vpn", "z", 50),
		}, "hosting", "medium", []string{"vpn", "proxy"}},
		{"too little evidence", []model.Signal{sig("hosting", "a", 20)}, "unknown", "low", nil},
		{"one source cannot vote twice", []model.Signal{
			sig("residential", "a", 25), sig("residential", "a", 25), sig("residential", "a", 25),
		}, "unknown", "low", nil},
	}
	for _, c := range cases {
		v, f := Decide(c.sig)
		if v.Type != c.typ || v.Confidence != c.conf {
			t.Errorf("%s: type=%s conf=%s, want %s %s (totals %v)", c.name, v.Type, v.Confidence, c.typ, c.conf, Totals(c.sig))
		}
		if !slices.Equal(v.Usage, c.usage) && !(len(v.Usage) == 0 && len(c.usage) == 0) {
			t.Errorf("%s: usage=%v, want %v", c.name, v.Usage, c.usage)
		}
		if len(v.Usage) != len(v.UsageLabels) {
			t.Errorf("%s: usage and labels differ in length", c.name)
		}
		if c.typ == "cdn" && (!f.CDN || !f.Hosting) {
			t.Errorf("%s: cdn verdict should set is_cdn and is_hosting, got %+v", c.name, f)
		}
		if slices.Contains(c.usage, "tor") && !f.Tor {
			t.Errorf("%s: is_tor not set", c.name)
		}
	}
}

func TestRDNS(t *testing.T) {
	cases := map[string]string{
		"modemcable001.0-48-24.mc.videotron.ca": "residential",
		"c-73-15-2-1.hsd1.ca.comcast.net":       "residential",
		"pool-71-1-1-1.nycmny.fios.verizon.net": "residential",
		"crawl-66-249-66-1.googlebot.com":       "",
		"static.1.2.3.4.clients.your-server.de": "hosting",
		"mobile-166-1-1-1.mycingular.net":       "mobile",
		"ns1.cs.tsinghua.edu.cn":                "",
		"host-1-2-3-4.ox.ac.uk":                 "education",
		"ec2-3-4-5-6.compute-1.amazonaws.com":   "hosting",
	}
	for name, want := range cases {
		got := RDNS([]string{name})
		kinds := []string{}
		for _, s := range got {
			kinds = append(kinds, s.Kind)
		}
		if want == "" {
			continue // only checks that nothing panics
		}
		if !slices.Contains(kinds, want) {
			t.Errorf("RDNS(%s) = %v, want %s", name, kinds, want)
		}
	}
}

func TestProviderType(t *testing.T) {
	for in, want := range map[string]string{
		"Hosting": "hosting", "DCH": "hosting", "数据中心": "hosting", "isp": "residential",
		"Residential": "residential", "家庭宽带": "residential", "Mobile": "mobile", "business": "business",
		"Education": "education", "gov": "government", "": "", "Wireless Broadband": "mobile",
	} {
		if got := ProviderType(in); got != want {
			t.Errorf("ProviderType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNativeAndScore(t *testing.T) {
	if n := Native([]string{"", "EU", "us"}, "US", "arin"); n.Status != "native" || n.RegisteredCountry != "US" {
		t.Errorf("native: %+v", n)
	}
	if n := Native([]string{"US"}, "GB", ""); n.Status != "broadcast" {
		t.Errorf("broadcast: %+v", n)
	}
	if n := Native(nil, "GB", ""); n.Status != "unknown" {
		t.Errorf("unknown: %+v", n)
	}
	r := &model.Result{Flags: model.Flags{Tor: true, Proxy: true, Hosting: true}}
	if s := Score(r); s.Value != 100-60-10-25 || s.Level != "可疑" {
		t.Errorf("score: %+v", s)
	}
	clean := &model.Result{Risk: []model.Risk{{Value: 0}, {Value: 20}}}
	if s := Score(clean); s.Value != 98 || s.Level != "极度纯净" {
		t.Errorf("clean score: %+v", s)
	}
}
