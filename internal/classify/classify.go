// Package classify turns the signals reported by data sources into a verdict,
// boolean flags, a native/broadcast judgement and a purity score.
package classify

import (
	"cmp"
	"slices"
	"strings"

	"github.com/zzusec/ip-lookup/internal/model"
)

// Network types a Signal may vote for, in tie-break order: when two types
// collect the same weight the earlier one wins.
var Types = []string{"cdn", "hosting", "mobile", "residential", "education", "government", "business"}

// Usages are flags that describe how an address is used, independent of its type.
var Usages = []string{"tor", "vpn", "proxy", "icloud_relay", "crawler", "abuser", "public_service", "anycast", "satellite"}

var TypeLabels = map[string]string{
	"residential": "家庭宽带", "mobile": "移动网络", "hosting": "机房", "cdn": "CDN",
	"business": "企业", "education": "教育网", "government": "政府", "unknown": "未知",
}

var UsageLabels = map[string]string{
	"tor": "Tor 出口", "vpn": "VPN", "proxy": "代理", "icloud_relay": "iCloud 专用代理",
	"crawler": "爬虫", "abuser": "滥用记录", "public_service": "公共服务",
	"anycast": "任播", "satellite": "卫星网络",
}

const (
	typeMin  = 30  // weight a type needs before it is reported at all
	usageMin = 60  // weight a usage flag needs: one strong source or two agreeing ones
	cdnMin   = 120 // CDN evidence that turns a hosting verdict into CDN
	flagMin  = 60  // weight that sets is_hosting / is_cdn even when another type won
)

// Totals adds up the evidence per kind. Each source counts once per kind, at
// its strongest weight, so one provider cannot outvote the others by repeating itself.
func Totals(sig []model.Signal) map[string]int {
	best := map[[2]string]int{}
	for _, s := range sig {
		k := [2]string{s.Kind, s.Source}
		best[k] = max(best[k], s.Weight)
	}
	t := map[string]int{}
	for k, w := range best {
		t[k[0]] += w
	}
	return t
}

// Decide picks the network type and the usage flags.
func Decide(sig []model.Signal) (model.Verdict, model.Flags) {
	t := Totals(sig)
	v := model.Verdict{Type: "unknown", Usage: []string{}, UsageLabels: []string{}}
	// CDN edges are data-center addresses that most providers file under
	// hosting, so the two compete as one family against the other types and
	// CDN is then chosen within the family.
	weight := func(k string) int {
		if k == "hosting" {
			return max(t["hosting"], t["cdn"])
		}
		return t[k]
	}
	top, second := 0, 0
	for _, k := range Types {
		if k == "cdn" {
			continue
		}
		switch w := weight(k); {
		case w > top:
			top, second, v.Type = w, top, k
		case w > second:
			second = w
		}
	}
	if top < typeMin {
		v.Type = "unknown"
	}
	if v.Type == "hosting" && (t["cdn"] >= cdnMin || t["cdn"] > t["hosting"]) {
		v.Type = "cdn"
	}
	switch {
	case v.Type == "unknown":
		v.Confidence = "low"
	case top >= 120 && top-second >= 60:
		v.Confidence = "high"
	case top >= 60 && top > second:
		v.Confidence = "medium"
	default:
		v.Confidence = "low"
	}
	for _, k := range Usages {
		if t[k] >= usageMin {
			v.Usage = append(v.Usage, k)
		}
	}
	slices.SortStableFunc(v.Usage, func(a, b string) int { return cmp.Compare(t[b], t[a]) })
	for _, k := range v.Usage {
		v.UsageLabels = append(v.UsageLabels, UsageLabels[k])
	}
	v.TypeLabel = TypeLabels[v.Type]
	v.Label = v.TypeLabel
	if len(v.UsageLabels) > 0 {
		v.Label += " · " + strings.Join(v.UsageLabels, " / ")
	}
	v.Evidence = evidence(sig)

	has := func(k string) bool { return slices.Contains(v.Usage, k) }
	f := model.Flags{
		Tor: has("tor"), VPN: has("vpn"), Proxy: has("proxy"), Crawler: has("crawler"),
		Abuser: has("abuser"), ICloudRelay: has("icloud_relay"), PublicService: has("public_service"),
		Anycast: has("anycast"), Satellite: has("satellite"),
		Hosting:     v.Type == "hosting" || t["hosting"] >= flagMin,
		CDN:         v.Type == "cdn" || t["cdn"] >= flagMin,
		Mobile:      v.Type == "mobile",
		Residential: v.Type == "residential",
	}
	return v, f
}

// evidence keeps the strongest signal per (kind, source), strongest first.
func evidence(sig []model.Signal) []model.Signal {
	out := []model.Signal{}
	seen := map[[2]string]int{}
	for _, s := range sig {
		k := [2]string{s.Kind, s.Source}
		if i, ok := seen[k]; ok {
			if s.Weight > out[i].Weight {
				out[i] = s
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, s)
	}
	slices.SortStableFunc(out, func(a, b model.Signal) int { return cmp.Compare(b.Weight, a.Weight) })
	return out
}
