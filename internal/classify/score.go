package classify

import (
	"fmt"
	"strings"

	"github.com/zzusec/ip-lookup/internal/model"
)

// Native compares where a block is registered with where it is located.
// reg lists registration countries in priority order; region codes such as
// EU or AP are skipped because they cannot be compared with a country.
func Native(reg []string, geo, registry string) model.Native {
	n := model.Native{Status: "unknown", Label: "未知", GeoCountry: strings.ToUpper(geo), Registry: registry}
	for _, c := range reg {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) == 2 && c != "EU" && c != "AP" && c != "ZZ" {
			n.RegisteredCountry = c
			break
		}
	}
	switch {
	case n.RegisteredCountry == "" || n.GeoCountry == "":
		n.Detail = "缺少注册地或定位国家"
	case n.RegisteredCountry == n.GeoCountry:
		n.Status, n.Label = "native", "原生 IP"
		n.Detail = "注册地与定位国家一致：" + n.GeoCountry
	default:
		n.Status, n.Label = "broadcast", "广播 IP"
		n.Detail = "注册地 " + n.RegisteredCountry + "，定位 " + n.GeoCountry
	}
	return n
}

// Score rates how clean an address looks, 100 being best. It only reads the
// verdict-derived fields of r, so call it after Decide and Native.
func Score(r *model.Result) model.Score {
	s := model.Score{Value: 100, Factors: []model.Factor{}}
	add := func(name string, d int) {
		if d != 0 {
			s.Factors = append(s.Factors, model.Factor{Name: name, Delta: d})
			s.Value += d
		}
	}
	f := r.Flags
	// Anonymizer flags overlap (a Tor exit is usually also listed as a proxy),
	// so the strongest one counts fully and each further one adds a little.
	first := true
	for _, x := range []struct {
		on   bool
		name string
		d    int
	}{{f.Tor, "Tor 出口", -60}, {f.Proxy, "代理", -40}, {f.VPN, "VPN", -35}} {
		if !x.on {
			continue
		}
		if first {
			add(x.name, x.d)
			first = false
		} else {
			add(x.name, -10)
		}
	}
	if f.Hosting {
		add("机房 IP", -25)
	} else if f.CDN {
		add("CDN IP", -15)
	}
	if f.Abuser {
		add("滥用记录", -25)
	}
	if f.Crawler {
		add("爬虫网段", -10)
	}
	if f.ICloudRelay {
		add("iCloud 专用代理", -10)
	}
	if r.Native.Status == "broadcast" {
		add("广播 IP", -10)
	}
	if f.Leased {
		add("商业租赁网段", -8)
	}
	if r.Audit != nil {
		if r.Audit.Flow != nil && r.Audit.Flow.Masquerade {
			add("出向型流量与家宽声明冲突", -10)
		}
		if nb := r.Audit.Neighbor; nb != nil && nb.Total == 256 {
			switch {
			case nb.Flagged >= 32:
				add(fmt.Sprintf("同 /24 风险邻居 %d/256", nb.Flagged), -8)
			case nb.Flagged >= 8:
				add(fmt.Sprintf("同 /24 风险邻居 %d/256", nb.Flagged), -4)
			}
		}
	}
	listed, _ := model.SummarizeDNSBL(r.DNSBL)
	if listed > 0 {
		add(fmt.Sprintf("DNSBL 命中 %d 个", listed), -min(listed*5, 20))
	}
	if len(r.Risk) > 0 {
		sum := 0
		for _, x := range r.Risk {
			value := x.Value
			if x.EffectiveValue != nil && *x.EffectiveValue >= 0 && *x.EffectiveValue <= 100 {
				value = *x.EffectiveValue
			}
			sum += value
		}
		add(fmt.Sprintf("第三方风险分均值 %d", sum/len(r.Risk)), -sum/len(r.Risk)/4)
	}
	s.Value = max(0, min(100, s.Value))
	s.Level, s.Tone = LevelAndTone(s.Value)
	s.DataStatus, s.Coverage = scoreCoverage(r, len(s.Factors) > 0)
	if s.DataStatus == "unavailable" {
		s.Tone = "unknown"
	}
	return s
}

func Level(v int) string {
	lvl, _ := LevelAndTone(v)
	return lvl
}

// LevelAndTone pairs each score band with an unambiguous semantic color tier:
// green is reserved strictly for clean addresses (>=78), while 55..77 is amber
// ("一般") and 30..54 is orange-red ("风险偏高").
func LevelAndTone(v int) (level, tone string) {
	switch {
	case v >= 90:
		return "极度纯净", "excellent"
	case v >= 78:
		return "纯净", "good"
	case v >= 55:
		return "一般", "fair"
	case v >= 30:
		return "风险偏高", "poor"
	default:
		return "可疑", "bad"
	}
}
