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
	listed := 0
	for _, d := range r.DNSBL {
		if d.Listed {
			listed++
		}
	}
	if listed > 0 {
		add(fmt.Sprintf("DNSBL 命中 %d 个", listed), -min(listed*5, 20))
	}
	if len(r.Risk) > 0 {
		sum := 0
		for _, x := range r.Risk {
			sum += x.Value
		}
		add(fmt.Sprintf("第三方风险分均值 %d", sum/len(r.Risk)), -sum/len(r.Risk)/4)
	}
	s.Value = max(0, min(100, s.Value))
	s.Level = Level(s.Value)
	return s
}

func Level(v int) string {
	switch {
	case v >= 95:
		return "极度纯净"
	case v >= 80:
		return "纯净"
	case v >= 50:
		return "良好"
	case v >= 25:
		return "中性"
	}
	return "可疑"
}
