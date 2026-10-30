package sources

import (
	"strings"

	"github.com/zzusec/ip-lookup/internal/model"
)

// Chinese IP databases file these under 中国; ISO 3166 and the other sources
// give them codes of their own.
var cnSpecial = map[string]string{"香港": "HK", "澳门": "MO", "台湾": "TW"}

// zhCountry returns the country a Chinese place name starts with, e.g. 美国
// in 美国加利福尼亚. The longest name wins, so 印度尼西亚 is not read as 印度.
func zhCountry(s string) (name, cc string) {
	for n, c := range countryZH {
		if len(n) > len(name) && strings.HasPrefix(s, n) {
			name, cc = n, c
		}
	}
	return name, cc
}

// cnPlace splits a Chinese place such as 广东省广州市, 北京市北京市 or
// 广西壮族自治区南宁市 after its province-level part; ok is false when s has
// none.
func cnPlace(s string) (province, city string, ok bool) {
	for _, suffix := range []string{"特别行政区", "自治区", "省", "市"} {
		if i := strings.Index(s, suffix); i > 0 {
			i += len(suffix)
			return s[:i], s[i:], true
		}
	}
	return s, "", false
}

// zxincGeo reads 纯真's "国家–省–市[–区]" place and its note on the operator.
func zxincGeo(location, place, local string) model.GeoSource {
	g := model.GeoSource{Source: "纯真 (zxinc)", Text: strings.TrimSpace(strings.ReplaceAll(location, "–", " "))}
	var parts []string
	for _, p := range strings.Split(place, "–") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) > 0 {
		g.Country, g.CountryCode, parts = parts[0], countryZH[parts[0]], parts[1:]
		if g.Country == "中国" {
			g.CountryCode = "CN"
			if len(parts) > 0 && cnSpecial[parts[0]] != "" {
				g.Country, g.CountryCode, parts = parts[0], cnSpecial[parts[0]], parts[1:]
			}
		}
	}
	if len(parts) > 0 {
		g.Region = parts[0]
	}
	if len(parts) > 1 {
		// 中国–省–市–区 but 美国–州–县–市: the city is the second level below
		// the province in China and the last one elsewhere.
		g.City = parts[len(parts)-1]
		if g.CountryCode == "CN" {
			g.City = parts[1]
		}
	}
	if local = strings.TrimSpace(local); !strings.EqualFold(local, "CZ88.NET") { // 纯真's "no data"
		g.ISP = local
	}
	return g
}

// baiduGeo reads 百度's location line, e.g. "广东省广州市 移动" or "美国加利福尼亚".
// Abroad it runs the country and a region or city together; region and city,
// the main result's names, tell the two apart when they are Chinese too.
func baiduGeo(location, region, city string) model.GeoSource {
	g := model.GeoSource{Source: "百度 IP", Text: strings.TrimSpace(location)}
	f := strings.Fields(location)
	if len(f) == 0 {
		return g
	}
	place, isp := f[0], strings.Join(f[1:], " ")
	if name, cc := zhCountry(place); cc != "" {
		g.Country, g.CountryCode, g.ISP = name, cc, isp
		switch rest := place[len(name):]; {
		case rest == "":
		case city != "" && strings.HasSuffix(rest, city):
			g.Region, g.City = strings.TrimSuffix(rest, city), city
		case region != "" && strings.HasPrefix(rest, region):
			g.Region, g.City = region, strings.TrimPrefix(rest, region)
		default:
			g.Region = rest
		}
		return g
	}
	cn := strings.TrimPrefix(place, "中国")
	province, town, ok := cnPlace(cn)
	if !ok && cn == place {
		return g // neither a known country nor a Chinese place: only the text is kept
	}
	g.Country, g.CountryCode, g.Region, g.City, g.ISP = "中国", "CN", province, town, isp
	if k := strings.TrimSuffix(strings.TrimSuffix(province, "特别行政区"), "省"); cnSpecial[k] != "" {
		g.Country, g.CountryCode, g.Region, g.City = k, cnSpecial[k], town, ""
	}
	return g
}
