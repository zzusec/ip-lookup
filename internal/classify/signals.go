package classify

import (
	"strings"

	"github.com/zzusec/ip-lookup/internal/model"
)

func Sig(kind, source, detail string, weight int) model.Signal {
	return model.Signal{Kind: kind, Source: source, Detail: detail, Weight: weight}
}

// KW is the type a keyword or tag votes for and how strongly.
type KW struct {
	Kind   string
	Weight int
}

// ASClass maps the bgp.tools network class of the origin AS.
func ASClass(class string) (string, int) {
	switch class {
	case "Eyeball":
		return "residential", 40
	case "Content":
		return "hosting", 40
	}
	return "", 0
}

// ASTags maps bgp.tools AS tags. Tags describe the whole AS, so they stay
// below the thresholds unless another source agrees.
var ASTags = map[string]KW{
	"dsl": {"residential", 50}, "mobile": {"mobile", 35}, "cdn": {"cdn", 50}, "ddosm": {"cdn", 30},
	"anycast": {"anycast", 40}, "vpn": {"vpn", 20}, "corp": {"business", 50}, "gov": {"government", 60},
	"uni": {"education", 60}, "satnet": {"satellite", 70},
}

// PeeringDBTypes maps the PeeringDB network type.
var PeeringDBTypes = map[string]KW{
	"Cable/DSL/ISP": {"residential", 40}, "Educational/Research": {"education", 50},
	"Enterprise": {"business", 40}, "Government": {"government", 50}, "Content": {"hosting", 40},
}

// ProviderType maps the usage or connection type string an online provider reports.
func ProviderType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	has := func(w ...string) bool {
		for _, x := range w {
			if strings.Contains(t, x) {
				return true
			}
		}
		return false
	}
	switch {
	case t == "":
		return ""
	case has("hosting", "datacenter", "data center", "数据中心", "机房", "idc") || t == "dch" || t == "dc":
		return "hosting"
	case has("cdn", "content delivery"):
		return "cdn"
	case has("mob", "wireless", "cellular", "蜂窝", "移动网络"):
		return "mobile"
	case has("residential", "家庭", "家宽", "宽带") || t == "isp":
		return "residential"
	case has("business", "企业", "banking") || t == "com":
		return "business"
	case has("edu", "university", "教育"):
		return "education"
	case has("gov", "政府") || t == "mil":
		return "government"
	}
	return ""
}

var rdnsSub = map[string]string{
	"dsl": "residential", "cable": "residential", "ftth": "residential", "fttp": "residential",
	"fttx": "residential", "fibre": "residential", "fiber": "residential", "dynamic": "residential",
	"dhcp": "residential", "pppoe": "residential", "broadband": "residential", "dialup": "residential",
	"mobile": "mobile", "gprs": "mobile", "cellular": "mobile", "tmodns": "mobile", "myvzw": "mobile",
	"server": "hosting", "hosting": "hosting", "vps": "hosting", "colo": "hosting", "dedicated": "hosting",
	"cloud": "hosting", "datacenter": "hosting", "usercontent": "hosting", "compute": "hosting",
}

var rdnsExact = map[string]string{
	"dyn": "residential", "pool": "residential", "ppp": "residential", "cpe": "residential",
	"hsd": "residential", "res": "residential", "resi": "residential", "home": "residential",
	"cust": "residential", "customer": "residential", "user": "residential", "users": "residential",
	"client": "residential", "subscriber": "residential", "catv": "residential", "hfc": "residential",
	"mob": "mobile", "lte": "mobile", "wap": "mobile", "umts": "mobile", "g": "mobile",
	"srv": "hosting", "host": "hosting", "vds": "hosting", "ec": "hosting", "static": "",
	"edu": "education", "gov": "government", "mil": "government",
}

// RDNS guesses the network type from reverse DNS names, one vote per type.
func RDNS(names []string) []model.Signal {
	var out []model.Signal
	seen := map[string]bool{}
	vote := func(kind, name string) {
		if kind != "" && !seen[kind] {
			seen[kind] = true
			out = append(out, Sig(kind, "rDNS", name, 30))
		}
	}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		labels := strings.Split(name, ".")
		if n := len(labels); n >= 3 && labels[n-2] == "ac" && len(labels[n-1]) == 2 {
			vote("education", name)
		}
		for _, tok := range strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
			// 3g/4g/5g keep their letter; other tokens drop digits at both ends (pool123, hsd1).
			t := strings.Trim(tok, "0123456789")
			vote(rdnsExact[t], name)
			for sub, kind := range rdnsSub {
				if strings.Contains(t, sub) {
					vote(kind, name)
				}
			}
		}
	}
	return out
}

var orgWords = []struct {
	word string
	KW
}{
	{"hosting", KW{"hosting", 30}}, {"datacenter", KW{"hosting", 30}}, {"data center", KW{"hosting", 30}},
	{"data centre", KW{"hosting", 30}}, {"server", KW{"hosting", 30}}, {"vps", KW{"hosting", 30}},
	{"colocation", KW{"hosting", 30}}, {"dedicated", KW{"hosting", 30}}, {"cloud", KW{"hosting", 30}},
	{"idc", KW{"hosting", 30}}, {"阿里", KW{"hosting", 40}}, {"腾讯", KW{"hosting", 40}},
	{"华为云", KW{"hosting", 40}}, {"金山云", KW{"hosting", 40}}, {"百度", KW{"hosting", 40}},
	{"京东", KW{"hosting", 40}}, {"ucloud", KW{"hosting", 40}}, {"天翼云", KW{"hosting", 40}},
	{"数据中心", KW{"hosting", 40}}, {"机房", KW{"hosting", 40}},
	{"university", KW{"education", 40}}, {"college", KW{"education", 40}}, {"school", KW{"education", 40}},
	{"教育网", KW{"education", 50}}, {"大学", KW{"education", 40}},
	{"government", KW{"government", 40}}, {"ministry", KW{"government", 40}}, {"政府", KW{"government", 40}},
	{"mobile", KW{"mobile", 30}}, {"wireless", KW{"mobile", 30}}, {"cellular", KW{"mobile", 30}},
	{"broadband", KW{"residential", 30}}, {"cable", KW{"residential", 30}}, {"dsl", KW{"residential", 30}},
	{"fiber", KW{"residential", 30}}, {"fibre", KW{"residential", 30}},
	{"电信", KW{"residential", 20}}, {"联通", KW{"residential", 20}}, {"移动", KW{"residential", 20}},
	{"广电", KW{"residential", 20}}, {"铁通", KW{"residential", 20}},
}

// OrgText scans organisation and ISP names, one vote per type.
func OrgText(names []string) []model.Signal {
	var out []model.Signal
	seen := map[string]bool{}
	for _, n := range names {
		l := strings.ToLower(n)
		for _, w := range orgWords {
			if !seen[w.Kind] && strings.Contains(l, w.word) {
				seen[w.Kind] = true
				out = append(out, Sig(w.Kind, "名称关键词", n, w.Weight))
			}
		}
	}
	return out
}
