package datasets

const laHome = "https://github.com/lord-alfred/ipranges"

// cloud returns a hosting dataset built from a provider's published ranges.
func cloud(id, label string, f Format, urls []string, home string) Spec {
	return Spec{ID: id, Label: label, Category: "hosting", Format: f, URLs: urls, Every: day, Homepage: home, Weight: 90}
}

func cnCloud(id, label string) Spec {
	return Spec{ID: id, Label: label + "（axpwx/IP-Data）", Category: "hosting", Format: CIDRLines,
		URLs: axp(id), Every: 7 * day, Homepage: "https://github.com/axpwx/IP-Data", License: "MIT", Weight: 80}
}

func crawler(id, label string, urls []string) Spec {
	return Spec{ID: id, Label: label, Category: "crawler", Format: CIDRLines, URLs: urls, Every: day,
		Homepage: laHome, License: "CC0-1.0"}
}

func tag(t, label string) Spec {
	return Spec{ID: "bgptools-" + t, Label: "bgp.tools 标签：" + label, Category: "as_tag", Format: ASNTag,
		URLs: []string{"https://bgp.tools/tags/" + t + ".csv"}, Every: day, Homepage: "https://bgp.tools/tags", Tag: t}
}

var rangeSpecs = []Spec{
	cloud("aws", "AWS 官方网段", AWSJSON, []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"},
		"https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"),
	cloud("gcp", "Google Cloud 官方网段", GCPJSON, []string{"https://www.gstatic.com/ipranges/cloud.json"},
		"https://cloud.google.com/compute/docs/faq#find_ip_range"),
	cloud("oracle", "Oracle Cloud 官方网段", OracleJSON,
		[]string{"https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"},
		"https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm"),
	cloud("digitalocean", "DigitalOcean 官方 geofeed", FirstCol, []string{"https://digitalocean.com/geo/google.csv"},
		"https://docs.digitalocean.com/platform/"),
	cloud("linode", "Linode/Akamai 官方 geofeed", FirstCol, []string{"https://geoip.linode.com/"}, "https://www.linode.com/"),
	cloud("vultr", "Vultr 官方 geofeed", FirstCol, []string{"https://geofeed.constant.com/"}, "https://www.vultr.com/"),
	cloud("azure", "Microsoft Azure 网段", CIDRLines, axp("azure"), "https://github.com/axpwx/IP-Data"),
	cloud("ibmcloud", "IBM Cloud 网段", CIDRLines, axp("ibmcloud"), "https://github.com/axpwx/IP-Data"),
	cnCloud("aliyun", "阿里云"),
	cnCloud("tencent", "腾讯云"),
	cnCloud("huawei", "华为云"),
	cnCloud("baidu", "百度智能云"),
	cnCloud("jdcloud", "京东云"),
	cnCloud("ksyun", "金山云"),
	cnCloud("ucloud", "UCloud"),

	{ID: "cloudflare", Label: "Cloudflare 官方网段", Category: "cdn", Format: CIDRLines, Every: day, Weight: 90,
		URLs:     []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"},
		Homepage: "https://www.cloudflare.com/ips/"},
	{ID: "fastly", Label: "Fastly 官方网段", Category: "cdn", Format: FastlyJSON, Every: day, Weight: 90,
		URLs: []string{"https://api.fastly.com/public-ip-list"}, Homepage: "https://www.fastly.com/documentation/"},
	{ID: "cloudfront", Label: "AWS CloudFront", Category: "cdn", Format: AWSJSON, Tag: "CLOUDFRONT", Every: day, Weight: 90,
		URLs: []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"}, Homepage: "https://docs.aws.amazon.com/"},

	crawler("googlebot", "Googlebot", both(la+"googlebot/")),
	crawler("bingbot", "Bingbot", v4(la+"bing/")),
	crawler("duckduckbot", "DuckDuckBot", v4(la+"duckduckbot/")),
	crawler("duckassistbot", "DuckAssistBot", v4(la+"duckassistbot/")),
	crawler("openai", "OpenAI（GPTBot 等）", v4(la+"openai/")),
	crawler("perplexity", "PerplexityBot", v4(la+"perplexity/")),
	crawler("pingdom", "Pingdom 监控", both(la+"pingdom/")),
	crawler("statuscake", "StatusCake 监控", v4(la+"statuscake/")),

	{ID: "google", Label: "Google 网段", Category: "org", Format: GCPJSON, Every: day,
		URLs: []string{"https://www.gstatic.com/ipranges/goog.json"}, Homepage: "https://support.google.com/a/answer/10026322"},
	{ID: "public-dns", Label: "公共 DNS 解析器", Category: "public_service", Format: CIDRLines, Static: publicDNS},
	{ID: "github", Label: "GitHub 网段", Category: "org", Format: CIDRLines, URLs: both(la + "github/"),
		Every: day, Homepage: laHome, License: "CC0-1.0"},
	{ID: "facebook", Label: "Meta 网段", Category: "org", Format: CIDRLines, URLs: both(la + "facebook/"),
		Every: day, Homepage: laHome, License: "CC0-1.0"},
	{ID: "microsoft", Label: "Microsoft 网段", Category: "org", Format: CIDRLines, URLs: both(la + "microsoft/"),
		Every: day, Homepage: laHome, License: "CC0-1.0"},
	{ID: "telegram", Label: "Telegram 网段", Category: "org", Format: CIDRLines, URLs: both(la + "telegram/"),
		Every: day, Homepage: laHome, License: "CC0-1.0"},
	{ID: "twitter", Label: "X/Twitter 网段", Category: "org", Format: CIDRLines, URLs: both(la + "twitter/"),
		Every: day, Homepage: laHome, License: "CC0-1.0"},

	tag("dsl", "家宽"), tag("mobile", "移动网络"), tag("cdn", "CDN"), tag("ddosm", "DDoS 防护"),
	tag("anycast", "任播"), tag("vpn", "VPN"), tag("tor", "Tor"), tag("corp", "企业"), tag("gov", "政府"),
	tag("uni", "高校"), tag("satnet", "卫星"), tag("perso", "个人网络"), tag("icrit", "关键基础设施"),
}

// publicDNS lists the anycast addresses of well-known resolvers.
const publicDNS = `1.1.1.1
1.0.0.1
1.1.1.2
1.0.0.2
1.1.1.3
1.0.0.3
2606:4700:4700::/48
8.8.8.8
8.8.4.4
2001:4860:4860::8888
2001:4860:4860::8844
9.9.9.9
149.112.112.112
2620:fe::/48
208.67.222.222
208.67.220.220
2620:119::/32
94.140.14.14
94.140.15.15
223.5.5.5
223.6.6.6
2400:3200::1
2400:3200:baba::1
119.29.29.29
180.76.76.76
114.114.114.114
114.114.115.115
101.226.4.6
218.30.118.6
`

// Specs lists every dataset the service knows about.
var Specs = append(append([]Spec{}, coreSpecs...), rangeSpecs...)
