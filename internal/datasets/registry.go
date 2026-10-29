// Package datasets downloads offline databases and IP lists, keeps them fresh
// and answers lookups against whatever was loaded last.
package datasets

import "time"

// Format says how a downloaded file is parsed.
type Format int

const (
	MMDB      Format = iota // MaxMind DB, opened with mmap
	MMDBGzip                // gzip-compressed MaxMind DB
	XDB                     // ip2region xdb
	CIDRLines               // one address or block per line, # comments
	ProxyURLs               // scheme://ip:port per line
	Ipsum                   // "ip<TAB>count" per line
	FirstCol                // CSV whose first column is a block (geofeeds, iCloud relay)
	AWSJSON
	GCPJSON
	OracleJSON
	SpamhausNDJSON
	FastlyJSON
	ASNCSV // bgp.tools asns.csv
	ASNTag // bgp.tools tags/<tag>.csv
	ASNDrop
)

// Spec is one downloadable dataset.
type Spec struct {
	ID       string
	Label    string
	Category string // geo | asn | tor | vpn | proxy | icloud_relay | hosting | cdn | crawler | public_service | abuse | as_tag
	Format   Format
	URLs     []string // all parts are merged into one set
	Every    time.Duration
	Homepage string
	License  string
	Weight   int    // evidence weight of a hit; 0 means the category default
	Tag      string // format-specific filter or bgp.tools tag name
	Static   string // built-in content used instead of URLs
}

const (
	gh  = "https://raw.githubusercontent.com/"
	la  = gh + "lord-alfred/ipranges/main/"
	ax  = gh + "axpwx/IP-Data/master/provider/"
	x4b = gh + "X4BNet/lists_vpn/main/output/"
	day = 24 * time.Hour
)

func both(base string) []string { return []string{base + "ipv4_merged.txt", base + "ipv6_merged.txt"} }
func v4(base string) []string   { return []string{base + "ipv4_merged.txt"} }
func axp(name string) []string {
	return []string{ax + name + "-cidr-ipv4.txt", ax + name + "-cidr-ipv6.txt"}
}

// coreSpecs are the geolocation databases and the curated lists; see Specs.
var coreSpecs = []Spec{
	{ID: "merged", Label: "Merged-IP（GeoLite2 + IPinfo Lite + DB-IP）", Category: "geo", Format: MMDB,
		URLs:  []string{"https://github.com/NetworkCats/Merged-IP-Data/releases/latest/download/Merged-IP.mmdb"},
		Every: day, Homepage: "https://github.com/NetworkCats/Merged-IP-Data", License: "CC BY-SA 4.0 / CC BY 4.0"},
	{ID: "dbip-city", Label: "DB-IP City Lite", Category: "geo", Format: MMDBGzip,
		URLs:  []string{"https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"},
		Every: 7 * day, Homepage: "https://db-ip.com/db/lite.php", License: "CC BY 4.0"},
	{ID: "dbip-asn", Label: "DB-IP ASN Lite", Category: "asn", Format: MMDBGzip,
		URLs:  []string{"https://download.db-ip.com/free/dbip-asn-lite-{month}.mmdb.gz"},
		Every: 7 * day, Homepage: "https://db-ip.com/db/lite.php", License: "CC BY 4.0"},
	{ID: "ip2region-v4", Label: "ip2region IPv4（国内省市与运营商）", Category: "geo", Format: XDB,
		URLs:  []string{gh + "lionsoul2014/ip2region/master/data/ip2region_v4.xdb"},
		Every: 7 * day, Homepage: "https://github.com/lionsoul2014/ip2region", License: "Apache-2.0"},
	{ID: "ip2region-v6", Label: "ip2region IPv6", Category: "geo", Format: XDB,
		URLs:  []string{gh + "lionsoul2014/ip2region/master/data/ip2region_v6.xdb"},
		Every: 7 * day, Homepage: "https://github.com/lionsoul2014/ip2region", License: "Apache-2.0"},
	{ID: "bgptools-asns", Label: "bgp.tools AS 分类", Category: "asn", Format: ASNCSV,
		URLs: []string{"https://bgp.tools/asns.csv"}, Every: day, Homepage: "https://bgp.tools/kb/api"},

	{ID: "tor", Label: "Tor 出口节点", Category: "tor", Format: CIDRLines,
		URLs: []string{"https://check.torproject.org/torbulkexitlist"}, Every: time.Hour,
		Homepage: "https://metrics.torproject.org/"},
	{ID: "x4b-vpn", Label: "X4BNet VPN 网段", Category: "vpn", Format: CIDRLines, Weight: 60,
		URLs: []string{x4b + "vpn/ipv4.txt", x4b + "vpn/ipv6.txt"}, Every: day, Homepage: "https://github.com/X4BNet/lists_vpn"},
	{ID: "protonvpn", Label: "ProtonVPN 出口", Category: "vpn", Format: CIDRLines, URLs: v4(la + "protonvpn/"),
		Every: day, Homepage: "https://github.com/lord-alfred/ipranges", License: "CC0-1.0"},
	{ID: "icloud-relay", Label: "iCloud 专用代理出口", Category: "icloud_relay", Format: FirstCol,
		URLs: []string{"https://mask-api.icloud.com/egress-ip-ranges.csv"}, Every: day,
		Homepage: "https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/"},
	{ID: "monosans", Label: "monosans 公开代理", Category: "proxy", Format: ProxyURLs,
		URLs: []string{gh + "monosans/proxy-list/main/proxies/all.txt"}, Every: 2 * time.Hour,
		Homepage: "https://github.com/monosans/proxy-list", License: "MIT"},
	{ID: "proxifly", Label: "proxifly 公开代理", Category: "proxy", Format: ProxyURLs,
		URLs: []string{gh + "proxifly/free-proxy-list/main/proxies/all/data.txt"}, Every: 2 * time.Hour,
		Homepage: "https://github.com/proxifly/free-proxy-list", License: "GPL-3.0"},
	{ID: "x4b-dc", Label: "X4BNet 机房网段", Category: "hosting", Format: CIDRLines, Weight: 60,
		URLs: []string{x4b + "datacenter/ipv4.txt", x4b + "datacenter/ipv6.txt"}, Every: day,
		Homepage: "https://github.com/X4BNet/lists_vpn"},
	{ID: "ipsum", Label: "IPsum 威胁情报（≥3 个黑名单）", Category: "abuse", Format: Ipsum,
		URLs: []string{gh + "stamparm/ipsum/master/ipsum.txt"}, Every: 6 * time.Hour,
		Homepage: "https://github.com/stamparm/ipsum", License: "Unlicense"},
	{ID: "spamhaus-drop", Label: "Spamhaus DROP", Category: "abuse", Format: SpamhausNDJSON, Weight: 70,
		URLs:  []string{"https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"},
		Every: 12 * time.Hour, Homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"},
	{ID: "spamhaus-asndrop", Label: "Spamhaus ASN-DROP", Category: "abuse", Format: ASNDrop,
		URLs: []string{"https://www.spamhaus.org/drop/asndrop.json"}, Every: 12 * time.Hour,
		Homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"},
	{ID: "firehol-l1", Label: "FireHOL Level 1", Category: "abuse", Format: CIDRLines,
		URLs: []string{"https://iplists.firehol.org/files/firehol_level1.netset"}, Every: 12 * time.Hour,
		Homepage: "https://iplists.firehol.org/"},
}
