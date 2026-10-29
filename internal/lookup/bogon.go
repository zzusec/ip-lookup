// Package lookup assembles the full report for one address from the offline
// datasets, the online providers and the DNS checks.
package lookup

import "net/netip"

var bogons = []struct {
	p      netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "本网络地址（0.0.0.0/8）"},
	{netip.MustParsePrefix("10.0.0.0/8"), "私有地址（RFC 1918）"},
	{netip.MustParsePrefix("100.64.0.0/10"), "运营商级 NAT 地址（RFC 6598）"},
	{netip.MustParsePrefix("127.0.0.0/8"), "本机回环地址"},
	{netip.MustParsePrefix("169.254.0.0/16"), "链路本地地址"},
	{netip.MustParsePrefix("172.16.0.0/12"), "私有地址（RFC 1918）"},
	{netip.MustParsePrefix("192.0.0.0/24"), "IETF 协议分配地址"},
	{netip.MustParsePrefix("192.0.2.0/24"), "文档示例地址（TEST-NET-1）"},
	{netip.MustParsePrefix("192.88.99.0/24"), "已废弃的 6to4 中继任播地址"},
	{netip.MustParsePrefix("192.168.0.0/16"), "私有地址（RFC 1918）"},
	{netip.MustParsePrefix("198.18.0.0/15"), "基准测试地址（常见于代理软件 fake-ip）"},
	{netip.MustParsePrefix("198.51.100.0/24"), "文档示例地址（TEST-NET-2）"},
	{netip.MustParsePrefix("203.0.113.0/24"), "文档示例地址（TEST-NET-3）"},
	{netip.MustParsePrefix("224.0.0.0/4"), "组播地址"},
	{netip.MustParsePrefix("240.0.0.0/4"), "保留地址"},
	{netip.MustParsePrefix("::/128"), "未指定地址"},
	{netip.MustParsePrefix("::1/128"), "本机回环地址"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "本地 NAT64 地址"},
	{netip.MustParsePrefix("100::/64"), "丢弃前缀"},
	{netip.MustParsePrefix("2001:db8::/32"), "文档示例地址"},
	{netip.MustParsePrefix("2001::/23"), "IETF 协议分配地址"},
	{netip.MustParsePrefix("fc00::/7"), "唯一本地地址（ULA）"},
	{netip.MustParsePrefix("fe80::/10"), "链路本地地址"},
	{netip.MustParsePrefix("ff00::/8"), "组播地址"},
}

// Bogon explains why a is not a routable public address, or returns "".
func Bogon(a netip.Addr) string {
	a = a.Unmap()
	for _, b := range bogons {
		if b.p.Contains(a) {
			return b.reason
		}
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return "未分配的 IPv6 地址空间"
	}
	return ""
}
