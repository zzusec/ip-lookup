package cidr

import (
	"net/netip"
	"testing"
)

func TestLookupMostSpecific(t *testing.T) {
	b := NewBuilder()
	for _, c := range [][2]string{
		{"10.0.0.0/8", "big"},
		{"10.1.0.0/16", "mid"},
		{"10.1.2.0/24", "small"},
		{"10.1.2.3", "host"},
		{"10.2.0.0/16", ""},
		{" 10.2.0.0/16 ", "dup"},
		{"192.168.0.0/24", "c"},
		{"2001:db8::/32", "v6"},
		{"2001:db8:1::/48", "v6s"},
		{"2001:db8:1::1", "v6h"},
		{"::ffff:172.16.0.0/108", "mapped"},
	} {
		if !b.AddText(c[0], c[1]) {
			t.Fatalf("AddText(%q) failed", c[0])
		}
	}
	for _, bad := range []string{"", "not-an-ip", "1.2.3.4/33", "1.2.3"} {
		if b.AddText(bad, "") {
			t.Fatalf("AddText(%q) accepted", bad)
		}
	}
	s := b.Build()
	if got := s.Len(); got != 10 {
		t.Fatalf("Len = %d, want 10", got)
	}
	cases := []struct{ ip, prefix, detail string }{
		{"10.1.2.3", "10.1.2.3/32", "host"},
		{"10.1.2.4", "10.1.2.0/24", "small"},
		{"10.1.3.1", "10.1.0.0/16", "mid"},
		{"10.200.0.1", "10.0.0.0/8", "big"},
		{"10.255.255.255", "10.0.0.0/8", "big"},
		{"10.2.9.9", "10.2.0.0/16", "dup"},
		{"11.0.0.0", "", ""},
		{"9.255.255.255", "", ""},
		{"192.168.0.255", "192.168.0.0/24", "c"},
		{"192.168.1.0", "", ""},
		{"2001:db8:1::1", "2001:db8:1::1/128", "v6h"},
		{"2001:db8:1::5", "2001:db8:1::/48", "v6s"},
		{"2001:db8:2::5", "2001:db8::/32", "v6"},
		{"2001:db9::", "", ""},
		{"172.16.5.5", "172.16.0.0/12", "mapped"},
		{"::ffff:10.1.2.3", "10.1.2.3/32", "host"},
	}
	for _, c := range cases {
		p, d, ok := s.Lookup(netip.MustParseAddr(c.ip))
		if ok != (c.prefix != "") {
			t.Errorf("Lookup(%s) ok = %v", c.ip, ok)
			continue
		}
		if ok && (p.String() != c.prefix || d != c.detail) {
			t.Errorf("Lookup(%s) = %s %q, want %s %q", c.ip, p, d, c.prefix, c.detail)
		}
	}
}

func TestEdgeLengths(t *testing.T) {
	b := NewBuilder()
	b.AddText("0.0.0.0/0", "all4")
	b.AddText("2001:db8:aa::/64", "half")
	b.AddText("::/0", "all6")
	s := b.Build()
	for ip, want := range map[string]string{
		"203.0.113.9":      "0.0.0.0/0",
		"2001:db8:aa::9":   "2001:db8:aa::/64",
		"2001:db8:ab::9":   "::/0",
		"fe80::1%eth0":     "::/0",
		"255.255.255.255":  "0.0.0.0/0",
		"ffff:ffff:ffff::": "::/0",
	} {
		p, _, ok := s.Lookup(netip.MustParseAddr(ip))
		if !ok || p.String() != want {
			t.Errorf("Lookup(%s) = %s %v, want %s", ip, p, ok, want)
		}
	}
	var empty *Set
	if _, _, ok := empty.Lookup(netip.MustParseAddr("1.1.1.1")); ok || empty.Len() != 0 {
		t.Error("nil Set should match nothing")
	}
}

func TestUnionCountInPrefix(t *testing.T) {
	b1 := NewBuilder()
	b1.AddText("198.51.100.1", "a")
	b1.AddText("198.51.100.2", "b")
	b1.AddText("198.51.100.16/28", "sub") // 16 addresses: .16 .. .31
	s1 := b1.Build()

	b2 := NewBuilder()
	b2.AddText("198.51.100.2", "dup")
	b2.AddText("198.51.100.20", "inside-sub")
	b2.AddText("198.51.100.32", "adjacent")
	b2.AddText("255.255.255.250/31", "edge")
	s2 := b2.Build()

	addrs, blocks := UnionCountInPrefix([]*Set{s1, s2}, netip.MustParsePrefix("198.51.100.0/24"))
	// .1 + .2 (2 contiguous) + .16..32 (17 contiguous) = 19 distinct addresses in 2 merged spans.
	if addrs != 19 || blocks != 2 {
		t.Fatalf("got addrs=%d blocks=%d, want 19, 2", addrs, blocks)
	}
	if !s1.HasIntersection(netip.MustParsePrefix("198.51.100.0/24")) {
		t.Fatal("expected s1 intersection")
	}
	if s1.HasIntersection(netip.MustParsePrefix("203.0.113.0/24")) {
		t.Fatal("unexpected intersection")
	}
	edgeAddrs, _ := UnionCountInPrefix([]*Set{s2}, netip.MustParsePrefix("255.255.255.0/24"))
	if edgeAddrs != 2 {
		t.Fatalf("edge /24 addrs=%d, want 2", edgeAddrs)
	}

	b3 := NewBuilder()
	b3.AddText("198.51.0.0/16", "enclosing")
	s3 := b3.Build()
	fullAddrs, _ := UnionCountInPrefix([]*Set{s3}, netip.MustParsePrefix("198.51.100.0/24"))
	if fullAddrs != 256 {
		t.Fatalf("enclosing /16 should cover all 256 /24 addresses, got %d", fullAddrs)
	}

	bv6 := NewBuilder()
	bv6.AddText("2001:db8:abcd:1::1", "h1")
	bv6.AddText("2001:db8:abcd:2::/64", "sub6")
	sv6 := bv6.Build()
	_, v6Blocks := UnionCountInPrefix([]*Set{sv6}, netip.MustParsePrefix("2001:db8:abcd::/48"))
	if v6Blocks != 2 {
		t.Fatalf("IPv6 /48 blocks=%d, want 2", v6Blocks)
	}
}
