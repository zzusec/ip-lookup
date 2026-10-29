package dnsq

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

func TestReversed(t *testing.T) {
	for in, want := range map[string]string{
		"69.63.223.19":         "19.223.63.69",
		"::ffff:1.2.3.4":       "4.3.2.1",
		"2001:4860:4860::8888": "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2",
	} {
		if got := reversed(netip.MustParseAddr(in)); got != want {
			t.Errorf("reversed(%s) = %s, want %s", in, got, want)
		}
	}
}

// Query names must be absolute, or the resolver asks again with every search
// domain of the host after each not-found answer.
func TestQueryNames(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	for _, c := range [][2]string{
		{dnsblName(v4, "bl.spamcop.net"), "1.2.0.192.bl.spamcop.net."},
		{originName(v4), "1.2.0.192.origin.asn.cymru.com."},
		{originName(v6), reversed(v6) + ".origin6.asn.cymru.com."},
		{asName(13335), "AS13335.asn.cymru.com."},
		{abs("host.example"), "host.example."},
		{abs("host.example."), "host.example."},
	} {
		if c[0] != c[1] {
			t.Errorf("got %q, want %q", c[0], c[1])
		}
	}
}

// Live network test; run with IPL_NET=1.
func TestLive(t *testing.T) {
	if os.Getenv("IPL_NET") == "" {
		t.Skip("IPL_NET not set")
	}
	r := New([]string{"1.1.1.1:53", "8.8.8.8:53"})
	ctx := context.Background()
	for _, ip := range []string{"69.63.223.19", "2001:4860:4860::8888", "127.0.0.2"} {
		a := netip.MustParseAddr(ip)
		names, fc, err := r.Reverse(ctx, a)
		o, oerr := r.Cymru(ctx, a)
		t.Logf("%s ptr=%v fcrdns=%v err=%v | cymru=%+v err=%v", ip, names, fc, err, o, oerr)
	}
	for _, d := range r.DNSBL(ctx, netip.MustParseAddr("127.0.0.2")) {
		t.Logf("dnsbl test %+v", d)
	}
}
