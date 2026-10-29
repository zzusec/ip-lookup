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
