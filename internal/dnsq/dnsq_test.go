package dnsq

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

type stubDNS struct {
	names     []string
	ptrErr    error
	lookupIP  func(string, string) ([]netip.Addr, error)
	lookupTXT func(string) ([]string, error)
}

func (d stubDNS) LookupAddr(context.Context, string) ([]string, error) {
	return slices.Clone(d.names), d.ptrErr
}
func (d stubDNS) LookupNetIP(_ context.Context, network, name string) ([]netip.Addr, error) {
	return d.lookupIP(network, name)
}
func (d stubDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	return d.lookupTXT(name)
}

func TestReverseUsesBoundedSameFamilyEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, target, verdict string
		names, states         []string
		queries               int
	}{
		{"mapped IPv4 and duplicate PTR", "::ffff:192.0.2.1", "true", []string{"OTHER.test.", "other.test.", "match.test.", "skip.test."}, []string{"mismatch", "matched", "not_checked"}, 2},
		{"IPv6", "2001:db8::1", "true", []string{"match.test."}, []string{"matched"}, 1},
		{"all checked", "192.0.2.1", "false", []string{"other.test.", "missing.test."}, []string{"mismatch", "no_address"}, 2},
		{"partial failure", "192.0.2.1", "unknown", []string{"failed.test.", "other.test."}, []string{"error", "mismatch"}, 2},
		{"positive after failure", "192.0.2.1", "true", []string{"failed.test.", "match.test."}, []string{"error", "matched"}, 2},
		{"candidate beyond budget", "192.0.2.1", "unknown", []string{"a.test.", "b.test.", "c.test.", "match.test."}, []string{"mismatch", "mismatch", "mismatch", "not_checked"}, 3},
		{"no names", "192.0.2.1", "unknown", []string{"."}, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := netip.MustParseAddr(tc.target)
			family, other := "ip4", netip.MustParseAddr("192.0.2.2")
			if target.Unmap().Is6() {
				family, other = "ip6", netip.MustParseAddr("2001:db8::2")
			}
			queries := 0
			client := stubDNS{names: tc.names, lookupIP: func(network, name string) ([]netip.Addr, error) {
				queries++
				if network != family || !strings.HasSuffix(name, ".") {
					t.Fatalf("lookup %s %q, want %s and absolute name", network, name, family)
				}
				switch name {
				case "match.test.":
					return []netip.Addr{other, target}, nil
				case "failed.test.":
					return nil, context.DeadlineExceeded
				case "missing.test.":
					return nil, &net.DNSError{IsNotFound: true}
				}
				return []netip.Addr{other}, nil
			}}
			checks, confirmed, err := (&Resolver{Timeout: time.Second, r: client}).Reverse(context.Background(), target)
			var states []string
			for _, check := range checks {
				states = append(states, check.Status)
				if check.Name == "" || strings.HasSuffix(check.Name, ".") {
					t.Errorf("invalid result name %q", check.Name)
				}
			}
			if err != nil || queries != tc.queries || !slices.Equal(states, tc.states) {
				t.Fatalf("checks=%v queries=%d err=%v", checks, queries, err)
			}
			if (confirmed == nil) != (tc.verdict == "unknown") || (confirmed != nil && *confirmed != (tc.verdict == "true")) {
				t.Fatalf("aggregate confirmation does not match %s", tc.verdict)
			}
		})
	}
}

func TestReverseNoPTRVersusUnavailable(t *testing.T) {
	for _, ptrErr := range []error{&net.DNSError{IsNotFound: true}, context.DeadlineExceeded} {
		client := stubDNS{ptrErr: ptrErr}
		checks, confirmed, err := (&Resolver{Timeout: time.Second, r: client}).Reverse(context.Background(), netip.MustParseAddr("192.0.2.1"))
		if len(checks) != 0 || confirmed != nil || (err != nil) != errors.Is(ptrErr, context.DeadlineExceeded) {
			t.Errorf("PTR err=%v yielded checks=%v confirmation=%v err=%v", ptrErr, checks, confirmed, err)
		}
	}
}

func TestReverseBenchmarkResponseIsNotPublicMismatch(t *testing.T) {
	for _, tc := range []struct {
		target, other, benchmark string
	}{
		{"1.1.1.1", "1.0.0.1", "::ffff:198.18.101.41"},
		{"2606:4700:4700::1111", "2606:4700:4700::1001", "2001:2::1"},
	} {
		target, other, benchmark := netip.MustParseAddr(tc.target), netip.MustParseAddr(tc.other), netip.MustParseAddr(tc.benchmark)
		for _, additional := range []netip.Addr{other, target} {
			client := stubDNS{names: []string{"ptr.example."}, lookupIP: func(string, string) ([]netip.Addr, error) {
				return []netip.Addr{benchmark, additional}, nil
			}}
			checks, confirmed, err := (&Resolver{Timeout: time.Second, r: client}).Reverse(context.Background(), target)
			if err != nil || len(checks) != 1 {
				t.Fatalf("invalid observation: %v, %v", checks, err)
			}
			if additional == target {
				if confirmed == nil || !*confirmed || checks[0].Status != "matched" {
					t.Fatal("lost explicit match")
				}
			} else if confirmed != nil || checks[0].Status != "benchmark_answer" {
				t.Fatalf("benchmark answer treated as a conclusive mismatch: %+v", checks)
			}
		}
	}
}

func TestReverseKeepsValidNamesFromPartialPTR(t *testing.T) {
	target := netip.MustParseAddr("192.0.2.1")
	partial := errors.New("one PTR name was malformed")
	for _, addr := range []netip.Addr{target, netip.MustParseAddr("192.0.2.2")} {
		client := stubDNS{names: []string{"valid.test."}, ptrErr: partial, lookupIP: func(string, string) ([]netip.Addr, error) {
			return []netip.Addr{addr}, nil
		}}
		checks, confirmed, err := (&Resolver{Timeout: time.Second, r: client}).Reverse(context.Background(), target)
		if len(checks) != 1 || checks[0].Name != "valid.test" || !errors.Is(err, partial) || (confirmed != nil) != (addr == target) || (confirmed != nil && !*confirmed) {
			t.Fatalf("addr=%v: checks=%v confirmed=%v err=%v", addr, checks, confirmed, err)
		}
	}
}

func TestDNSBLMixedAndMappedAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []netip.Addr
		err     error
		listed  bool
		failed  bool
	}{
		{"listed", []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil, true, false},
		{"mapped listing", []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.2")}, nil, true, false},
		{"mixed refusal", []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.255.255.254")}, nil, false, true},
		{"refused first", []netip.Addr{netip.MustParseAddr("127.255.255.254"), netip.MustParseAddr("127.0.0.2")}, nil, false, true},
		{"outside loopback", []netip.Addr{netip.MustParseAddr("192.0.2.4")}, nil, false, true},
		{"empty successful answer", nil, nil, false, true},
		{"not listed", nil, &net.DNSError{IsNotFound: true}, false, false},
		{"resolver error", nil, errors.New("SERVFAIL"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Resolver{Timeout: time.Second, r: stubDNS{lookupIP: func(string, string) ([]netip.Addr, error) { return tc.answers, tc.err }}}
			for _, entry := range r.DNSBL(context.Background(), netip.MustParseAddr("192.0.2.1")) {
				if entry.Listed != tc.listed || (entry.Error != "") != tc.failed {
					t.Fatalf("got %+v, want listed=%v error=%v", entry, tc.listed, tc.failed)
				}
			}
		})
	}
}

func TestCymruUsesContainingPrefixAndValidASN(t *testing.T) {
	target := netip.MustParseAddr("192.0.2.1")
	client := stubDNS{lookupTXT: func(name string) ([]string, error) {
		if name == originName(target) {
			return []string{"64999 | 192.0.0.0/16 | US | arin | 2000-01-01", "65001 65003 | 192.0.2.0/24 | US | arin | 2000-01-01", "65002 | 198.51.100.1/32 | FR | ripe | 2000-01-01", "NA | 192.0.2.0/30 | US | arin | 2000-01-01", " | 192.0.2.1/32 | US | arin | 2000-01-01", "4294967296 | 192.0.2.1/32 | US | arin | 2000-01-01"}, nil
		}
		if name != asName(65001) {
			t.Fatalf("unexpected AS name query %s", name)
		}
		return []string{"65002 | FR | ripe | 2000-01-01 | Unrelated", "65001 | US | arin | 2000-01-01 | Example"}, nil
	}}
	got, err := (&Resolver{Timeout: time.Second, r: client}).Cymru(context.Background(), target)
	if err != nil || got.ASN != 65001 || got.Prefix != "192.0.2.0/24" || got.ASName != "Example" {
		t.Fatalf("origin=%+v err=%v", got, err)
	}
}

func TestReversed(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":            "7.2.0.192",
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
	for _, ip := range []string{"9.9.9.9", "2001:4860:4860::8888", "127.0.0.2"} {
		a := netip.MustParseAddr(ip)
		names, fc, err := r.Reverse(ctx, a)
		o, oerr := r.Cymru(ctx, a)
		t.Logf("%s ptr=%v fcrdns=%v err=%v | cymru=%+v err=%v", ip, names, fc, err, o, oerr)
	}
	for _, d := range r.DNSBL(ctx, netip.MustParseAddr("127.0.0.2")) {
		t.Logf("dnsbl test %+v", d)
	}
}
