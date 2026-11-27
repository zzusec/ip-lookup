// Package dnsq runs the DNS based lookups: reverse DNS with forward
// confirmation, Team Cymru IP-to-ASN and DNS blocklists. Queries go straight
// to public resolvers so the host's resolver configuration does not matter.
package dnsq

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

// Resolver is a DNS client bound to fixed upstream servers.
type Resolver struct {
	r       dnsClient
	Timeout time.Duration
}

type dnsClient interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
	LookupTXT(context.Context, string) ([]string, error)
}

// New returns a resolver that tries servers in turn, e.g. "1.1.1.1:53".
func New(servers []string) *Resolver {
	var mu sync.Mutex
	next := 0
	d := &net.Dialer{Timeout: 2 * time.Second}
	return &Resolver{Timeout: 3 * time.Second, r: &net.Resolver{PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			mu.Lock()
			s := servers[next%len(servers)]
			next++
			mu.Unlock()
			return d.DialContext(ctx, network, s)
		}}}
}

func (r *Resolver) ctx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, r.Timeout)
}

// Reverse reports each PTR and whether any resolves back to the queried address.
func (r *Resolver) Reverse(ctx context.Context, a netip.Addr) ([]model.FCrDNSCheck, *bool, error) {
	a = a.Unmap()
	c, cancel := r.ctx(ctx)
	names, ptrErr := r.r.LookupAddr(c, a.String())
	cancel()
	if len(names) == 0 && ptrErr != nil {
		if notFound(ptrErr) {
			return nil, nil, nil
		}
		return nil, nil, ptrErr
	}
	network := "ip4"
	if a.Is6() {
		network = "ip6"
	}
	var checks []model.FCrDNSCheck
	seen := map[string]bool{}
	matched, uncertain := false, ptrErr != nil
	for _, name := range names {
		name = strings.TrimRight(name, ".")
		key := strings.ToLower(name)
		if name == "" || seen[key] {
			continue
		}
		seen[key] = true
		status := "not_checked"
		if len(checks) < 3 && !matched && ctx.Err() == nil {
			forward, stop := r.ctx(ctx)
			addrs, err := r.r.LookupNetIP(forward, network, abs(name))
			stop()
			switch {
			case notFound(err):
				status = "no_address"
			case err != nil:
				status = "error"
			case len(addrs) == 0:
				status = "no_address"
			case slices.ContainsFunc(addrs, func(addr netip.Addr) bool { return addr.Unmap() == a }):
				status, matched = "matched", true
			case slices.ContainsFunc(addrs, benchmarkAddress):
				status = "benchmark_answer"
			default:
				status = "mismatch"
			}
		}
		uncertain = uncertain || status == "error" || status == "not_checked" || status == "benchmark_answer"
		checks = append(checks, model.FCrDNSCheck{Name: name, Status: status})
	}
	if len(checks) == 0 || (!matched && uncertain) {
		return checks, nil, ptrErr
	}
	return checks, &matched, ptrErr
}

var benchmarkV4 = netip.MustParsePrefix("198.18.0.0/15")
var benchmarkV6 = netip.MustParsePrefix("2001:2::/48")

func benchmarkAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	return benchmarkV4.Contains(addr) || benchmarkV6.Contains(addr)
}

// abs makes name absolute. The Go resolver still appends the search domains
// of resolv.conf to relative names, so every not-found answer, the usual
// DNSBL reply, would be asked again once per search domain.
func abs(name string) string { return strings.TrimSuffix(name, ".") + "." }

func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// reversed returns the nibble (v6) or octet (v4) form used under in-addr.arpa style zones.
func reversed(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0]))
	}
	b := a.As16()
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 63)
	for i := 15; i >= 0; i-- {
		out = append(out, hex[b[i]&0xf], '.', hex[b[i]>>4], '.')
	}
	return string(out[:len(out)-1])
}

// Origin is one Team Cymru origin answer.
type Origin struct {
	ASN       int
	Prefix    string
	CC        string
	Registry  string
	Allocated string
	ASName    string
}

// Cymru asks Team Cymru for the origin AS, prefix, country and registry of a.
func (r *Resolver) Cymru(ctx context.Context, a netip.Addr) (Origin, error) {
	c, cancel := r.ctx(ctx)
	defer cancel()
	txt, err := r.r.LookupTXT(c, originName(a))
	if err != nil {
		if notFound(err) {
			return Origin{}, nil
		}
		return Origin{}, err
	}
	// Several origins may be listed; prefer the most specific prefix.
	var best Origin
	bestLen := -1
	for _, t := range txt {
		f := fields(t)
		if len(f) < 5 {
			continue
		}
		asns := strings.Fields(f[0])
		if len(asns) == 0 {
			continue
		}
		asn, err := strconv.Atoi(asns[0])
		if err != nil || asn <= 0 || uint64(asn) > 1<<32-1 {
			continue
		}
		p, err := netip.ParsePrefix(f[1])
		if err != nil || !p.Contains(a.Unmap()) || p.Bits() <= bestLen {
			continue
		}
		best, bestLen = Origin{ASN: asn, Prefix: p.Masked().String(), CC: f[2], Registry: f[3], Allocated: f[4]}, p.Bits()
	}
	if bestLen < 0 {
		return Origin{}, errors.New("no origin record")
	}
	c2, cancel2 := r.ctx(ctx)
	defer cancel2()
	if txt, err := r.r.LookupTXT(c2, asName(best.ASN)); err == nil {
		for _, record := range txt {
			if f := fields(record); len(f) >= 5 && f[0] == strconv.Itoa(best.ASN) {
				best.ASName = f[4]
				break
			}
		}
	}
	return best, nil
}

func originName(a netip.Addr) string {
	zone := "origin.asn.cymru.com"
	if a.Unmap().Is6() {
		zone = "origin6.asn.cymru.com"
	}
	return abs(reversed(a) + "." + zone)
}

func asName(asn int) string { return abs("AS" + strconv.Itoa(asn) + ".asn.cymru.com") }

func fields(t string) []string {
	f := strings.Split(t, "|")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

// Zones are DNSBLs that answer queries relayed through public resolvers.
var Zones = []string{
	"bl.spamcop.net", "dnsbl.dronebl.org", "b.barracudacentral.org", "dnsbl-1.uceprotect.net",
	"psbl.surriel.com", "bl.blocklist.de", "all.s5h.net", "spam.dnsbl.anonmails.de", "bl.0spam.org",
	"rbl.interserver.net", "truncate.gbudb.net", "bl.nordspam.com", "bl.mailspike.net", "torexit.dan.me.uk",
}

func dnsblName(a netip.Addr, zone string) string { return abs(reversed(a) + "." + zone) }

func dnsblAnswer(zone string, addrs []netip.Addr, err error) model.DNSBL {
	res := model.DNSBL{Zone: zone}
	if err != nil {
		if !notFound(err) {
			res.Error = "lookup failed"
		}
		return res
	}
	var code netip.Addr
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !addr.Is4() || !addr.IsLoopback() {
			res.Error = "unexpected answer " + addr.String()
			return res
		}
		octets := addr.As4()
		if octets[1] == 255 && octets[2] == 255 {
			res.Answer, res.Error = addr.String(), "refused "+addr.String()
			return res
		}
		if !code.IsValid() || addr.Less(code) {
			code = addr
		}
	}
	if code.IsValid() {
		res.Listed, res.Answer = true, code.String()
	} else {
		res.Error = "empty resolver response"
	}
	return res
}

// DNSBL checks a against every zone concurrently. IPv6 is skipped by most
// zones, so only IPv4 is queried.
func (r *Resolver) DNSBL(ctx context.Context, a netip.Addr) []model.DNSBL {
	if !a.Unmap().Is4() {
		return nil
	}
	out := make([]model.DNSBL, len(Zones))
	var wg sync.WaitGroup
	for i, z := range Zones {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := r.ctx(ctx)
			defer cancel()
			addrs, err := r.r.LookupNetIP(c, "ip4", dnsblName(a, z))
			out[i] = dnsblAnswer(z, addrs, err)
		}()
	}
	wg.Wait()
	return out
}
