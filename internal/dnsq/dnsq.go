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
	r       *net.Resolver
	Timeout time.Duration
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

// Reverse returns the PTR names of a and whether one of them resolves back to a.
func (r *Resolver) Reverse(ctx context.Context, a netip.Addr) ([]string, bool, error) {
	c, cancel := r.ctx(ctx)
	defer cancel()
	names, err := r.r.LookupAddr(c, a.String())
	if err != nil {
		if notFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	names = slices.DeleteFunc(names, func(n string) bool { return strings.Trim(n, ".") == "" })
	for i, n := range names {
		names[i] = strings.TrimSuffix(n, ".")
	}
	if len(names) == 0 {
		return nil, false, nil
	}
	for _, n := range names[:min(len(names), 3)] {
		c2, cancel2 := r.ctx(ctx)
		addrs, err := r.r.LookupNetIP(c2, "ip", abs(n))
		cancel2()
		if err == nil && slices.ContainsFunc(addrs, func(x netip.Addr) bool { return x.Unmap() == a.Unmap() }) {
			return names, true, nil
		}
	}
	return names, false, nil
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
		asn, _ := strconv.Atoi(strings.Fields(f[0])[0])
		p, err := netip.ParsePrefix(f[1])
		if err != nil || p.Bits() <= bestLen {
			continue
		}
		best, bestLen = Origin{ASN: asn, Prefix: f[1], CC: f[2], Registry: f[3], Allocated: f[4]}, p.Bits()
	}
	if bestLen < 0 {
		return Origin{}, errors.New("no origin record")
	}
	c2, cancel2 := r.ctx(ctx)
	defer cancel2()
	if txt, err := r.r.LookupTXT(c2, asName(best.ASN)); err == nil && len(txt) > 0 {
		if f := fields(txt[0]); len(f) >= 5 {
			best.ASName = f[4]
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
	"rbl.interserver.net", "truncate.gbudb.net", "bl.nordspam.com",
}

func dnsblName(a netip.Addr, zone string) string { return abs(reversed(a) + "." + zone) }

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
			res := model.DNSBL{Zone: z}
			c, cancel := r.ctx(ctx)
			defer cancel()
			addrs, err := r.r.LookupNetIP(c, "ip4", dnsblName(a, z))
			switch {
			case err == nil && len(addrs) > 0 && addrs[0].Is4() && addrs[0].As4()[0] == 127:
				res.Listed, res.Answer = true, addrs[0].String()
			case err == nil && len(addrs) > 0:
				// 127.255.255.x and non-loopback answers are resolver refusals, not listings.
				res.Error = "unexpected answer " + addrs[0].String()
			case err != nil && !notFound(err):
				res.Error = "lookup failed"
			}
			if res.Listed && strings.HasPrefix(res.Answer, "127.255.255.") {
				res.Listed, res.Error = false, "refused "+res.Answer
			}
			out[i] = res
		}()
	}
	wg.Wait()
	return out
}
