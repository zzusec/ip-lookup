package lookup

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/internal/sources"
)

// dnsChecks runs reverse DNS, Team Cymru and the DNSBLs concurrently.
func (s *Service) dnsChecks(ctx context.Context, o *sources.Out, a netip.Addr) []model.Source {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []model.Source
	run := func(name string, f func() (string, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			status, err := f()
			st := model.Source{Name: name, Kind: "dns", Status: status, Ms: time.Since(start).Milliseconds()}
			if err != nil {
				st.Status, st.Error = "error", err.Error()
				if ctx.Err() != nil {
					st.Status = "timeout"
				}
			}
			mu.Lock()
			out = append(out, st)
			mu.Unlock()
		}()
	}
	run("反向解析 (PTR)", func() (string, error) {
		names, fc, err := s.DNS.Reverse(ctx, a)
		if err != nil || len(names) == 0 {
			return "empty", err
		}
		o.Do(func(r *model.Result) { r.Network.RDNS, r.Network.FCrDNS = names, &fc })
		return "ok", nil
	})
	run("Team Cymru", func() (string, error) {
		c, err := s.DNS.Cymru(ctx, a)
		if err != nil {
			return "empty", err
		}
		o.Hint("bgp_prefix:cymru", c.Prefix)
		o.Hint("origin_asn:cymru", itoa(c.ASN))
		o.Hint("reg_cc:cymru", c.CC)
		o.Hint("registry:cymru", c.Registry)
		o.Do(func(r *model.Result) {
			n := &r.Network
			if n.ASN == 0 {
				n.ASN, n.ASName = c.ASN, c.ASName
			}
			if n.Allocated == "" {
				n.Allocated = c.Allocated
			}
			if n.Registry == "" {
				n.Registry = c.Registry
			}
		})
		return "ok", nil
	})
	if a.Is4() {
		run("DNSBL", func() (string, error) {
			res := s.DNS.DNSBL(ctx, a)
			listed := 0
			for _, d := range res {
				if d.Listed {
					listed++
				}
			}
			o.Do(func(r *model.Result) { r.DNSBL = res })
			if listed > 0 {
				o.Signal("abuser", "DNSBL", itoa(listed)+" 个黑名单命中", min(30+10*listed, 70))
			}
			return "ok", nil
		})
	}
	wg.Wait()
	return out
}
