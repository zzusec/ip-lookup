package lookup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/internal/sources"
)

// dnsCheck runs one DNS based check and reports it as a source.
func dnsCheck(ctx context.Context, name string, f func() (string, error)) model.Source {
	start := time.Now()
	status, err := f()
	st := model.Source{Name: name, Kind: "dns", Status: status, Ms: time.Since(start).Milliseconds()}
	if err != nil {
		st.Status, st.Error = "error", err.Error()
		var netErr net.Error
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			st.Status = "timeout"
		}
	}
	return st
}

// dnsChecks runs reverse DNS and the DNSBLs concurrently.
func (s *Service) dnsChecks(ctx context.Context, o *sources.Out, a netip.Addr) []model.Source {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []model.Source
	run := func(name string, f func() (string, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := dnsCheck(ctx, name, f)
			mu.Lock()
			out = append(out, st)
			mu.Unlock()
		}()
	}
	run("反向解析 (PTR)", func() (string, error) {
		checks, fc, err := s.DNS.Reverse(ctx, a)
		if len(checks) == 0 {
			return "empty", err
		}
		names := make([]string, len(checks))
		for i, check := range checks {
			names[i] = check.Name
		}
		o.Do(func(r *model.Result) { r.Network.RDNS, r.Network.FCrDNS, r.Network.FCrDNSChecks = names, fc, checks })
		return "ok", err
	})
	if a.Is4() {
		run("DNSBL", func() (string, error) {
			res := s.DNS.DNSBL(ctx, a)
			o.Do(func(r *model.Result) { r.DNSBL = res })
			listed, checked := model.SummarizeDNSBL(res)
			if checked == 0 {
				return "error", fmt.Errorf("DNSBL：%d 个查询均未取得有效回答", len(res))
			}
			if listed > 0 {
				o.Signal("abuser", "DNSBL", itoa(listed)+" 个黑名单命中", min(30+10*listed, 70))
			}
			return "ok", nil
		})
	}
	wg.Wait()
	return out
}

// cymru asks Team Cymru for the announced route and the origin AS of a.
func (s *Service) cymru(ctx context.Context, o *sources.Out, a netip.Addr) model.Source {
	return dnsCheck(ctx, "Team Cymru", func() (string, error) {
		c, err := s.DNS.Cymru(ctx, a)
		if err != nil || c.ASN == 0 {
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
}
