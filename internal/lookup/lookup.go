package lookup

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/datasets"
	"github.com/zzusec/ip-lookup/internal/dnsq"
	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/internal/sources"
)

// Service answers lookups.
type Service struct {
	Data    *datasets.Manager
	Online  *sources.Set
	DNS     *dnsq.Resolver
	Timeout time.Duration // overall budget of a full lookup
}

func itoa(n int) string { return strconv.Itoa(n) }

// Lookup builds the report for a. Fast mode uses only offline data; full
// mode also queries the online providers and DNS, bounded by s.Timeout.
func (s *Service) Lookup(ctx context.Context, a netip.Addr, full bool) *model.Result {
	start := time.Now()
	a = a.Unmap().WithZone("")
	r := &model.Result{IP: a.String(), Version: 4, Mode: "fast", QueriedAt: start.UTC().Format(time.RFC3339),
		GeoSources: []model.GeoSource{}, Lists: []model.ListHit{}, DNSBL: []model.DNSBL{}, Risk: []model.Risk{},
		Sources: []model.Source{}}
	if a.Is6() {
		r.Version = 6
	}
	if full {
		r.Mode = "full"
	}
	if r.Bogon = Bogon(a); r.Bogon != "" {
		r.Verdict = model.Verdict{Type: "unknown", TypeLabel: classify.TypeLabels["unknown"], Usage: []string{},
			UsageLabels: []string{}, Label: "非公网地址", Confidence: "high", Evidence: []model.Signal{}}
		r.Native = model.Native{Status: "unknown", Label: "不适用"}
		r.Score = model.Score{Factors: []model.Factor{}, Level: "不适用"}
		r.ElapsedMs = time.Since(start).Milliseconds()
		return r
	}
	o := &sources.Out{Res: r}
	asn, prefix := s.offline(o, a)
	if full {
		s.online(ctx, o, a, asn, prefix)
	}
	s.finish(o)
	r.ElapsedMs = time.Since(start).Milliseconds()
	return r
}

func (s *Service) online(ctx context.Context, o *sources.Out, a netip.Addr, asn int, prefix netip.Prefix) {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	var wg sync.WaitGroup
	var dnsSources, after []model.Source
	q := sources.Query{Addr: a, ASN: asn, Prefix: prefix}
	wg.Add(1)
	go func() {
		defer wg.Done()
		dnsSources = s.dnsChecks(ctx, o, a)
		// RPKI validates the announced route and its origin, which Team Cymru
		// has just reported; the network of the offline databases is not a route.
		h := o.Hints()
		aq := q
		aq.Prefix, _ = netip.ParsePrefix(firstOf(h, "bgp_prefix:cymru", "bgp_prefix:ripe"))
		if n, err := strconv.Atoi(firstOf(h, "origin_asn:cymru", "origin_asn:ripe")); err == nil && n > 0 {
			aq.ASN = n
		}
		after = s.Online.Run(ctx, aq, o, true)
	}()
	st := s.Online.Run(ctx, q, o, false)
	wg.Wait()
	st = append(st, after...)
	o.Do(func(r *model.Result) {
		r.Sources = append(r.Sources, st...)
		r.Sources = append(r.Sources, dnsSources...)
	})
}

// finish runs the classification once every source has reported.
func (s *Service) finish(o *sources.Out) {
	r := o.Res
	h := o.Hints()
	n := &r.Network
	if n.BGPPrefix == "" {
		n.BGPPrefix = firstOf(h, "bgp_prefix:ripe", "bgp_prefix:cymru")
	}
	if n.Registry == "" {
		n.Registry = firstOf(h, "registry:cymru", "registry:rdap")
	}
	if n.ASCountry == "" {
		n.ASCountry = h["as_cc:cymru"]
	}
	var names []string
	for _, g := range r.GeoSources {
		names = append(names, g.ISP, g.Org)
		if k := classify.ProviderType(g.Type); k != "" && g.Source != "ipapi.is" && g.Source != "proxycheck.io" &&
			g.Source != "ipyou.net" && g.Source != "ipinfo.io" {
			o.Signal(k, g.Source, "type="+g.Type, 40)
		}
	}
	if len(n.RDNS) == 0 {
		if v := firstOf(h, "rdns:ipinfo", "rdns:ip-api"); v != "" {
			n.RDNS = []string{v} // reported by a provider, FCrDNS stays unknown
		}
	}
	names = append(names, n.ASName, n.Org, n.ISP)
	fillCountries(r)
	sig := append([]model.Signal{}, o.Sig...)
	sig = append(sig, classify.OrgText(names)...)
	sig = append(sig, classify.RDNS(n.RDNS)...)
	r.Verdict, r.Flags = classify.Decide(sig)
	// RIR delegation statistics are the authoritative registration country;
	// the others are fallbacks when it is unavailable.
	reg := []string{h["reg_cc:rir"], h["reg_cc:rdap"], h["reg_cc:cymru"], h["reg_cc:ipyou"], h["reg_cc:merged"]}
	r.Native = classify.Native(reg, r.Geo.CountryCode, n.Registry)
	r.Score = classify.Score(r)
}

func firstOf(h map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := h[k]; v != "" {
			return v
		}
	}
	return ""
}

// fillCountries completes country names and codes that some sources omit,
// using what the other sources reported for the same country.
func fillCountries(r *model.Result) {
	code := map[string]string{} // lower-case country name -> ISO code
	name := map[string]string{} // ISO code -> a country name
	add := func(n, c string) {
		if n == "" || len(c) != 2 {
			return
		}
		c = strings.ToUpper(c)
		code[strings.ToLower(n)] = c
		if name[c] == "" {
			name[c] = n
		}
	}
	add(r.Geo.Country, r.Geo.CountryCode)
	add(r.Geo.CountryEN, r.Geo.CountryCode)
	for _, g := range r.GeoSources {
		add(g.Country, g.CountryCode)
	}
	for i := range r.GeoSources {
		g := &r.GeoSources[i]
		if g.CountryCode == "" && g.Country != "" {
			g.CountryCode = code[strings.ToLower(g.Country)]
		}
	}
	if r.Geo.Country == "" && r.Geo.CountryCode != "" {
		r.Geo.Country = name[strings.ToUpper(r.Geo.CountryCode)]
	}
}
