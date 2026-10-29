package sources

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

// Set is the configured list of providers plus their shared cache.
type Set struct {
	Providers []*Provider
	Client    *Client
	cache     *cache
}

func NewSet(c *Client, providers []*Provider) *Set {
	return &Set{Providers: providers, Client: c, cache: newCache(4000)}
}

// Run queries every applicable provider of one phase concurrently and waits
// for all of them, each bounded by its own timeout and by ctx.
func (s *Set) Run(ctx context.Context, q Query, o *Out, after bool) []model.Source {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []model.Source
	for _, p := range s.Providers {
		if p.After != after || (p.V4Only && !q.Addr.Unmap().Is4()) || (p.NeedASN && q.ASN == 0) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := s.one(ctx, p, q, o)
			mu.Lock()
			out = append(out, st)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Set) one(ctx context.Context, p *Provider, q Query, o *Out) (st model.Source) {
	start := time.Now()
	st = model.Source{Name: p.Name, Kind: p.Kind, Status: "ok"}
	defer func() {
		if r := recover(); r != nil { // a malformed answer must not take the request down
			st.Status, st.Error = "error", "internal error while parsing"
		}
		st.Ms = time.Since(start).Milliseconds()
	}()
	key := p.Name + "|" + q.Addr.String()
	if p.Key != nil {
		key = p.Name + "|" + p.Key(q)
	}
	raw, hit := s.cache.get(key)
	if hit {
		st.Cached = true
	} else {
		if !p.Limit.Take() {
			st.Status = "quota"
			return st
		}
		tmo := p.Timeout
		if tmo == 0 {
			tmo = 6 * time.Second
		}
		cctx, cancel := context.WithTimeout(ctx, tmo)
		defer cancel()
		var err error
		raw, err = p.Fetch(cctx, s.Client, q)
		switch {
		case errors.Is(err, ErrNotFound):
			st.Status = "empty"
			s.cache.put(key, nil, ttl(p)/4)
			return st
		case errors.Is(err, ErrQuota):
			p.Limit.Block(0)
			st.Status = "quota"
			return st
		case err != nil && cctx.Err() != nil:
			st.Status, st.Error = "timeout", "timed out after "+time.Since(start).Round(100*time.Millisecond).String()
			return st
		case err != nil:
			st.Status, st.Error = "error", err.Error()
			return st
		}
		s.cache.put(key, raw, ttl(p))
	}
	if raw == nil {
		st.Status = "empty"
		return st
	}
	if err := p.Apply(o, q, raw); err != nil {
		if errors.Is(err, ErrNotFound) {
			st.Status = "empty"
		} else {
			st.Status, st.Error = "error", err.Error()
		}
	}
	return st
}

func ttl(p *Provider) time.Duration {
	if p.TTL == 0 {
		return 6 * time.Hour
	}
	return p.TTL
}

// Report lists providers with their budgets for /api/sources.
func (s *Set) Report() []model.OnlineSource {
	out := make([]model.OnlineSource, 0, len(s.Providers))
	for _, p := range s.Providers {
		os := model.OnlineSource{Name: p.Name, Homepage: p.Homepage, Keyed: p.Keyed}
		if p.Limit != nil {
			os.Quota = p.Limit.Label
			used, until := p.Limit.State()
			os.Used = used
			if !until.IsZero() {
				os.Blocked = until.UTC().Format(time.RFC3339)
			}
		}
		out = append(out, os)
	}
	return out
}
