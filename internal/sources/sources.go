// Package sources queries online IP intelligence providers. Every provider
// gets a timeout, a request budget and a response cache, and each call is
// reported back as a model.Source so the page can show what answered.
package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

var (
	ErrQuota    = errors.New("quota exhausted")
	ErrNotFound = errors.New("no data") // reported as status "empty"
)

// Out collects everything providers contribute to one result. Providers run
// concurrently and must only touch it through the methods below.
type Out struct {
	mu    sync.Mutex
	Res   *model.Result
	Sig   []model.Signal
	hints map[string]string
}

// Hint records a fact the lookup combines later, e.g. "reg_cc:rdap" -> "US".
func (o *Out) Hint(key, value string) {
	if value == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.hints == nil {
		o.hints = map[string]string{}
	}
	o.hints[key] = value
}

// Hints returns a copy of the recorded hints.
func (o *Out) Hints() map[string]string {
	o.mu.Lock()
	defer o.mu.Unlock()
	h := make(map[string]string, len(o.hints))
	for k, v := range o.hints {
		h[k] = v
	}
	return h
}

// Query is what a provider is asked about.
type Query struct {
	Addr   netip.Addr
	ASN    int          // origin AS from the offline databases, 0 when unknown
	Prefix netip.Prefix // origin prefix from the offline databases, may be invalid
}

func (o *Out) Do(f func(r *model.Result)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	f(o.Res)
}

func (o *Out) Signal(kind, source, detail string, weight int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Sig = append(o.Sig, model.Signal{Kind: kind, Source: source, Detail: detail, Weight: weight})
}

// Provider is one online source.
type Provider struct {
	Name     string
	Homepage string
	Kind     string        // online | dns
	Keyed    bool          // a key or token is configured
	Timeout  time.Duration // per call; 0 means 6s
	TTL      time.Duration // cache lifetime of an answer; 0 means 6h
	Limit    *Limiter      // nil means unlimited
	V4Only   bool
	NeedASN  bool // skipped when the origin AS is unknown
	After    bool // runs once the others finished, when the announced route is known
	// Fetch returns the raw answer; Apply parses it into o. Splitting the two
	// lets the cache keep the raw bytes, which are small.
	Fetch func(ctx context.Context, c *Client, q Query) ([]byte, error)
	Apply func(o *Out, q Query, raw []byte) error
	Key   func(q Query) string // cache key; nil means the address
}

// Client wraps an http.Client with the service's User-Agent and a size cap.
type Client struct {
	HTTP *http.Client
	UA   string
}

const maxBody = 2 << 20

// Get fetches u and returns the body of a 2xx answer. A 404 becomes
// ErrNotFound unless keep404 is set, in which case its body is returned.
func (c *Client) Get(ctx context.Context, u string, hdr map[string]string, keep404 bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UA)
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL may carry an API key and errors reach the page
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, ErrQuota
	case resp.StatusCode == http.StatusNotFound && keep404:
		return body, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// JSON fetches u and decodes it into v.
func (c *Client) JSON(ctx context.Context, u string, hdr map[string]string, v any) ([]byte, error) {
	b, err := c.Get(ctx, u, hdr, false)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return b, nil
}
