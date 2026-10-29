package sources

import (
	"sync"
	"time"
)

// Limiter is a fixed-window request budget, e.g. 40 per minute or 900 per day.
// After a 429 the provider is paused until the window ends.
type Limiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	start   time.Time
	used    int
	blocked time.Time
	Label   string // human readable budget, e.g. "40/分钟"
}

func NewLimiter(max int, window time.Duration, label string) *Limiter {
	return &Limiter{max: max, window: window, Label: label}
}

func (l *Limiter) roll(now time.Time) {
	if now.Sub(l.start) >= l.window {
		l.start, l.used = now.Truncate(l.window), 0
	}
}

// Take reserves one request. It returns false when the budget is spent.
func (l *Limiter) Take() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Before(l.blocked) {
		return false
	}
	l.roll(now)
	if l.used >= l.max {
		return false
	}
	l.used++
	return true
}

// Block pauses the provider for d, or until the current window ends when d is 0.
func (l *Limiter) Block(d time.Duration) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if d == 0 {
		d = max(time.Until(l.start.Add(l.window)), time.Minute)
	}
	l.blocked = time.Now().Add(d)
}

// State reports the requests used in the current window and the end of a block.
func (l *Limiter) State() (used int, blockedUntil time.Time) {
	if l == nil {
		return 0, time.Time{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(time.Now())
	if time.Now().After(l.blocked) {
		return l.used, time.Time{}
	}
	return l.used, l.blocked
}

// cache keeps raw answers per (provider, address) with a size bound. Entries
// are dropped oldest-first once the bound is reached.
type cache struct {
	mu    sync.Mutex
	max   int
	items map[string]cacheItem
	order []string
}

type cacheItem struct {
	raw     []byte
	expires time.Time
}

func newCache(max int) *cache { return &cache{max: max, items: map[string]cacheItem{}} }

func (c *cache) get(k string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[k]
	if !ok || time.Now().After(it.expires) {
		return nil, false
	}
	return it.raw, true
}

func (c *cache) put(k string, raw []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[k]; !ok {
		c.order = append(c.order, k)
	}
	c.items[k] = cacheItem{raw: raw, expires: time.Now().Add(ttl)}
	for len(c.items) > c.max && len(c.order) > 0 {
		delete(c.items, c.order[0])
		c.order = c.order[1:]
	}
	if len(c.order) > 2*c.max { // compact keys that were re-put
		live := c.order[:0]
		for _, k := range c.order {
			if _, ok := c.items[k]; ok {
				live = append(live, k)
			}
		}
		c.order = live
	}
}
