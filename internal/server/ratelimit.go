package server

import (
	"net/netip"
	"sync"
	"time"
)

// rateLimiter is a per-client fixed-window counter. IPv6 clients are grouped
// by /64 so one host cannot dodge the limit by rotating addresses.
type rateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	start  time.Time
	counts map[netip.Prefix]int
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{max: max, window: window, counts: map[netip.Prefix]int{}}
}

// allow counts one request and reports whether it is within the budget, plus
// the seconds until the window resets.
func (l *rateLimiter) allow(a netip.Addr) (bool, int) {
	bits := 32
	if a.Is6() {
		bits = 64
	}
	key, _ := a.Prefix(bits)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.start) >= l.window {
		l.start, l.counts = now, map[netip.Prefix]int{}
	}
	retry := int(l.start.Add(l.window).Sub(now).Seconds()) + 1
	if l.counts[key] >= l.max {
		return false, retry
	}
	l.counts[key]++
	return true, retry
}
