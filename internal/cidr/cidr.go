// Package cidr matches addresses against large immutable sets of CIDR blocks.
//
// Blocks are kept as sorted [lo, hi] spans with a parent link to the nearest
// enclosing block, so a lookup is one binary search plus a short walk up the
// nesting chain and always returns the most specific matching block.
package cidr

import (
	"cmp"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"slices"
	"strings"
)

type u128 struct{ hi, lo uint64 }

func cmp128(a, b u128) int {
	if c := cmp.Compare(a.hi, b.hi); c != 0 {
		return c
	}
	return cmp.Compare(a.lo, b.lo)
}

type span[K any] struct {
	lo, hi K
	parent int32
	detail uint32
}

// Set is an immutable set of blocks, each carrying an optional detail string.
type Set struct {
	v4      []span[uint32]
	v6      []span[u128]
	details []string
}

// Builder collects blocks for a Set. The zero value is not usable; call NewBuilder.
type Builder struct {
	s     Set
	index map[string]uint32
}

func NewBuilder() *Builder {
	return &Builder{s: Set{details: []string{""}}, index: map[string]uint32{"": 0}}
}

func (b *Builder) intern(d string) uint32 {
	if i, ok := b.index[d]; ok {
		return i
	}
	i := uint32(len(b.s.details))
	b.s.details = append(b.s.details, d)
	b.index[d] = i
	return i
}

// Add inserts a block. IPv4-mapped IPv6 blocks are stored as IPv4.
func (b *Builder) Add(p netip.Prefix, detail string) {
	if !p.IsValid() {
		return
	}
	p = p.Masked()
	a, n := p.Addr(), p.Bits()
	if a.Is4In6() && n >= 96 {
		a, n = a.Unmap(), n-96
	}
	d := b.intern(detail)
	if a.Is4() {
		lo := binary.BigEndian.Uint32(a.AsSlice())
		b.s.v4 = append(b.s.v4, span[uint32]{lo: lo, hi: lo | ^uint32(0)>>n, detail: d})
		return
	}
	a16 := a.As16()
	lo := u128{binary.BigEndian.Uint64(a16[:8]), binary.BigEndian.Uint64(a16[8:])}
	hi := lo
	if n <= 64 {
		hi.hi |= ^uint64(0) >> n
		hi.lo = ^uint64(0)
	} else {
		hi.lo |= ^uint64(0) >> (n - 64)
	}
	b.s.v6 = append(b.s.v6, span[u128]{lo: lo, hi: hi, detail: d})
}

// AddAddr inserts a single address.
func (b *Builder) AddAddr(a netip.Addr, detail string) {
	b.Add(netip.PrefixFrom(a, a.BitLen()), detail)
}

// AddText parses "1.2.3.4", "1.2.3.0/24" or "2001:db8::/32" and reports success.
func (b *Builder) AddText(s, detail string) bool {
	s = strings.TrimSpace(s)
	if strings.IndexByte(s, '/') >= 0 {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return false
		}
		b.Add(p, detail)
		return true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	b.AddAddr(a.WithZone(""), detail)
	return true
}

// Build sorts the collected blocks. The Builder must not be used afterwards.
func (b *Builder) Build() *Set {
	s := b.s
	s.v4 = finish(s.v4, cmp.Compare[uint32])
	s.v6 = finish(s.v6, cmp128)
	s.details = slices.Clip(s.details)
	b.index = nil
	return &s
}

func finish[K any](sp []span[K], c func(a, b K) int) []span[K] {
	slices.SortFunc(sp, func(x, y span[K]) int {
		if r := c(x.lo, y.lo); r != 0 {
			return r
		}
		return c(y.hi, x.hi) // wider block first, so it becomes the parent
	})
	out := sp[:0]
	for _, x := range sp {
		if n := len(out); n > 0 && c(out[n-1].lo, x.lo) == 0 && c(out[n-1].hi, x.hi) == 0 {
			if out[n-1].detail == 0 {
				out[n-1].detail = x.detail
			}
			continue
		}
		out = append(out, x)
	}
	var stack []int32
	for i := range out {
		for len(stack) > 0 && c(out[stack[len(stack)-1]].hi, out[i].lo) < 0 {
			stack = stack[:len(stack)-1]
		}
		out[i].parent = -1
		if len(stack) > 0 {
			out[i].parent = stack[len(stack)-1]
		}
		stack = append(stack, int32(i))
	}
	return slices.Clip(out)
}

func find[K any](sp []span[K], k K, c func(a, b K) int) int {
	i, _ := slices.BinarySearchFunc(sp, k, func(x span[K], t K) int {
		if c(x.lo, t) <= 0 {
			return -1
		}
		return 1
	})
	j := int32(i - 1)
	for j >= 0 && c(sp[j].hi, k) < 0 {
		j = sp[j].parent
	}
	return int(j)
}

// Lookup returns the most specific block containing a and its detail.
func (s *Set) Lookup(a netip.Addr) (netip.Prefix, string, bool) {
	if s == nil || !a.IsValid() {
		return netip.Prefix{}, "", false
	}
	a = a.Unmap()
	if a.Is4() {
		k := binary.BigEndian.Uint32(a.AsSlice())
		i := find(s.v4, k, cmp.Compare[uint32])
		if i < 0 {
			return netip.Prefix{}, "", false
		}
		x := s.v4[i]
		return netip.PrefixFrom(a, 32-bits.Len32(x.hi^x.lo)).Masked(), s.details[x.detail], true
	}
	a16 := a.As16()
	k := u128{binary.BigEndian.Uint64(a16[:8]), binary.BigEndian.Uint64(a16[8:])}
	i := find(s.v6, k, cmp128)
	if i < 0 {
		return netip.Prefix{}, "", false
	}
	x := s.v6[i]
	n := 128 - bits.Len64(x.hi.lo^x.lo.lo)
	if x.hi.hi != x.lo.hi {
		n = 64 - bits.Len64(x.hi.hi^x.lo.hi)
	}
	return netip.PrefixFrom(a.WithZone(""), n).Masked(), s.details[x.detail], true
}

// Len reports the number of distinct blocks.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.v4) + len(s.v6)
}
