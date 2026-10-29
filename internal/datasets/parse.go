package datasets

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/zzusec/ip-lookup/internal/cidr"
)

var errEmpty = errors.New("no entries parsed")

// parseList adds one downloaded part to b and returns how many entries it added.
func parseList(f Format, tag string, r io.Reader, b *cidr.Builder) (int, error) {
	switch f {
	case CIDRLines, ProxyURLs, Ipsum, FirstCol:
		return parseLines(f, r, b)
	}
	return parseJSON(f, tag, r, b)
}

func parseLines(f Format, r io.Reader, b *cidr.Builder) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		ok := false
		switch f {
		case ProxyURLs:
			ok = addProxyURL(b, line)
		case Ipsum:
			ip, cnt, _ := strings.Cut(line, "\t")
			c, err := strconv.Atoi(strings.TrimSpace(cnt))
			if err != nil || c < 3 {
				continue
			}
			ok = b.AddText(ip, fmt.Sprintf("命中 %d 个黑名单", c))
		case FirstCol:
			first, rest, _ := strings.Cut(line, ",")
			ok = b.AddText(first, strings.Join(strings.FieldsFunc(rest, func(r rune) bool { return r == ',' }), " "))
		default:
			ok = b.AddText(strings.Fields(line)[0], "")
		}
		if ok {
			n++
		}
	}
	return n, sc.Err()
}

func addProxyURL(b *cidr.Builder, line string) bool {
	u, err := url.Parse(line)
	if err != nil || u.Host == "" {
		return false
	}
	ap, err := netip.ParseAddrPort(u.Host)
	if err != nil {
		return false
	}
	b.AddAddr(ap.Addr().Unmap(), u.Scheme+":"+strconv.Itoa(int(ap.Port())))
	return true
}

type prefixDetail struct{ prefix, detail string }

func parseJSON(f Format, tag string, r io.Reader, b *cidr.Builder) (int, error) {
	var list []prefixDetail
	dec := json.NewDecoder(r)
	switch f {
	case AWSJSON:
		type entry struct {
			V4      string `json:"ip_prefix"`
			V6      string `json:"ipv6_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		}
		var d struct {
			Prefixes []entry `json:"prefixes"`
			V6       []entry `json:"ipv6_prefixes"`
		}
		if err := dec.Decode(&d); err != nil {
			return 0, err
		}
		for _, e := range append(d.Prefixes, d.V6...) {
			if tag != "" && e.Service != tag {
				continue
			}
			detail := e.Region
			if e.Service != "AMAZON" {
				detail += " " + e.Service
			}
			list = append(list, prefixDetail{e.V4 + e.V6, detail})
		}
	case GCPJSON:
		var d struct {
			Prefixes []struct{ IPv4Prefix, IPv6Prefix, Service, Scope string } `json:"prefixes"`
		}
		if err := dec.Decode(&d); err != nil {
			return 0, err
		}
		for _, e := range d.Prefixes {
			list = append(list, prefixDetail{e.IPv4Prefix + e.IPv6Prefix, strings.TrimSpace(e.Service + " " + e.Scope)})
		}
	case OracleJSON:
		var d struct {
			Regions []struct {
				Region string `json:"region"`
				CIDRs  []struct {
					CIDR string `json:"cidr"`
				} `json:"cidrs"`
			} `json:"regions"`
		}
		if err := dec.Decode(&d); err != nil {
			return 0, err
		}
		for _, reg := range d.Regions {
			for _, c := range reg.CIDRs {
				list = append(list, prefixDetail{c.CIDR, reg.Region})
			}
		}
	case FastlyJSON:
		var d struct {
			V4 []string `json:"addresses"`
			V6 []string `json:"ipv6_addresses"`
		}
		if err := dec.Decode(&d); err != nil {
			return 0, err
		}
		for _, p := range append(d.V4, d.V6...) {
			list = append(list, prefixDetail{p, ""})
		}
	case SpamhausNDJSON:
		for {
			var e struct{ CIDR, SBLID string }
			if err := dec.Decode(&e); err == io.EOF {
				break
			} else if err != nil {
				return 0, err
			}
			if e.CIDR != "" {
				list = append(list, prefixDetail{e.CIDR, e.SBLID})
			}
		}
	default:
		return 0, fmt.Errorf("format %d is not a list", f)
	}
	n := 0
	for _, e := range list {
		if b.AddText(e.prefix, e.detail) {
			n++
		}
	}
	return n, nil
}
