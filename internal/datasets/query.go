package datasets

import (
	"net/netip"
	"strings"
)

type names map[string]string

// Pick returns the zh-CN name, falling back to English.
func (n names) Pick() (zh, en string) {
	en = n["en"]
	if zh = n["zh-CN"]; zh == "" {
		zh = en
	}
	return zh, en
}

type place struct {
	Code    string `maxminddb:"code"`
	ISOCode string `maxminddb:"iso_code"`
	Names   names  `maxminddb:"names"`
}

// MergedRecord is the subset of a Merged-IP (GeoIP2 City layout) record we use.
type MergedRecord struct {
	ASN struct {
		Number uint32 `maxminddb:"autonomous_system_number"`
		Org    string `maxminddb:"autonomous_system_organization"`
		Domain string `maxminddb:"as_domain"`
	} `maxminddb:"asn"`
	City              place   `maxminddb:"city"`
	Continent         place   `maxminddb:"continent"`
	Country           place   `maxminddb:"country"`
	RegisteredCountry place   `maxminddb:"registered_country"`
	Subdivisions      []place `maxminddb:"subdivisions"`
	Location          struct {
		Accuracy  int     `maxminddb:"accuracy_radius"`
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
	Proxy struct {
		Anonymous bool `maxminddb:"is_anonymous"`
		Hosting   bool `maxminddb:"is_hosting"`
		Proxy     bool `maxminddb:"is_proxy"`
		Tor       bool `maxminddb:"is_tor"`
		VPN       bool `maxminddb:"is_vpn"`
		CDN       bool `maxminddb:"is_cdn"`
	} `maxminddb:"proxy"`
}

// DBIPCity is the DB-IP City Lite record layout.
type DBIPCity struct {
	City         place   `maxminddb:"city"`
	Country      place   `maxminddb:"country"`
	Subdivisions []place `maxminddb:"subdivisions"`
	Location     struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// DBIPASN is the DB-IP ASN Lite record layout.
type DBIPASN struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// Region is an ip2region record split into fields; "0" means unknown.
type Region struct{ Country, Province, City, ISP, CC string }

// Hit is one list that contains the address.
type Hit struct {
	Spec   Spec
	Prefix netip.Prefix
	Detail string
}

// LookupMMDB decodes the record for a into v and returns the matched network.
func (m *Manager) LookupMMDB(id string, a netip.Addr, v any) (netip.Prefix, bool, error) {
	l := m.Get(id)
	if l == nil || l.MMDB == nil {
		return netip.Prefix{}, false, nil
	}
	r := l.MMDB.Lookup(a)
	if err := r.Err(); err != nil || !r.Found() {
		return netip.Prefix{}, false, err
	}
	return r.Prefix(), true, r.Decode(v)
}

// LookupRegion queries ip2region; ok is false when the database is missing
// or has no record.
func (m *Manager) LookupRegion(a netip.Addr) (Region, bool, error) {
	a = a.Unmap()
	id := "ip2region-v4"
	if a.Is6() {
		id = "ip2region-v6"
	}
	l := m.Get(id)
	if l == nil || l.XDB == nil {
		return Region{}, false, nil
	}
	raw, err := l.XDB.Search(a.AsSlice())
	if err != nil || raw == "" {
		return Region{}, false, err
	}
	f := strings.Split(raw, "|")
	for len(f) < 5 {
		f = append(f, "0")
	}
	clean := func(s string) string {
		if s == "0" {
			return ""
		}
		return strings.TrimSpace(s)
	}
	return Region{clean(f[0]), clean(f[1]), clean(f[2]), clean(f[3]), clean(f[4])}, true, nil
}

// Lists returns every IP list containing a, in registry order.
func (m *Manager) Lists(a netip.Addr) []Hit {
	var out []Hit
	for _, e := range m.entries {
		l := e.Get()
		if l == nil || l.List == nil {
			continue
		}
		if p, d, ok := l.List.Lookup(a); ok {
			out = append(out, Hit{Spec: e.Spec, Prefix: p, Detail: d})
		}
	}
	return out
}

// ASLookup reports what the AS-level datasets say about asn: the bgp.tools
// class, the bgp.tools tags and, when listed, the ASN-DROP entry.
func (m *Manager) ASLookup(asn uint32) (class string, tags []string, drop string, dropped bool) {
	if asn == 0 {
		return "", nil, "", false
	}
	for _, e := range m.entries {
		l := e.Get()
		if l == nil || l.ASN == nil {
			continue
		}
		v, ok := l.ASN[asn]
		if !ok {
			continue
		}
		switch e.Spec.Format {
		case ASNCSV:
			class = v
		case ASNTag:
			tags = append(tags, e.Spec.Tag)
		case ASNDrop:
			drop, dropped = v, true
		}
	}
	return class, tags, drop, dropped
}
