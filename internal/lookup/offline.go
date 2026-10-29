package lookup

import (
	"net/netip"
	"strings"

	"github.com/zzusec/ip-lookup/internal/datasets"
	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/internal/sources"
)

var continentZH = map[string]string{"AF": "非洲", "AN": "南极洲", "AS": "亚洲", "EU": "欧洲", "NA": "北美洲", "OC": "大洋洲", "SA": "南美洲"}

// offline fills r from the downloaded databases and lists and returns the
// origin AS and prefix it found.
func (s *Service) offline(o *sources.Out, a netip.Addr) (asn int, prefix netip.Prefix) {
	r := o.Res
	var m datasets.MergedRecord
	p, ok, err := s.Data.LookupMMDB("merged", a, &m)
	r.Sources = append(r.Sources, offlineStatus("Merged-IP", ok, err))
	if ok {
		prefix, asn = p, int(m.ASN.Number)
		g := &r.Geo
		g.Country, g.CountryEN = m.Country.Names.Pick()
		g.CountryCode = m.Country.ISOCode
		g.ContinentCode = m.Continent.Code
		if g.Continent, _ = m.Continent.Names.Pick(); g.Continent == "" {
			g.Continent = continentZH[g.ContinentCode]
		}
		if len(m.Subdivisions) > 0 {
			g.Region, g.RegionEN = m.Subdivisions[0].Names.Pick()
			g.RegionCode = m.Subdivisions[0].ISOCode
		}
		g.City, g.CityEN = m.City.Names.Pick()
		g.Postal = m.Postal.Code
		g.Lat, g.Lon, g.AccuracyKm = m.Location.Latitude, m.Location.Longitude, m.Location.Accuracy
		g.TimeZone = m.Location.TimeZone
		g.Flag = flag(g.CountryCode)
		g.IsEU = euCountries[g.CountryCode]
		n := &r.Network
		n.ASN, n.ASName, n.ASDomain = asn, m.ASN.Org, m.ASN.Domain
		n.Prefix = p.String()
		o.Hint("reg_cc:merged", m.RegisteredCountry.ISOCode)
		px := m.Proxy
		for _, f := range []struct {
			on   bool
			kind string
			w    int
		}{{px.Tor, "tor", 80}, {px.VPN, "vpn", 50}, {px.CDN, "cdn", 50}, {px.Hosting, "hosting", 50}} {
			if f.on {
				o.Signal(f.kind, "Merged-IP", "is_"+f.kind, f.w)
			}
		}
		r.GeoSources = append(r.GeoSources, model.GeoSource{Source: "Merged-IP", Country: g.Country,
			CountryCode: g.CountryCode, Region: g.Region, City: g.City, Org: m.ASN.Org, ASN: asn, Lat: g.Lat, Lon: g.Lon})
	}

	var dc datasets.DBIPCity
	if _, ok, err := s.Data.LookupMMDB("dbip-city", a, &dc); ok || err != nil {
		r.Sources = append(r.Sources, offlineStatus("DB-IP City Lite", ok, err))
		if ok {
			gs := model.GeoSource{Source: "DB-IP City Lite", CountryCode: dc.Country.ISOCode,
				Lat: dc.Location.Latitude, Lon: dc.Location.Longitude}
			gs.Country, _ = dc.Country.Names.Pick()
			gs.City, _ = dc.City.Names.Pick()
			if len(dc.Subdivisions) > 0 {
				gs.Region, _ = dc.Subdivisions[0].Names.Pick()
			}
			var da datasets.DBIPASN
			if _, ok, _ := s.Data.LookupMMDB("dbip-asn", a, &da); ok {
				gs.ASN, gs.Org = int(da.Number), da.Org
			}
			r.GeoSources = append(r.GeoSources, gs)
		}
	}

	reg, ok, err := s.Data.LookupRegion(a)
	if ok || err != nil {
		r.Sources = append(r.Sources, offlineStatus("ip2region", ok, err))
	}
	if ok {
		r.GeoSources = append(r.GeoSources, model.GeoSource{Source: "ip2region", Country: reg.Country,
			CountryCode: reg.CC, Region: reg.Province, City: reg.City, ISP: reg.ISP})
		if reg.CC == "CN" && reg.ISP != "" {
			r.Network.ISP = reg.ISP
			// ip2region knows Chinese cities better than the global databases.
			if r.Geo.CountryCode == "CN" || r.Geo.CountryCode == "" {
				r.Geo.Region, r.Geo.City = orKeep(reg.Province, r.Geo.Region), orKeep(reg.City, r.Geo.City)
			}
		}
	}
	if asn == 0 {
		if o, ok := s.asnFromDBIP(a); ok {
			asn = o
		}
	}
	s.lists(o, a)
	s.asSignals(o, asn)
	return asn, prefix
}

func (s *Service) asnFromDBIP(a netip.Addr) (int, bool) {
	var da datasets.DBIPASN
	if _, ok, _ := s.Data.LookupMMDB("dbip-asn", a, &da); ok && da.Number != 0 {
		return int(da.Number), true
	}
	return 0, false
}

func orKeep(v, old string) string {
	if v != "" {
		return v
	}
	return old
}

func offlineStatus(name string, ok bool, err error) model.Source {
	st := model.Source{Name: name, Kind: "offline", Status: "ok"}
	switch {
	case err != nil:
		st.Status, st.Error = "error", err.Error()
	case !ok:
		st.Status = "empty"
	}
	return st
}

// flag turns an ISO country code into its emoji flag.
func flag(cc string) string {
	if len(cc) != 2 || cc == "EU" {
		return ""
	}
	cc = strings.ToUpper(cc)
	return string([]rune{rune(cc[0]) - 'A' + 0x1F1E6, rune(cc[1]) - 'A' + 0x1F1E6})
}

var euCountries = map[string]bool{"AT": true, "BE": true, "BG": true, "HR": true, "CY": true, "CZ": true,
	"DK": true, "EE": true, "FI": true, "FR": true, "DE": true, "GR": true, "HU": true, "IE": true, "IT": true,
	"LV": true, "LT": true, "LU": true, "MT": true, "NL": true, "PL": true, "PT": true, "RO": true, "SK": true,
	"SI": true, "ES": true, "SE": true}
