package sources

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
)

func ipapiIs(key string) *Provider {
	u, lim := "https://api.ipapi.is/?q={ip}", NewLimiter(900, 24*time.Hour, "1000/天")
	if key != "" {
		u += "&key=" + url.QueryEscape(key)
	}
	return &Provider{Name: "ipapi.is", Homepage: "https://ipapi.is/", Kind: "online", Keyed: key != "", Limit: lim,
		Fetch: get(u, nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Company                                                                     json.RawMessage `json:"company"`
				ASN                                                                         json.RawMessage `json:"asn"`
				City, Region, Country                                                       string
				Lat, Lon                                                                    float64
				IsBogon, IsMobile, IsDatacenter, IsTor, IsProxy, IsVPN, IsAbuser, IsCrawler bool
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			// Free answers use strings; keyed answers use objects with more detail.
			var asn int
			var asName, company, ctype string
			var s string
			if json.Unmarshal(d.ASN, &s) == nil {
				asn, asName = asnOf(s)
			} else {
				var ao struct {
					ASN  int
					Org  string
					Type string
				}
				json.Unmarshal(d.ASN, &ao)
				asn, asName = ao.ASN, ao.Org
			}
			if json.Unmarshal(d.Company, &company) != nil {
				var co struct{ Name, Type string }
				json.Unmarshal(d.Company, &co)
				company, ctype = co.Name, co.Type
			}
			if d.Country == "" && asn == 0 {
				return ErrNotFound
			}
			addGeo(o, model.GeoSource{Source: "ipapi.is", Country: d.Country, Region: d.Region, City: d.City,
				ISP: asName, Org: company, ASN: asn, Lat: d.Lat, Lon: d.Lon, Type: ctype})
			if k := classify.ProviderType(ctype); k != "" {
				o.Signal(k, "ipapi.is", "company.type="+ctype, 50)
			}
			for _, f := range []struct {
				on      bool
				kind, d string
				w       int
			}{{d.IsMobile, "mobile", "is_mobile", 60}, {d.IsDatacenter, "hosting", "is_datacenter", 60},
				{d.IsTor, "tor", "is_tor", 80}, {d.IsProxy, "proxy", "is_proxy", 50}, {d.IsVPN, "vpn", "is_vpn", 50},
				{d.IsAbuser, "abuser", "is_abuser", 40}, {d.IsCrawler, "crawler", "is_crawler", 60}} {
				if f.on {
					o.Signal(f.kind, "ipapi.is", f.d, f.w)
				}
			}
			return nil
		}}
}

func ipinfo(token string) *Provider {
	lim, hdr := NewLimiter(1500, 24*time.Hour, "约 1500/天（无 token）"), map[string]string(nil)
	if token != "" {
		lim, hdr = NewLimiter(1500, 24*time.Hour, "50000/月"), map[string]string{"Authorization": "Bearer " + token}
	}
	return &Provider{Name: "ipinfo.io", Homepage: "https://ipinfo.io/", Kind: "online", Keyed: token != "", Limit: lim,
		Fetch: get("https://ipinfo.io/{ip}/json", hdr),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Bogon                                     bool
				Hostname, City, Region, Country, Loc, Org string
				Anycast                                   bool
				ASN                                       *struct{ ASN, Name, Domain, Type string }
				Company                                   *struct{ Name, Domain, Type string }
				Privacy                                   *struct{ VPN, Proxy, Tor, Relay, Hosting bool }
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.Bogon || (d.Country == "" && d.Org == "") {
				return ErrNotFound
			}
			asn, org := asnOf(d.Org)
			lat, lon, _ := strings.Cut(d.Loc, ",")
			g := model.GeoSource{Source: "ipinfo.io", CountryCode: d.Country, Region: d.Region, City: d.City,
				Org: org, ASN: asn}
			g.Lat, _ = strconv.ParseFloat(lat, 64)
			g.Lon, _ = strconv.ParseFloat(lon, 64)
			if d.ASN != nil {
				g.Type = d.ASN.Type
				if k := classify.ProviderType(d.ASN.Type); k != "" {
					o.Signal(k, "ipinfo.io", "asn.type="+d.ASN.Type, 40)
				}
			}
			if d.Company != nil && d.Company.Type != "" {
				g.Type = d.Company.Type
				if k := classify.ProviderType(d.Company.Type); k != "" {
					o.Signal(k, "ipinfo.io", "company.type="+d.Company.Type, 50)
				}
			}
			if p := d.Privacy; p != nil {
				for _, f := range []struct {
					on   bool
					kind string
				}{{p.VPN, "vpn"}, {p.Proxy, "proxy"}, {p.Tor, "tor"}, {p.Relay, "icloud_relay"}, {p.Hosting, "hosting"}} {
					if f.on {
						o.Signal(f.kind, "ipinfo.io", "privacy."+f.kind, 60)
					}
				}
			}
			addGeo(o, g)
			if d.Anycast {
				o.Signal("anycast", "ipinfo.io", "anycast=true", 70)
			}
			o.Hint("rdns:ipinfo", d.Hostname)
			return nil
		}}
}

func ipapiCo() *Provider {
	return &Provider{Name: "ipapi.co", Homepage: "https://ipapi.co/", Kind: "online", Limit: NewLimiter(900, 24*time.Hour, "1000/天"),
		Fetch: get("https://ipapi.co/{ip}/json/", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Error                              bool
				Reason, City, Region, Country, Org string
				CountryName                        string `json:"country_name"`
				Network, Currency                  string
				UTCOffset                          string  `json:"utc_offset"`
				Calling                            string  `json:"country_calling_code"`
				ASN                                string  `json:"asn"`
				Lat                                float64 `json:"latitude"`
				Lon                                float64 `json:"longitude"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.Error {
				if strings.Contains(strings.ToLower(d.Reason), "limit") {
					return fmt.Errorf("%w: %s", ErrQuota, d.Reason)
				}
				return fmt.Errorf("%w: %s", ErrNotFound, d.Reason)
			}
			asn, _ := asnOf(d.ASN)
			addGeo(o, model.GeoSource{Source: "ipapi.co", Country: d.CountryName, CountryCode: d.Country,
				Region: d.Region, City: d.City, Org: d.Org, ASN: asn, Lat: d.Lat, Lon: d.Lon})
			o.Do(func(r *model.Result) {
				if r.Geo.Currency == "" {
					r.Geo.Currency = d.Currency
				}
				if r.Geo.CallingCode == "" {
					r.Geo.CallingCode = d.Calling
				}
				if r.Geo.UTCOffset == "" && len(d.UTCOffset) == 5 {
					r.Geo.UTCOffset = d.UTCOffset[:3] + ":" + d.UTCOffset[3:]
				}
			})
			return nil
		}}
}
