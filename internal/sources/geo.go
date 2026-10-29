package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

// get fetches a URL template; {ip} is replaced by the queried address.
func get(u string, hdr map[string]string) func(context.Context, *Client, Query) ([]byte, error) {
	return func(ctx context.Context, c *Client, q Query) ([]byte, error) {
		return c.Get(ctx, strings.ReplaceAll(u, "{ip}", url.PathEscape(q.Addr.String())), hdr, false)
	}
}

// asnOf parses "AS906", "AS906 DMIT Cloud Services" or "906" into the number and the trailing name.
func asnOf(s string) (int, string) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.EqualFold(s[:2], "AS") {
		s = s[2:]
	}
	num, rest, _ := strings.Cut(s, " ")
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, ""
	}
	return n, strings.TrimSpace(rest)
}

func addGeo(o *Out, g model.GeoSource) {
	o.Do(func(r *model.Result) { r.GeoSources = append(r.GeoSources, g) })
}

func ipAPI() *Provider {
	return &Provider{Name: "ip-api.com", Homepage: "https://ip-api.com/", Kind: "online",
		Limit: NewLimiter(40, time.Minute, "40/分钟（免费版仅限非商业用途）"),
		Fetch: get("http://ip-api.com/json/{ip}?fields=66846719&lang=zh-CN", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Status, Message, Country, CountryCode, RegionName, City, District, Zip, ISP, Org, AS, ASName, Reverse string
				Lat, Lon                                                                                              float64
				Mobile, Proxy, Hosting                                                                                bool
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.Status != "success" {
				return fmt.Errorf("%w: %s", ErrNotFound, d.Message)
			}
			asn, _ := asnOf(d.AS)
			typ := []string{}
			for _, x := range []struct {
				on   bool
				name string
			}{{d.Mobile, "mobile"}, {d.Proxy, "proxy"}, {d.Hosting, "hosting"}} {
				if x.on {
					typ = append(typ, x.name)
				}
			}
			addGeo(o, model.GeoSource{Source: "ip-api.com", Country: d.Country, CountryCode: d.CountryCode,
				Region: d.RegionName, City: strings.TrimSpace(d.City + " " + d.District), ISP: d.ISP, Org: d.Org,
				ASN: asn, Lat: d.Lat, Lon: d.Lon, Type: strings.Join(typ, ",")})
			if d.Mobile {
				o.Signal("mobile", "ip-api.com", "mobile=true", 70)
			}
			if d.Hosting {
				o.Signal("hosting", "ip-api.com", "hosting=true", 60)
			}
			if d.Proxy {
				o.Signal("proxy", "ip-api.com", "proxy=true（含 VPN/Tor）", 40)
			}
			if !d.Mobile && !d.Hosting && !d.Proxy {
				o.Signal("residential", "ip-api.com", "mobile/hosting/proxy 均为 false", 25)
			}
			o.Hint("rdns:ip-api", d.Reverse)
			o.Do(func(r *model.Result) {
				if r.Network.ISP == "" {
					r.Network.ISP = d.ISP
				}
				if r.Geo.District == "" {
					r.Geo.District = d.District
				}
			})
			return nil
		}}
}

func ipWho() *Provider {
	return &Provider{Name: "ipwho.is", Homepage: "https://ipwho.is/", Kind: "online",
		Limit: NewLimiter(300, 24*time.Hour, "300/天（自限）"),
		Fetch: get("https://ipwho.is/{ip}?lang=zh-CN", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Success                                bool
				Message, Country, Region, City, Postal string
				CountryCode                            string  `json:"country_code"`
				CallingCode                            string  `json:"calling_code"`
				IsEU                                   bool    `json:"is_eu"`
				Lat                                    float64 `json:"latitude"`
				Lon                                    float64 `json:"longitude"`
				Flag                                   struct {
					Emoji string
				}
				Connection struct {
					ASN              int
					Org, ISP, Domain string
				}
				TimeZone struct {
					ID, UTC string
				} `json:"timezone"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if !d.Success {
				return fmt.Errorf("%w: %s", ErrNotFound, d.Message)
			}
			addGeo(o, model.GeoSource{Source: "ipwho.is", Country: d.Country, CountryCode: d.CountryCode,
				Region: d.Region, City: d.City, ISP: d.Connection.ISP, Org: d.Connection.Org,
				ASN: d.Connection.ASN, Lat: d.Lat, Lon: d.Lon})
			o.Do(func(r *model.Result) {
				if r.Geo.CallingCode == "" && d.CallingCode != "" {
					r.Geo.CallingCode = "+" + strings.TrimPrefix(d.CallingCode, "+")
				}
				if r.Geo.Flag == "" {
					r.Geo.Flag = d.Flag.Emoji
				}
				if r.Geo.UTCOffset == "" {
					r.Geo.UTCOffset = d.TimeZone.UTC
				}
				r.Geo.IsEU = r.Geo.IsEU || d.IsEU
				if r.Network.ASDomain == "" {
					r.Network.ASDomain = d.Connection.Domain
				}
			})
			return nil
		}}
}

func ipSB() *Provider {
	return &Provider{Name: "ip.sb", Homepage: "https://ip.sb/", Kind: "online",
		Limit: NewLimiter(300, 24*time.Hour, "300/天（自限）"),
		Fetch: get("https://api.ip.sb/geoip/{ip}", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Country, Region, City, ISP, Organization string
				CountryCode                              string  `json:"country_code"`
				ASN                                      int     `json:"asn"`
				ASNOrg                                   string  `json:"asn_organization"`
				Lat                                      float64 `json:"latitude"`
				Lon                                      float64 `json:"longitude"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.Country == "" && d.ASN == 0 {
				return ErrNotFound
			}
			addGeo(o, model.GeoSource{Source: "ip.sb", Country: d.Country, CountryCode: d.CountryCode,
				Region: d.Region, City: d.City, ISP: d.ISP, Org: d.Organization, ASN: d.ASN, Lat: d.Lat, Lon: d.Lon})
			return nil
		}}
}
