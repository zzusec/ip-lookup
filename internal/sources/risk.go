package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
)

func proxycheck(key string) *Provider {
	u, lim := "https://proxycheck.io/v3/{ip}", NewLimiter(900, 24*time.Hour, "1000/天")
	if key != "" {
		u += "?key=" + url.QueryEscape(key)
	}
	return &Provider{Name: "proxycheck.io", Homepage: "https://proxycheck.io/", Kind: "online", Keyed: key != "",
		Limit: lim, Fetch: get(u, nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var top map[string]json.RawMessage
			if err := json.Unmarshal(raw, &top); err != nil {
				return err
			}
			var status, msg string
			json.Unmarshal(top["status"], &status)
			json.Unmarshal(top["message"], &msg)
			body, ok := top[q.Addr.String()]
			if !ok {
				if status == "denied" {
					return fmt.Errorf("%w: %s", ErrQuota, msg)
				}
				return fmt.Errorf("%w: %s %s", ErrNotFound, status, msg)
			}
			var d struct {
				Network struct {
					ASN, Range, Hostname, Provider, Organisation, Type string
				}
				Location struct {
					CountryName string `json:"country_name"`
					CountryCode string `json:"country_code"`
					RegionName  string `json:"region_name"`
					CityName    string `json:"city_name"`
					Latitude    float64
					Longitude   float64
				}
				Detections struct {
					Proxy, VPN, Compromised, Scraper, Tor, Hosting, Anonymous bool
					Risk, Confidence                                          int
				}
				Operator *struct{ Name string }
			}
			if err := json.Unmarshal(body, &d); err != nil {
				return err
			}
			asn, _ := asnOf(d.Network.ASN)
			addGeo(o, model.GeoSource{Source: "proxycheck.io", Country: d.Location.CountryName,
				CountryCode: d.Location.CountryCode, Region: d.Location.RegionName, City: d.Location.CityName,
				ISP: d.Network.Provider, Org: d.Network.Organisation, ASN: asn,
				Lat: d.Location.Latitude, Lon: d.Location.Longitude, Type: d.Network.Type})
			if k := classify.ProviderType(d.Network.Type); k != "" {
				o.Signal(k, "proxycheck.io", "network.type="+d.Network.Type, 60)
			}
			det := d.Detections
			for _, f := range []struct {
				on   bool
				kind string
				w    int
			}{{det.Tor, "tor", 80}, {det.VPN, "vpn", vpnWeight(det.Hosting)}, {det.Proxy, "proxy", 60}, {det.Hosting, "hosting", 40},
				{det.Compromised, "abuser", 50}, {det.Scraper, "crawler", 40}} {
				if f.on {
					o.Signal(f.kind, "proxycheck.io", "detections."+f.kind, f.w)
				}
			}
			detail := fmt.Sprintf("risk %d，置信度 %d", det.Risk, det.Confidence)
			if d.Operator != nil && d.Operator.Name != "" {
				detail += "，运营方 " + d.Operator.Name
				o.Signal("vpn", "proxycheck.io", "operator="+d.Operator.Name, 70)
			}
			o.Do(func(r *model.Result) {
				r.Risk = append(r.Risk, model.Risk{Source: "proxycheck.io", Value: det.Risk, Detail: detail})
				if r.Network.Prefix == "" {
					r.Network.Prefix = d.Network.Range
				}
			})
			return nil
		}}
}

// vpnWeight discounts proxycheck's VPN flag on data-center ranges, where it
// is set for most addresses of a hosting provider.
func vpnWeight(hosting bool) int {
	if hosting {
		return 30
	}
	return 50
}

func ipyou() *Provider {
	return &Provider{Name: "ipyou.net", Homepage: "https://ipyou.net/", Kind: "online",
		Limit: NewLimiter(300, 24*time.Hour, "300/天（自限）"), Timeout: 8 * time.Second,
		Fetch: get("https://ipyou.net/{ip}", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Geo struct {
					Country, Province, City, ISP string
					CountryCode                  string `json:"country_code"`
					Latitude, Longitude          float64
				}
				Intel struct {
					IsProxy  bool `json:"is_proxy"`
					IsVPN    bool `json:"is_vpn"`
					IsTor    bool `json:"is_tor"`
					IsBot    bool `json:"is_bot"`
					IsHost   bool `json:"is_hosting"`
					IsAbuser bool `json:"is_abuser"`
				} `json:"intel_summary"`
				Usage struct {
					Label      string
					Confidence float64
					Source     string
				} `json:"usage_inferred"`
				Score struct {
					Score int
					Level string
				} `json:"ip_score"`
				Native struct {
					Native     *bool
					RegistryCC string `json:"registry_cc"`
					Registry   string
				} `json:"native_ip"`
				ProxyInfo struct {
					Found      bool
					ProxyLabel string `json:"proxy_label"`
					UsageType  string `json:"usage_type"`
					UsageLabel string `json:"usage_label"`
					FraudScore int    `json:"fraud_score"`
				} `json:"proxy_info"`
				Blocklisted bool
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			addGeo(o, model.GeoSource{Source: "ipyou.net", Country: d.Geo.Country, CountryCode: d.Geo.CountryCode,
				Region: d.Geo.Province, City: d.Geo.City, ISP: d.Geo.ISP, Lat: d.Geo.Latitude, Lon: d.Geo.Longitude,
				Type: d.Usage.Label})
			if k := classify.ProviderType(d.Usage.Label); k != "" {
				o.Signal(k, "ipyou.net", "usage_inferred="+d.Usage.Label, int(30+40*d.Usage.Confidence))
			}
			if d.ProxyInfo.Found {
				if k := classify.ProviderType(d.ProxyInfo.UsageType); k != "" {
					o.Signal(k, "IP2Proxy（经 ipyou.net）", d.ProxyInfo.UsageType+" "+d.ProxyInfo.UsageLabel, 50)
				}
				if d.ProxyInfo.ProxyLabel != "" {
					o.Signal("proxy", "IP2Proxy（经 ipyou.net）", d.ProxyInfo.ProxyLabel, 50)
				}
			}
			in := d.Intel
			for _, f := range []struct {
				on   bool
				kind string
			}{{in.IsTor, "tor"}, {in.IsVPN, "vpn"}, {in.IsProxy, "proxy"}, {in.IsBot, "crawler"},
				{in.IsHost, "hosting"}, {in.IsAbuser, "abuser"}} {
				if f.on {
					o.Signal(f.kind, "ipyou.net", "intel."+f.kind, 40)
				}
			}
			if d.Native.RegistryCC != "" {
				o.Hint("reg_cc:ipyou", d.Native.RegistryCC)
			}
			o.Do(func(r *model.Result) {
				r.Risk = append(r.Risk, model.Risk{Source: "ipyou.net", Value: d.Score.Score, Detail: "等级 " + d.Score.Level})
				if d.ProxyInfo.Found && d.ProxyInfo.FraudScore > 0 {
					r.Risk = append(r.Risk, model.Risk{Source: "IP2Proxy 欺诈分（经 ipyou.net）", Value: d.ProxyInfo.FraudScore})
				}
				if r.Network.UsageType == "" && d.ProxyInfo.UsageLabel != "" {
					r.Network.UsageType = d.ProxyInfo.UsageType + " " + d.ProxyInfo.UsageLabel
				}
			})
			if d.Blocklisted {
				o.Signal("abuser", "ipyou.net", "blocklisted", 30)
			}
			return nil
		}}
}

func greynoise(key string) *Provider {
	hdr := map[string]string(nil)
	if key != "" {
		hdr = map[string]string{"key": key}
	}
	return &Provider{Name: "GreyNoise", Homepage: "https://viz.greynoise.io/", Kind: "online", Keyed: key != "", V4Only: true,
		Limit: NewLimiter(45, 24*time.Hour, "50/周（社区版）"), TTL: 24 * time.Hour,
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			return c.Get(ctx, "https://api.greynoise.io/v3/community/"+q.Addr.String(), hdr, true)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Noise, Riot                   bool
				Classification, Name, Message string
				LastSeen                      string `json:"last_seen"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if !d.Noise && !d.Riot {
				return ErrNotFound
			}
			detail := strings.TrimSpace(d.Classification + " " + d.Name)
			if d.Riot {
				o.Signal("public_service", "GreyNoise", "RIOT: "+d.Name, 60)
			}
			if d.Noise {
				v := map[string]int{"malicious": 90, "unknown": 50, "benign": 10}[d.Classification]
				if d.Classification == "malicious" {
					o.Signal("abuser", "GreyNoise", "正在扫描互联网："+detail, 70)
				}
				if d.Classification == "benign" && d.Name != "" {
					o.Signal("crawler", "GreyNoise", "良性扫描："+d.Name, 50)
				}
				o.Do(func(r *model.Result) {
					r.Risk = append(r.Risk, model.Risk{Source: "GreyNoise", Value: v, Detail: detail + " " + d.LastSeen})
				})
			}
			return nil
		}}
}
