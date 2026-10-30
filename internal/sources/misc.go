package sources

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

func internetDB() *Provider {
	return &Provider{Name: "Shodan InternetDB", Homepage: "https://internetdb.shodan.io/", Kind: "online",
		TTL: 24 * time.Hour, Fetch: get("https://internetdb.shodan.io/{ip}", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d model.Ports
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if len(d.Ports) == 0 && len(d.Hostnames) == 0 && len(d.Tags) == 0 {
				return ErrNotFound
			}
			slices.Sort(d.Ports)
			for _, t := range d.Tags {
				switch t {
				case "vpn":
					o.Signal("vpn", "Shodan InternetDB", "tag vpn", 60)
				case "proxy":
					o.Signal("proxy", "Shodan InternetDB", "tag proxy", 50)
				case "tor":
					o.Signal("tor", "Shodan InternetDB", "tag tor", 60)
				case "cloud":
					o.Signal("hosting", "Shodan InternetDB", "tag cloud", 50)
				case "cdn":
					o.Signal("cdn", "Shodan InternetDB", "tag cdn", 50)
				case "compromised", "malware":
					o.Signal("abuser", "Shodan InternetDB", "tag "+t, 50)
				}
			}
			o.Do(func(r *model.Result) { r.Ports = &d })
			return nil
		}}
}

func hackertarget() *Provider {
	return &Provider{Name: "HackerTarget 反查域名", Homepage: "https://hackertarget.com/reverse-ip-lookup/",
		Kind: "online", Limit: NewLimiter(45, 24*time.Hour, "50/天"), TTL: 24 * time.Hour,
		Fetch: get("https://api.hackertarget.com/reverseiplookup/?q={ip}", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			t := strings.TrimSpace(string(raw))
			low := strings.ToLower(t)
			switch {
			case strings.Contains(low, "api count exceeded"):
				return ErrQuota
			case t == "" || strings.HasPrefix(low, "no dns a records") || strings.HasPrefix(low, "error"):
				return ErrNotFound
			}
			var domains []string
			sc := bufio.NewScanner(bytes.NewReader(raw))
			for sc.Scan() {
				if d := strings.TrimSpace(sc.Text()); d != "" && !strings.ContainsAny(d, " \t") && len(domains) < 50 {
					domains = append(domains, d)
				}
			}
			if len(domains) == 0 {
				return ErrNotFound
			}
			o.Do(func(r *model.Result) { r.Network.Domains = domains })
			return nil
		}}
}

func zxinc() *Provider {
	return &Provider{Name: "纯真 (zxinc)", Homepage: "https://ip.zxinc.org/", Kind: "online", V4Only: true,
		Limit: NewLimiter(300, 24*time.Hour, "300/天（自限）"),
		Fetch: get("https://ip.zxinc.org/api.php?type=json&ip={ip}", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Data struct {
					Location string
					Country  string
					Local    string
				}
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			g := zxincGeo(d.Data.Location, d.Data.Country, d.Data.Local)
			if g.Text == "" && g.Country == "" {
				return ErrNotFound
			}
			addGeo(o, g)
			return nil
		}}
}

func baidu() *Provider {
	return &Provider{Name: "百度 IP", Homepage: "https://www.baidu.com/s?wd=ip", Kind: "online", V4Only: true,
		Limit: NewLimiter(300, 24*time.Hour, "300/天（自限）"),
		Fetch: get("https://opendata.baidu.com/api.php?co=&resource_id=6006&oe=utf8&query={ip}", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Status string
				Data   []struct{ Location string }
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.Status != "0" || len(d.Data) == 0 || d.Data[0].Location == "" {
				return ErrNotFound
			}
			var region, city string
			o.Do(func(r *model.Result) { region, city = r.Geo.Region, r.Geo.City })
			addGeo(o, baiduGeo(d.Data[0].Location, region, city))
			return nil
		}}
}

func ip2locationIO(key string) *Provider {
	u := "https://api.ip2location.io/?ip={ip}"
	if key != "" {
		u += "&key=" + url.QueryEscape(key)
	}
	return &Provider{Name: "IP2Location.io", Homepage: "https://www.ip2location.io/", Kind: "online", Keyed: key != "",
		Limit: NewLimiter(900, 24*time.Hour, "1000/天"), Fetch: get(u, nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				CountryCode string  `json:"country_code"`
				CountryName string  `json:"country_name"`
				RegionName  string  `json:"region_name"`
				CityName    string  `json:"city_name"`
				Lat         float64 `json:"latitude"`
				Lon         float64 `json:"longitude"`
				ASN         string  `json:"asn"`
				AS          string  `json:"as"`
				IsProxy     bool    `json:"is_proxy"`
				UsageType   string  `json:"usage_type"`
				Error       *struct {
					Message string `json:"error_message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.Error != nil {
				return ErrNotFound
			}
			asn, _ := asnOf(d.ASN)
			addGeo(o, model.GeoSource{Source: "IP2Location.io", Country: d.CountryName, CountryCode: d.CountryCode,
				Region: d.RegionName, City: d.CityName, Org: d.AS, ASN: asn, Lat: d.Lat, Lon: d.Lon, Type: d.UsageType})
			if d.IsProxy { // the free tier also sets is_proxy for data-center ranges
				o.Signal("proxy", "IP2Location.io", "is_proxy（含机房网段）", 20)
			}
			return nil
		}}
}
