package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
)

func ipdata(key string) *Provider {
	return &Provider{Name: "ipdata.co", Homepage: "https://ipdata.co", Kind: "online", Keyed: true,
		Limit: NewLimiter(100, 24*time.Hour, "100/天（共享额度自限）"), TTL: 24 * time.Hour, Timeout: 6 * time.Second,
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			if key == "" {
				return nil, errors.New("ipdata.co API key is not configured")
			}
			if !q.Addr.IsValid() || q.Addr.Zone() != "" {
				return nil, errors.New("invalid IP address")
			}
			// Addr.String is safe as a path component and preserves IPv6 colons.
			u := "https://api.ipdata.co/" + q.Addr.String() + "?" + url.Values{"api-key": {key}}.Encode()
			raw, err := c.Get(ctx, u, nil, false)
			if err == nil {
				return raw, nil
			}
			switch {
			case errors.Is(err, ErrQuota), err.Error() == "HTTP 403":
				return nil, ErrQuota
			case errors.Is(err, ErrNotFound):
				return nil, ErrNotFound
			case err.Error() == "HTTP 401":
				return nil, errors.New("ipdata.co authentication failed (HTTP 401)")
			case errors.Is(err, context.Canceled):
				return nil, context.Canceled
			case errors.Is(err, context.DeadlineExceeded):
				return nil, context.DeadlineExceeded
			}
			// Client.Get removes url.Error's URL. Also redact the key if an
			// underlying transport error happens to include the request URL.
			message := err.Error()
			for _, secret := range []string{url.QueryEscape(key), url.PathEscape(key), key} {
				message = strings.ReplaceAll(message, secret, "[redacted]")
			}
			return nil, errors.New(message)
		},
		Apply: applyIPData,
	}
}

func applyIPData(o *Out, q Query, raw []byte) error {
	var d struct {
		IP          string
		Message     string
		Error       bool
		CountryName string `json:"country_name"`
		CountryCode string `json:"country_code"`
		Region      string
		City        string
		Postal      string
		Latitude    *float64
		Longitude   *float64
		TimeZone    *struct{ Name string } `json:"time_zone"`
		ASN         *struct{ ASN, Name, Domain, Route, Type string }
		Company     *struct{ Name, Network, Type string }
		Carrier     *struct{ Name string }
		Threat      *struct {
			IsTor           *bool `json:"is_tor"`
			IsVPN           *bool `json:"is_vpn"`
			IsProxy         *bool `json:"is_proxy"`
			IsICloudRelay   *bool `json:"is_icloud_relay"`
			IsDatacenter    *bool `json:"is_datacenter"`
			IsKnownAttacker *bool `json:"is_known_attacker"`
			IsKnownAbuser   *bool `json:"is_known_abuser"`
			IsThreat        *bool `json:"is_threat"`
			IsAnonymous     *bool `json:"is_anonymous"`
			Scores          *struct {
				Trust *int `json:"trust_score"`
			}
		}
	}
	// Decode everything before contributing anything. A malformed optional
	// field cannot leave a partially applied location or a false clean score.
	if json.Unmarshal(raw, &d) != nil {
		return errors.New("invalid ipdata.co response")
	}
	ip, err := netip.ParseAddr(d.IP)
	if err != nil || ip.Zone() != "" || ip.Unmap() != q.Addr.Unmap() || d.Error || d.Message != "" {
		return ErrNotFound
	}
	g := model.GeoSource{Source: "ipdata.co", Country: ipdataText(d.CountryName),
		Region: ipdataText(d.Region), City: ipdataText(d.City)}
	cc := strings.ToUpper(strings.TrimSpace(d.CountryCode))
	if len(cc) == 2 && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z' {
		g.CountryCode = cc
	}
	coordinates := d.Latitude != nil && d.Longitude != nil && *d.Latitude >= -90 && *d.Latitude <= 90 &&
		*d.Longitude >= -180 && *d.Longitude <= 180
	if coordinates {
		g.Lat, g.Lon = *d.Latitude, *d.Longitude
	}
	var asType, companyType, domain, route, network, carrier string
	if d.ASN != nil {
		asn := strings.TrimSpace(d.ASN.ASN)
		if len(asn) >= 2 && strings.EqualFold(asn[:2], "AS") {
			asn = asn[2:]
		}
		if n, err := strconv.ParseUint(asn, 10, 32); err == nil && n > 0 {
			g.ASN = int(n)
		}
		g.ISP, asType = ipdataText(d.ASN.Name), ipdataText(d.ASN.Type)
		domain = ipdataDomain(d.ASN.Domain)
		if p, err := netip.ParsePrefix(d.ASN.Route); err == nil && p.Contains(q.Addr.Unmap()) {
			route = p.Masked().String()
		}
	}
	if d.Company != nil {
		g.Org, companyType = ipdataText(d.Company.Name), ipdataText(d.Company.Type)
		if p, err := netip.ParsePrefix(d.Company.Network); err == nil && p.Contains(q.Addr.Unmap()) {
			network = p.Masked().String()
		}
	}
	if d.Carrier != nil {
		carrier = ipdataText(d.Carrier.Name)
		if carrier != "" {
			g.ISP = carrier
		}
	}
	g.Type = companyType
	if g.Type == "" {
		g.Type = asType
	}
	postal, timezone := ipdataText(d.Postal), ""
	if d.TimeZone != nil {
		if name := ipdataText(d.TimeZone.Name); name != "" {
			if _, err := time.LoadLocation(name); err == nil {
				timezone = name
			}
		}
	}
	useful := g.Country != "" || g.CountryCode != "" || g.Region != "" || g.City != "" || coordinates ||
		g.ASN > 0 || g.ISP != "" || g.Org != "" || domain != "" || route != "" || network != "" || postal != "" || timezone != "" ||
		classify.ProviderType(asType) != "" || classify.ProviderType(companyType) != ""
	var signals []model.Signal
	var trust *int
	if t := d.Threat; t != nil {
		for _, f := range []struct {
			on           *bool
			kind, detail string
			weight       int
		}{
			{t.IsTor, "tor", "is_tor", 80}, {t.IsVPN, "vpn", "is_vpn", 60}, {t.IsProxy, "proxy", "is_proxy", 60},
			{t.IsICloudRelay, "icloud_relay", "is_icloud_relay", 60}, {t.IsDatacenter, "hosting", "is_datacenter", 60},
			{t.IsKnownAttacker, "abuser", "is_known_attacker", 60}, {t.IsKnownAbuser, "abuser", "is_known_abuser", 60},
			{t.IsThreat, "abuser", "is_threat", 60},
		} {
			if f.on != nil {
				useful = true // An explicit false is still a real security check.
				if *f.on {
					signals = append(signals, classify.Sig(f.kind, "ipdata.co", "threat."+f.detail, f.weight))
				}
			}
		}
		if t.Scores != nil && validRiskScore(t.Scores.Trust) {
			trust, useful = t.Scores.Trust, true
		}
	}
	if !useful {
		return ErrNotFound
	}
	switch {
	case d.Threat != nil && d.Threat.IsDatacenter != nil && *d.Threat.IsDatacenter:
		g.Type = "hosting" // Explicit data-center evidence takes priority over generic ISP labels.
	case carrier != "":
		g.Type = "mobile"
		signals = append(signals, classify.Sig("mobile", "ipdata.co", "carrier.name="+carrier, 60))
	default:
		for _, f := range []struct {
			typ, field string
			weight     int
		}{{asType, "asn.type", 40}, {companyType, "company.type", 50}} {
			if kind := classify.ProviderType(f.typ); kind != "" {
				signals = append(signals, classify.Sig(kind, "ipdata.co", f.field+"="+f.typ, f.weight))
			}
		}
	}
	addGeo(o, g)
	for _, s := range signals {
		o.Signal(s.Kind, s.Source, s.Detail, s.Weight)
	}
	o.Hint("geo_cc:ipdata", g.CountryCode)
	o.Do(func(r *model.Result) {
		n := &r.Network
		if n.ASN == 0 {
			n.ASN = g.ASN
		}
		if n.ASName == "" && d.ASN != nil {
			n.ASName = ipdataText(d.ASN.Name)
		}
		if n.ASDomain == "" {
			n.ASDomain = domain
		}
		if n.ISP == "" {
			n.ISP = g.ISP
		}
		if n.Org == "" {
			n.Org = g.Org
		}
		if n.Prefix == "" {
			n.Prefix = route
		}
		if n.NetRange == "" {
			n.NetRange = network
		}
		if n.UsageType == "" {
			n.UsageType = g.Type
		}
		// Only combine location details when no geography has been selected,
		// or both providers identify the same country by a nonempty code.
		unselected := r.Geo == (model.Geo{})
		sameCountry := r.Geo.CountryCode != "" && g.CountryCode != "" && strings.EqualFold(r.Geo.CountryCode, g.CountryCode)
		if unselected || sameCountry {
			if r.Geo.Country == "" {
				r.Geo.Country = g.Country
			}
			if r.Geo.CountryCode == "" {
				r.Geo.CountryCode = g.CountryCode
			}
			if r.Geo.Region == "" {
				r.Geo.Region = g.Region
			}
			if r.Geo.City == "" {
				r.Geo.City = g.City
			}
			if r.Geo.Lat == 0 && r.Geo.Lon == 0 && coordinates {
				r.Geo.Lat, r.Geo.Lon = g.Lat, g.Lon
			}
			if r.Geo.Postal == "" {
				r.Geo.Postal = postal
			}
			if r.Geo.TimeZone == "" {
				r.Geo.TimeZone = timezone
			}
		}
		if trust != nil {
			r.Risk = append(r.Risk, model.Risk{Source: "ipdata.co", Value: 100 - *trust, Detail: fmt.Sprintf("trust_score %d（越高越可信）", *trust)})
		}
	})
	return nil
}

func ipdataText(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 || strings.ContainsFunc(s, unicode.IsControl) {
		return ""
	}
	return s
}

func ipdataDomain(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) == 0 || len(s) > 253 {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return ""
			}
		}
	}
	return s
}
