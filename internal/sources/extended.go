package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
)

func ensureAudit(r *model.Result) *model.NetworkAudit {
	if r.Audit == nil {
		r.Audit = &model.NetworkAudit{}
	}
	return r.Audit
}

func ensureActivity(r *model.Result) *model.ThreatActivity {
	a := ensureAudit(r)
	if a.Activity == nil {
		a.Activity = &model.ThreatActivity{}
	}
	return a.Activity
}

func ipQuery() *Provider {
	return &Provider{
		Name:     "IPQuery",
		Homepage: "https://ipquery.io/",
		Kind:     "online",
		Limit:    NewLimiter(600, 24*time.Hour, "600/天（自限）"),
		Timeout:  6 * time.Second,
		Fetch:    get("https://api.ipquery.io/{ip}?format=json", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				IP  string `json:"ip"`
				ISP *struct {
					ASN string `json:"asn"`
					Org string `json:"org"`
					ISP string `json:"isp"`
				} `json:"isp"`
				Location *struct {
					Country     string  `json:"country"`
					CountryCode string  `json:"country_code"`
					City        string  `json:"city"`
					State       string  `json:"state"`
					Zipcode     string  `json:"zipcode"`
					Latitude    float64 `json:"latitude"`
					Longitude   float64 `json:"longitude"`
					Timezone    string  `json:"timezone"`
				} `json:"location"`
				Risk *struct {
					IsMobile     *bool `json:"is_mobile"`
					IsVPN        *bool `json:"is_vpn"`
					IsTor        *bool `json:"is_tor"`
					IsProxy      *bool `json:"is_proxy"`
					IsDatacenter *bool `json:"is_datacenter"`
					RiskScore    *int  `json:"risk_score"`
				} `json:"risk"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if ip, err := netip.ParseAddr(strings.TrimSpace(d.IP)); err != nil || ip.Unmap() != q.Addr.Unmap() {
				return ErrNotFound
			}
			g := model.GeoSource{Source: "IPQuery"}
			if d.Location != nil {
				g.Country = d.Location.Country
				g.CountryCode = d.Location.CountryCode
				g.Region = d.Location.State
				g.City = d.Location.City
				g.Lat = d.Location.Latitude
				g.Lon = d.Location.Longitude
			}
			if d.ISP != nil {
				g.ASN, _ = asnOf(d.ISP.ASN)
				g.ISP = d.ISP.ISP
				g.Org = d.ISP.Org
			}
			if rsk := d.Risk; rsk != nil {
				switch {
				case rsk.IsDatacenter != nil && *rsk.IsDatacenter:
					g.Type = "hosting"
				case rsk.IsMobile != nil && *rsk.IsMobile:
					g.Type = "mobile"
				}
				for _, f := range []struct {
					on     *bool
					kind   string
					detail string
					w      int
				}{
					{rsk.IsTor, "tor", "risk.is_tor", 80},
					{rsk.IsVPN, "vpn", "risk.is_vpn", 50},
					{rsk.IsProxy, "proxy", "risk.is_proxy", 50},
					{rsk.IsDatacenter, "hosting", "risk.is_datacenter", 55},
					{rsk.IsMobile, "mobile", "risk.is_mobile", 55},
				} {
					if f.on != nil && *f.on {
						o.Signal(f.kind, "IPQuery", f.detail, f.w)
					}
				}
				if validRiskScore(rsk.RiskScore) {
					val := *rsk.RiskScore
					entry := model.Risk{Source: "IPQuery", Value: val, Detail: fmt.Sprintf("risk_score %d", val)}
					if val > 0 && val < 15 {
						zero := 0
						entry.EffectiveValue = &zero
						entry.ScoringNote = "低基线读数（<15），仅作参考不单独扣分"
					}
					o.Do(func(r *model.Result) {
						r.Risk = append(r.Risk, entry)
					})
				}
			}
			if g.Country != "" || g.CountryCode != "" || g.ASN > 0 || g.Org != "" {
				addGeo(o, g)
			}
			return nil
		},
	}
}

func blackbox() *Provider {
	return &Provider{
		Name:     "IPinfo Blackbox",
		Homepage: "https://ipinfo.app/",
		Kind:     "online",
		Limit:    NewLimiter(600, 24*time.Hour, "600/天（自限）"),
		Timeout:  6 * time.Second,
		Fetch:    get("https://blackbox.ipinfo.app/api/v3beta/{ip}", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				IP             string          `json:"ip"`
				Error          json.RawMessage `json:"error"`
				Classification string          `json:"classification"`
				Confidence     float64         `json:"confidence"`
				ASN            *struct {
					Name    string `json:"name"`
					Number  int    `json:"number"`
					Network string `json:"network"`
					CIDR    int    `json:"cidr"`
				} `json:"asn"`
				RDNS *struct {
					Hostname string `json:"hostname"`
				} `json:"rdns"`
				Signals *struct {
					Bogon     *bool `json:"bogon"`
					Cloud     *bool `json:"cloud"`
					Hosting   *bool `json:"hosting"`
					Proxy     *bool `json:"proxy"`
					Tor       *bool `json:"tor"`
					VPNASN    *bool `json:"vpnasn"`
					GoodVPN   *bool `json:"goodvpn"`
					MobileASN *bool `json:"mobileasn"`
				} `json:"signals"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if len(d.Error) > 0 && string(d.Error) != "null" {
				return ErrNotFound
			}
			if d.Signals == nil && d.Classification == "" {
				return ErrNotFound
			}
			cls := strings.ToLower(strings.TrimSpace(d.Classification))
			w := int(math.Round(35 + 30*max(0, min(1, d.Confidence))))
			switch cls {
			case "residential", "mobile", "business", "hosting":
				o.Signal(cls, "IPinfo Blackbox", fmt.Sprintf("classification=%s (%.0f%%)", cls, d.Confidence*100), w)
			case "vpn":
				o.Signal("vpn", "IPinfo Blackbox", "classification=vpn", 65)
			case "tor":
				o.Signal("tor", "IPinfo Blackbox", "classification=tor", 80)
			case "privacy_relay":
				o.Signal("icloud_relay", "IPinfo Blackbox", "classification=privacy_relay", 65)
			}
			if s := d.Signals; s != nil {
				if (s.Hosting != nil && *s.Hosting) || (s.Cloud != nil && *s.Cloud) {
					o.Signal("hosting", "IPinfo Blackbox", "signals.hosting/cloud", 55)
				}
				if s.Proxy != nil && *s.Proxy {
					o.Signal("proxy", "IPinfo Blackbox", "signals.proxy", 55)
				}
				if s.Tor != nil && *s.Tor {
					o.Signal("tor", "IPinfo Blackbox", "signals.tor", 80)
				}
				if s.VPNASN != nil && *s.VPNASN {
					o.Signal("vpn", "IPinfo Blackbox", "signals.vpnasn", 45)
				}
				if s.MobileASN != nil && *s.MobileASN && cls == "mobile" {
					o.Signal("mobile", "IPinfo Blackbox", "signals.mobileasn", 55)
				}
			}
			if d.RDNS != nil && d.RDNS.Hostname != "" {
				o.Hint("rdns:blackbox", d.RDNS.Hostname)
			}
			if d.ASN != nil && d.ASN.Network != "" && d.ASN.CIDR > 0 {
				pfx := fmt.Sprintf("%s/%d", d.ASN.Network, d.ASN.CIDR)
				if parsed, err := netip.ParsePrefix(pfx); err == nil && parsed.Contains(q.Addr.Unmap()) {
					o.Do(func(r *model.Result) {
						if r.Network.Prefix == "" {
							r.Network.Prefix = parsed.Masked().String()
						}
					})
				}
			}
			return nil
		},
	}
}

func stopForumSpam() *Provider {
	return &Provider{
		Name:     "StopForumSpam",
		Homepage: "https://www.stopforumspam.com/",
		Kind:     "online",
		V4Only:   true,
		TTL:      12 * time.Hour,
		Limit:    NewLimiter(500, 24*time.Hour, "500/天（自限）"),
		Fetch:    get("https://api.stopforumspam.org/api?ip={ip}&json", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Success int `json:"success"`
				IP      *struct {
					Appears    int     `json:"appears"`
					Frequency  int     `json:"frequency"`
					Confidence float64 `json:"confidence"`
					LastSeen   string  `json:"lastseen"`
					TorExit    int     `json:"torexit"`
				} `json:"ip"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.Success != 1 || d.IP == nil {
				return ErrNotFound
			}
			if d.IP.Appears == 0 || d.IP.Frequency <= 0 {
				o.Hint("source_note:StopForumSpam", "未见垃圾注册或灌水提交记录")
				return nil
			}
			freq := d.IP.Frequency
			last := strings.TrimSpace(d.IP.LastSeen)
			if len(last) >= 10 {
				last = last[:10]
			}
			o.Signal("abuser", "StopForumSpam", fmt.Sprintf("垃圾注册/灌水记录 %d 次", freq), min(40+freq*2, 70))
			if d.IP.TorExit > 0 {
				o.Signal("tor", "StopForumSpam", "torexit=1", 70)
			}
			o.Hint("source_note:StopForumSpam", fmt.Sprintf("命中垃圾提交记录 %d 次", freq))
			o.Do(func(r *model.Result) {
				act := ensureActivity(r)
				act.SpamReports = freq
				act.SpamLastSeen = last
			})
			return nil
		},
	}
}

func sansDShield() *Provider {
	return &Provider{
		Name:     "SANS DShield",
		Homepage: "https://isc.sans.edu/",
		Kind:     "online",
		V4Only:   true,
		TTL:      12 * time.Hour,
		Limit:    NewLimiter(400, 24*time.Hour, "400/天（自限）"),
		Fetch:    get("https://isc.sans.edu/api/ip/{ip}?json", nil),
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				IP *struct {
					Number         string                     `json:"number"`
					Count          *int                       `json:"count"`
					Attacks        *int                       `json:"attacks"`
					ASSize         *int                       `json:"assize"`
					ASAbuseContact string                     `json:"asabusecontact"`
					ThreatFeeds    map[string]json.RawMessage `json:"threatfeeds"`
				} `json:"ip"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.IP == nil || d.IP.Number == "" {
				return ErrNotFound
			}
			packets, targets, assize := 0, 0, 0
			if d.IP.Count != nil && *d.IP.Count > 0 {
				packets = *d.IP.Count
			}
			if d.IP.Attacks != nil && *d.IP.Attacks > 0 {
				targets = *d.IP.Attacks
			}
			if d.IP.ASSize != nil && *d.IP.ASSize > 0 {
				assize = *d.IP.ASSize
			}
			abuse := strings.TrimSpace(d.IP.ASAbuseContact)
			if packets == 0 && targets == 0 && abuse == "" && assize == 0 {
				return ErrNotFound
			}
			if packets >= 20 || targets >= 5 {
				o.Signal("abuser", "SANS DShield", fmt.Sprintf("蜜罐捕获 %d 包 / %d 目标", packets, targets), 55)
			}
			o.Do(func(r *model.Result) {
				if abuse != "" && r.Network.Abuse == "" {
					r.Network.Abuse = abuse
				}
				if assize > 0 && r.Network.ASIPv4Count == 0 {
					r.Network.ASIPv4Count = assize
				}
				if packets > 0 || targets > 0 {
					act := ensureActivity(r)
					act.DShieldPackets = packets
					act.DShieldTargets = targets
				}
			})
			return nil
		},
	}
}

func alienVaultOTX() *Provider {
	return &Provider{
		Name:     "AlienVault OTX",
		Homepage: "https://otx.alienvault.com/",
		Kind:     "online",
		TTL:      12 * time.Hour,
		Limit:    NewLimiter(400, 24*time.Hour, "400/天（自限）"),
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			kind := "IPv4"
			if q.Addr.Unmap().Is6() {
				kind = "IPv6"
			}
			return c.Get(ctx, "https://otx.alienvault.com/api/v1/indicators/"+kind+"/"+url.PathEscape(q.Addr.String())+"/general", nil, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				FalsePositive json.RawMessage `json:"false_positive"`
				Validation    []struct {
					Source string `json:"source"`
					Name   string `json:"name"`
				} `json:"validation"`
				PulseInfo *struct {
					Count  int `json:"count"`
					Pulses []struct {
						Name string `json:"name"`
					} `json:"pulses"`
				} `json:"pulse_info"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.PulseInfo == nil || d.PulseInfo.Count <= 0 {
				return ErrNotFound
			}
			if otxFalsePositive(d.FalsePositive) {
				o.Hint("source_note:AlienVault OTX", "来源已标注误报/白名单，忽略脉冲计数")
				return nil
			}
			for _, v := range d.Validation {
				txt := strings.ToLower(v.Source + " " + v.Name)
				for _, kw := range []string{"whitelist", "alexa", "majestic", "akamai", "cloudflare", "google", "false"} {
					if strings.Contains(txt, kw) {
						o.Hint("source_note:AlienVault OTX", "命中良性基础设施白名单校验，不计为威胁")
						return nil
					}
				}
			}
			count := d.PulseInfo.Count
			var names []string
			for _, p := range d.PulseInfo.Pulses {
				if n := strings.TrimSpace(p.Name); n != "" && len(names) < 4 {
					names = append(names, n)
				}
			}
			if count >= 3 {
				o.Signal("abuser", "AlienVault OTX", fmt.Sprintf("关联 %d 条威胁脉冲", count), 45)
			}
			o.Do(func(r *model.Result) {
				act := ensureActivity(r)
				act.OTXPulses = count
				act.OTXNames = names
			})
			return nil
		},
	}
}

func otxFalsePositive(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "false" || s == "[]" {
		return false
	}
	if s == "true" {
		return true
	}
	var arr []struct {
		Assessment string `json:"assessment"`
	}
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, item := range arr {
			if item.Assessment == "" || strings.EqualFold(item.Assessment, "accepted") {
				return true
			}
		}
		return false
	}
	return false
}

func torOnionoo() *Provider {
	return &Provider{
		Name:     "Tor Onionoo",
		Homepage: "https://metrics.torproject.org/onionoo.html",
		Kind:     "online",
		TTL:      6 * time.Hour,
		Limit:    NewLimiter(400, 24*time.Hour, "400/天（自限）"),
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			a := q.Addr.Unmap()
			search := a.String()
			if a.Is4() {
				b := a.As4()
				search = fmt.Sprintf("%d.%d.%d.", b[0], b[1], b[2])
			}
			u := "https://onionoo.torproject.org/details?search=" + url.QueryEscape(search) +
				"&fields=nickname,or_addresses,exit_addresses,flags,running"
			return c.Get(ctx, u, nil, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Relays []struct {
					Nickname      string   `json:"nickname"`
					ORAddresses   []string `json:"or_addresses"`
					ExitAddresses []string `json:"exit_addresses"`
					Flags         []string `json:"flags"`
				} `json:"relays"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if len(d.Relays) == 0 {
				return ErrNotFound
			}
			target := q.Addr.Unmap()
			v4Prefix := ""
			if target.Is4() {
				b := target.As4()
				v4Prefix = fmt.Sprintf("%d.%d.%d.", b[0], b[1], b[2])
			}
			stripHost := func(s string) (netip.Addr, bool) {
				s = strings.TrimSpace(s)
				if ap, err := netip.ParseAddrPort(s); err == nil {
					return ap.Addr().Unmap(), true
				}
				s = strings.Trim(s, "[]")
				if a, err := netip.ParseAddr(s); err == nil {
					return a.Unmap(), true
				}
				return netip.Addr{}, false
			}
			isRelay, isExit := false, false
			var nicks []string
			neighbors := 0
			for _, rel := range d.Relays {
				matchedSelf, matchedNeighbor := false, false
				for _, ea := range rel.ExitAddresses {
					if a, ok := stripHost(ea); ok {
						if a == target {
							matchedSelf, isExit = true, true
						} else if v4Prefix != "" && strings.HasPrefix(a.String(), v4Prefix) {
							matchedNeighbor = true
						}
					}
				}
				for _, oa := range rel.ORAddresses {
					if a, ok := stripHost(oa); ok {
						if a == target {
							matchedSelf = true
						} else if v4Prefix != "" && strings.HasPrefix(a.String(), v4Prefix) {
							matchedNeighbor = true
						}
					}
				}
				if matchedSelf {
					isRelay = true
					for _, f := range rel.Flags {
						if f == "Exit" {
							isExit = true
						}
					}
					if rel.Nickname != "" && len(nicks) < 3 {
						nicks = append(nicks, rel.Nickname)
					}
				} else if matchedNeighbor {
					neighbors++
				}
			}
			if !isRelay && neighbors == 0 {
				return ErrNotFound
			}
			if isExit {
				o.Signal("tor", "Tor Onionoo", "Tor Exit "+strings.Join(nicks, ","), 90)
			}
			o.Do(func(r *model.Result) {
				act := ensureActivity(r)
				act.TorRelay = isRelay
				act.TorExit = isExit
				act.TorNicknames = nicks
				act.TorNeighbors = neighbors
			})
			return nil
		},
	}
}

type cfRadarCombined struct {
	BotRaw    json.RawMessage `json:"bot"`
	DeviceRaw json.RawMessage `json:"device,omitempty"`
}

func cloudflareRadar(token string) *Provider {
	token = strings.TrimSpace(token)
	return &Provider{
		Name:     "Cloudflare Radar",
		Homepage: "https://radar.cloudflare.com/",
		Kind:     "online",
		Keyed:    true,
		NeedASN:  true,
		After:    true,
		TTL:      12 * time.Hour,
		Timeout:  7 * time.Second,
		Key:      asKey,
		Limit:    NewLimiter(500, time.Hour, "500/小时（按 ASN 缓存 12h）"),
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			if token == "" {
				return nil, errors.New("Cloudflare Radar token is not configured")
			}
			hdr := map[string]string{"Authorization": "Bearer " + token}
			asn := strconv.Itoa(q.ASN)
			base := "https://api.cloudflare.com/client/v4/radar/http/summary/"
			botURL := base + "bot_class?asn=" + asn + "&dateRange=7d&format=json"
			devURL := base + "device_type?asn=" + asn + "&dateRange=7d&format=json"

			var botBody, devBody []byte
			var botErr error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				botBody, botErr = c.Get(ctx, botURL, hdr, false)
			}()
			go func() {
				defer wg.Done()
				devBody, _ = c.Get(ctx, devURL, hdr, false)
			}()
			wg.Wait()
			if botErr != nil {
				msg := strings.ReplaceAll(botErr.Error(), token, "[redacted]")
				switch {
				case errors.Is(botErr, ErrQuota):
					return nil, ErrQuota
				case errors.Is(botErr, ErrNotFound):
					return nil, ErrNotFound
				case msg == "HTTP 401" || msg == "HTTP 403":
					return nil, errors.New("Cloudflare Radar authentication failed (" + msg + ")")
				}
				return nil, errors.New(msg)
			}
			out := cfRadarCombined{BotRaw: botBody}
			if json.Valid(devBody) {
				out.DeviceRaw = devBody
			}
			return json.Marshal(out)
		},
		Apply: applyCloudflareRadar,
	}
}

func applyCloudflareRadar(o *Out, q Query, raw []byte) error {
	var combo cfRadarCombined
	if err := json.Unmarshal(raw, &combo); err != nil || len(combo.BotRaw) == 0 {
		// Also accept a plain bot_class JSON document directly for flexibility in tests.
		combo.BotRaw = raw
	}
	summary := parseRadarSummary(combo.BotRaw)
	if len(summary) == 0 {
		return ErrNotFound
	}
	human, hasHuman := pickRadarPct(summary, "human", "likely_human")
	bot, hasBot := pickRadarPct(summary, "bot", "likely_automated", "automated")
	if !hasHuman && !hasBot {
		return ErrNotFound
	}
	if !hasHuman {
		human = max(0, 100-bot)
	} else if !hasBot {
		bot = max(0, 100-human)
	}
	total := human + bot
	if total <= 0 {
		return ErrNotFound
	}
	humanPct := math.Round((human/total)*1000) / 10
	botPct := math.Round((100-humanPct)*10) / 10

	lvl, tone := classify.TrafficLevelAndTone(humanPct, botPct)
	tr := &model.Traffic{
		Mode:     "radar",
		Source:   "Cloudflare Radar",
		Window:   "7d",
		ASN:      q.ASN,
		HumanPct: humanPct,
		BotPct:   botPct,
		Level:    lvl,
		Tone:     tone,
		Note:     fmt.Sprintf("Cloudflare Radar 观测 AS%d 近 7 天 HTTP 请求人机占比", q.ASN),
	}
	if len(combo.DeviceRaw) > 0 {
		dev := parseRadarSummary(combo.DeviceRaw)
		d, okD := pickRadarPct(dev, "desktop")
		m, okM := pickRadarPct(dev, "mobile")
		ot, okO := pickRadarPct(dev, "other")
		if okD || okM {
			d = math.Round(d*10) / 10
			m = math.Round(m*10) / 10
			tr.DesktopPct, tr.MobilePct = &d, &m
			if okO && ot > 0 {
				ot = math.Round(ot*10) / 10
				tr.OtherPct = &ot
			}
		}
	}
	o.Do(func(r *model.Result) {
		r.Traffic = tr
	})
	return nil
}

func parseRadarSummary(raw []byte) map[string]float64 {
	var doc struct {
		Success bool `json:"success"`
		Result  struct {
			Summary0 map[string]any `json:"summary_0"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &doc) != nil || !doc.Success || len(doc.Result.Summary0) == 0 {
		return nil
	}
	out := map[string]float64{}
	for k, v := range doc.Result.Summary0 {
		key := strings.ToLower(strings.TrimSpace(k))
		switch val := v.(type) {
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 {
				out[key] = f
			}
		case float64:
			if !math.IsNaN(val) && !math.IsInf(val, 0) && val >= 0 {
				out[key] = val
			}
		}
	}
	return out
}

func pickRadarPct(m map[string]float64, keys ...string) (float64, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v, true
		}
	}
	return 0, false
}
