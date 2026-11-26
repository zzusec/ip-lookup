package sources

import (
	"context"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/zzusec/ip-lookup/internal/cidr"
	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
)

func asKey(q Query) string { return "AS" + strconv.Itoa(q.ASN) }

func peeringDB() *Provider {
	return &Provider{Name: "PeeringDB", Homepage: "https://www.peeringdb.com/", Kind: "online", NeedASN: true,
		Timeout: 8 * time.Second, TTL: 7 * 24 * time.Hour, Key: asKey,
		Limit: NewLimiter(18, time.Minute, "20/分钟（匿名）"),
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			return c.Get(ctx, "https://www.peeringdb.com/api/net?asn="+strconv.Itoa(q.ASN), nil, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Data []struct {
					Name, Website, Policy string
					IRRASSet              string   `json:"irr_as_set"`
					InfoType              string   `json:"info_type"`
					InfoTypes             []string `json:"info_types"`
					InfoTraffic           string   `json:"info_traffic"`
					InfoRatio             string   `json:"info_ratio"`
					InfoScope             string   `json:"info_scope"`
					PolicyGeneral         string   `json:"policy_general"`
					IXCount               int      `json:"ix_count"`
					FacCount              int      `json:"fac_count"`
				}
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if len(d.Data) == 0 {
				return ErrNotFound
			}
			n := d.Data[0]
			types := n.InfoTypes
			if len(types) == 0 && n.InfoType != "" {
				types = []string{n.InfoType}
			}
			for _, t := range types {
				if m, ok := classify.PeeringDBTypes[t]; ok {
					o.Signal(m.Kind, "PeeringDB", "info_type="+t, m.Weight)
				}
			}
			o.Do(func(r *model.Result) {
				r.Network.PeeringDB = &model.PeeringDB{Name: n.Name, InfoType: strings.Join(types, ", "),
					InfoTraffic: n.InfoTraffic, InfoScope: n.InfoScope, InfoRatio: n.InfoRatio, Website: n.Website,
					IRRASSet: n.IRRASSet, Policy: n.PolicyGeneral, IXCount: n.IXCount, FacCount: n.FacCount}
			})
			return nil
		}}
}

// rdapASN fetches AS registration date and registrant metadata from RDAP autnum.
func rdapASN() *Provider {
	return &Provider{
		Name:     "RDAP ASN",
		Homepage: "https://about.rdap.org/",
		Kind:     "online",
		NeedASN:  true,
		After:    true,
		Timeout:  6 * time.Second,
		TTL:      7 * 24 * time.Hour,
		Key:      asKey,
		Limit:    NewLimiter(60, time.Minute, "60/分钟（按 ASN 缓存 7d）"),
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			return c.Get(ctx, "https://rdap.org/autnum/"+strconv.Itoa(q.ASN), map[string]string{"Accept": "application/rdap+json"}, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Name     string `json:"name"`
				Country  string `json:"country"`
				Port43   string `json:"port43"`
				Events   []struct {
					Action string `json:"eventAction"`
					Date   string `json:"eventDate"`
				} `json:"events"`
				Entities []rdapEntity `json:"entities"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			created := ""
			for _, ev := range d.Events {
				if ev.Action == "registration" && len(ev.Date) >= 10 {
					created = ev.Date[:10]
					break
				}
			}
			var org string
			for _, top := range d.Entities {
				top.walk(func(e rdapEntity) {
					fn, kind, _ := e.vcard()
					for _, role := range e.Roles {
						if role == "registrant" && org == "" && (kind == "org" || fn != "") {
							org = fn
						}
					}
				})
			}
			if created == "" && org == "" && d.Name == "" {
				return ErrNotFound
			}
			reg := registryFromWhois(d.Port43)
			o.Do(func(r *model.Result) {
				n := &r.Network
				if created != "" && n.ASCreated == "" {
					n.ASCreated = created
				}
				if org != "" && n.Registrant == "" {
					n.Registrant = org
				}
				if d.Country != "" && n.ASCountry == "" {
					n.ASCountry = strings.ToUpper(strings.TrimSpace(d.Country))
				}
				if reg != "" && n.Registry == "" {
					n.Registry = reg
				}
			})
			return nil
		},
	}
}

// asnSpace computes exact deduplicated IPv4 address space and announced prefix
// counts for the origin AS via RIPEstat announced-prefixes.
func asnSpace() *Provider {
	return &Provider{
		Name:     "RIPEstat AS 规模",
		Homepage: "https://stat.ripe.net/",
		Kind:     "online",
		NeedASN:  true,
		After:    true,
		Timeout:  7 * time.Second,
		TTL:      24 * time.Hour,
		Key:      asKey,
		Limit:    NewLimiter(60, time.Minute, "60/分钟（按 ASN 缓存 24h）"),
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			return c.Get(ctx, ripeURL("announced-prefixes", "AS"+strconv.Itoa(q.ASN), nil), nil, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Data struct {
					Prefixes []struct {
						Prefix string `json:"prefix"`
					} `json:"prefixes"`
				} `json:"data"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if len(d.Data.Prefixes) == 0 {
				return ErrNotFound
			}
			b := cidr.NewBuilder()
			v4Count, v6Count := 0, 0
			for _, item := range d.Data.Prefixes {
				pfx, err := netip.ParsePrefix(strings.TrimSpace(item.Prefix))
				if err != nil || pfx.Bits() == 0 {
					continue
				}
				if pfx.Addr().Unmap().Is4() {
					v4Count++
					b.Add(pfx, "")
				} else {
					v6Count++
				}
			}
			v4IPs := 0
			if v4Count > 0 {
				v4IPs, _ = cidr.UnionCountInPrefix([]*cidr.Set{b.Build()}, netip.MustParsePrefix("0.0.0.0/0"))
			}
			o.Do(func(r *model.Result) {
				n := &r.Network
				if v4IPs > 0 {
					n.ASIPv4Count = v4IPs
				}
				n.ASPrefixesV4 = v4Count
				n.ASPrefixesV6 = v6Count
			})
			return nil
		},
	}
}
