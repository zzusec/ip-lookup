package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
)

type rdapEntity struct {
	Handle   string          `json:"handle"`
	Roles    []string        `json:"roles"`
	VCard    json.RawMessage `json:"vcardArray"`
	Entities []rdapEntity    `json:"entities"`
}

// vcard pulls fn, kind and the first e-mail out of a jCard array.
func (e rdapEntity) vcard() (fn, kind, email string) {
	var arr []json.RawMessage
	if json.Unmarshal(e.VCard, &arr) != nil || len(arr) < 2 {
		return
	}
	var props [][]json.RawMessage
	json.Unmarshal(arr[1], &props)
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name, val string
		json.Unmarshal(p[0], &name)
		if json.Unmarshal(p[3], &val) != nil {
			continue
		}
		switch {
		case name == "fn" && fn == "":
			fn = val
		case name == "kind" && kind == "":
			kind = val
		case name == "email" && email == "":
			email = val
		}
	}
	return
}

// walk visits e and its nested entities depth first.
func (e rdapEntity) walk(f func(rdapEntity)) {
	f(e)
	for _, c := range e.Entities {
		c.walk(f)
	}
}

func rdap() *Provider {
	return &Provider{Name: "RDAP", Homepage: "https://about.rdap.org/", Kind: "online", Timeout: 8 * time.Second,
		TTL: 24 * time.Hour,
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			return c.Get(ctx, "https://rdap.org/ip/"+q.Addr.String(), map[string]string{"Accept": "application/rdap+json"}, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Handle, Name, Type, Country, Port43 string
				StartAddress                        string `json:"startAddress"`
				EndAddress                          string `json:"endAddress"`
				Events                              []struct {
					Action string `json:"eventAction"`
					Date   string `json:"eventDate"`
				}
				CIDRs []struct {
					V4     string `json:"v4prefix"`
					V6     string `json:"v6prefix"`
					Length int    `json:"length"`
				} `json:"cidr0_cidrs"`
				Entities []rdapEntity
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if d.StartAddress == "" && d.Name == "" {
				return ErrNotFound
			}
			var org, abuse string
			for _, top := range d.Entities {
				top.walk(func(e rdapEntity) {
					fn, kind, email := e.vcard()
					for _, r := range e.Roles {
						switch {
						case r == "registrant" && org == "" && kind == "org":
							org = fn
						case r == "abuse" && abuse == "" && email != "":
							abuse = email
						}
					}
				})
			}
			reg := registryFromWhois(d.Port43)
			o.Hint("reg_cc:rdap", d.Country)
			o.Hint("registry:rdap", reg)
			o.Do(func(r *model.Result) {
				n := &r.Network
				n.NetName = d.Name
				if d.StartAddress != "" {
					n.NetRange = d.StartAddress + " - " + d.EndAddress
				}
				if len(d.CIDRs) > 0 && n.Prefix == "" {
					c := d.CIDRs[0]
					n.Prefix = c.V4 + c.V6 + "/" + strconv.Itoa(c.Length)
				}
				if n.Registry == "" {
					n.Registry = reg
				}
				if org != "" && n.Org == "" {
					n.Org = org
				}
				n.Abuse = abuse
				for _, ev := range d.Events {
					if ev.Action == "registration" && n.Allocated == "" && len(ev.Date) >= 10 {
						n.Allocated = ev.Date[:10]
					}
				}
			})
			if k := rdapType(d.Type, org); k != "" {
				o.Signal(k, "RDAP", d.Type+" "+org, 30)
			}
			return nil
		}}
}

func registryFromWhois(port43 string) string {
	for _, r := range []string{"arin", "ripe", "apnic", "lacnic", "afrinic"} {
		if strings.Contains(port43, r) {
			return r
		}
	}
	return ""
}

// rdapType reads hints such as "Private Customer" registrants; most RDAP
// answers say nothing about the network type.
func rdapType(typ, org string) string {
	switch l := strings.ToLower(org); {
	case strings.Contains(l, "private customer"), strings.Contains(l, "private residence"):
		return "hosting" // ARIN reassignments of hosting providers use this placeholder
	}
	return classify.ProviderType(typ)
}

func ripeURL(endpoint, resource string, extra url.Values) string {
	v := url.Values{"resource": {resource}, "sourceapp": {"ip-lookup"}}
	for k, x := range extra {
		v[k] = x
	}
	return "https://stat.ripe.net/data/" + endpoint + "/data.json?" + v.Encode()
}

func ripeRPKI() *Provider {
	return &Provider{Name: "RIPEstat RPKI", Homepage: "https://stat.ripe.net/", Kind: "online", Timeout: 8 * time.Second,
		TTL: 12 * time.Hour, NeedASN: true, After: true,
		Key: func(q Query) string { return fmt.Sprintf("AS%d|%s", q.ASN, q.Prefix) },
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			if !q.Prefix.IsValid() {
				return nil, ErrNotFound
			}
			return c.Get(ctx, ripeURL("rpki-validation", "AS"+strconv.Itoa(q.ASN), url.Values{"prefix": {q.Prefix.String()}}), nil, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Data struct {
					Status         string
					ValidatingROAs []struct {
						Origin    string
						Prefix    string
						MaxLength int `json:"max_length"`
					} `json:"validating_roas"`
				}
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			label := map[string]string{"valid": "有效", "invalid": "无效", "unknown": "未签名 ROA", "invalid_asn": "无效（AS 不符）",
				"invalid_length": "无效（前缀长度不符）"}[strings.ToLower(d.Data.Status)]
			if label == "" {
				label = d.Data.Status
			}
			o.Do(func(r *model.Result) { r.Network.RPKI = label })
			return nil
		}}
}

func ripeRouting() *Provider {
	return &Provider{Name: "RIPEstat 可见度", Homepage: "https://stat.ripe.net/", Kind: "online", Timeout: 8 * time.Second,
		TTL: 12 * time.Hour,
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			return c.Get(ctx, ripeURL("routing-status", q.Addr.String(), nil), nil, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			type vis struct {
				Seeing int `json:"ris_peers_seeing"`
				Total  int `json:"total_ris_peers"`
			}
			var d struct {
				Data struct {
					Resource   string
					FirstSeen  struct{ Time string } `json:"first_seen"`
					Visibility struct{ V4, V6 vis }
					Origins    []struct{ Origin int }
				}
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			v := d.Data.Visibility.V4
			if q.Addr.Unmap().Is6() {
				v = d.Data.Visibility.V6
			}
			if v.Total == 0 || d.Data.Resource == "" {
				return ErrNotFound
			}
			text := fmt.Sprintf("%d/%d 个 RIS 对等点可见", v.Seeing, v.Total)
			if t := d.Data.FirstSeen.Time; len(t) >= 10 {
				text += "，首次出现 " + t[:10]
			}
			o.Hint("bgp_prefix:ripe", d.Data.Resource)
			if len(d.Data.Origins) > 0 {
				o.Hint("origin_asn:ripe", strconv.Itoa(d.Data.Origins[0].Origin))
			}
			o.Do(func(r *model.Result) {
				r.Network.Visibility = text
				r.Network.BGPPrefix = d.Data.Resource
				if len(d.Data.Origins) > 0 && r.Network.ASN == 0 {
					r.Network.ASN = d.Data.Origins[0].Origin
				}
			})
			return nil
		}}
}

func ripeRIR() *Provider {
	return &Provider{Name: "RIPEstat RIR 统计", Homepage: "https://stat.ripe.net/", Kind: "online", Timeout: 8 * time.Second,
		TTL: 24 * time.Hour,
		Fetch: func(ctx context.Context, c *Client, q Query) ([]byte, error) {
			return c.Get(ctx, ripeURL("rir-stats-country", q.Addr.String(), nil), nil, false)
		},
		Apply: func(o *Out, q Query, raw []byte) error {
			var d struct {
				Data struct {
					Located []struct{ Resource, Location string } `json:"located_resources"`
				}
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if len(d.Data.Located) == 0 || d.Data.Located[0].Location == "" {
				return ErrNotFound
			}
			o.Hint("reg_cc:rir", d.Data.Located[0].Location)
			return nil
		}}
}
