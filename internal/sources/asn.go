package sources

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

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
