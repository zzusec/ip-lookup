package lookup

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
	"github.com/zzusec/ip-lookup/internal/sources"
)

// categoryWeight is the evidence a list hit gives when the spec sets none.
var categoryWeight = map[string]int{
	"tor": 100, "vpn": 70, "proxy": 70, "icloud_relay": 100, "hosting": 70, "cdn": 80,
	"crawler": 90, "public_service": 90, "abuse": 60,
}

// lists records every list containing a and turns category hits into signals.
func (s *Service) lists(o *sources.Out, a netip.Addr) {
	r := o.Res
	for _, h := range s.Data.Lists(a) {
		match := h.Prefix.String()
		if h.Prefix.IsSingleIP() {
			match = h.Prefix.Addr().String()
		}
		r.Lists = append(r.Lists, model.ListHit{List: h.Spec.ID, Label: h.Spec.Label, Category: h.Spec.Category,
			Match: match, Detail: h.Detail})
		kind := h.Spec.Category
		if kind == "abuse" {
			kind = "abuser"
		}
		w := h.Spec.Weight
		if w == 0 {
			w = categoryWeight[h.Spec.Category]
		}
		if w > 0 {
			o.Signal(kind, h.Spec.Label, strings.TrimSpace(match+" "+h.Detail), w)
		}
	}
}

// asSignals adds what the AS-level datasets say about the origin AS.
func (s *Service) asSignals(o *sources.Out, asn int) {
	if asn <= 0 {
		return
	}
	class, tags, drop, dropped := s.Data.ASLookup(uint32(asn))
	r := o.Res
	r.Network.ASClass = class
	slices.Sort(tags)
	r.Network.ASTags = tags
	if k, w := classify.ASClass(class); k != "" {
		o.Signal(k, "bgp.tools AS 分类", class, w)
	}
	for _, t := range tags {
		if m, ok := classify.ASTags[t]; ok {
			o.Signal(m.Kind, "bgp.tools 标签", t, m.Weight)
		}
	}
	if dropped {
		r.Lists = append(r.Lists, model.ListHit{List: "spamhaus-asndrop", Label: "Spamhaus ASN-DROP", Category: "abuse",
			Match: "AS" + itoa(asn), Detail: drop})
		o.Signal("abuser", "Spamhaus ASN-DROP", "AS"+itoa(asn), 70)
	}
}
