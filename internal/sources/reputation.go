package sources

import (
	"encoding/json"
	"net/netip"
)

// reputationSource declares a provider's capability, independently of whether
// its response for one address includes any reputation evidence.
func reputationSource(name string) bool {
	switch name {
	case "ip-api.com", "ipapi.is", "ipinfo.io", "proxycheck.io", "ipyou.net", "GreyNoise":
		return true
	default:
		return false
	}
}

// reputationData only counts explicit, correctly typed reputation fields.
// Callers also require Apply to succeed before using this evidence.
func reputationData(name string, raw []byte, addr netip.Addr) bool {
	if !reputationSource(name) {
		return false
	}
	top := reputationObject(raw)
	switch name {
	case "ip-api.com":
		return reputationBool(top, "proxy", "hosting")
	case "ipapi.is":
		return reputationBool(top, "is_vpn", "is_proxy", "is_tor", "is_abuser", "is_datacenter", "is_crawler")
	case "ipinfo.io":
		return reputationBool(reputationObject(top["privacy"]), "vpn", "proxy", "tor", "relay", "hosting")
	case "proxycheck.io":
		body := reputationObject(top[addr.String()])
		detections := reputationObject(body["detections"])
		return reputationBool(detections, "proxy", "vpn", "tor", "hosting", "compromised", "scraper", "anonymous") ||
			reputationRisk(detections["risk"])
	case "ipyou.net":
		intel := reputationObject(top["intel_summary"])
		return reputationBool(intel, "is_proxy", "is_vpn", "is_tor", "is_bot", "is_hosting", "is_abuser") ||
			reputationRisk(reputationObject(top["ip_score"])["score"])
	case "GreyNoise":
		var riot *bool
		if json.Unmarshal(top["riot"], &riot) == nil && riot != nil && *riot {
			return true
		}
		var classification string
		if json.Unmarshal(top["classification"], &classification) != nil {
			return false
		}
		switch classification {
		case "malicious", "unknown", "benign":
			return reputationBool(top, "noise", "riot")
		}
	}
	return false
}

func reputationObject(raw []byte) map[string]json.RawMessage {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	return object
}

func reputationBool(object map[string]json.RawMessage, fields ...string) bool {
	for _, field := range fields {
		var value *bool
		if json.Unmarshal(object[field], &value) == nil && value != nil {
			return true // explicit false is also evidence
		}
	}
	return false
}

func reputationRisk(raw []byte) bool {
	var value *int
	return json.Unmarshal(raw, &value) == nil && validRiskScore(value)
}

func validRiskScore(value *int) bool {
	return value != nil && *value >= 0 && *value <= 100
}
