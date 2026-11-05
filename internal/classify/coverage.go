package classify

import (
	"strings"

	"github.com/zzusec/ip-lookup/internal/model"
)

// Coverage describes evidence availability, not a probability of safety.
// Preserve the numeric formula for API compatibility; consumers must show an
// unknown assessment when DataStatus is unavailable, rather than its base 100.
func scoreCoverage(r *model.Result, hasDeductions bool) (string, *model.ScoreCoverage) {
	expected, received := map[string]bool{}, map[string]bool{}
	for _, source := range r.Sources {
		if source.ReputationSource {
			expected[source.Name] = true
		}
		if source.Reputation && source.Status == "ok" {
			expected[source.Name], received[source.Name] = true, true
		}
	}
	for _, risk := range r.Risk {
		if risk.Source == "" || risk.Value < 0 || risk.Value > 100 {
			continue
		}
		name := risk.Source
		// IP2Proxy via ipyou is one provider, not an independent second check.
		if strings.Contains(name, "经 ipyou.net") {
			name = "ipyou.net"
		}
		expected[name], received[name] = true, true
	}
	c := &model.ScoreCoverage{Received: len(received), Total: len(expected)}
	if c.Received == 0 && !hasDeductions {
		return "unavailable", c
	}
	if c.Received >= 2 && c.Received == c.Total && r.Mode != "fast" {
		return "complete", c
	}
	return "limited", c
}
