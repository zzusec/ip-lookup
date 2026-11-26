package classify

import (
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

func TestDetectLeaseAndAuditFlow(t *testing.T) {
	lease := DetectLease("Example ISP", "IPXO LLC sub-allocation")
	if !lease.Leased || lease.Broker != "IPXO" {
		t.Fatalf("expected IPXO lease hit, got %+v", lease)
	}
	borrower := DetectLease("Verizon Business", "PF IPV4 Borrower, LLC")
	if !borrower.Leased || borrower.Broker != "PF IPv4 Borrower" {
		t.Fatalf("expected PF IPv4 Borrower lease hit, got %+v", borrower)
	}
	clean := DetectLease("China Telecom", "CHINANET-BACKBONE")
	if clean.Leased {
		t.Fatalf("unexpected lease hit: %+v", clean)
	}

	// Claimed residential ISP with Heavy Outbound traffic -> masquerade warning.
	flow := AuditFlow(
		model.Verdict{Type: "residential"},
		model.Flags{Residential: true},
		&model.PeeringDB{InfoRatio: "Heavy Outbound"},
		clean,
	)
	if flow == nil || !flow.Masquerade {
		t.Fatalf("expected masquerade on residential + Heavy Outbound, got %+v", flow)
	}

	// Leased block announced under Mostly Inbound ISP -> lease noted, not outbound masquerade.
	leasedInbound := AuditFlow(
		model.Verdict{Type: "residential", Usage: []string{"leased"}},
		model.Flags{Residential: true, Leased: true},
		&model.PeeringDB{InfoRatio: "Mostly Inbound"},
		borrower,
	)
	if leasedInbound == nil || leasedInbound.Masquerade || leasedInbound.Detail == "" {
		t.Fatalf("expected non-masquerade lease note on Mostly Inbound ISP, got %+v", leasedInbound)
	}

	// Normal residential with Mostly Inbound -> clean.
	normalFlow := AuditFlow(
		model.Verdict{Type: "residential"},
		model.Flags{Residential: true},
		&model.PeeringDB{InfoRatio: "Mostly Inbound"},
		clean,
	)
	if normalFlow == nil || normalFlow.Masquerade {
		t.Fatalf("unexpected masquerade on Mostly Inbound: %+v", normalFlow)
	}
}

func TestBuildTrafficModes(t *testing.T) {
	devDesk, devMob := 62.5, 37.5
	radarIn := &model.Traffic{
		Mode:       "radar",
		Source:     "Cloudflare Radar",
		Window:     "7d",
		ASN:        13335,
		HumanPct:   78.4,
		BotPct:     21.6,
		DesktopPct: &devDesk,
		MobilePct:  &devMob,
	}
	r := &model.Result{
		IP:      "1.1.1.1",
		Mode:    "full",
		Verdict: model.Verdict{Type: "cdn"},
		Flags:   model.Flags{CDN: true, Crawler: true},
		Network: model.Network{ASN: 13335},
	}
	probe := &model.RequestProbe{Verdict: "human_browser", Label: "标准浏览器真人交互", HumanShare: 96, AutomationShare: 4}
	gotRadar := BuildTraffic(r, radarIn, probe)
	if gotRadar == nil || gotRadar.Mode != "radar" || gotRadar.Level != "真人主导" || gotRadar.RequestProbe == nil || len(gotRadar.BotSignals) == 0 {
		t.Fatalf("unexpected radar traffic: %+v", gotRadar)
	}

	// Estimated residential vs hosting+spam comparison.
	resIP := &model.Result{
		IP:      "203.0.113.5",
		Mode:    "full",
		Verdict: model.Verdict{Type: "residential"},
		Flags:   model.Flags{Residential: true},
		Score:   model.Score{DataStatus: "complete"},
		Network: model.Network{ASN: 4134},
	}
	trRes := BuildTraffic(resIP, nil, nil)
	if trRes == nil || trRes.Mode != "estimated" || trRes.HumanPct < 85 || trRes.Level != "真人主导" {
		t.Fatalf("residential traffic estimate = %+v", trRes)
	}

	botIP := &model.Result{
		IP:      "198.51.100.9",
		Mode:    "full",
		Verdict: model.Verdict{Type: "hosting"},
		Flags:   model.Flags{Hosting: true, Proxy: true, Abuser: true, Leased: true},
		Score:   model.Score{DataStatus: "complete"},
		Audit: &model.NetworkAudit{
			Neighbor: &model.NeighborDensity{Prefix: "198.51.100.0/24", Flagged: 40, Total: 256, DensityPct: 15.6},
			Flow:     &model.FlowAudit{TrafficRatio: "Heavy Outbound"},
			Activity: &model.ThreatActivity{SpamReports: 25, DShieldPackets: 200},
		},
	}
	trBot := BuildTraffic(botIP, nil, nil)
	if trBot == nil || trBot.Mode != "estimated" || trBot.BotPct < 80 || trBot.Level != "高度自动化" {
		t.Fatalf("bot hosting traffic estimate = %+v", trBot)
	}

	// Score includes lease, masquerade and dirty /24 deductions when present.
	botIP.Audit.Flow.Masquerade = true
	sc := Score(botIP)
	if sc.Value >= 30 || sc.Tone != "bad" {
		t.Fatalf("expected heavy deductions on leased masquerading dirty /24, got %+v", sc)
	}

	// Verify 62-point score maps to amber ("一般", "fair"), never green ("良好"/"good").
	lvl62, tone62 := LevelAndTone(62)
	if lvl62 != "一般" || tone62 != "fair" {
		t.Fatalf("62 score mapped to %s/%s, want 一般/fair", lvl62, tone62)
	}
	lvl80, tone80 := LevelAndTone(80)
	if lvl80 != "纯净" || tone80 != "good" {
		t.Fatalf("80 score mapped to %s/%s, want 纯净/good", lvl80, tone80)
	}

	// Scenarios and threat summaries populate on full lookups.
	PopulateThreatAndScenarios(resIP)
	resIP.Audit = &model.NetworkAudit{}
	PopulateThreatAndScenarios(resIP)
	if len(resIP.Audit.Scenarios) != 4 || resIP.Audit.AbuseLevel == "" || resIP.Audit.RiskTone != "good" {
		t.Fatalf("scenarios / threat summary missing: %+v", resIP.Audit)
	}
}
