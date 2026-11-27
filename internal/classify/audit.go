package classify

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/zzusec/ip-lookup/internal/model"
)

var leaseBrokers = []struct {
	match string
	label string
}{
	{"ipxo", "IPXO"},
	{"interlir", "InterLIR"},
	{"cloud innovation", "Cloud Innovation"},
	{"larus", "LARUS"},
	{"heficed", "Heficed"},
	{"ipbroker", "IPBroker"},
	{"internet utilities", "Internet Utilities"},
	{"ip-volume", "IP Volume"},
	{"ipvolume", "IP Volume"},
	{"ipv4.global", "IPv4.Global"},
	{"ipv4 borrower", "PF IPv4 Borrower"},
	{"borrower, llc", "IPv4 Borrower"},
	{"packetfabric", "PacketFabric"},
	{"unitas global", "Unitas Global"},
	{"ipv4 mall", "IPv4 Mall"},
	{"ipv4 market", "IPv4 Market"},
	{"logicweb", "LogicWeb"},
}

// DetectLease inspects RDAP / ASN / ISP / NetName strings for commercial IP
// leasing brokers whose blocks are frequently sub-allocated to proxy/VPS pools.
func DetectLease(texts ...string) *model.LeaseCheck {
	hasName := false
	for _, raw := range texts {
		low := strings.ToLower(strings.TrimSpace(raw))
		if low == "" {
			continue
		}
		hasName = true
		for _, b := range leaseBrokers {
			if strings.Contains(low, b.match) {
				return &model.LeaseCheck{
					Leased: true,
					Broker: b.label,
					Detail: fmt.Sprintf("注册或运营信息命中商业地址租赁平台 %s（%s）", b.label, strings.TrimSpace(raw)),
				}
			}
		}
	}
	if !hasName {
		return &model.LeaseCheck{Detail: "缺少可核验的注册或运营名称"}
	}
	return &model.LeaseCheck{Leased: false, Detail: "未命中已知商业 IP 租赁经纪商"}
}

var ratioLabels = map[string]string{
	"Heavy Inbound":   "重度入向（典型宽带终端特征）",
	"Mostly Inbound":  "入向为主（终端接入特征）",
	"Balanced":        "入出均衡（混合网络）",
	"Mostly Outbound": "出向为主（服务端/内容特征）",
	"Heavy Outbound":  "重度出向（内容源/机房特征）",
	"Not Disclosed":   "未披露",
}

// AuditFlow checks PeeringDB traffic direction and lease signals against the
// inferred network type to catch datacenter blocks masquerading as residential ISPs.
func AuditFlow(v model.Verdict, f model.Flags, pdb *model.PeeringDB, lease *model.LeaseCheck) *model.FlowAudit {
	out := &model.FlowAudit{}
	if pdb != nil && strings.TrimSpace(pdb.InfoRatio) != "" {
		r := strings.TrimSpace(pdb.InfoRatio)
		out.TrafficRatio = r
		out.RatioLabel = ratioLabels[r]
		if out.RatioLabel == "" {
			out.RatioLabel = r
		}
	}
	outbound := out.TrafficRatio == "Heavy Outbound" || out.TrafficRatio == "Mostly Outbound"
	switch {
	case v.Type == "residential" && outbound:
		out.Masquerade = true
		out.Detail = "部分数据源标注为家庭宽带，但 PeeringDB 报告该自治系统以出向流量为主（" + out.TrafficRatio + "），呈现机房或内容分发特征"
	case v.Type == "residential" && lease != nil && lease.Leased:
		out.Detail = "归属商业地址租赁商 " + lease.Broker + " 挂靠宽带自治系统宣告（常见于双 ISP 静态商宽/专线）"
	case v.Type == "residential" && (out.TrafficRatio == "Mostly Inbound" || out.TrafficRatio == "Heavy Inbound"):
		out.Detail = "入向下载流量占主导，与普通家庭终端上网特征一致"
	case outbound && (f.Hosting || f.CDN):
		out.Detail = "出向流量占主导，与服务器/CDN 节点特征一致"
	case out.RatioLabel != "" && out.TrafficRatio != "Not Disclosed":
		out.Detail = "自治系统申报流量方向：" + out.RatioLabel
	}
	if out.TrafficRatio == "" && !out.Masquerade && out.Detail == "" {
		return nil
	}
	return out
}

// FormatASTypeLabel produces a bilingual ASN self-reported / inferred type string
// such as "NSP / backbone（国际骨干网）" or "Cable/DSL/ISP（宽带运营商）".
func FormatASTypeLabel(n model.Network, v model.Verdict) string {
	if n.PeeringDB != nil && strings.TrimSpace(n.PeeringDB.InfoType) != "" {
		raw := strings.TrimSpace(n.PeeringDB.InfoType)
		first, _, _ := strings.Cut(raw, ",")
		first = strings.TrimSpace(first)
		zhMap := map[string]string{
			"NSP":                  "backbone（骨干网）",
			"Cable/DSL/ISP":        "ISP（宽带接入网）",
			"Content":              "Content（内容/云服务）",
			"Enterprise":           "Enterprise（企业网）",
			"Educational/Research": "Education（教育科研网）",
			"Government":           "Government（政府机构网）",
			"Non-Profit":           "Non-Profit（非营利组织）",
			"Route Server":         "Route Server（路由服务器）",
		}
		if zh, ok := zhMap[first]; ok {
			return zh
		}
		return raw
	}
	switch n.ASClass {
	case "Eyeball":
		return "Eyeball（终端接入网）"
	case "Content":
		return "Content（内容/云机房）"
	case "Transit":
		return "backbone（骨干网）"
	}
	switch v.Type {
	case "hosting":
		return "Hosting（机房托管）"
	case "residential":
		return "ISP（家庭宽带）"
	case "mobile":
		return "Cellular（移动蜂窝）"
	case "cdn":
		return "CDN（边缘分发网）"
	case "business":
		return "Business（企业专线）"
	case "education":
		return "Education（教育科研）"
	case "government":
		return "Government（政府网络）"
	}
	return ""
}

// TrafficLevelAndTone maps human-vs-bot traffic shares to aligned labels and color tiers.
func TrafficLevelAndTone(humanPct, botPct float64) (level, tone string) {
	switch {
	case humanPct >= 70:
		return "真人主导", "good"
	case humanPct >= 45:
		return "人机混合", "warn"
	case botPct >= 80:
		return "高度自动化", "bad"
	default:
		return "机器偏多", "poor"
	}
}

// TrafficLevel preserves the single-string helper for callers that only need the label.
func TrafficLevel(humanPct, botPct float64) string {
	lvl, _ := TrafficLevelAndTone(humanPct, botPct)
	return lvl
}

// CollectBotSignals extracts human-readable evidence of automated, crawler,
// scanner or spam bot activity observed on r.
func CollectBotSignals(r *model.Result) []string {
	var sigs []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		for _, existing := range sigs {
			if existing == s {
				return
			}
		}
		sigs = append(sigs, s)
	}
	if r.Flags.Crawler {
		add("多源情报识别为爬虫或自动采集节点")
	}
	if r.Flags.Tor {
		add("Tor 匿名出口节点（高频自动化与代理共享流量）")
	}
	for _, l := range r.Lists {
		switch l.Category {
		case "crawler":
			add("命中爬虫网段：" + l.Label)
		case "abuse":
			add("命中威胁/自动化攻击名单：" + l.Label)
		}
	}
	if r.Audit != nil && r.Audit.Activity != nil {
		act := r.Audit.Activity
		if act.SpamReports > 0 {
			add(fmt.Sprintf("StopForumSpam 记录垃圾注册/表单提交 %d 次", act.SpamReports))
		}
		if act.DShieldPackets > 0 || act.DShieldTargets > 0 {
			add(fmt.Sprintf("DShield 蜜罐捕获扫描 %d 包（涉及 %d 个目标）", act.DShieldPackets, act.DShieldTargets))
		}
		if act.OTXPulses > 0 {
			add(fmt.Sprintf("AlienVault OTX 关联 %d 条威胁情报脉冲", act.OTXPulses))
		}
		if act.TorRelay && !act.TorExit {
			add("Tor 网络中继节点")
		}
	}
	for _, e := range r.Verdict.Evidence {
		if e.Kind == "crawler" {
			add(e.Source + " 报告爬虫/自动化活动（" + e.Detail + "）")
		}
	}
	if r.Audit != nil && r.Audit.Flow != nil &&
		(r.Audit.Flow.TrafficRatio == "Heavy Outbound" || r.Audit.Flow.TrafficRatio == "Mostly Outbound") {
		add("自治系统以服务端出向流量为主（" + r.Audit.Flow.TrafficRatio + "）")
	}
	return sigs
}

// BuildTraffic combines an optional Cloudflare Radar ASN breakdown with
// observed per-IP bot/abuse telemetry and the visitor's live request probe.
func BuildTraffic(r *model.Result, radar *model.Traffic, reqProbe *model.RequestProbe) *model.Traffic {
	if r == nil || r.Bogon != "" {
		return nil
	}
	botSigs := CollectBotSignals(r)
	if radar != nil && radar.Mode == "radar" && (radar.HumanPct > 0 || radar.BotPct > 0) {
		cp := *radar
		cp.BotSignals = botSigs
		cp.RequestProbe = reqProbe
		cp.Level, cp.Tone = TrafficLevelAndTone(cp.HumanPct, cp.BotPct)
		return &cp
	}
	if r.Mode == "fast" && r.Verdict.Type == "unknown" && len(botSigs) == 0 {
		if reqProbe == nil {
			return nil
		}
		return &model.Traffic{
			Mode:         "unavailable",
			Level:        "暂未评估",
			Tone:         "neutral",
			Note:         "等待完整在线情报返回后计算网络人机流量分布",
			BotSignals:   botSigs,
			RequestProbe: reqProbe,
		}
	}
	if r.Score.DataStatus == "unavailable" && r.Verdict.Type == "unknown" && len(botSigs) == 0 {
		return &model.Traffic{
			Mode:         "unavailable",
			ASN:          r.Network.ASN,
			Level:        "暂未评估",
			Tone:         "neutral",
			Note:         "缺少足够的在线信誉与自治系统统计数据，暂不估算人机比例",
			BotSignals:   botSigs,
			RequestProbe: reqProbe,
		}
	}

	botScore := 22.0
	switch r.Verdict.Type {
	case "residential":
		botScore = 8.0
	case "mobile":
		botScore = 6.0
	case "education":
		botScore = 15.0
	case "business":
		botScore = 18.0
	case "government":
		botScore = 14.0
	case "cdn":
		botScore = 46.0
	case "hosting":
		botScore = 66.0
	}
	f := r.Flags
	if f.Crawler {
		botScore = max(botScore, 82.0)
	}
	if f.Tor {
		botScore += 24.0
	} else if f.Proxy || f.VPN {
		botScore += 16.0
	}
	if f.Abuser {
		botScore += 18.0
	}
	if f.Leased {
		botScore += 8.0
	}
	if r.Audit != nil {
		if r.Audit.Flow != nil {
			switch r.Audit.Flow.TrafficRatio {
			case "Heavy Inbound":
				botScore -= 3.0
			case "Mostly Inbound":
				botScore -= 2.0
			case "Mostly Outbound":
				botScore += 6.0
			case "Heavy Outbound":
				botScore += 12.0
			}
		}
		if act := r.Audit.Activity; act != nil {
			if act.SpamReports > 0 {
				botScore += min(18.0, 6.0+math.Log2(float64(act.SpamReports)+1)*3.0)
			}
			if act.DShieldPackets > 0 {
				botScore += min(16.0, 5.0+math.Log10(float64(act.DShieldPackets)+1)*4.0)
			}
			if act.OTXPulses >= 3 {
				botScore += min(10.0, float64(act.OTXPulses))
			}
		}
		if nb := r.Audit.Neighbor; nb != nil && nb.Total == 256 && nb.Flagged >= 8 {
			botScore += min(10.0, float64(nb.Flagged)/8.0)
		}
	}
	if len(r.Risk) > 0 {
		sum := 0
		for _, x := range r.Risk {
			v := x.Value
			if x.EffectiveValue != nil && *x.EffectiveValue >= 0 && *x.EffectiveValue <= 100 {
				v = *x.EffectiveValue
			}
			sum += v
		}
		mean := float64(sum) / float64(len(r.Risk))
		if mean >= 25 {
			botScore += (mean - 20) * 0.22
		}
	}
	botPct := math.Round(max(2.0, min(98.0, botScore))*10) / 10
	humanPct := math.Round((100.0-botPct)*10) / 10
	lvl, tone := TrafficLevelAndTone(humanPct, botPct)
	return &model.Traffic{
		Mode:         "estimated",
		Source:       "多源行为与网络特征推算",
		ASN:          r.Network.ASN,
		HumanPct:     humanPct,
		BotPct:       botPct,
		Level:        lvl,
		Tone:         tone,
		Note:         "基于网络类型、流量方向、爬虫/扫描记录与同段信誉信号综合推算（配置 CF_RADAR_TOKEN 可启用 Cloudflare Radar 自治系统实测占比）",
		BotSignals:   botSigs,
		RequestProbe: reqProbe,
	}
}

var aiRestrictedCountries = []string{"CN", "HK", "MO", "RU", "BY", "IR", "KP", "SY", "CU"}

func scenarioToneAndStatus(score int, id string) (tone, status string) {
	switch {
	case score >= 8:
		return "good", "优质可用"
	case score >= 6:
		if id == "ai" {
			return "warn", "可以尝试"
		}
		return "warn", "可用"
	case score >= 4:
		return "poor", "易受限"
	default:
		return "bad", "高风控 / 受限"
	}
}

// PopulateThreatAndScenarios computes structured threat badges and 0..10
// suitability scores across TikTok, Social Media, AI Apps and Mail/Turnstile.
func PopulateThreatAndScenarios(r *model.Result) {
	if r == nil || r.Bogon != "" || r.Audit == nil {
		return
	}
	a := r.Audit
	f := r.Flags
	act := a.Activity

	dnsblHits, dnsblChecked := model.SummarizeDNSBL(r.DNSBL)
	blacklistChecked := dnsblChecked > 0 || (a.Neighbor != nil && a.Neighbor.ListsLoaded > 0)
	hasReputation := r.Score.DataStatus == "complete" || (r.Score.Coverage != nil && r.Score.Coverage.Received > 0)
	spamChecked := slices.ContainsFunc(r.Sources, func(source model.Source) bool {
		return source.Name == "StopForumSpam" && source.Status == "ok" && source.Reputation
	})
	abuseLists := 0
	for _, l := range r.Lists {
		if l.Category == "abuse" {
			abuseLists++
		}
	}

	// 1. RiskSummary
	switch {
	case f.Tor || f.Abuser || dnsblHits >= 2 || abuseLists > 0:
		a.RiskSummary, a.RiskTone = "发现明显威胁标记", "bad"
	case f.Proxy || f.VPN || (a.Flow != nil && a.Flow.Masquerade):
		a.RiskSummary, a.RiskTone = "存在代理或流量伪装特征", "warn"
	case dnsblHits > 0 || (act != nil && (act.SpamReports > 0 || act.DShieldPackets > 0 || act.DShieldTargets > 0 || act.OTXPulses > 0)):
		a.RiskSummary, a.RiskTone = "有名单或活动记录", "warn"
	case f.Leased:
		a.RiskSummary, a.RiskTone = "商业租赁网段", "warn"
	case !blacklistChecked && !hasReputation:
		a.RiskSummary, a.RiskTone = "威胁数据不足", "neutral"
	case f.Hosting || f.CDN:
		a.RiskSummary, a.RiskTone = "已查来源未见明显威胁（机房段）", "good"
	default:
		a.RiskSummary, a.RiskTone = "已查来源未见明显威胁", "good"
	}

	// 2. AbuseLevel
	abuserRaw := strings.ToLower(r.Network.AbuserScore)
	switch {
	case f.Abuser || (act != nil && (act.SpamReports >= 5 || act.OTXPulses >= 3)) || strings.Contains(abuserRaw, "very high") || strings.Contains(abuserRaw, "high"):
		a.AbuseLevel, a.AbuseTone = "高风险", "bad"
	case (act != nil && act.SpamReports > 0) || dnsblHits > 0 || strings.Contains(abuserRaw, "elevated"):
		a.AbuseLevel, a.AbuseTone = "中等", "warn"
	case strings.Contains(abuserRaw, "low"):
		a.AbuseLevel, a.AbuseTone = "来源报告低滥用", "good"
	case spamChecked:
		a.AbuseLevel, a.AbuseTone = "未见垃圾提交记录", "good"
	default:
		a.AbuseLevel, a.AbuseTone = "缺少滥用评级", "neutral"
	}

	// 3. Honeypot / Scanner / DNSBL status
	switch {
	case dnsblHits >= 2:
		a.HoneypotStatus, a.HoneypotTone = fmt.Sprintf("黑名单命中（DNSBL %d）", dnsblHits), "bad"
	case abuseLists > 0:
		a.HoneypotStatus, a.HoneypotTone = "命中离线滥用名单", "bad"
	case act != nil && act.DShieldPackets >= 20:
		a.HoneypotStatus, a.HoneypotTone = "蜜罐有扫描记录", "bad"
	case (act != nil && (act.DShieldPackets > 0 || act.DShieldTargets > 0)) || dnsblHits == 1:
		a.HoneypotStatus, a.HoneypotTone = "观测到扫描或单点记录", "warn"
	case blacklistChecked:
		a.HoneypotStatus, a.HoneypotTone = "已查名单未命中", "good"
	default:
		a.HoneypotStatus, a.HoneypotTone = "缺少名单观测", "neutral"
	}

	if r.Mode == "fast" || r.Score.DataStatus == "unavailable" {
		return
	}

	cc := strings.ToUpper(strings.TrimSpace(r.Geo.CountryCode))
	isBroadcast := r.Native.Status == "broadcast"
	botHigh := r.Traffic != nil && r.Traffic.BotPct >= 65
	dirtySub := a.Neighbor != nil && a.Neighbor.Total == 256 && a.Neighbor.Flagged >= 16

	clamp10 := func(n int) int { return max(1, min(10, n)) }
	makeSc := func(id, name string, pts int, reason string) model.Scenario {
		s := clamp10(pts)
		tone, st := scenarioToneAndStatus(s, id)
		return model.Scenario{ID: id, Name: name, Score: s, Max: 10, Status: st, Tone: tone, Detail: reason}
	}

	// Scenario 1: TikTok / 短视频出海
	tk := 9
	tkNote := "原生家庭/移动网络，适合内容分发与定位"
	if cc == "CN" || cc == "IR" || cc == "KP" {
		tk, tkNote = 1, "当前定位国家不在国际版服务区"
	} else {
		if f.Hosting || f.CDN {
			tk -= 3
			tkNote = "机房网段可用但自然推荐权重低于本地家宽"
		}
		if isBroadcast {
			tk -= 2
			tkNote = "广播 IP 注册国与定位国不一致，易出现分区偏移"
		}
		if f.Tor || f.Proxy {
			tk -= 3
			tkNote = "命中公开代理或 Tor 标记，易触发限流"
		} else if f.VPN || f.Leased {
			tk -= 1
		}
		if f.Abuser || dirtySub {
			tk -= 2
		}
	}

	// Scenario 2: 社媒运营 (Instagram / X / Reddit / 电商养号)
	sm := 9
	smNote := "网络属性与信誉良好，适合常规账号登录维护"
	if f.Hosting || f.CDN {
		sm -= 3
		smNote = "机房 IP 可正常浏览，新注册或高频操作易弹验证"
	}
	if isBroadcast {
		sm -= 1
	}
	if f.Tor {
		sm -= 5
		smNote = "Tor 出口节点极易触发社媒风控拦截"
	} else if f.Proxy || f.VPN {
		sm -= 2
		smNote = "共享代理/VPN 信号会提高二次验证概率"
	}
	if f.Abuser || (act != nil && act.SpamReports > 0) {
		sm -= 3
		smNote = "存在历史垃圾注册或滥用记录，注册风控风险高"
	} else if botHigh || dirtySub {
		sm -= 1
	}

	// Scenario 3: AI 应用 (ChatGPT / Claude / Gemini)
	ai := 9
	aiNote := "地区与信誉均满足主流大模型平台要求"
	if slices.Contains(aiRestrictedCountries, cc) {
		ai, aiNote = 2, fmt.Sprintf("定位地区（%s）不在部分主流大模型直接支持列表", cc)
	} else {
		if f.Hosting || f.CDN {
			ai -= 2
			aiNote = "原生机房段通常可访问，严格平台偶发人机质询"
		}
		if isBroadcast {
			ai -= 1
		}
		if f.Tor {
			ai -= 5
			aiNote = "Tor 出口通常被 AI 平台直接拒绝"
		} else if f.Proxy || f.Abuser {
			ai -= 3
			aiNote = "存在代理或滥用标记，易遭遇封禁或降智门槛"
		} else if botHigh {
			ai -= 1
		}
	}

	// Scenario 4: 免盾浏览 / 邮局信誉 (Turnstile & SMTP)
	cf := 9
	cfNote := "未见黑名单与扫描记录，正常浏览较少弹盾"
	if dnsblHits >= 2 || f.Abuser {
		cf -= 4
		cfNote = "命中多项黑名单或滥用库，极易触发验证码与拒信"
	} else if dnsblHits == 1 {
		cf -= 2
		cfNote = "存在单点 DNSBL 记录，部分严格邮局或 WAF 会拦截"
	}
	if f.Tor {
		cf -= 4
		cfNote = "Tor 出口访问受保护站点会频繁触发人机盾"
	} else if f.Hosting || f.CDN {
		cf -= 2
		if cfNote == "未见黑名单与扫描记录，正常浏览较少弹盾" {
			cfNote = "机房 ASN 默认人机初始信任分低于住宅宽带"
		}
	}
	if botHigh {
		cf -= 1
	}

	a.Scenarios = []model.Scenario{
		makeSc("tiktok", "TikTok", tk, tkNote),
		makeSc("social", "社媒运营", sm, smNote),
		makeSc("ai", "AI 应用", ai, aiNote),
		makeSc("shield", "免盾浏览", cf, cfNote),
	}
}
