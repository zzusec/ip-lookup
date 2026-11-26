package server

import (
	"fmt"
	"strings"

	"github.com/zzusec/ip-lookup/internal/model"
)

// Text renders a result for terminals (`curl host`); host is used in the hint line.
func Text(r *model.Result, host string) string {
	var b strings.Builder
	line := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			b.WriteString(k + strings.Repeat(" ", max(1, 11-width(k))) + v + "\n")
		}
	}
	join := func(parts ...string) string {
		var keep []string
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" && (len(keep) == 0 || keep[len(keep)-1] != p) {
				keep = append(keep, p)
			}
		}
		return strings.Join(keep, " ")
	}
	line("IP", r.IP)
	if r.Bogon != "" {
		line("类型", "非公网地址："+r.Bogon)
		return b.String()
	}
	line("类型", fmt.Sprintf("%s（置信度 %s）", r.Verdict.Label, confidenceZH[r.Verdict.Confidence]))
	if r.Score.DataStatus == "unavailable" {
		line("纯净度", "未知 · 信誉数据不足")
	} else {
		score := fmt.Sprintf("%d 分 · %s", r.Score.Value, r.Score.Level)
		if r.Score.DataStatus == "limited" {
			score += "（数据有限）"
		}
		line("纯净度", score)
	}
	line("原生", r.Native.Label+"  "+r.Native.Detail)
	if tr := r.Traffic; tr != nil {
		if tr.Mode == "radar" || tr.Mode == "estimated" {
			src := tr.Source
			if tr.Window != "" && tr.Mode == "radar" {
				src += " " + tr.Window
			}
			line("人机流量", fmt.Sprintf("真人 %.1f%% / 机器 %.1f%% · %s（%s）", tr.HumanPct, tr.BotPct, tr.Level, src))
			if tr.DesktopPct != nil && tr.MobilePct != nil {
				line("设备分布", fmt.Sprintf("桌面 %.1f%% / 移动 %.1f%%", *tr.DesktopPct, *tr.MobilePct))
			}
		}
		if rp := tr.RequestProbe; rp != nil {
			line("当前请求", fmt.Sprintf("%s（真人特征 %d%% / 自动化特征 %d%% · %s）", rp.Label, rp.HumanShare, rp.AutomationShare, rp.ClientFamily))
		}
	}
	g := r.Geo
	line("位置", join(g.Flag, g.Country, g.Region, g.City, g.District))
	if g.Lat != 0 || g.Lon != 0 {
		acc := ""
		if g.AccuracyKm > 0 {
			acc = fmt.Sprintf("（±%d km）", g.AccuracyKm)
		}
		line("坐标", fmt.Sprintf("%.4f, %.4f%s", g.Lat, g.Lon, acc))
	}
	line("时区", join(g.TimeZone, g.UTCOffset))
	n := r.Network
	if n.ASN != 0 {
		line("ASN", join(fmt.Sprintf("AS%d", n.ASN), n.ASName, bracket(orStr(n.ASTypeLabel, n.ASClass))))
	}
	if n.ASIPv4Count > 0 {
		line("ASN 规模", fmt.Sprintf("IPv4 约 %d 个地址（前缀 v4:%d / v6:%d）", n.ASIPv4Count, n.ASPrefixesV4, n.ASPrefixesV6))
	}
	if n.ASCreated != "" {
		line("ASN 注册", n.ASCreated)
	}
	if n.PeeringDB != nil && n.PeeringDB.InfoTraffic != "" {
		line("预估带宽", n.PeeringDB.InfoTraffic)
	}
	line("运营商", join(n.ISP))
	if n.Org != n.ASName {
		line("组织", n.Org)
	}
	if n.Registrant != "" && n.Registrant != n.Org {
		line("企业信息", n.Registrant)
	}
	line("网段", join(n.Prefix, bracket(n.NetName)))
	if n.BGPPrefix != "" && n.BGPPrefix != n.Prefix {
		line("BGP 前缀", n.BGPPrefix)
	}
	line("注册机构", join(strings.ToUpper(n.Registry), n.Allocated))
	if len(n.RDNS) > 0 {
		fc := ""
		if n.FCrDNS != nil && *n.FCrDNS {
			fc = "（正反解一致）"
		}
		line("反向解析", strings.Join(n.RDNS, ", ")+fc)
	}
	line("RPKI", n.RPKI)
	line("路由可见度", n.Visibility)
	line("滥用联系", n.Abuse)
	if len(r.Lists) > 0 {
		var names []string
		for _, l := range r.Lists {
			names = append(names, l.Label)
		}
		line("命中名单", strings.Join(names, "；"))
	}
	listed := 0
	for _, d := range r.DNSBL {
		if d.Listed {
			listed++
		}
	}
	if len(r.DNSBL) > 0 {
		line("DNSBL", fmt.Sprintf("%d/%d 命中", listed, len(r.DNSBL)))
	}
	if r.Ports != nil && len(r.Ports.Ports) > 0 {
		ports := make([]string, len(r.Ports.Ports))
		for i, p := range r.Ports.Ports {
			ports[i] = fmt.Sprint(p)
		}
		line("开放端口", strings.Join(ports, ", "))
	}
	if a := r.Audit; a != nil {
		if nb := a.Neighbor; nb != nil {
			if nb.Total > 0 {
				line("同段邻居", fmt.Sprintf("%s 内 %d/%d (%.1f%%) 命中风险名单 · %s", nb.Prefix, nb.Flagged, nb.Total, nb.DensityPct, nb.Level))
			} else if nb.Flagged > 0 {
				line("同段邻居", fmt.Sprintf("%s 内 %d 个风险子网命中 · %s", nb.Prefix, nb.Flagged, nb.Level))
			}
		}
		if a.Lease != nil && a.Lease.Leased {
			line("地址租赁", a.Lease.Broker+" 商业租赁网段")
		}
		if a.Flow != nil && a.Flow.Masquerade {
			line("流量核验", a.Flow.Detail)
		}
		if act := a.Activity; act != nil {
			var parts []string
			if act.SpamReports > 0 {
				parts = append(parts, fmt.Sprintf("垃圾提交 %d 次", act.SpamReports))
			}
			if act.DShieldPackets > 0 {
				parts = append(parts, fmt.Sprintf("DShield %d 包", act.DShieldPackets))
			}
			if act.OTXPulses > 0 {
				parts = append(parts, fmt.Sprintf("OTX %d 脉冲", act.OTXPulses))
			}
			if act.TorExit {
				parts = append(parts, "Tor 出口")
			} else if act.TorRelay {
				parts = append(parts, "Tor 中继")
			}
			if len(parts) > 0 {
				line("威胁活动", strings.Join(parts, "；"))
			}
		}
		if len(a.Scenarios) > 0 {
			var sc []string
			for _, s := range a.Scenarios {
				sc = append(sc, fmt.Sprintf("%s %d/%d(%s)", s.Name, s.Score, s.Max, s.Status))
			}
			line("场景评估", strings.Join(sc, " · "))
		}
	}
	ok := 0
	for _, s := range r.Sources {
		if s.Status == "ok" {
			ok++
		}
	}
	fmt.Fprintf(&b, "\n%d/%d 个数据源返回结果，耗时 %d ms。JSON：curl %s/json/%s\n", ok, len(r.Sources), r.ElapsedMs, host, r.IP)
	return b.String()
}

// width approximates the terminal columns of s: CJK characters take two.
func width(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x1100 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

var confidenceZH = map[string]string{"high": "高", "medium": "中", "low": "低"}

func bracket(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}

func orStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
