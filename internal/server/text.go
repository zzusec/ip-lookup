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
	line("纯净度", fmt.Sprintf("%d 分 · %s", r.Score.Value, r.Score.Level))
	line("原生", r.Native.Label+"  "+r.Native.Detail)
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
		line("ASN", join(fmt.Sprintf("AS%d", n.ASN), n.ASName, bracket(n.ASClass)))
	}
	line("运营商", join(n.ISP))
	if n.Org != n.ASName {
		line("组织", n.Org)
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
