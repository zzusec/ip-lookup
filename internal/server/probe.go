package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/zzusec/ip-lookup/internal/lookup"
	"github.com/zzusec/ip-lookup/internal/model"
)

func cleanHeaderToken(s string, limit int) string {
	s = strings.TrimSpace(s)
	if len(s) > limit {
		s = s[:limit]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

var headlessTokens = []struct {
	sub   string
	label string
}{
	{"headlesschrome", "HeadlessChrome"},
	{"phantomjs", "PhantomJS"},
	{"playwright", "Playwright"},
	{"puppeteer", "Puppeteer"},
	{"selenium", "Selenium"},
	{"webdriver", "WebDriver"},
	{"cypress", "Cypress"},
	{"chromeless", "Chromeless"},
	{"splash", "Splash"},
}

var cliTokens = []struct {
	sub   string
	label string
}{
	{"curl/", "curl"},
	{"wget/", "Wget"},
	{"httpie/", "HTTPie"},
	{"python-requests", "python-requests"},
	{"python-httpx", "python-httpx"},
	{"aiohttp/", "aiohttp"},
	{"urllib", "Python urllib"},
	{"go-http-client", "Go-http-client"},
	{"node-fetch", "node-fetch"},
	{"undici", "Node undici"},
	{"axios/", "axios"},
	{"okhttp/", "OkHttp"},
	{"scrapy", "Scrapy"},
	{"aria2", "aria2"},
	{"powershell", "PowerShell"},
	{"libwww-perl", "Perl LWP"},
	{"java/", "Java HTTP"},
}

// inspectRequestProbe evaluates the visitor's own HTTP handshake headers
// without echoing cookies, credentials or query parameters.
func (s *Server) inspectRequestProbe(r *http.Request) *model.RequestProbe {
	uaRaw := cleanHeaderToken(r.Header.Get("User-Agent"), 240)
	uaLow := strings.ToLower(uaRaw)
	secFetchMode := cleanHeaderToken(r.Header.Get("Sec-Fetch-Mode"), 40)
	secFetchSite := cleanHeaderToken(r.Header.Get("Sec-Fetch-Site"), 40)
	secFetchDest := cleanHeaderToken(r.Header.Get("Sec-Fetch-Dest"), 40)
	secCHUA := cleanHeaderToken(r.Header.Get("Sec-CH-UA"), 180)
	secCHPlat := strings.Trim(cleanHeaderToken(r.Header.Get("Sec-CH-UA-Platform"), 40), `"`)
	acceptLang := cleanHeaderToken(r.Header.Get("Accept-Language"), 80)
	acceptEnc := strings.ToLower(cleanHeaderToken(r.Header.Get("Accept-Encoding"), 80))
	via := cleanHeaderToken(r.Header.Get("Via"), 80)
	forwarded := cleanHeaderToken(r.Header.Get("Forwarded"), 80)
	isHTTPS := r.TLS != nil || s.forwardedProto(r) == "https"

	var checks []model.ProbeCheck
	add := func(name, status, detail string) {
		checks = append(checks, model.ProbeCheck{Name: name, Status: status, Detail: detail})
	}

	autoScore := 0
	family := "未知客户端"
	isCLI, isHeadless, isModernBrowser := false, false, false

	switch {
	case uaRaw == "":
		isCLI = true
		family = "空 User-Agent"
		autoScore += 80
		add("客户端标识", "bot", "未发送 User-Agent 请求头")
	default:
		for _, h := range headlessTokens {
			if strings.Contains(uaLow, h.sub) {
				isHeadless = true
				family = h.label
				autoScore += 85
				add("客户端标识", "bot", "User-Agent 包含无头/自动化框架标识："+h.label)
				break
			}
		}
		if !isHeadless {
			for _, c := range cliTokens {
				if strings.Contains(uaLow, c.sub) {
					isCLI = true
					family = c.label
					autoScore += 85
					add("客户端标识", "bot", "识别为命令行或程序化 HTTP 库："+c.label)
					break
				}
			}
		}
		if !isHeadless && !isCLI {
			switch {
			case strings.Contains(uaLow, "edg/"):
				family, isModernBrowser = "Microsoft Edge", true
			case strings.Contains(uaLow, "chrome/") || strings.Contains(uaLow, "crios/"):
				family, isModernBrowser = "Chromium / Chrome", true
			case strings.Contains(uaLow, "firefox/") || strings.Contains(uaLow, "fxios/"):
				family, isModernBrowser = "Firefox", true
			case strings.Contains(uaLow, "safari/") && strings.Contains(uaLow, "version/"):
				family, isModernBrowser = "Safari", true
			case strings.HasPrefix(uaLow, "mozilla/5.0"):
				family, isModernBrowser = "Web 浏览器", true
			default:
				family = "非标准 HTTP 客户端"
				autoScore += 45
			}
			if isModernBrowser {
				add("客户端标识", "pass", "标准浏览器标识（"+family+"）")
			} else {
				add("客户端标识", "warn", "非典型浏览器标识（"+family+"）")
			}
		}
	}

	// Fetch Metadata checks (Sec-Fetch-*)
	if secFetchMode != "" || secFetchSite != "" {
		add("请求上下文 (Sec-Fetch)", "pass", fmt.Sprintf("携带浏览器安全上下文（site=%s, mode=%s）", orDash(secFetchSite), orDash(secFetchMode)))
		_ = secFetchDest
	} else if isModernBrowser {
		if isHTTPS {
			autoScore += 28
			add("请求上下文 (Sec-Fetch)", "warn", "自称现代浏览器但缺失 Sec-Fetch-* 请求头，常见于脚本伪造 UA")
		} else {
			add("请求上下文 (Sec-Fetch)", "info", "明文 HTTP 下未携带 Sec-Fetch-*（仅安全上下文强制发送）")
		}
	} else {
		add("请求上下文 (Sec-Fetch)", "info", "非浏览器客户端未携带 Fetch Metadata")
	}

	// Client Hints consistency (Sec-CH-UA)
	chLow := strings.ToLower(secCHUA)
	switch {
	case strings.Contains(chLow, "headlesschrome"):
		isHeadless = true
		autoScore = max(autoScore, 90)
		add("客户端提示 (Client Hints)", "bot", "Sec-CH-UA 暴露 HeadlessChrome 品牌标识")
	case secCHUA != "":
		platMismatch := false
		pLow := strings.ToLower(secCHPlat)
		if pLow != "" {
			switch {
			case strings.Contains(pLow, "win") && !strings.Contains(uaLow, "windows"):
				platMismatch = true
			case strings.Contains(pLow, "mac") && !strings.Contains(uaLow, "macintosh") && !strings.Contains(uaLow, "mac os"):
				platMismatch = true
			case strings.Contains(pLow, "android") && !strings.Contains(uaLow, "android"):
				platMismatch = true
			}
		}
		if platMismatch {
			autoScore += 35
			add("客户端提示 (Client Hints)", "warn", fmt.Sprintf("Sec-CH-UA-Platform (%s) 与 User-Agent 系统声明不一致", secCHPlat))
		} else {
			add("客户端提示 (Client Hints)", "pass", "Client Hints 品牌与系统声明自洽")
		}
	case (family == "Chromium / Chrome" || family == "Microsoft Edge") && !strings.Contains(uaLow, "crios/"):
		if isHTTPS {
			autoScore += 18
			add("客户端提示 (Client Hints)", "warn", "桌面/安卓 Chromium 系请求缺失 Sec-CH-UA")
		} else {
			add("客户端提示 (Client Hints)", "info", "未包含可选 Sec-CH-UA 客户端提示")
		}
	}

	// Accept-Language & Accept-Encoding negotiation
	hasModernEnc := strings.Contains(acceptEnc, "br") || strings.Contains(acceptEnc, "zstd")
	switch {
	case acceptLang != "" && (hasModernEnc || strings.Contains(acceptEnc, "gzip")):
		add("语言与压缩协商", "pass", "携带 Accept-Language 与现代内容压缩协商")
	case acceptLang == "" && isModernBrowser:
		autoScore += 22
		add("语言与压缩协商", "warn", "浏览器标识下缺失 Accept-Language 首选语言头")
	default:
		if !isCLI {
			autoScore += 10
		}
		add("语言与压缩协商", "info", "精简 HTTP 协商头（无语言偏好或现代压缩）")
	}

	// Explicit forward-proxy leak headers
	if via != "" || forwarded != "" || r.Header.Get("Proxy-Connection") != "" {
		autoScore += 12
		add("代理透传链路", "warn", "请求暴露显式正向代理转发头（Via / Forwarded）")
	} else {
		add("代理透传链路", "pass", "未见明文 HTTP 代理透传头泄露")
	}

	autoScore = max(2, min(98, autoScore))
	if isModernBrowser && !isHeadless && autoScore == 2 {
		autoScore = 4
	}
	humanShare := 100 - autoScore
	verdict, label := "human_browser", "标准浏览器真人交互"
	switch {
	case isHeadless:
		verdict, label = "automated_client", "无头浏览器 / 自动化框架"
	case isCLI:
		verdict, label = "cli_tool", "命令行 / 程序化客户端"
	case autoScore >= 45:
		verdict, label = "suspect_automation", "疑似脚本伪装请求"
	case autoScore >= 25:
		verdict, label = "suspect_automation", "浏览器特征部分缺失"
	}

	return &model.RequestProbe{
		Verdict:         verdict,
		Label:           label,
		HumanShare:      humanShare,
		AutomationShare: autoScore,
		Proto:           r.Proto,
		ClientFamily:    family,
		Checks:          checks,
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// realityBaitBrands maps commonly borrowed VLESS-Reality / ShadowTLS target
// domains to their legitimate origin/CDN ASNs.
var realityBaitBrands = []struct {
	suffixes []string
	asns     []int
	brand    string
}{
	{[]string{"microsoft.com", "msecnd.net", "live.com", "bing.com", "office.com", "windowsupdate.com"}, []int{8075, 8068, 8069, 3598, 20940, 16625}, "Microsoft / Bing"},
	{[]string{"apple.com", "icloud.com", "cdn-apple.com", "mzstatic.com", "itunes.com", "aaplimg.com"}, []int{714, 6185, 20940, 16625, 54113}, "Apple / iCloud"},
	{[]string{"yahoo.com", "yimg.com", "yahoo.co.jp"}, []int{10310, 36646, 36647, 26101, 54113, 20940}, "Yahoo"},
	{[]string{"google.com", "googleapis.com", "gstatic.com", "1e100.net", "youtube.com"}, []int{15169, 396982, 19527, 36040}, "Google"},
	{[]string{"amazonaws.com", "awsstatic.com", "cloudfront.net", "amazon.com"}, []int{16509, 14618, 8987}, "Amazon / AWS"},
	{[]string{"cloudflare.com", "cloudflare-dns.com", "one.one.one.one"}, []int{13335, 209242}, "Cloudflare"},
	{[]string{"amd.com", "nvidia.com", "intel.com", "samsung.com"}, []int{20940, 16625, 13335, 54113, 16509}, "硬件厂商官网"},
	{[]string{"steampowered.com", "steamstatic.com", "discord.com", "epicgames.com"}, []int{32590, 20940, 54113, 13335, 16509}, "游戏平台官网"},
}

func matchBaitBrand(domain string, asn int) (brand string, hit bool) {
	d := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "*."))
	if d == "" {
		return "", false
	}
	for _, b := range realityBaitBrands {
		for _, suf := range b.suffixes {
			if d == suf || strings.HasSuffix(d, "."+suf) {
				if asn > 0 && slices.Contains(b.asns, asn) {
					return "", false
				}
				return b.brand, true
			}
		}
	}
	return "", false
}

type tlsCacheEntry struct {
	until time.Time
	val   model.TLS443Probe
}

type tlsProbeCache struct {
	mu sync.Mutex
	m  map[string]tlsCacheEntry
}

func newTLSProbeCache() *tlsProbeCache {
	return &tlsProbeCache{m: map[string]tlsCacheEntry{}}
}

func (c *tlsProbeCache) get(key string) (model.TLS443Probe, bool) {
	if c == nil {
		return model.TLS443Probe{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.until) {
		delete(c.m, key)
		return model.TLS443Probe{}, false
	}
	return e.val, true
}

func (c *tlsProbeCache) put(key string, val model.TLS443Probe, ttl time.Duration) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 1024 {
		now := time.Now()
		for k, v := range c.m {
			if now.After(v.until) {
				delete(c.m, k)
			}
		}
	}
	c.m[key] = tlsCacheEntry{until: time.Now().Add(ttl), val: val}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return ""
	}
}

// probeVisitorTLS443 performs a read-only TCP/TLS handshake against the
// visitor's own public IP on port 443 to spot open server ports or borrowed
// Reality/ShadowTLS certificates. Never called for arbitrary third-party IPs.
func (s *Server) probeVisitorTLS443(ctx context.Context, ip netip.Addr, asn int) *model.TLS443Probe {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() || lookup.Bogon(ip) != "" {
		return &model.TLS443Probe{
			Probed:  false,
			Verdict: "skipped",
			Detail:  "本地或保留网段地址不执行公网 443 端口回探",
		}
	}
	if s.DisableActiveProbe {
		return &model.TLS443Probe{
			Probed:  false,
			Verdict: "skipped",
			Detail:  "服务端已关闭主动 443 端口回探",
		}
	}
	cacheKey := fmt.Sprintf("%s|%d", ip.String(), asn)
	if cached, ok := s.tlsCache.get(cacheKey); ok {
		cp := cached
		return &cp
	}

	target := net.JoinHostPort(ip.String(), "443")
	start := time.Now()
	d := &net.Dialer{Timeout: 1500 * time.Millisecond}
	rawConn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		res := model.TLS443Probe{
			Probed:   true,
			PortOpen: false,
			Verdict:  "closed",
			Detail:   "出口 IP 的 443 端口未开放或被防火墙拦截（符合普通家庭宽带/移动终端特征）",
		}
		s.tlsCache.put(cacheKey, res, 10*time.Minute)
		return &res
	}
	rtt := time.Since(start).Milliseconds()
	_ = rawConn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	res := model.TLS443Probe{
		Probed:   true,
		PortOpen: true,
		RTTMs:    rtt,
		Verdict:  "open_non_tls",
		Detail:   "443 端口开放，但无默认 TLS 证书响应",
	}

	tconn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true}) // read-only peer cert inspection
	if err := tconn.HandshakeContext(ctx); err == nil {
		st := tconn.ConnectionState()
		res.TLSActive = true
		res.TLSVersion = tlsVersionName(st.Version)
		res.Verdict = "open_tls"
		res.Detail = "出口 IP 开放 443/TLS 服务（通常为服务器、网关或反向代理节点）"
		if len(st.PeerCertificates) > 0 {
			leaf := st.PeerCertificates[0]
			res.SubjectCN = cleanHeaderToken(leaf.Subject.CommonName, 120)
			if len(leaf.Issuer.Organization) > 0 {
				res.Issuer = cleanHeaderToken(leaf.Issuer.Organization[0], 120)
			} else {
				res.Issuer = cleanHeaderToken(leaf.Issuer.CommonName, 120)
			}
			if leaf.Subject.String() == leaf.Issuer.String() {
				res.SelfSigned = true
			}
			for _, san := range leaf.DNSNames {
				if clean := cleanHeaderToken(san, 120); clean != "" && len(res.SANs) < 8 {
					res.SANs = append(res.SANs, clean)
				}
			}
			candidates := append([]string{res.SubjectCN}, res.SANs...)
			for _, dom := range candidates {
				if brand, hit := matchBaitBrand(dom, asn); hit {
					res.RealitySuspect = true
					res.RealityBrand = brand
					res.RealityDomain = dom
					res.Verdict = "reality_suspect"
					res.Detail = fmt.Sprintf("非 %s 官方自治系统却返回其有效域名证书（%s），疑似 VLESS-Reality / ShadowTLS 借证伪装节点", brand, dom)
					break
				}
			}
		}
		_ = tconn.Close()
	} else {
		_ = rawConn.Close()
		// Strict Reality relays often close handshakes without a whitelisted SNI;
		// test one verified handshake with Microsoft SNI if ASN is non-Microsoft.
		if asn > 0 && !slices.Contains([]int{8075, 8068, 8069, 20940, 16625}, asn) {
			c2, cancel2 := context.WithTimeout(ctx, 1400*time.Millisecond)
			td := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 1200 * time.Millisecond}, Config: &tls.Config{ServerName: "www.microsoft.com"}}
			if conn2, err2 := td.DialContext(c2, "tcp", target); err2 == nil {
				if tc, ok := conn2.(*tls.Conn); ok {
					res.TLSVersion = tlsVersionName(tc.ConnectionState().Version)
				}
				_ = conn2.Close()
				res.TLSActive = true
				res.RealitySuspect = true
				res.RealityBrand = "Microsoft"
				res.RealityDomain = "www.microsoft.com"
				res.Verdict = "reality_suspect"
				res.Detail = "默认无 SNI 拒绝握手但对 www.microsoft.com 通过严格证书验签，疑似 VLESS-Reality 透明转发伪装"
			}
			cancel2()
		}
	}

	s.tlsCache.put(cacheKey, res, 15*time.Minute)
	return &res
}

// apiProbe inspects the visitor's own HTTP request traits and (optionally)
// probes the visitor's own public exit IP on TCP/443.
func (s *Server) apiProbe(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r).Unmap().WithZone("")
	if !ip.IsValid() {
		apiError(w, http.StatusBadRequest, "无法识别访客 IP", 0)
		return
	}
	if s.probeLimit != nil {
		if ok, retry := s.probeLimit.allow(ip); !ok {
			apiError(w, http.StatusTooManyRequests, "探测太频繁，请稍后再试", retry)
			return
		}
	}
	v := 4
	if ip.Is6() {
		v = 6
	}
	asn := 0
	if s.Lookup != nil {
		asn = s.Lookup.OriginASN(ip)
	}
	ctx, cancel := ctxTimeout(r, 4*time.Second)
	defer cancel()
	out := model.ActiveProbe{
		IP:           ip.String(),
		Version:      v,
		QueriedAt:    time.Now().UTC().Format(time.RFC3339),
		RequestProbe: s.inspectRequestProbe(r),
	}
	if r.URL.Query().Get("tls") != "0" {
		out.TLS443 = s.probeVisitorTLS443(ctx, ip, asn)
	}
	writeJSON(w, http.StatusOK, out)
}
