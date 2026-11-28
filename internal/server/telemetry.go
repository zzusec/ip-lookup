package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxVisitRing   = 1000
	maxLoginLogs   = 200
	maxTrackedDist = 200
	maxTrackedIPs  = 500
	maxDailyUVSet  = 50000
)

type visitRecord struct {
	ID          uint64 `json:"id"`
	Time        string `json:"time"`
	Day         string `json:"day"`
	IP          string `json:"ip"`
	CC          string `json:"cc,omitempty"`
	Location    string `json:"location"`
	Country     string `json:"country"`
	ASN         string `json:"asn"`
	ISP         string `json:"isp"`
	Kind        string `json:"kind"` // view | self_lookup | target_lookup | cli | probe | error
	TargetIP    string `json:"targetIp,omitempty"`
	TargetLabel string `json:"targetLabel,omitempty"`
	OS          string `json:"os"`
	Browser     string `json:"browser"`
	Status      int    `json:"status"`
	Ms          int64  `json:"ms"`
}

type distItem struct {
	Name     string `json:"name"`
	CC       string `json:"cc,omitempty"`
	Visitors int    `json:"visitors"`
	Requests int    `json:"requests"`
}

type ipAggItem struct {
	IP        string   `json:"ip"`
	CC        string   `json:"cc,omitempty"`
	Location  string   `json:"location"`
	ASN       string   `json:"asn"`
	ISP       string   `json:"isp"`
	Label     string   `json:"label,omitempty"`
	OS        string   `json:"os"`
	Browser   string   `json:"browser"`
	Views     int      `json:"views"`
	Lookups   int      `json:"lookups"`
	Probes    int      `json:"probes"`
	Errors    int      `json:"errors"`
	FirstSeen string   `json:"firstSeen"`
	LastSeen  string   `json:"lastSeen"`
	Targets   []string `json:"targets,omitempty"`
}

type liveOverview struct {
	TodayUV     uint64      `json:"todayUv"`
	YestUV      uint64      `json:"yestUv"`
	UV7d        uint64      `json:"uv7d"`
	UV30d       uint64      `json:"uv30d"`
	RecentCount int         `json:"recentCount"`
	Regions     []distItem  `json:"regions"`
	ASNs        []distItem  `json:"asns"`
	Clients     []distItem  `json:"clients"`
	TopIPs      []ipAggItem `json:"topIps"`
}

type ipBlockEntry struct {
	IP           string `json:"ip"`
	Location     string `json:"location"`
	FailCount    int    `json:"failCount"`
	Strike       int    `json:"strike"`
	BlockedUntil string `json:"blockedUntil,omitempty"`
	Permanent    bool   `json:"permanent"`
	UpdatedAt    string `json:"updatedAt"`
}

type loginLogEntry struct {
	Time     string `json:"time"`
	IP       string `json:"ip"`
	Location string `json:"location"`
	Username string `json:"username"`
	OK       bool   `json:"ok"`
	Reason   string `json:"reason"`
}

type distCounter struct {
	cc       string
	requests int
	visitors map[uint64]struct{}
}

type ipAggState struct {
	item    ipAggItem
	lastSeq uint64
}

type liveTelemetry struct {
	mu        sync.Mutex
	salt      [32]byte
	seq       uint64
	ring      []visitRecord
	dayUV     map[string]map[uint64]struct{}
	regions   map[string]*distCounter
	asns      map[string]*distCounter
	clients   map[string]*distCounter
	ipAgg     map[string]*ipAggState
	blocks    map[string]*ipBlockState
	loginLogs []loginLogEntry
}

type ipBlockState struct {
	ip           string
	location     string
	failCount    int
	strike       int
	blockedUntil time.Time
	permanent    bool
	updatedAt    time.Time
}

func newLiveTelemetry() *liveTelemetry {
	t := &liveTelemetry{
		dayUV:   make(map[string]map[uint64]struct{}),
		regions: make(map[string]*distCounter),
		asns:    make(map[string]*distCounter),
		clients: make(map[string]*distCounter),
		ipAgg:   make(map[string]*ipAggState),
		blocks:  make(map[string]*ipBlockState),
	}
	rand.Read(t.salt[:])
	return t
}

func (t *liveTelemetry) ipHash(scope, ip string) uint64 {
	mac := hmac.New(sha256.New, t.salt[:])
	mac.Write([]byte(scope))
	mac.Write([]byte{0})
	mac.Write([]byte(ip))
	sum := mac.Sum(nil)
	return binary.LittleEndian.Uint64(sum[:8])
}

func bumpDist(m map[string]*distCounter, key, cc string, visitorHash uint64) {
	if key == "" {
		return
	}
	c, ok := m[key]
	if !ok {
		if len(m) >= maxTrackedDist {
			return
		}
		c = &distCounter{cc: cc, visitors: make(map[uint64]struct{})}
		m[key] = c
	} else if c.cc == "" && cc != "" {
		c.cc = cc
	}
	c.requests++
	if len(c.visitors) < 10000 {
		c.visitors[visitorHash] = struct{}{}
	}
}

func topDist(m map[string]*distCounter, limit int) []distItem {
	out := make([]distItem, 0, len(m))
	for name, c := range m {
		out = append(out, distItem{Name: name, CC: c.cc, Visitors: len(c.visitors), Requests: c.requests})
	}
	slices.SortFunc(out, func(a, b distItem) int {
		if a.Visitors != b.Visitors {
			return b.Visitors - a.Visitors
		}
		if a.Requests != b.Requests {
			return b.Requests - a.Requests
		}
		return strings.Compare(a.Name, b.Name)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (t *liveTelemetry) bumpIPAggLocked(rec visitRecord) {
	if rec.IP == "" {
		return
	}
	st, ok := t.ipAgg[rec.IP]
	if !ok {
		if len(t.ipAgg) >= maxTrackedIPs {
			var oldestKey string
			var oldestSeq uint64 = ^uint64(0)
			for k, v := range t.ipAgg {
				if v.lastSeq < oldestSeq {
					oldestSeq = v.lastSeq
					oldestKey = k
				}
			}
			if oldestKey != "" {
				delete(t.ipAgg, oldestKey)
			}
		}
		st = &ipAggState{
			item: ipAggItem{
				IP:        rec.IP,
				FirstSeen: rec.Time,
			},
		}
		t.ipAgg[rec.IP] = st
	}
	st.lastSeq = t.seq + 1
	st.item.LastSeen = rec.Time
	if rec.CC != "" {
		st.item.CC = rec.CC
	}
	if rec.Location != "" {
		st.item.Location = rec.Location
	}
	if rec.ASN != "" {
		st.item.ASN = rec.ASN
	}
	if rec.ISP != "" {
		st.item.ISP = rec.ISP
	}
	if (rec.TargetIP == "" || rec.TargetIP == rec.IP) && rec.TargetLabel != "" {
		st.item.Label = rec.TargetLabel
	}
	if rec.OS != "" {
		st.item.OS = rec.OS
	}
	if rec.Browser != "" {
		st.item.Browser = rec.Browser
	}
	switch rec.Kind {
	case "view":
		st.item.Views++
	case "probe":
		st.item.Probes++
	case "error":
		st.item.Errors++
	default:
		st.item.Lookups++
	}
	if rec.Status >= 400 && rec.Kind != "error" {
		st.item.Errors++
	}
	if rec.TargetIP != "" && rec.TargetIP != rec.IP && len(st.item.Targets) < 6 && !slices.Contains(st.item.Targets, rec.TargetIP) {
		st.item.Targets = append(st.item.Targets, rec.TargetIP)
	}
}

func topIPAgg(m map[string]*ipAggState, limit int) []ipAggItem {
	out := make([]ipAggItem, 0, len(m))
	for _, st := range m {
		cp := st.item
		if len(cp.Targets) > 0 {
			cp.Targets = slices.Clone(cp.Targets)
		}
		out = append(out, cp)
	}
	slices.SortFunc(out, func(a, b ipAggItem) int {
		totA := a.Views + a.Lookups + a.Probes + a.Errors
		totB := b.Views + b.Lookups + b.Probes + b.Errors
		if totA != totB {
			return totB - totA
		}
		return strings.Compare(b.LastSeen, a.LastSeen)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (t *liveTelemetry) markVisitorLocked(now time.Time, ip string) (bool, uint64) {
	if ip == "" {
		return false, 0
	}
	day := now.In(usageZone).Format(time.DateOnly)
	cutoff := now.In(usageZone).AddDate(0, 0, -29).Format(time.DateOnly)
	for d := range t.dayUV {
		if d < cutoff {
			delete(t.dayUV, d)
		}
	}
	set, ok := t.dayUV[day]
	if !ok {
		set = make(map[uint64]struct{})
		t.dayUV[day] = set
	}
	hDay := t.ipHash(day, ip)
	hAll := t.ipHash("30d", ip)
	if _, seen := set[hDay]; seen {
		return false, hAll
	}
	if len(set) < maxDailyUVSet {
		set[hDay] = struct{}{}
	}
	return true, hAll
}

func (t *liveTelemetry) pushVisit(now time.Time, rec visitRecord, vHash uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.bumpIPAggLocked(rec)
	if vHash != 0 {
		regionKey := rec.Country
		if regionKey == "" {
			regionKey = rec.Location
		}
		bumpDist(t.regions, regionKey, rec.CC, vHash)
		asnKey := strings.TrimSpace(rec.ASN + " " + rec.ISP)
		bumpDist(t.asns, asnKey, "", vHash)
		clientKey := strings.TrimSpace(rec.OS + " · " + rec.Browser)
		bumpDist(t.clients, clientKey, "", vHash)
	}

	// Coalesce an automatic self_lookup right after a browser page load from the same IP
	// so opening the homepage once shows one clean enriched row instead of two duplicate rows.
	if rec.Kind == "self_lookup" && rec.Status >= 200 && rec.Status < 300 && len(t.ring) > 0 {
		last := &t.ring[len(t.ring)-1]
		if last.IP == rec.IP && last.Kind == "view" && last.Day == rec.Day {
			if last.TargetLabel == "" && rec.TargetLabel != "" {
				last.TargetLabel = rec.TargetLabel
			}
			if rec.Ms > last.Ms {
				last.Ms = rec.Ms
			}
			return
		}
	}

	t.seq++
	rec.ID = t.seq
	if len(t.ring) >= maxVisitRing {
		copy(t.ring, t.ring[1:])
		t.ring[len(t.ring)-1] = rec
	} else {
		t.ring = append(t.ring, rec)
	}
}

func (t *liveTelemetry) overview(usage usageReport, now time.Time) liveOverview {
	t.mu.Lock()
	defer t.mu.Unlock()

	today := now.In(usageZone).Format(time.DateOnly)
	yest := now.In(usageZone).AddDate(0, 0, -1).Format(time.DateOnly)
	cut7 := now.In(usageZone).AddDate(0, 0, -6).Format(time.DateOnly)

	var todayUV, yestUV, uv7, uv30 uint64
	for _, d := range usage.Days {
		uv := d.UV
		if d.Date == today {
			todayUV = uv
		}
		if d.Date == yest {
			yestUV = uv
		}
		if d.Date >= cut7 {
			uv7 += uv
		}
		uv30 += uv
	}

	return liveOverview{
		TodayUV:     todayUV,
		YestUV:      yestUV,
		UV7d:        uv7,
		UV30d:       uv30,
		RecentCount: len(t.ring),
		Regions:     topDist(t.regions, 12),
		ASNs:        topDist(t.asns, 12),
		Clients:     topDist(t.clients, 12),
		TopIPs:      topIPAgg(t.ipAgg, 100),
	}
}

type visitQuery struct {
	Page  int
	Size  int
	Q     string
	Kind  string
	From  string
	To    string
	Today bool
	Err   bool
	Sort  string
	Order string
}

func (t *liveTelemetry) queryVisits(q visitQuery, now time.Time) ([]visitRecord, int) {
	t.mu.Lock()
	snap := slices.Clone(t.ring)
	t.mu.Unlock()

	today := now.In(usageZone).Format(time.DateOnly)
	kw := strings.ToLower(strings.TrimSpace(q.Q))
	filtered := make([]visitRecord, 0, len(snap))
	for i := len(snap) - 1; i >= 0; i-- {
		r := snap[i]
		if q.Today && r.Day != today {
			continue
		}
		if q.Err && r.Status < 400 && r.Kind != "error" {
			continue
		}
		if q.Kind != "" {
			switch q.Kind {
			case "cli_json":
				if r.Kind != "cli" {
					continue
				}
			default:
				if r.Kind != q.Kind {
					continue
				}
			}
		}
		if q.From != "" && r.Day < q.From {
			continue
		}
		if q.To != "" && r.Day > q.To {
			continue
		}
		if kw != "" {
			hay := strings.ToLower(r.IP + " " + r.TargetIP + " " + r.Location + " " + r.ASN + " " + r.ISP + " " + r.OS + " " + r.Browser + " " + r.TargetLabel)
			if !strings.Contains(hay, kw) {
				continue
			}
		}
		filtered = append(filtered, r)
	}

	asc := q.Order == "asc"
	switch q.Sort {
	case "ms":
		slices.SortStableFunc(filtered, func(a, b visitRecord) int {
			if asc {
				return int(a.Ms - b.Ms)
			}
			return int(b.Ms - a.Ms)
		})
	default:
		if asc {
			slices.Reverse(filtered)
		}
	}

	total := len(filtered)
	size := max(1, min(100, q.Size))
	page := max(1, q.Page)
	start := (page - 1) * size
	if start >= total {
		return []visitRecord{}, total
	}
	end := min(total, start+size)
	return filtered[start:end], total
}

func (t *liveTelemetry) visitorHistory(ip string) []visitRecord {
	t.mu.Lock()
	snap := slices.Clone(t.ring)
	t.mu.Unlock()

	var out []visitRecord
	for i := len(snap) - 1; i >= 0; i-- {
		if snap[i].IP == ip || snap[i].TargetIP == ip {
			out = append(out, snap[i])
			if len(out) >= 100 {
				break
			}
		}
	}
	return out
}

// Brute-force login protection: 3 failures -> 1h lock -> +3 failures -> 3h lock -> +3 failures -> permanent block.
func (t *liveTelemetry) checkIPBlock(ip string, now time.Time) (blocked bool, retrySec int, msg string) {
	if ip == "" {
		return false, 0, ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.blocks[ip]
	if !ok {
		return false, 0, ""
	}
	if b.permanent {
		return true, 3600, "该 IP 因多次登录失败已被永久封锁"
	}
	if now.Before(b.blockedUntil) {
		rem := int(b.blockedUntil.Sub(now).Seconds()) + 1
		return true, rem, fmt.Sprintf("登录失败过多，已锁定至 %s", b.blockedUntil.In(usageZone).Format("15:04:05"))
	}
	return false, 0, ""
}

func (t *liveTelemetry) recordLoginAttempt(now time.Time, ip, loc, username string, ok bool, reason string, threshold int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry := loginLogEntry{
		Time:     now.In(usageZone).Format("2006-01-02 15:04:05"),
		IP:       ip,
		Location: loc,
		Username: username,
		OK:       ok,
		Reason:   reason,
	}
	if len(t.loginLogs) >= maxLoginLogs {
		copy(t.loginLogs, t.loginLogs[1:])
		t.loginLogs[len(t.loginLogs)-1] = entry
	} else {
		t.loginLogs = append(t.loginLogs, entry)
	}

	if ip == "" {
		return
	}
	if ok {
		delete(t.blocks, ip)
		return
	}
	b, exists := t.blocks[ip]
	if !exists {
		if len(t.blocks) >= 2000 {
			return
		}
		b = &ipBlockState{ip: ip}
		t.blocks[ip] = b
	}
	b.location = loc
	b.updatedAt = now
	b.failCount++
	if threshold <= 0 {
		threshold = 3
	}
	if b.failCount >= threshold {
		b.failCount = 0
		b.strike++
		switch {
		case b.strike == 1:
			b.blockedUntil = now.Add(time.Hour)
		case b.strike == 2:
			b.blockedUntil = now.Add(3 * time.Hour)
		default:
			b.permanent = true
		}
	}
}

func (t *liveTelemetry) listIPBlocks() []ipBlockEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ipBlockEntry, 0, len(t.blocks))
	for _, b := range t.blocks {
		until := ""
		if !b.blockedUntil.IsZero() {
			until = b.blockedUntil.In(usageZone).Format("2006-01-02 15:04:05")
		}
		out = append(out, ipBlockEntry{
			IP:           b.ip,
			Location:     b.location,
			FailCount:    b.failCount,
			Strike:       b.strike,
			BlockedUntil: until,
			Permanent:    b.permanent,
			UpdatedAt:    b.updatedAt.In(usageZone).Format("2006-01-02 15:04:05"),
		})
	}
	slices.SortFunc(out, func(a, b ipBlockEntry) int { return strings.Compare(b.UpdatedAt, a.UpdatedAt) })
	return out
}

func (t *liveTelemetry) unblockIP(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.blocks[ip]; !ok {
		return false
	}
	delete(t.blocks, ip)
	return true
}

func (t *liveTelemetry) listLoginLogs() []loginLogEntry {
	t.mu.Lock()
	snap := slices.Clone(t.loginLogs)
	t.mu.Unlock()
	slices.Reverse(snap)
	return snap
}

var (
	reIOSOS    = regexp.MustCompile(`(?:iPhone|iPad|iPod)[^)]*?OS (\d+(?:[._]\d+){1,2})`)
	reSafVer   = regexp.MustCompile(`\bVersion/(\d+\.\d+(?:\.\d+)?)`)
	reAndroid  = regexp.MustCompile(`Android (\d+(?:\.\d+)?)`)
	reMacOSX   = regexp.MustCompile(`Mac OS X (\d+[._]\d+)`)
	reMajorBrowser = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"微信", regexp.MustCompile(`MicroMessenger/(\d+\.\d+)`)},
		{"Edge", regexp.MustCompile(`Edg(?:iOS|A)?/(\d+)`)},
		{"Opera", regexp.MustCompile(`(?:OPR|OPiOS)/(\d+)`)},
		{"Chrome iOS", regexp.MustCompile(`CriOS/(\d+)`)},
		{"Firefox iOS", regexp.MustCompile(`FxiOS/(\d+)`)},
		{"Firefox", regexp.MustCompile(`Firefox/(\d+)`)},
		{"Chrome", regexp.MustCompile(`Chrome/(\d+)`)},
	}
)

func parseVerTuple3(raw string) ([3]int, string) {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == '.' || r == '_' })
	var v [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		v[i] = n
	}
	if v[2] > 0 {
		return v, fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
	}
	return v, fmt.Sprintf("%d.%d", v[0], v[1])
}

func cmpTuple3(a, b [3]int) int {
	for i := range 3 {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return 0
}

// parseUABrief maps a raw User-Agent to clean canonical (OS, Client) labels without
// echoing arbitrary user-controlled substrings into telemetry.
func parseUABrief(uaRaw string) (string, string) {
	ua := strings.TrimSpace(uaRaw)
	if ua == "" {
		return "未知系统", "空 UA"
	}
	low := strings.ToLower(ua)
	for _, cli := range []struct{ kw, name string }{
		{"curl/", "curl"},
		{"wget/", "Wget"},
		{"httpie/", "HTTPie"},
		{"python-requests", "Python Requests"},
		{"python-urllib", "Python urllib"},
		{"go-http-client", "Go HTTP"},
		{"headlesschrome", "HeadlessChrome"},
		{"playwright", "Playwright"},
		{"puppeteer", "Puppeteer"},
		{"googlebot", "Googlebot"},
		{"bingbot", "Bingbot"},
		{"uptimerobot", "UptimeRobot"},
	} {
		if strings.Contains(low, cli.kw) {
			return "CLI / 自动化", cli.name
		}
	}

	osLbl := "未知系统"
	mIOS := reIOSOS.FindStringSubmatch(ua)
	var mSaf []string
	if strings.Contains(ua, "Safari/") && !strings.Contains(ua, "CriOS/") && !strings.Contains(ua, "FxiOS/") &&
		!strings.Contains(ua, "EdgiOS/") && !strings.Contains(ua, "OPiOS/") && !strings.Contains(ua, "Android") {
		mSaf = reSafVer.FindStringSubmatch(ua)
	}
	if len(mIOS) > 1 || (strings.Contains(ua, "iPad") && len(mSaf) > 1) {
		dev := "iOS"
		if strings.Contains(ua, "iPad") {
			dev = "iPadOS"
		}
		var verStr string
		if len(mIOS) > 1 && len(mSaf) > 1 {
			vOS, sOS := parseVerTuple3(mIOS[1])
			vSF, sSF := parseVerTuple3(mSaf[1])
			if cmpTuple3(vSF, vOS) > 0 {
				verStr = sSF
			} else {
				verStr = sOS
			}
		} else if len(mSaf) > 1 {
			_, verStr = parseVerTuple3(mSaf[1])
		} else if len(mIOS) > 1 {
			_, verStr = parseVerTuple3(mIOS[1])
		}
		osLbl = strings.TrimSpace(dev + " " + verStr)
	} else if strings.Contains(ua, "HarmonyOS") || strings.Contains(ua, "OpenHarmony") {
		osLbl = "HarmonyOS"
	} else if m := reAndroid.FindStringSubmatch(ua); len(m) > 1 {
		osLbl = "Android " + m[1]
	} else if strings.Contains(ua, "Windows NT 10.0") {
		osLbl = "Windows 10/11"
	} else if strings.Contains(ua, "Windows NT") {
		osLbl = "Windows"
	} else if m := reMacOSX.FindStringSubmatch(ua); len(m) > 1 {
		mv := strings.ReplaceAll(m[1], "_", ".")
		if mv == "10.15" {
			osLbl = "macOS 11+"
		} else {
			osLbl = "macOS " + mv
		}
	} else if strings.Contains(ua, "CrOS") {
		osLbl = "ChromeOS"
	} else if strings.Contains(ua, "Linux") {
		osLbl = "Linux"
	}

	brLbl := "Web 浏览器"
	matched := false
	for _, b := range reMajorBrowser {
		if m := b.re.FindStringSubmatch(ua); len(m) > 1 {
			brLbl = b.name + " " + m[1]
			matched = true
			break
		}
	}
	if !matched {
		if len(mSaf) > 1 {
			parts := strings.Split(mSaf[1], ".")
			if len(parts) >= 2 {
				brLbl = "Safari " + parts[0] + "." + parts[1]
			} else {
				brLbl = "Safari " + mSaf[1]
			}
		} else if strings.Contains(ua, "Safari/") {
			brLbl = "Safari / WebKit"
		}
	}
	return osLbl, brLbl
}

type ipSummary struct {
	CC       string `json:"cc,omitempty"`
	Country  string `json:"country"`
	Location string `json:"location"`
	ASN      string `json:"asn"`
	ISP      string `json:"isp"`
	Label    string `json:"label"`
	Prefix   string `json:"prefix,omitempty"`
}

func (s *Server) offlineIPSummary(addr netip.Addr) ipSummary {
	if !addr.IsValid() || s == nil || s.Lookup == nil || s.Lookup.Data == nil {
		return ipSummary{}
	}
	res := s.Lookup.Lookup(context.Background(), addr, false)
	if res == nil {
		return ipSummary{}
	}
	var locParts []string
	for _, p := range []string{res.Geo.Country, res.Geo.Region, res.Geo.City} {
		p = strings.TrimSpace(p)
		if p != "" && (len(locParts) == 0 || locParts[len(locParts)-1] != p) {
			locParts = append(locParts, p)
		}
	}
	asn := ""
	if res.Network.ASN > 0 {
		asn = "AS" + strconv.Itoa(res.Network.ASN)
	}
	isp := firstNonEmptyStr(res.Network.ISP, res.Network.ASName, res.Network.Org)
	lbl := firstNonEmptyStr(res.Verdict.TypeLabel, res.Verdict.Label)
	return ipSummary{
		CC:       strings.ToUpper(strings.TrimSpace(res.Geo.CountryCode)),
		Country:  res.Geo.Country,
		Location: strings.Join(locParts, " · "),
		ASN:      asn,
		ISP:      isp,
		Label:    lbl,
		Prefix:   firstNonEmptyStr(res.Network.BGPPrefix, res.Network.Prefix),
	}
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func (panel *AdminPanel) observeRequest(srv *Server, r *http.Request, status int, contentType string, elapsed time.Duration) {
	if panel == nil {
		return
	}
	now := time.Now()
	pattern := r.Pattern
	var usageKind, eventKind string
	var isCLI, isTarget bool

	switch pattern {
	case "GET /{$}", "GET /{ip}":
		if status == http.StatusNotFound {
			return
		}
		if status == http.StatusOK && strings.HasPrefix(contentType, "text/html;") {
			usageKind = "view"
			eventKind = "view"
		} else if status >= 400 {
			usageKind = "error"
			eventKind = "error"
		} else if status >= 200 && status < 300 {
			usageKind = "lookup"
			eventKind = "cli"
			isCLI = true
		} else {
			return
		}
	case "GET /json", "GET /json/{ip}":
		if status >= 400 {
			usageKind = "error"
			eventKind = "error"
		} else if status >= 200 && status < 300 {
			usageKind = "lookup"
			eventKind = "cli"
			isCLI = true
		} else {
			return
		}
	case "GET /api/lookup":
		if status >= 400 {
			usageKind = "error"
			eventKind = "error"
		} else if status >= 200 && status < 300 {
			usageKind = "lookup"
			eventKind = "self_lookup"
		} else {
			return
		}
	case "GET /api/probe":
		if status >= 400 {
			usageKind = "error"
			eventKind = "error"
		} else if status >= 200 && status < 300 {
			usageKind = "probe"
			eventKind = "probe"
		} else {
			return
		}
	default:
		return
	}

	clientAddr := srv.clientIP(r)
	clientIP := ""
	if clientAddr.IsValid() {
		clientIP = clientAddr.String()
	}
	rawTarget := strings.TrimSpace(r.PathValue("ip"))
	if rawTarget == "" {
		rawTarget = strings.TrimSpace(r.URL.Query().Get("ip"))
	}
	var targetAddr netip.Addr
	targetIP := ""
	if rawTarget != "" {
		if parsed, err := netip.ParseAddr(strings.Trim(rawTarget, "[]")); err == nil {
			targetAddr = parsed.Unmap().WithZone("")
			targetIP = targetAddr.String()
			if targetAddr != clientAddr {
				isTarget = true
				if eventKind == "self_lookup" {
					eventKind = "target_lookup"
				}
			}
		}
	}

	panel.live.mu.Lock()
	newUV, vHash := panel.live.markVisitorLocked(now, clientIP)
	panel.live.mu.Unlock()

	panel.usage.recordDetailed(now, usageKind, newUV, isCLI, isTarget)

	cSum := srv.offlineIPSummary(clientAddr)
	targetLabel := cSum.Label
	if isTarget && targetAddr.IsValid() {
		tSum := srv.offlineIPSummary(targetAddr)
		targetLabel = tSum.Label
	} else if targetIP == "" {
		targetIP = clientIP
	}
	osLbl, brLbl := parseUABrief(r.Header.Get("User-Agent"))
	panel.live.pushVisit(now, visitRecord{
		Time:        now.In(usageZone).Format("2006-01-02 15:04:05"),
		Day:         now.In(usageZone).Format(time.DateOnly),
		IP:          clientIP,
		CC:          cSum.CC,
		Location:    cSum.Location,
		Country:     cSum.Country,
		ASN:         cSum.ASN,
		ISP:         cSum.ISP,
		Kind:        eventKind,
		TargetIP:    targetIP,
		TargetLabel: targetLabel,
		OS:          osLbl,
		Browser:     brLbl,
		Status:      status,
		Ms:          elapsed.Milliseconds(),
	}, vHash)
}
