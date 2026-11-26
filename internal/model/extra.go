package model

// GeoSource is one provider's opinion about where an address is and who runs it.
type GeoSource struct {
	Source      string  `json:"source"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
	ASN         int     `json:"asn,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	Type        string  `json:"type,omitempty"` // the provider's own usage/connection type
	Text        string  `json:"text,omitempty"` // free-form location line from text APIs
}

// ListHit records membership in a downloaded IP or ASN list.
type ListHit struct {
	List     string `json:"list"`
	Label    string `json:"label"`
	Category string `json:"category"` // tor vpn proxy icloud_relay hosting cdn crawler public_service abuse
	Match    string `json:"match"`
	Detail   string `json:"detail,omitempty"`
}

type DNSBL struct {
	Zone   string `json:"zone"`
	Listed bool   `json:"listed"`
	Answer string `json:"answer,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Risk preserves a provider's risk figure normalised to 0..100, higher is worse.
// EffectiveValue optionally records the value used by our scoring policy;
// Value remains the original reading, not a claim that the address is safe.
type Risk struct {
	Source         string `json:"source"`
	Value          int    `json:"value"`
	Detail         string `json:"detail,omitempty"`
	EffectiveValue *int   `json:"effective_value,omitempty"`
	ScoringNote    string `json:"scoring_note,omitempty"`
}

// Ports comes from Shodan InternetDB.
type Ports struct {
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Vulns     []string `json:"vulns,omitempty"`
}

// Source reports how one data source behaved for this query.
type Source struct {
	Name             string `json:"name"`
	Kind             string `json:"kind"`   // offline | online | dns
	Status           string `json:"status"` // ok | empty | error | timeout | skipped | quota
	Ms               int64  `json:"ms"`
	Error            string `json:"error,omitempty"`
	Note             string `json:"note,omitempty"`
	Cached           bool   `json:"cached,omitempty"`
	ReputationSource bool   `json:"reputation_source,omitempty"` // applicable provider can return reputation data
	Reputation       bool   `json:"reputation,omitempty"`        // this answer actually included valid reputation fields
}

// ClientIP is the answer of /api/ip.
type ClientIP struct {
	IP      string `json:"ip"`
	Version int    `json:"version"`
}

// Dataset describes one downloaded offline dataset for /api/sources.
type Dataset struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Category  string `json:"category"`
	Entries   int    `json:"entries"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	Homepage  string `json:"homepage,omitempty"`
	License   string `json:"license,omitempty"`
}

// OnlineSource describes one online provider for /api/sources.
type OnlineSource struct {
	Name     string `json:"name"`
	Homepage string `json:"homepage,omitempty"`
	Keyed    bool   `json:"keyed"`
	Quota    string `json:"quota,omitempty"`
	Used     int    `json:"used"`
	Blocked  string `json:"blocked_until,omitempty"`
}

type SourcesReport struct {
	Datasets []Dataset      `json:"datasets"`
	Online   []OnlineSource `json:"online"`
}

// APIError is the body of every non-2xx JSON answer.
type APIError struct {
	Error      string `json:"error"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// Traffic reports ASN/network human-vs-bot traffic distribution and, for
// self-queries, real-time request-level human/automation probing.
type Traffic struct {
	Mode         string        `json:"mode"`             // radar | estimated | unavailable
	Source       string        `json:"source,omitempty"` // e.g. "Cloudflare Radar" or "多源行为信号评估"
	Window       string        `json:"window,omitempty"` // e.g. "7d"
	ASN          int           `json:"asn,omitempty"`
	HumanPct     float64       `json:"human_pct"`
	BotPct       float64       `json:"bot_pct"`
	DesktopPct   *float64      `json:"desktop_pct,omitempty"`
	MobilePct    *float64      `json:"mobile_pct,omitempty"`
	OtherPct     *float64      `json:"other_pct,omitempty"`
	Level        string        `json:"level"`                 // 真人主导 | 人机混合 | 机器偏多 | 高度自动化 | 暂未评估
	Tone         string        `json:"tone,omitempty"`        // good | warn | poor | bad | neutral
	Note         string        `json:"note,omitempty"`        // methodology / coverage note
	BotSignals   []string      `json:"bot_signals,omitempty"` // observed automated/bot evidence
	RequestProbe *RequestProbe `json:"request_probe,omitempty"`
}

// RequestProbe inspects the visitor's own HTTP handshake headers and client
// traits to distinguish interactive browsers from scripts and headless tools.
type RequestProbe struct {
	Verdict         string       `json:"verdict"` // human_browser | cli_tool | automated_client | suspect_automation
	Label           string       `json:"label"`
	HumanShare      int          `json:"human_share"`      // 0..100 confidence toward interactive human client
	AutomationShare int          `json:"automation_share"` // 0..100 confidence toward script/headless client
	Proto           string       `json:"proto,omitempty"`
	ClientFamily    string       `json:"client_family,omitempty"`
	Checks          []ProbeCheck `json:"checks,omitempty"`
}

// ProbeCheck is one transparent signal in RequestProbe.
type ProbeCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | info | warn | bot
	Detail string `json:"detail"`
}

// NetworkAudit groups deeper network, subnet-neighbor, lease, traffic-direction,
// scenario suitability and threat-activity checks.
type NetworkAudit struct {
	Neighbor       *NeighborDensity `json:"neighbor,omitempty"`
	Lease          *LeaseCheck      `json:"lease,omitempty"`
	Flow           *FlowAudit       `json:"flow,omitempty"`
	Activity       *ThreatActivity  `json:"activity,omitempty"`
	Scenarios      []Scenario       `json:"scenarios,omitempty"`
	RiskSummary    string           `json:"risk_summary,omitempty"`
	RiskTone       string           `json:"risk_tone,omitempty"`
	AbuseLevel     string           `json:"abuse_level,omitempty"`
	AbuseTone      string           `json:"abuse_tone,omitempty"`
	HoneypotStatus string           `json:"honeypot_status,omitempty"`
	HoneypotTone   string           `json:"honeypot_tone,omitempty"`
}

// Scenario rates suitability (0..10) for common real-world usage scenarios.
type Scenario struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Max    int    `json:"max"`
	Status string `json:"status"`
	Tone   string `json:"tone"` // good | warn | poor | bad
	Detail string `json:"detail,omitempty"`
}

// NeighborDensity measures how many addresses in the enclosing /24 (IPv4) or
// /48 (IPv6) appear in loaded abuse, proxy, VPN or Tor datasets.
type NeighborDensity struct {
	Prefix     string   `json:"prefix"`
	Flagged    int      `json:"flagged"`
	Total      int      `json:"total,omitempty"` // 256 for IPv4 /24; omitted for IPv6 block counts
	DensityPct float64  `json:"density_pct,omitempty"`
	Level      string   `json:"level"` // 纯净网段 | 轻度连带 | 中度污染 | 高危脏段
	Categories []string `json:"categories,omitempty"`
	ListsLoaded int     `json:"lists_loaded"`
}

// LeaseCheck identifies IP leasing brokers (IPXO, InterLIR, Cloud Innovation, etc.).
type LeaseCheck struct {
	Leased bool   `json:"leased"`
	Broker string `json:"broker,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// FlowAudit cross-checks claimed residential ISP types against PeeringDB
// traffic direction and leasing signals.
type FlowAudit struct {
	TrafficRatio string `json:"traffic_ratio,omitempty"`
	RatioLabel   string `json:"ratio_label,omitempty"`
	Masquerade   bool   `json:"masquerade"`
	Detail       string `json:"detail,omitempty"`
}

// ThreatActivity summarises concrete automated/attack telemetry across
// StopForumSpam, SANS DShield, AlienVault OTX and Tor Onionoo.
type ThreatActivity struct {
	SpamReports    int      `json:"spam_reports,omitempty"`
	SpamLastSeen   string   `json:"spam_last_seen,omitempty"`
	DShieldPackets int      `json:"dshield_packets,omitempty"`
	DShieldTargets int      `json:"dshield_targets,omitempty"`
	OTXPulses      int      `json:"otx_pulses,omitempty"`
	OTXNames       []string `json:"otx_names,omitempty"`
	TorRelay       bool     `json:"tor_relay,omitempty"`
	TorExit        bool     `json:"tor_exit,omitempty"`
	TorNicknames   []string `json:"tor_nicknames,omitempty"`
	TorNeighbors   int      `json:"tor_neighbors,omitempty"`
}

// ActiveProbe is returned by /api/probe for on-demand visitor connection and
// exit :443 TLS / Reality masquerade inspection.
type ActiveProbe struct {
	IP           string        `json:"ip"`
	Version      int           `json:"version"`
	QueriedAt    string        `json:"queried_at"`
	RequestProbe *RequestProbe `json:"request_probe,omitempty"`
	TLS443       *TLS443Probe  `json:"tls443,omitempty"`
}

// TLS443Probe inspects the visitor's own public exit IP on TCP/443 to detect
// open proxy services or borrowed-SNI Reality/ShadowTLS certificates.
type TLS443Probe struct {
	Probed         bool     `json:"probed"`
	PortOpen       bool     `json:"port_open"`
	TLSActive      bool     `json:"tls_active"`
	TLSVersion     string   `json:"tls_version,omitempty"`
	SubjectCN      string   `json:"subject_cn,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	SANs           []string `json:"sans,omitempty"`
	SelfSigned     bool     `json:"self_signed,omitempty"`
	RealitySuspect bool     `json:"reality_suspect,omitempty"`
	RealityBrand   string   `json:"reality_brand,omitempty"`
	RealityDomain  string   `json:"reality_domain,omitempty"`
	Verdict        string   `json:"verdict"` // closed | open_tls | open_non_tls | reality_suspect | skipped
	Detail         string   `json:"detail,omitempty"`
	RTTMs          int64    `json:"rtt_ms,omitempty"`
}
