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

// Risk is a provider's risk figure normalised to 0..100, higher is worse.
type Risk struct {
	Source string `json:"source"`
	Value  int    `json:"value"`
	Detail string `json:"detail,omitempty"`
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
	Name   string `json:"name"`
	Kind   string `json:"kind"`   // offline | online | dns
	Status string `json:"status"` // ok | empty | error | timeout | skipped | quota
	Ms     int64  `json:"ms"`
	Error  string `json:"error,omitempty"`
	Cached bool   `json:"cached,omitempty"`
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
