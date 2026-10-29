// Package model defines the JSON documents served by the HTTP API.
package model

// Result is the full report for one IP address.
type Result struct {
	IP         string      `json:"ip"`
	Version    int         `json:"version"`
	Bogon      string      `json:"bogon,omitempty"`
	Mode       string      `json:"mode"`
	QueriedAt  string      `json:"queried_at"`
	ElapsedMs  int64       `json:"elapsed_ms"`
	Verdict    Verdict     `json:"verdict"`
	Score      Score       `json:"score"`
	Flags      Flags       `json:"flags"`
	Native     Native      `json:"native"`
	Geo        Geo         `json:"geo"`
	Network    Network     `json:"network"`
	GeoSources []GeoSource `json:"geo_sources"`
	Lists      []ListHit   `json:"lists"`
	DNSBL      []DNSBL     `json:"dnsbl"`
	Risk       []Risk      `json:"risk"`
	Ports      *Ports      `json:"ports,omitempty"`
	Sources    []Source    `json:"sources"`
}

// Signal is one piece of evidence about what kind of address this is.
// Kind is a network type (residential, mobile, hosting, cdn, business,
// education, government) or a usage flag (tor, vpn, proxy, crawler, abuser,
// icloud_relay, public_service, anycast, satellite).
type Signal struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Detail string `json:"detail,omitempty"`
	Weight int    `json:"weight"`
}

type Verdict struct {
	Type        string   `json:"type"`
	TypeLabel   string   `json:"type_label"`
	Usage       []string `json:"usage"`
	UsageLabels []string `json:"usage_labels"`
	Label       string   `json:"label"`
	Confidence  string   `json:"confidence"`
	Evidence    []Signal `json:"evidence"`
}

type Score struct {
	Value   int      `json:"value"`
	Level   string   `json:"level"`
	Factors []Factor `json:"factors"`
}

type Factor struct {
	Name  string `json:"name"`
	Delta int    `json:"delta"`
}

type Flags struct {
	Tor           bool `json:"is_tor"`
	VPN           bool `json:"is_vpn"`
	Proxy         bool `json:"is_proxy"`
	Hosting       bool `json:"is_hosting"`
	CDN           bool `json:"is_cdn"`
	Mobile        bool `json:"is_mobile"`
	Residential   bool `json:"is_residential"`
	Crawler       bool `json:"is_crawler"`
	Abuser        bool `json:"is_abuser"`
	ICloudRelay   bool `json:"is_icloud_relay"`
	PublicService bool `json:"is_public_service"`
	Anycast       bool `json:"is_anycast"`
	Satellite     bool `json:"is_satellite"`
}

// Native compares the registration country with the geolocated country.
type Native struct {
	Status            string `json:"status"` // native | broadcast | unknown
	Label             string `json:"label"`
	RegisteredCountry string `json:"registered_country,omitempty"`
	GeoCountry        string `json:"geo_country,omitempty"`
	Registry          string `json:"registry,omitempty"`
	Detail            string `json:"detail,omitempty"`
}

type Geo struct {
	Continent     string  `json:"continent,omitempty"`
	ContinentCode string  `json:"continent_code,omitempty"`
	Country       string  `json:"country,omitempty"`
	CountryEN     string  `json:"country_en,omitempty"`
	CountryCode   string  `json:"country_code,omitempty"`
	Region        string  `json:"region,omitempty"`
	RegionEN      string  `json:"region_en,omitempty"`
	RegionCode    string  `json:"region_code,omitempty"`
	City          string  `json:"city,omitempty"`
	CityEN        string  `json:"city_en,omitempty"`
	District      string  `json:"district,omitempty"`
	Postal        string  `json:"postal,omitempty"`
	Lat           float64 `json:"lat,omitempty"`
	Lon           float64 `json:"lon,omitempty"`
	AccuracyKm    int     `json:"accuracy_km,omitempty"`
	TimeZone      string  `json:"time_zone,omitempty"`
	UTCOffset     string  `json:"utc_offset,omitempty"`
	Currency      string  `json:"currency,omitempty"`
	CallingCode   string  `json:"calling_code,omitempty"`
	Flag          string  `json:"flag,omitempty"`
	IsEU          bool    `json:"is_eu,omitempty"`
}

type Network struct {
	ASN        int        `json:"asn,omitempty"`
	ASName     string     `json:"as_name,omitempty"`
	ASDomain   string     `json:"as_domain,omitempty"`
	ASCountry  string     `json:"as_country,omitempty"`
	ASClass    string     `json:"as_class,omitempty"`
	ASTags     []string   `json:"as_tags,omitempty"`
	Org        string     `json:"org,omitempty"`
	ISP        string     `json:"isp,omitempty"`
	Prefix     string     `json:"prefix,omitempty"`
	BGPPrefix  string     `json:"bgp_prefix,omitempty"`
	NetName    string     `json:"net_name,omitempty"`
	NetRange   string     `json:"net_range,omitempty"`
	Registry   string     `json:"registry,omitempty"`
	Allocated  string     `json:"allocated,omitempty"`
	RDNS       []string   `json:"rdns,omitempty"`
	FCrDNS     *bool      `json:"fcrdns,omitempty"` // nil when rDNS came from a provider and was not verified
	UsageType  string     `json:"usage_type,omitempty"`
	RPKI       string     `json:"rpki,omitempty"`
	Visibility string     `json:"visibility,omitempty"`
	Abuse      string     `json:"abuse,omitempty"`
	Domains    []string   `json:"domains,omitempty"`
	PeeringDB  *PeeringDB `json:"peeringdb,omitempty"`
}

type PeeringDB struct {
	Name        string `json:"name,omitempty"`
	InfoType    string `json:"info_type,omitempty"`
	InfoTraffic string `json:"info_traffic,omitempty"`
	InfoScope   string `json:"info_scope,omitempty"`
	InfoRatio   string `json:"info_ratio,omitempty"`
	Website     string `json:"website,omitempty"`
	IRRASSet    string `json:"irr_as_set,omitempty"`
	Policy      string `json:"policy,omitempty"`
	IXCount     int    `json:"ix_count,omitempty"`
	FacCount    int    `json:"fac_count,omitempty"`
}
