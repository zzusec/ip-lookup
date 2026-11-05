package sources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zzusec/ip-lookup/internal/classify"
	"github.com/zzusec/ip-lookup/internal/model"
)

type ipdataTransport func(*http.Request) (*http.Response, error)

func (f ipdataTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func ipdataClient(f ipdataTransport) *Client {
	return &Client{HTTP: &http.Client{Transport: f}, UA: "ip-lookup-test"}
}

func ipdataReply(status int, raw string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(raw))}
}

func TestIPDataFetchExactIP(t *testing.T) {
	const key = "fake-key+with/symbols?"
	for _, addr := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		t.Run(addr, func(t *testing.T) {
			q := Query{Addr: netip.MustParseAddr(addr)}
			c := ipdataClient(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "api.ipdata.co" || r.URL.Path != "/"+addr {
					t.Errorf("request = %s %s", r.Method, r.URL.Redacted())
				}
				if strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%3a") {
					t.Errorf("IPv6 colons escaped in %q", r.URL.EscapedPath())
				}
				if r.URL.Query().Get("api-key") != key || len(r.URL.Query()) != 1 {
					t.Error("API key query was not encoded correctly")
				}
				if r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") != "ip-lookup-test" {
					t.Errorf("headers = %v", r.Header)
				}
				return ipdataReply(200, fmt.Sprintf(`{"ip":%q,"country_code":"US"}`, addr)), nil
			})
			p := ipdata(key)
			raw, err := p.Fetch(context.Background(), c, q)
			if err != nil {
				t.Fatal(err)
			}
			o := &Out{Res: &model.Result{}}
			if err := p.Apply(o, q, raw); err != nil || len(o.Res.GeoSources) != 1 || o.Res.GeoSources[0].CountryCode != "US" {
				t.Fatalf("Fetch/Apply = %+v, %v", o.Res.GeoSources, err)
			}
		})
	}
}

func TestIPDataBudgetAndTimeout(t *testing.T) {
	p := ipdata("fake-key")
	if p.Name != "ipdata.co" || p.Homepage != "https://ipdata.co" || p.Kind != "online" || !p.Keyed || p.V4Only ||
		p.TTL != 24*time.Hour || p.Timeout != 6*time.Second || p.Limit.Label != "100/天（共享额度自限）" || p.Limit.window != 24*time.Hour {
		t.Fatalf("provider configuration = %+v", p)
	}
	for i := range 100 {
		if !p.Limit.Take() {
			t.Fatalf("request %d denied before daily budget", i+1)
		}
	}
	if p.Limit.Take() {
		t.Error("request 101 exceeded the self-imposed shared budget")
	}
	c := ipdataClient(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	p = ipdata("fake-key")
	st := NewSet(c, []*Provider{p}).one(ctx, p, Query{Addr: netip.MustParseAddr("8.8.8.8")}, &Out{Res: &model.Result{}})
	if st.Status != "timeout" || strings.Contains(st.Error, "fake-key") {
		t.Fatalf("source = %+v", st)
	}
}

func TestIPDataFetchSafeErrors(t *testing.T) {
	const key = "fake-secret+with/symbols?"
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	for _, status := range []int{401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			p := ipdata(key)
			c := ipdataClient(func(r *http.Request) (*http.Response, error) {
				return ipdataReply(status, `{"message":"`+key+` upstream private error"}`), nil
			})
			_, err := p.Fetch(context.Background(), c, q)
			if err == nil || strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "upstream private error") {
				t.Fatalf("unsafe or missing error = %v", err)
			}
			if got := errors.Is(err, ErrQuota); got != (status == 403 || status == 429) {
				t.Errorf("quota = %v for HTTP %d", got, status)
			}
			if status == 401 && !strings.Contains(err.Error(), "authentication") {
				t.Errorf("401 did not report authentication failure: %v", err)
			}
			if status == 404 && !errors.Is(err, ErrNotFound) {
				t.Errorf("404 = %v", err)
			}
		})
	}
	c := ipdataClient(func(r *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: r.URL.String(), Err: fmt.Errorf("transport failed for %s (%s)", r.URL, key)}
	})
	_, err := ipdata(key).Fetch(context.Background(), c, q)
	if err == nil || strings.Contains(err.Error(), key) || strings.Contains(err.Error(), url.QueryEscape(key)) {
		t.Fatalf("network error leaked API key: %v", err)
	}
	called := false
	c = ipdataClient(func(r *http.Request) (*http.Response, error) {
		called = true
		return ipdataReply(200, `{}`), nil
	})
	if _, err := ipdata("").Fetch(context.Background(), c, q); err == nil || called {
		t.Fatalf("empty key: err=%v, requested=%t", err, called)
	}
}

func TestIPDataApplyDetails(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	selectedGeo := model.Geo{Country: "已选国家", CountryCode: "ZZ", Region: "已选地区", City: "已选城市",
		Lat: 40.7, Lon: -73.9}
	o := &Out{Res: &model.Result{Geo: selectedGeo}}
	raw := []byte(`{"ip":"8.8.8.8","country_name":"United States","country_code":"US","region":"California","city":"Mountain View","postal":"94043","latitude":37.386,"longitude":-122.084,"time_zone":{"name":"America/Los_Angeles"},"asn":{"asn":"AS15169","name":"Google LLC","domain":"google.com","route":"8.8.8.0/24","type":"hosting"},"company":{"name":"Google Public DNS","network":"8.8.8.0/24","type":"hosting"},"threat":{"is_datacenter":true,"scores":{"trust_score":73,"vpn_score":100,"proxy_score":100,"threat_score":100}}}`)
	if err := ipdata("fake-key").Apply(o, q, raw); err != nil {
		t.Fatal(err)
	}
	if len(o.Res.GeoSources) != 1 {
		t.Fatalf("GeoSources = %+v", o.Res.GeoSources)
	}
	g := o.Res.GeoSources[0]
	if g.Source != "ipdata.co" || g.Country != "United States" || g.Region != "California" || g.City != "Mountain View" || g.CountryCode != "US" ||
		g.ASN != 15169 || g.ISP != "Google LLC" || g.Org != "Google Public DNS" || g.Lat != 37.386 || g.Lon != -122.084 {
		t.Errorf("geographic/ASN evidence = %+v", g)
	}
	n := o.Res.Network
	if n.ASN != 15169 || n.ASName != "Google LLC" || n.ASDomain != "google.com" || n.Prefix != "8.8.8.0/24" || n.NetRange != "8.8.8.0/24" || n.UsageType != "hosting" {
		t.Errorf("network = %+v", n)
	}
	if o.Res.Geo != selectedGeo {
		t.Errorf("selected geography = %+v, want %+v", o.Res.Geo, selectedGeo)
	}
	if len(o.Res.Risk) != 1 || o.Res.Risk[0].Value != 27 {
		t.Errorf("trust-derived risk = %+v", o.Res.Risk)
	}
	if got := classify.Totals(o.Sig)["hosting"]; got != 60 {
		t.Errorf("same provider's hosting weight = %d, want 60", got)
	}
	if hints := o.Hints(); len(hints) != 1 || hints["geo_cc:ipdata"] != "US" {
		t.Errorf("geography provenance hints = %v", hints)
	}
	t.Run("empty geography receives fallback", func(t *testing.T) {
		o := &Out{Res: &model.Result{}}
		if err := ipdata("fake-key").Apply(o, q, raw); err != nil {
			t.Fatal(err)
		}
		want := model.Geo{Country: "United States", CountryCode: "US", Region: "California", City: "Mountain View",
			Lat: 37.386, Lon: -122.084, Postal: "94043", TimeZone: "America/Los_Angeles"}
		if o.Res.Geo != want {
			t.Errorf("fallback geography = %+v, want %+v", o.Res.Geo, want)
		}
	})
	t.Run("partial coordinates remain paired", func(t *testing.T) {
		selected := model.Geo{Lat: 40.7}
		o := &Out{Res: &model.Result{Geo: selected}}
		if err := ipdata("fake-key").Apply(o, q, raw); err != nil {
			t.Fatal(err)
		}
		if o.Res.Geo != selected {
			t.Errorf("partially selected geography was changed: %+v, want %+v", o.Res.Geo, selected)
		}
	})
}

func TestIPDataGeoCountryConsistency(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	fullUS := model.Geo{Country: "United States", CountryCode: "US", Region: "California", City: "Mountain View",
		Lat: 37.386, Lon: -122.084, Postal: "94043", TimeZone: "America/Los_Angeles"}
	for _, c := range []struct {
		name       string
		selected   model.Geo
		providerCC string
		want       model.Geo
	}{
		{"different countries", model.Geo{Country: "中国", CountryCode: "CN"}, "US", model.Geo{Country: "中国", CountryCode: "CN"}},
		{"partial ip2region location without country", model.Geo{Region: "广东", City: "深圳"}, "US", model.Geo{Region: "广东", City: "深圳"}},
		{"selected country name without code", model.Geo{Country: "United States"}, "US", model.Geo{Country: "United States"}},
		{"provider country name without code", model.Geo{Country: "United States", CountryCode: "US"}, "", model.Geo{Country: "United States", CountryCode: "US"}},
		{"same country code ignores case", model.Geo{Country: "美国", CountryCode: "us"}, "US",
			model.Geo{Country: "美国", CountryCode: "us", Region: fullUS.Region, City: fullUS.City, Lat: fullUS.Lat, Lon: fullUS.Lon, Postal: fullUS.Postal, TimeZone: fullUS.TimeZone}},
		{"no selected country", model.Geo{}, "US", fullUS},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"ip":"8.8.8.8","country_name":"United States","country_code":%q,"region":"California","city":"Mountain View","postal":"94043","latitude":37.386,"longitude":-122.084,"time_zone":{"name":"America/Los_Angeles"},"asn":{"asn":"AS15169","name":"Google LLC"}}`, c.providerCC))
			o := &Out{Res: &model.Result{Geo: c.selected}}
			if err := ipdata("fake-key").Apply(o, q, raw); err != nil {
				t.Fatal(err)
			}
			if o.Res.Geo != c.want {
				t.Errorf("selected geography = %+v, want %+v", o.Res.Geo, c.want)
			}
			if len(o.Res.GeoSources) != 1 || o.Res.GeoSources[0].Region != fullUS.Region || o.Res.GeoSources[0].City != fullUS.City ||
				o.Res.GeoSources[0].Lat != fullUS.Lat || o.Res.GeoSources[0].Lon != fullUS.Lon || o.Res.Network.ASN != 15169 {
				t.Errorf("provider geography or network evidence lost: %+v, %+v", o.Res.GeoSources, o.Res.Network)
			}
		})
	}
}

func TestIPDataNullableResponseShape(t *testing.T) {
	// Public fixture matching the observed API shape: nullable location and
	// organization objects, explicit negative flags, no VPN field or scores.
	raw := []byte(`{"ip":"8.8.8.8","country_name":"United States","country_code":"US","region":null,"city":null,"postal":null,"latitude":38.0,"longitude":-97.0,"time_zone":{"name":"America/Chicago"},"asn":{"asn":"AS15169","name":"Google LLC","domain":"google.com","route":"8.8.8.0/24","type":"hosting"},"company":null,"carrier":null,"threat":{"is_tor":false,"is_icloud_relay":false,"is_proxy":false,"is_datacenter":false,"is_anonymous":false,"is_known_attacker":false,"is_known_abuser":false,"is_threat":false,"is_bogon":false}}`)
	o := &Out{Res: &model.Result{}}
	if err := ipdata("fake-key").Apply(o, Query{Addr: netip.MustParseAddr("8.8.8.8")}, raw); err != nil {
		t.Fatal(err)
	}
	if len(o.Res.GeoSources) != 1 || o.Res.GeoSources[0].ASN != 15169 || o.Res.Network.ASN != 15169 {
		t.Errorf("geographic/ASN evidence = %+v, %+v", o.Res.GeoSources, o.Res.Network)
	}
	want := model.Geo{Country: "United States", CountryCode: "US", Lat: 38, Lon: -97, TimeZone: "America/Chicago"}
	if o.Res.Geo != want || o.Res.Network.Org != "" {
		t.Errorf("nullable fields should remain unknown: geo=%+v, network=%+v", o.Res.Geo, o.Res.Network)
	}
	if len(o.Res.Risk) != 0 {
		t.Errorf("missing scores produced risk: %+v", o.Res.Risk)
	}
	if got := classify.Totals(o.Sig); !reflect.DeepEqual(got, map[string]int{"hosting": 40}) {
		t.Errorf("negative or missing safety fields produced signals: %v", got)
	}
	if o.Res.Native != (model.Native{}) {
		t.Errorf("geolocation inferred registration: %+v", o.Res.Native)
	}
}

func TestIPDataApplyRejectsInvalidResponse(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{"message":"fake-secret"}`, `{"ip":"8.8.8.8"}`, `{"ip":"8.8.4.4","country_code":"US","threat":{"is_tor":true}}`,
		`{"ip":"invalid","country_name":"United States"}`, `{"country_name":"United States"}`, `{"ip":8,"country_name":"United States"}`,
		`{"ip":"8.8.8.8","country_name":"United States","message":"fake-secret"}`, `{"ip":"8.8.8.8","error":true,"threat":{"is_tor":true}}`,
		`{"ip":"8.8.8.8","country_name":{},"threat":{"is_tor":true}}`, `{"ip":"8.8.8.8","country_code":"US","latitude":"37.3"}`,
		`{"ip":"8.8.8.8","country_code":"US","asn":{"asn":15169}}`, `{"ip":"8.8.8.8","country_code":"US","company":[]}`,
		`{"ip":"8.8.8.8","country_code":"US","threat":{"is_tor":"false"}}`, `{"ip":"8.8.8.8","country_code":"US","threat":{"scores":{"trust_score":"0"}}}`,
		`{"ip":"8.8.8.8","country_code":"US","threat":{"scores":{"trust_score":0.5}}}`, `{"ip":"8.8.8.8","country_code":"US","threat":`,
	} {
		t.Run(raw, func(t *testing.T) {
			o := &Out{Res: &model.Result{}}
			err := ipdata("fake-secret").Apply(o, q, []byte(raw))
			if err == nil || strings.Contains(err.Error(), "fake-secret") {
				t.Fatalf("invalid response error = %v", err)
			}
			if !reflect.DeepEqual(o.Res, &model.Result{}) || len(o.Sig) != 0 || len(o.Hints()) != 0 {
				t.Fatalf("invalid response polluted output: %+v, %v, %v", o.Res, o.Sig, o.Hints())
			}
		})
	}
	// IPv4-mapped and unmapped forms identify the same address.
	o := &Out{Res: &model.Result{}}
	if err := ipdata("fake-key").Apply(o, q, []byte(`{"ip":"::ffff:8.8.8.8","country_code":"US"}`)); err != nil {
		t.Fatalf("mapped IPv4 response: %v", err)
	}
}

func TestIPDataTrustRisk(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	for _, c := range []struct {
		score string
		want  []int
	}{
		{"0", []int{100}}, {"100", []int{0}}, {"27", []int{73}}, {"null", nil}, {"-1", nil}, {"101", nil},
	} {
		t.Run(c.score, func(t *testing.T) {
			o := &Out{Res: &model.Result{}}
			raw := []byte(`{"ip":"8.8.8.8","country_code":"US","threat":{"scores":{"trust_score":` + c.score + `}}}`)
			if err := ipdata("fake-key").Apply(o, q, raw); err != nil {
				t.Fatal(err)
			}
			var got []int
			for _, risk := range o.Res.Risk {
				got = append(got, risk.Value)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("risk = %v, want %v", got, c.want)
			}
		})
	}
}

func TestIPDataTypesAndSecurity(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	for _, c := range []struct {
		name, fields string
		want         map[string]int
	}{
		{"dual ISP", `"asn":{"type":"isp"},"company":{"type":"isp"}`, map[string]int{"residential": 50}},
		{"hosting types", `"asn":{"type":"hosting"},"company":{"type":"hosting"}`, map[string]int{"hosting": 50}},
		{"explicit data center", `"asn":{"type":"isp"},"company":{"type":"isp"},"threat":{"is_datacenter":true}`, map[string]int{"hosting": 60}},
		{"carrier is mobile", `"asn":{"type":"isp"},"company":{"type":"isp"},"carrier":{"name":"Example Mobile"}`, map[string]int{"mobile": 60}},
		{"security flags", `"threat":{"is_tor":true,"is_vpn":true,"is_proxy":true,"is_icloud_relay":true,"is_known_attacker":true,"is_known_abuser":true,"is_threat":true}`, map[string]int{"tor": 80, "vpn": 60, "proxy": 60, "icloud_relay": 60, "abuser": 60}},
		{"explicit false", `"threat":{"is_tor":false,"is_vpn":false,"is_proxy":false,"is_icloud_relay":false,"is_datacenter":false,"is_known_attacker":false,"is_known_abuser":false,"is_threat":false}`, map[string]int{}},
		{"anonymous is not a VPN inference", `"country_code":"US","threat":{"is_anonymous":true}`, map[string]int{}},
		{"geography is not a clean verdict", `"country_code":"US"`, map[string]int{}},
		{"missing flags remain unknown", `"country_code":"US","threat":{"is_tor":null,"scores":{}}`, map[string]int{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := &Out{Res: &model.Result{}}
			raw := []byte(`{"ip":"8.8.8.8",` + c.fields + `}`)
			if err := ipdata("fake-key").Apply(o, q, raw); err != nil {
				t.Fatal(err)
			}
			if got := classify.Totals(o.Sig); !reflect.DeepEqual(got, c.want) {
				t.Errorf("signal totals = %v, want %v", got, c.want)
			}
			if len(o.Res.Risk) != 0 {
				t.Errorf("missing score produced risk: %+v", o.Res.Risk)
			}
		})
	}
}

func TestIPDataOptionalFieldFormats(t *testing.T) {
	q := Query{Addr: netip.MustParseAddr("8.8.8.8")}
	o := &Out{Res: &model.Result{}}
	raw := []byte(`{"ip":"8.8.8.8","country_name":"United States","country_code":"USA","latitude":91,"longitude":-181,"time_zone":{"name":"invalid/timezone"},"city":"bad\u0000city","asn":{"asn":"AS-1","domain":"https://example.com/path","route":"not a CIDR"},"company":{"network":"1.1.1.0/24"}}`)
	if err := ipdata("fake-key").Apply(o, q, raw); err != nil {
		t.Fatal(err)
	}
	g := o.Res.GeoSources[0]
	if g.CountryCode != "" || g.City != "" || g.ASN != 0 || g.Lat != 0 || g.Lon != 0 || o.Res.Geo.TimeZone != "" || !reflect.DeepEqual(o.Res.Network, model.Network{}) {
		t.Errorf("invalid optional formats were retained: %+v, %+v, %+v", g, o.Res.Geo, o.Res.Network)
	}
	o = &Out{Res: &model.Result{}}
	if err := ipdata("fake-key").Apply(o, q, []byte(`{"ip":"8.8.8.8","latitude":0,"longitude":0}`)); err != nil {
		t.Errorf("valid zero coordinates rejected: %v", err)
	}
}
