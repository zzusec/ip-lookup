package sources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

func TestRoutingStatusReportsOnlyExactOrigins(t *testing.T) {
	query := Query{Addr: netip.MustParseAddr("2001:db8::123")}
	for _, tc := range []struct {
		name, origins string
		want          []uint32
		asn           int
	}{
		{"multiple", `[{"origin":64502},{"origin":64501},{"origin":64502}]`, []uint32{64501, 64502}, 0},
		{"single", `[{"origin":64502}]`, []uint32{64502}, 64502},
		{"not observed", `[]`, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := &Out{Res: &model.Result{}}
			raw := `{"data":{"resource":"2001:db8::/48","visibility":{"v6":{"ris_peers_seeing":8,"total_ris_peers":9}},"origins":` + tc.origins + `,"less_specifics":[{"origin":64500}]}}`
			if err := ripeRouting().Apply(out, query, []byte(raw)); err != nil {
				t.Fatal(err)
			}
			network := out.Res.Network
			if !slices.Equal(network.BGPOrigins, tc.want) || network.ASN != tc.asn || network.BGPPrefix != "2001:db8::/48" || len(out.Sig) != 0 {
				t.Fatalf("unexpected route evidence: %+v, signals %+v", network, out.Sig)
			}
			if (out.Hints()["origin_asn:ripe"] != "") != (tc.asn > 0) {
				t.Fatalf("arbitrary or missing origin: %+v", out.Hints())
			}
		})
	}
	out := &Out{Res: &model.Result{}}
	wrong := []byte(`{"data":{"resource":"2001:db8:55::/48","visibility":{"v6":{"total_ris_peers":3}},"origins":[{"origin":64502}]}}`)
	if err := ripeRouting().Apply(out, query, wrong); err == nil || out.Res.Network.BGPPrefix != "" {
		t.Fatal("an unrelated prefix was reported for the query")
	}
}

func TestTelemetryDistinguishesZeroFromMissing(t *testing.T) {
	query := Query{Addr: netip.MustParseAddr("192.0.2.1")}
	for _, raw := range []string{`{"success":1,"ip":{}}`, `{"success":1,"ip":{"appears":1}}`} {
		out := &Out{Res: &model.Result{}}
		if err := stopForumSpam().Apply(out, query, []byte(raw)); err == nil || len(out.Hints()) != 0 {
			t.Fatal("incomplete telemetry became a negative spam observation")
		}
	}
	for _, raw := range []string{`{"ip":{"number":"192.0.2.1","assize":42}}`, `{"ip":{"number":"192.0.2.1","count":0}}`} {
		out := &Out{Res: &model.Result{}}
		if err := sansDShield().Apply(out, query, []byte(raw)); err != nil {
			t.Fatal(err)
		}
		gotCount := out.Res.Audit != nil && out.Res.Audit.Activity != nil && out.Res.Audit.Activity.DShieldCountKnown
		if gotCount != strings.Contains(raw, `"count"`) {
			t.Fatalf("wrong observation for %s", raw)
		}
	}
}

func TestExtendedProvidersAndReputation(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.10")
	q := Query{Addr: addr, ASN: 13335}

	// 1. IPQuery
	ipqRaw := []byte(`{"ip":"203.0.113.10","isp":{"asn":"AS13335","org":"Example Net","isp":"Example ISP"},"location":{"country":"Japan","country_code":"JP","city":"Tokyo","state":"Tokyo"},"risk":{"is_mobile":false,"is_vpn":true,"is_tor":false,"is_proxy":false,"is_datacenter":true,"risk_score":62}}`)
	if !reputationData("IPQuery", ipqRaw, addr) {
		t.Fatal("IPQuery reputationData should be true")
	}
	o := &Out{Res: &model.Result{}}
	if err := ipQuery().Apply(o, q, ipqRaw); err != nil {
		t.Fatalf("ipQuery Apply: %v", err)
	}
	if len(o.Res.Risk) != 1 || o.Res.Risk[0].Value != 62 {
		t.Fatalf("IPQuery risk = %+v", o.Res.Risk)
	}

	// 2. IPinfo Blackbox
	bbRaw := []byte(`{"ip":"203.0.113.10","error":null,"classification":"hosting","confidence":0.9,"asn":{"name":"Example","number":13335,"network":"203.0.113.0","cidr":24},"rdns":{"hostname":"srv1.example.com"},"signals":{"hosting":true,"proxy":false,"tor":false}}`)
	if !reputationData("IPinfo Blackbox", bbRaw, addr) {
		t.Fatal("IPinfo Blackbox reputationData should be true")
	}
	if err := blackbox().Apply(o, q, bbRaw); err != nil {
		t.Fatalf("blackbox Apply: %v", err)
	}
	if o.Hints()["rdns:blackbox"] != "srv1.example.com" || o.Res.Network.Prefix != "203.0.113.0/24" {
		t.Fatalf("blackbox metadata missing: %+v / %+v", o.Hints(), o.Res.Network)
	}

	// 3. StopForumSpam (clean and listed)
	sfsClean := []byte(`{"success":1,"ip":{"appears":0,"frequency":0}}`)
	if !reputationData("StopForumSpam", sfsClean, addr) {
		t.Fatal("StopForumSpam clean response is valid reputation data")
	}
	sfsHit := []byte(`{"success":1,"ip":{"appears":1,"frequency":14,"lastseen":"2026-11-20 10:00:00","torexit":0}}`)
	if err := stopForumSpam().Apply(o, q, sfsHit); err != nil {
		t.Fatalf("stopForumSpam Apply: %v", err)
	}
	if o.Res.Audit == nil || o.Res.Audit.Activity == nil || o.Res.Audit.Activity.SpamReports != 14 {
		t.Fatalf("StopForumSpam activity not recorded: %+v", o.Res.Audit)
	}

	// 4. SANS DShield (including assize fallback)
	dsRaw := []byte(`{"ip":{"number":"203.0.113.10","count":45,"attacks":7,"assize":91136,"asabusecontact":"abuse@example.net"}}`)
	if err := sansDShield().Apply(o, q, dsRaw); err != nil {
		t.Fatalf("sansDShield Apply: %v", err)
	}
	if o.Res.Audit.Activity.DShieldPackets != 45 || o.Res.Network.Abuse != "abuse@example.net" || o.Res.Network.ASIPv4Count != 91136 {
		t.Fatalf("DShield not applied: %+v / %+v", o.Res.Audit.Activity, o.Res.Network)
	}

	// 4b. RIPEstat AS space & RDAP ASN autnum
	spaceRaw := []byte(`{"data":{"prefixes":[{"prefix":"203.0.113.0/24"},{"prefix":"203.0.113.128/25"},{"prefix":"2001:db8::/32"}]}}`)
	oSpace := &Out{Res: &model.Result{}}
	if err := asnSpace().Apply(oSpace, q, spaceRaw); err != nil {
		t.Fatalf("asnSpace Apply: %v", err)
	}
	if oSpace.Res.Network.ASIPv4Count != 256 || oSpace.Res.Network.ASPrefixesV4 != 2 || oSpace.Res.Network.ASPrefixesV6 != 1 {
		t.Fatalf("asnSpace deduplicated count mismatch: %+v", oSpace.Res.Network)
	}
	autnumRaw := []byte(`{"name":"DMIT-AS","country":"US","port43":"whois.arin.net","events":[{"eventAction":"registration","eventDate":"2022-06-10T00:00:00Z"}]}`)
	if err := rdapASN().Apply(oSpace, q, autnumRaw); err != nil || oSpace.Res.Network.ASCreated != "2022-06-10" {
		t.Fatalf("rdapASN Apply: %v / %+v", err, oSpace.Res.Network)
	}

	// 5. AlienVault OTX whitelist ignore vs real pulse
	otxWhite := []byte(`{"false_positive":false,"validation":[{"source":"whitelist","name":"Known CDN"}],"pulse_info":{"count":5,"pulses":[{"name":"scan"}]}}`)
	o2 := &Out{Res: &model.Result{}}
	if err := alienVaultOTX().Apply(o2, q, otxWhite); err != nil {
		t.Fatalf("OTX whitelist Apply: %v", err)
	}
	if o2.Res.Audit != nil {
		t.Fatalf("whitelisted OTX entry must not create threat activity: %+v", o2.Res.Audit)
	}
	otxHit := []byte(`{"false_positive":[],"pulse_info":{"count":4,"pulses":[{"name":"SSH Brute"}]}}`)
	if err := alienVaultOTX().Apply(o, q, otxHit); err != nil || o.Res.Audit.Activity.OTXPulses != 4 {
		t.Fatalf("OTX hit with array false_positive failed: %v / %+v", err, o.Res.Audit.Activity)
	}
	otxAcceptedFP := []byte(`{"false_positive":[{"assessment":"accepted"}],"pulse_info":{"count":6,"pulses":[{"name":"Noise"}]}}`)
	oFP := &Out{Res: &model.Result{}}
	if err := alienVaultOTX().Apply(oFP, q, otxAcceptedFP); err != nil || oFP.Res.Audit != nil {
		t.Fatalf("OTX accepted false_positive array must be ignored: %v / %+v", err, oFP.Res.Audit)
	}

	// 6. Tor Onionoo
	torRaw := []byte(`{"relays":[{"nickname":"TestExit","or_addresses":["203.0.113.10:9001"],"exit_addresses":["203.0.113.10"],"flags":["Exit","Running"]},{"nickname":"NeighborRelay","or_addresses":["203.0.113.99:9001"],"flags":["Running"]}]}`)
	if err := torOnionoo().Apply(o, q, torRaw); err != nil {
		t.Fatalf("torOnionoo Apply: %v", err)
	}
	if !o.Res.Audit.Activity.TorExit || o.Res.Audit.Activity.TorNeighbors != 1 {
		t.Fatalf("Tor Onionoo activity mismatch: %+v", o.Res.Audit.Activity)
	}

	// 7. Cloudflare Radar combined payload & token redaction
	radarCombo := []byte(`{"bot":{"success":true,"result":{"summary_0":{"human":"81.24","bot":"18.76"}}},"device":{"success":true,"result":{"summary_0":{"desktop":"64.1","mobile":"35.9"}}}}`)
	if err := applyCloudflareRadar(o, q, radarCombo); err != nil {
		t.Fatalf("applyCloudflareRadar: %v", err)
	}
	tr := o.Res.Traffic
	if tr == nil || tr.Mode != "radar" || tr.HumanPct != 81.2 || tr.BotPct != 18.8 || tr.DesktopPct == nil || *tr.DesktopPct != 64.1 {
		t.Fatalf("Cloudflare Radar traffic = %+v", tr)
	}

	// Ensure secret token never leaks on error
	secret := "cf-secret-radar-token-xyz"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p := cloudflareRadar(secret)
	_, err := p.Fetch(context.Background(), &Client{
		HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed with header " + secret)
		})},
		UA: "test",
	}, q)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("token leaked in error: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
