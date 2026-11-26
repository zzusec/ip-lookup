package sources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

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
	otxHit := []byte(`{"false_positive":false,"pulse_info":{"count":4,"pulses":[{"name":"SSH Brute"}]}}`)
	if err := alienVaultOTX().Apply(o, q, otxHit); err != nil || o.Res.Audit.Activity.OTXPulses != 4 {
		t.Fatalf("OTX hit failed: %v / %+v", err, o.Res.Audit.Activity)
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
