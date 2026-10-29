package datasets

import (
	"log/slog"
	"net/netip"
	"os"
	"testing"
)

// Run with IPL_DATA_DIR pointing at a data directory produced by the service.
func TestSmokeCached(t *testing.T) {
	dir := os.Getenv("IPL_DATA_DIR")
	if dir == "" {
		t.Skip("IPL_DATA_DIR not set")
	}
	m := NewManager(dir, "test", slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.LoadCached()
	for _, ip := range []string{"69.63.223.19", "183.192.65.101", "24.48.0.1", "8.8.8.8", "2001:4860:4860::8888", "1.1.1.1"} {
		a := netip.MustParseAddr(ip)
		var r MergedRecord
		p, ok, err := m.LookupMMDB("merged", a, &r)
		zh, _ := r.Country.Names.Pick()
		reg, rok, rerr := m.LookupRegion(a)
		t.Logf("%s merged=%v %s %v AS%d %s %s/%s reg=%v proxy=%+v | i2r=%v %+v %v | lists=%d",
			ip, ok, p, err, r.ASN.Number, r.ASN.Org, zh, r.RegisteredCountry.ISOCode, r.Location.Accuracy, r.Proxy, rok, reg, rerr, len(m.Lists(a)))
	}
	for _, d := range m.Report() {
		if d.Status != "pending" {
			t.Logf("dataset %s %s %d %s", d.ID, d.Status, d.Entries, d.Error)
		}
	}
}
