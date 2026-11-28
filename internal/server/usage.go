package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

var usageZone = time.FixedZone("UTC+8", 8*60*60)

const maxTrackedUsageHosts = 16

func validUsageHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.ToLower(strings.Trim(s, "[]")), ".")
	if len(s) < 3 || len(s) > 120 || s == "localhost" || !strings.Contains(s, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		if (c == '.' || c == '-') && i > 0 && i+1 < len(s) && s[i-1] != '.' {
			continue
		}
		return ""
	}
	return s
}

type usageDay struct {
	Date          string `json:"date"`
	PageViews     uint64 `json:"pageViews"`
	Lookups       uint64 `json:"lookups"`
	Errors        uint64 `json:"errors"`
	UV            uint64 `json:"uv,omitempty"`
	CLILookups    uint64 `json:"cliLookups,omitempty"`
	TargetLookups uint64 `json:"targetLookups,omitempty"`
	Probes        uint64 `json:"probes,omitempty"`
}

type usageReport struct {
	Schema    int                   `json:"schema"`
	Site      string                `json:"site"`
	StartedAt time.Time             `json:"startedAt"`
	UpdatedAt time.Time             `json:"updatedAt"`
	Days      []usageDay            `json:"days"`
	ByHost    map[string][]usageDay `json:"byHost,omitempty"`
}

type SiteUsage struct {
	path    string
	mu      sync.Mutex
	writeMu sync.Mutex
	report  usageReport
	dirty   bool
}

func readUsageFile(path string) ([]byte, error) {
	const limit = 64 << 10
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > limit {
		return nil, fmt.Errorf("unsafe usage file type, permissions or size: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("usage state changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if len(data) > limit {
		return nil, errors.New("usage state is too large")
	}
	return data, err
}

func openSiteUsage(dataDir string) (*SiteUsage, error) {
	now := time.Now().UTC().Truncate(time.Second)
	usage := &SiteUsage{path: filepath.Join(dataDir, "site-usage.json"), report: usageReport{Schema: 1, Site: "ip", StartedAt: now, UpdatedAt: now, Days: []usageDay{}}}
	data, err := readUsageFile(usage.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		usage.dirty = true
	case err != nil:
		return nil, err
	default:
		var stored usageReport
		if err := json.Unmarshal(data, &stored); err != nil {
			return nil, fmt.Errorf("decode site usage: %w", err)
		}
		if stored.Schema != 1 || stored.Site != "ip" || stored.StartedAt.IsZero() || stored.UpdatedAt.Before(stored.StartedAt) || stored.Days == nil || len(stored.Days) > 30 || len(stored.ByHost) > maxTrackedUsageHosts {
			return nil, errors.New("invalid site usage state")
		}
		for index, day := range stored.Days {
			if _, err := time.Parse(time.DateOnly, day.Date); err != nil || (index > 0 && stored.Days[index-1].Date >= day.Date) {
				return nil, errors.New("invalid or unordered usage date")
			}
		}
		for host, hDays := range stored.ByHost {
			if validUsageHost(host) != host || len(hDays) > 30 {
				return nil, errors.New("invalid per-host site usage state")
			}
			for index, day := range hDays {
				if _, err := time.Parse(time.DateOnly, day.Date); err != nil || (index > 0 && hDays[index-1].Date >= day.Date) {
					return nil, errors.New("invalid or unordered per-host usage date")
				}
			}
		}
		usage.report = stored
	}
	if err := usage.Flush(); err != nil {
		return nil, err
	}
	return usage, nil
}

func (usage *SiteUsage) pruneLocked(now time.Time) {
	today := now.In(usageZone)
	cutoff, latest := today.AddDate(0, 0, -29).Format(time.DateOnly), today.Format(time.DateOnly)
	days := usage.report.Days
	kept := slices.DeleteFunc(days, func(day usageDay) bool { return day.Date < cutoff || day.Date > latest })
	if len(kept) != len(days) {
		usage.report.Days = kept
		usage.dirty = true
	}
	for host, hDays := range usage.report.ByHost {
		hKept := slices.DeleteFunc(hDays, func(day usageDay) bool { return day.Date < cutoff || day.Date > latest })
		if len(hKept) == 0 {
			delete(usage.report.ByHost, host)
			usage.dirty = true
		} else if len(hKept) != len(hDays) {
			usage.report.ByHost[host] = hKept
			usage.dirty = true
		}
	}
}

func (usage *SiteUsage) ensureHostDayLocked(host string, now time.Time) *usageDay {
	h := validUsageHost(host)
	if h == "" {
		return nil
	}
	if usage.report.ByHost == nil {
		usage.report.ByHost = make(map[string][]usageDay)
	}
	hDays, exists := usage.report.ByHost[h]
	if !exists && len(usage.report.ByHost) >= maxTrackedUsageHosts {
		return nil
	}
	date := now.In(usageZone).Format(time.DateOnly)
	idx, found := slices.BinarySearchFunc(hDays, date, func(day usageDay, d string) int { return strings.Compare(day.Date, d) })
	if !found {
		hDays = slices.Insert(hDays, idx, usageDay{Date: date})
	}
	usage.report.ByHost[h] = hDays
	return &usage.report.ByHost[h][idx]
}

func (usage *SiteUsage) ensureDayLocked(now time.Time) int {
	usage.pruneLocked(now)
	date := now.In(usageZone).Format(time.DateOnly)
	days := usage.report.Days
	index, found := slices.BinarySearchFunc(days, date, func(day usageDay, date string) int { return strings.Compare(day.Date, date) })
	if !found {
		days = slices.Insert(days, index, usageDay{Date: date})
		usage.report.Days = days
	}
	if now.After(usage.report.UpdatedAt) {
		usage.report.UpdatedAt = now.UTC().Truncate(time.Second)
	}
	usage.dirty = true
	return index
}

func (usage *SiteUsage) record(kind string) {
	usage.mu.Lock()
	defer usage.mu.Unlock()
	usage.recordLocked(time.Now(), kind)
}

func (usage *SiteUsage) recordLocked(now time.Time, kind string) {
	index := usage.ensureDayLocked(now)
	days := usage.report.Days
	switch kind {
	case "view":
		days[index].PageViews++
	case "lookup":
		days[index].Lookups++
	case "error":
		days[index].Errors++
	case "probe":
		days[index].Probes++
	}
}

func bumpUsageDay(day *usageDay, kind string, newVisitor, isCLI, isTarget bool) {
	if day == nil {
		return
	}
	if newVisitor {
		day.UV++
	}
	switch kind {
	case "view":
		day.PageViews++
	case "lookup":
		day.Lookups++
		if isCLI {
			day.CLILookups++
		}
		if isTarget {
			day.TargetLookups++
		}
	case "probe":
		day.Probes++
	case "error":
		day.Errors++
	}
}

func (usage *SiteUsage) recordDetailed(now time.Time, host, kind string, newVisitor, newHostVisitor, isCLI, isTarget bool) {
	usage.mu.Lock()
	defer usage.mu.Unlock()
	index := usage.ensureDayLocked(now)
	bumpUsageDay(&usage.report.Days[index], kind, newVisitor, isCLI, isTarget)
	if hDay := usage.ensureHostDayLocked(host, now); hDay != nil {
		bumpUsageDay(hDay, kind, newHostVisitor, isCLI, isTarget)
	}
}

func (usage *SiteUsage) observe(pattern string, status int, contentType string) {
	switch pattern {
	case "GET /json", "GET /json/{ip}", "GET /api/lookup":
	case "GET /{$}", "GET /{ip}":
		if status == http.StatusNotFound {
			return
		}
		if status == http.StatusOK && strings.HasPrefix(contentType, "text/html;") {
			usage.record("view")
			return
		}
	default:
		return
	}
	if status >= 400 {
		usage.record("error")
	} else if status >= 200 && status < 300 {
		usage.record("lookup")
	}
}

func (usage *SiteUsage) snapshotLocked() usageReport {
	report := usage.report
	report.Days = slices.Clone(report.Days)
	if len(usage.report.ByHost) > 0 {
		byHost := make(map[string][]usageDay, len(usage.report.ByHost))
		for k, v := range usage.report.ByHost {
			byHost[k] = slices.Clone(v)
		}
		report.ByHost = byHost
	} else {
		report.ByHost = nil
	}
	return report
}

func (usage *SiteUsage) snapshot() usageReport {
	usage.mu.Lock()
	defer usage.mu.Unlock()
	usage.pruneLocked(time.Now())
	return usage.snapshotLocked()
}

func (usage *SiteUsage) Flush() error {
	usage.writeMu.Lock()
	defer usage.writeMu.Unlock()
	usage.mu.Lock()
	usage.pruneLocked(time.Now())
	if !usage.dirty {
		usage.mu.Unlock()
		return nil
	}
	report := usage.snapshotLocked()
	usage.dirty = false
	usage.mu.Unlock()
	if err := saveSiteUsage(usage.path, report); err != nil {
		usage.mu.Lock()
		usage.dirty = true
		usage.mu.Unlock()
		return err
	}
	return nil
}

func saveSiteUsage(path string, report usageReport) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".site-usage-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = json.NewEncoder(file).Encode(report); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (panel *AdminPanel) Flush() error { return panel.usage.Flush() }

func (panel *AdminPanel) Run(ctx context.Context, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := panel.Flush(); err != nil {
				log.Error("persist site usage; will retry", "err", err)
			}
		}
	}
}
