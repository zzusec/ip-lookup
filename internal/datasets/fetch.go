package datasets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxDownload = 1 << 30

var errNotFound = errors.New("HTTP 404")

type partMeta struct {
	URL          string `json:"url"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// meta is persisted next to the downloaded parts so restarts reuse them.
type meta struct {
	Parts     []partMeta `json:"parts"`
	FetchedAt time.Time  `json:"fetched_at"` // content last changed
	CheckedAt time.Time  `json:"checked_at"` // last successful check with the origin
}

func readMeta(dir string) (meta, error) {
	var mt meta
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err == nil {
		err = json.Unmarshal(b, &mt)
	}
	return mt, err
}

func writeMeta(dir string, mt meta) error {
	b, err := json.MarshalIndent(mt, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "meta.json"))
}

// candidates expands {month} to the current and the previous UTC month, since
// DB-IP publishes the new month's file some hours into the month.
func candidates(raw string, now time.Time) []string {
	if !strings.Contains(raw, "{month}") {
		return []string{raw}
	}
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return []string{
		strings.ReplaceAll(raw, "{month}", first.Format("2006-01")),
		strings.ReplaceAll(raw, "{month}", first.AddDate(0, -1, 0).Format("2006-01")),
	}
}

// fetch downloads one part to dst. changed is false when the origin answered
// 304 to the validators in prev, in which case dst is not written.
func (m *Manager) fetch(ctx context.Context, spec Spec, raw string, prev partMeta, dst string) (pm partMeta, changed bool, err error) {
	for _, u := range candidates(raw, time.Now().UTC()) {
		pm, changed, err = m.get(ctx, u, prev, dst, spec.Format == MMDBGzip)
		if !errors.Is(err, errNotFound) {
			return pm, changed, err
		}
	}
	return pm, changed, err
}

func (m *Manager) get(ctx context.Context, u string, prev partMeta, dst string, gz bool) (partMeta, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return partMeta{}, false, err
	}
	req.Header.Set("User-Agent", m.ua)
	if prev.URL == u {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return partMeta{}, false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && prev.URL == u:
		return prev, false, nil
	case resp.StatusCode == http.StatusNotFound:
		return partMeta{}, false, errNotFound
	case resp.StatusCode != http.StatusOK:
		return partMeta{}, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	pm := partMeta{URL: u, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	tmp := dst
	if gz {
		tmp = dst + ".gz"
	}
	if err := save(resp.Body, tmp); err != nil {
		return partMeta{}, false, err
	}
	if gz {
		err := gunzip(tmp, dst)
		os.Remove(tmp)
		if err != nil {
			return partMeta{}, false, fmt.Errorf("gunzip: %w", err)
		}
	}
	return pm, true, nil
}

func save(r io.Reader, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, maxDownload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxDownload {
		err = fmt.Errorf("larger than %d bytes", maxDownload)
	}
	if err == nil && n == 0 {
		err = errors.New("empty response")
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
