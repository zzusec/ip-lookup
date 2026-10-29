package datasets

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

// Entry is the live state of one dataset.
type Entry struct {
	Spec Spec
	data atomic.Pointer[Loaded]
	mu   sync.Mutex // guards the fields below and serialises refreshes
	err  string
	mt   meta
}

// Get returns the current data, or nil when nothing could be loaded yet.
func (e *Entry) Get() *Loaded { return e.data.Load() }

// Manager owns all datasets under one directory.
type Manager struct {
	dir     string
	ua      string
	client  *http.Client
	entries []*Entry
	byID    map[string]*Entry
	log     *slog.Logger
}

func NewManager(dir, userAgent string, log *slog.Logger) *Manager {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	tr.ResponseHeaderTimeout = 60 * time.Second
	m := &Manager{dir: dir, ua: userAgent, log: log, byID: map[string]*Entry{},
		client: &http.Client{Transport: tr, Timeout: 15 * time.Minute}}
	for _, s := range Specs {
		e := &Entry{Spec: s}
		m.entries = append(m.entries, e)
		m.byID[s.ID] = e
	}
	return m
}

// Get returns the current data of a dataset, or nil.
func (m *Manager) Get(id string) *Loaded {
	if e := m.byID[id]; e != nil {
		return e.Get()
	}
	return nil
}

// Entries lists all datasets in registry order.
func (m *Manager) Entries() []*Entry { return m.entries }

// LoadCached loads whatever earlier runs left on disk, without network access.
func (m *Manager) LoadCached() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2) // parsing large lists is memory hungry; keep it narrow
	for _, e := range m.entries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.Spec.Static != "" && len(e.Spec.URLs) == 0 {
				m.install(e, nil, meta{FetchedAt: time.Now()})
				return
			}
			mt, err := readMeta(m.entryDir(e))
			if err != nil || len(mt.Parts) != len(e.Spec.URLs) {
				return
			}
			m.install(e, m.partPaths(e), mt)
		}()
	}
	wg.Wait()
}

// Run refreshes every dataset whose interval has passed until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		for _, e := range m.entries {
			if ctx.Err() != nil {
				return
			}
			if e.due(time.Now()) {
				m.Refresh(ctx, e)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (e *Entry) due(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.Spec.URLs) == 0 {
		return false
	}
	if e.err != "" {
		return now.Sub(e.mt.CheckedAt) > min(e.Spec.Every, time.Hour) // retry failures hourly
	}
	return now.Sub(e.mt.CheckedAt) >= e.Spec.Every
}

func (m *Manager) entryDir(e *Entry) string { return filepath.Join(m.dir, e.Spec.ID) }

func (m *Manager) partPaths(e *Entry) []string {
	p := make([]string, len(e.Spec.URLs))
	for i := range p {
		p[i] = filepath.Join(m.entryDir(e), partName(e.Spec, i))
	}
	return p
}

func partName(s Spec, i int) string {
	switch s.Format {
	case MMDB, MMDBGzip:
		return "data.mmdb"
	case XDB:
		return "data.xdb"
	}
	return "part" + string(rune('0'+i)) + ".txt"
}

// install loads parts and publishes the result. Callers hold e.mu.
func (m *Manager) install(e *Entry, paths []string, mt meta) bool {
	start := time.Now()
	l, err := load(e.Spec, paths)
	if err != nil {
		e.err = err.Error()
		m.log.Warn("dataset load failed", "id", e.Spec.ID, "err", err)
		return false
	}
	e.data.Store(l)
	e.err, e.mt = "", mt
	m.log.Info("dataset loaded", "id", e.Spec.ID, "entries", l.Count, "ms", time.Since(start).Milliseconds())
	return true
}

// Report describes every dataset for /api/sources.
func (m *Manager) Report() []model.Dataset {
	out := make([]model.Dataset, 0, len(m.entries))
	for _, e := range m.entries {
		e.mu.Lock()
		d := model.Dataset{ID: e.Spec.ID, Label: e.Spec.Label, Category: e.Spec.Category,
			Homepage: e.Spec.Homepage, License: e.Spec.License, Error: e.err, Status: "ok"}
		if !e.mt.FetchedAt.IsZero() && len(e.Spec.URLs) > 0 {
			d.UpdatedAt = e.mt.FetchedAt.UTC().Format(time.RFC3339)
		}
		e.mu.Unlock()
		switch l := e.Get(); {
		case l != nil && d.Error != "":
			d.Status, d.Entries = "stale", l.Count
		case l != nil:
			d.Entries = l.Count
		case d.Error != "":
			d.Status = "error"
		default:
			d.Status = "pending"
		}
		out = append(out, d)
	}
	return out
}
