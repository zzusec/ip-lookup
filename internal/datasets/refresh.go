package datasets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Refresh checks the origin of one dataset and reloads it when it changed.
// New parts are written to a staging directory and only moved over the live
// files after they loaded successfully, so a bad download never replaces good
// data. Open readers keep working: their files are replaced, not rewritten.
func (m *Manager) Refresh(ctx context.Context, e *Entry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	start := time.Now()
	err := m.refresh(ctx, e)
	e.mt.CheckedAt = time.Now()
	if err != nil {
		e.err = err.Error()
		m.log.Warn("dataset refresh failed", "id", e.Spec.ID, "err", err, "ms", time.Since(start).Milliseconds())
		return
	}
	if mterr := writeMeta(m.entryDir(e), e.mt); mterr != nil {
		m.log.Warn("dataset meta write failed", "id", e.Spec.ID, "err", mterr)
	}
}

func (m *Manager) refresh(ctx context.Context, e *Entry) error {
	dir := m.entryDir(e)
	stage := filepath.Join(dir, "staging")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	live := m.partPaths(e)
	have := e.Get() != nil && len(e.mt.Parts) == len(e.Spec.URLs)
	next := meta{Parts: make([]partMeta, len(e.Spec.URLs)), FetchedAt: e.mt.FetchedAt}
	staged := make([]string, len(live))
	changed := false
	for i, raw := range e.Spec.URLs {
		var prev partMeta
		if have {
			prev = e.mt.Parts[i]
		}
		dst := filepath.Join(stage, filepath.Base(live[i]))
		pm, ch, err := m.fetch(ctx, e.Spec, raw, prev, dst)
		if err != nil {
			return fmt.Errorf("part %d: %w", i, err)
		}
		next.Parts[i] = pm
		if ch {
			staged[i], changed = dst, true
		}
	}
	if !changed {
		e.err = ""
		e.mt.Parts = next.Parts
		return nil
	}
	// Load from a mix of new staged parts and unchanged live parts.
	paths := make([]string, len(live))
	for i := range live {
		paths[i] = live[i]
		if staged[i] != "" {
			paths[i] = staged[i]
		}
	}
	l, err := load(e.Spec, paths)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	for i, s := range staged {
		if s == "" {
			continue
		}
		if err := os.Rename(s, live[i]); err != nil {
			return errors.Join(fmt.Errorf("install part %d", i), err)
		}
	}
	next.FetchedAt = time.Now()
	e.data.Store(l)
	e.err, e.mt = "", next
	m.log.Info("dataset updated", "id", e.Spec.ID, "entries", l.Count)
	return nil
}
