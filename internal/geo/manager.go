// SPDX-License-Identifier: AGPL-3.0-or-later

package geo

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DefaultBaseURL is where the free monthly city-level database is published.
const DefaultBaseURL = "https://download.db-ip.com/free"

const dbName = "dbip-city-lite.mmdb"

// Status describes the map data for the portal.
type Status struct {
	Ready       bool      `json:"ready"`
	Updated     time.Time `json:"updated,omitempty"`
	Error       string    `json:"error,omitempty"`
	Attribution string    `json:"attribution"`
}

// Manager keeps a Locator supplied with a fresh database. A failed or invalid
// download never replaces a working database.
type Manager struct {
	Loc     *Locator
	Dir     string        // the database lives in <Dir>/geo/
	BaseURL string        // default DefaultBaseURL
	Client  *http.Client  // default: 10 minute timeout
	MaxAge  time.Duration // refresh when older than this (default 35 days)
	Every   time.Duration // Run re-checks this often (default 12 hours)
	Now     func() time.Time

	mu     sync.Mutex
	status Status
}

// NewManager returns a Manager whose database lives under dir.
func NewManager(loc *Locator, dir string) *Manager {
	return &Manager{Loc: loc, Dir: dir}
}

func (m *Manager) defaults() {
	if m.BaseURL == "" {
		m.BaseURL = DefaultBaseURL
	}
	if m.Client == nil {
		m.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if m.MaxAge <= 0 {
		m.MaxAge = 35 * 24 * time.Hour
	}
	if m.Every <= 0 {
		m.Every = 12 * time.Hour
	}
	if m.Now == nil {
		m.Now = time.Now
	}
}

func (m *Manager) path() string { return filepath.Join(m.Dir, "geo", dbName) }

// Status returns the current state of the map data.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.status
	st.Attribution = Attribution
	return st
}

func (m *Manager) set(f func(*Status)) {
	m.mu.Lock()
	f(&m.status)
	m.mu.Unlock()
}

// Ensure loads the database on disk and refreshes it when it is missing or old.
func (m *Manager) Ensure(ctx context.Context) error {
	m.defaults()
	if err := os.MkdirAll(filepath.Dir(m.path()), 0o750); err != nil {
		m.set(func(s *Status) { s.Error = err.Error() })
		return err
	}
	var fresh bool
	if info, err := os.Stat(m.path()); err == nil {
		if err := m.Loc.Open(m.path()); err == nil {
			m.set(func(s *Status) { s.Ready, s.Updated, s.Error = true, info.ModTime(), "" })
			fresh = m.Now().Sub(info.ModTime()) < m.MaxAge
		}
	}
	if fresh {
		return nil
	}
	err := m.download(ctx)
	m.set(func(s *Status) {
		if err != nil {
			s.Error = err.Error()
		} else {
			s.Ready, s.Updated, s.Error = true, m.Now(), ""
		}
	})
	return err
}

// download tries this month's file, then last month's (the new one is
// published a little after the month starts).
func (m *Manager) download(ctx context.Context) error {
	now := m.Now().UTC()
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf("%s/dbip-city-lite-%s.mmdb.gz", strings.TrimRight(m.BaseURL, "/"), month.Format("2006-01"))
		err := m.fetch(ctx, url)
		if err == nil {
			return nil
		}
		lastErr = err
		var nf notFound
		if !errors.As(err, &nf) {
			return err // only a missing month is worth trying the previous one
		}
	}
	return lastErr
}

type notFound struct{ url string }

func (n notFound) Error() string { return "not published yet: " + n.url }

func (m *Manager) fetch(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "shepherd")
	resp, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return notFound{url}
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("map data download failed: HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("map data is not gzip: %w", err)
	}
	tmp := m.path() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, io.LimitReader(gz, 1<<30))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(tmp)
		return fmt.Errorf("map data download interrupted: %w", errors.Join(copyErr, closeErr))
	}
	if err := validate(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, m.path()); err != nil {
		return err
	}
	return m.Loc.Open(m.path())
}

// validate checks that path is a city-level GeoIP database before it is trusted.
func validate(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("downloaded map data is not a GeoIP database: %w", err)
	}
	defer r.Close()
	md := r.Metadata
	if !strings.Contains(strings.ToLower(md.DatabaseType), "city") || md.NodeCount == 0 {
		return fmt.Errorf("downloaded map data is not a city database (%q)", md.DatabaseType)
	}
	return nil
}

// Run ensures the database now and re-checks on an interval until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.defaults()
	_ = m.Ensure(ctx)
	t := time.NewTicker(m.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = m.Ensure(ctx)
		}
	}
}
