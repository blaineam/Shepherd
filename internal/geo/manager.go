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

// DefaultBaseURL is where the free monthly databases (city-level and ASN) are
// published.
const DefaultBaseURL = "https://download.db-ip.com/free"

const (
	dbName    = "dbip-city-lite.mmdb"
	asnDBName = "dbip-asn-lite.mmdb"
)

// Status describes the map data for the portal.
type Status struct {
	Ready       bool      `json:"ready"`
	Updated     time.Time `json:"updated,omitempty"`
	Error       string    `json:"error,omitempty"`
	Attribution string    `json:"attribution"`
}

// spec says which database a feed keeps fresh: what the file is called on
// disk, the prefix of the published file name, how a downloaded file is
// judged trustworthy, where it is loaded, and the credit it carries.
type spec struct {
	file        string // name on disk under <Dir>/geo/
	prefix      string // published as <prefix>-YYYY-MM.mmdb.gz
	kind        string // what the data is called in errors ("map", "ASN")
	label       string // the database flavor named in a type mismatch ("city", "ASN")
	typeWord    string // the database type must contain this (lower case)
	attribution string
	load        func(path string) error
}

// feed keeps one database supplied with a fresh copy. A failed or invalid
// download never replaces a working database. The city-level Manager and the
// ASNManager are both a feed with a different spec.
type feed struct {
	Dir     string        // the database lives in <Dir>/geo/
	BaseURL string        // default DefaultBaseURL
	Client  *http.Client  // default: 10 minute timeout
	MaxAge  time.Duration // refresh when older than this (default 35 days)
	Every   time.Duration // Run re-checks this often (default 12 hours)
	Now     func() time.Time

	mu     sync.Mutex
	status Status
}

func (f *feed) defaults() {
	if f.BaseURL == "" {
		f.BaseURL = DefaultBaseURL
	}
	if f.Client == nil {
		f.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if f.MaxAge <= 0 {
		f.MaxAge = 35 * 24 * time.Hour
	}
	if f.Every <= 0 {
		f.Every = 12 * time.Hour
	}
	if f.Now == nil {
		f.Now = time.Now
	}
}

func (f *feed) path(s spec) string { return filepath.Join(f.Dir, "geo", s.file) }

func (f *feed) statusOf(s spec) Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.status
	st.Attribution = s.attribution
	return st
}

func (f *feed) set(fn func(*Status)) {
	f.mu.Lock()
	fn(&f.status)
	f.mu.Unlock()
}

// ensure loads the database on disk and refreshes it when it is missing or old.
func (f *feed) ensure(ctx context.Context, s spec) error {
	f.defaults()
	if err := os.MkdirAll(filepath.Dir(f.path(s)), 0o750); err != nil {
		f.set(func(st *Status) { st.Error = err.Error() })
		return err
	}
	var fresh bool
	if info, err := os.Stat(f.path(s)); err == nil {
		if err := s.load(f.path(s)); err == nil {
			f.set(func(st *Status) { st.Ready, st.Updated, st.Error = true, info.ModTime(), "" })
			fresh = f.Now().Sub(info.ModTime()) < f.MaxAge
		}
	}
	if fresh {
		return nil
	}
	err := f.download(ctx, s)
	f.set(func(st *Status) {
		if err != nil {
			st.Error = err.Error()
		} else {
			st.Ready, st.Updated, st.Error = true, f.Now(), ""
		}
	})
	return err
}

// download tries this month's file, then last month's (the new one is
// published a little after the month starts).
func (f *feed) download(ctx context.Context, s spec) error {
	now := f.Now().UTC()
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf("%s/%s-%s.mmdb.gz", strings.TrimRight(f.BaseURL, "/"), s.prefix, month.Format("2006-01"))
		err := f.fetch(ctx, s, url)
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

func (f *feed) fetch(ctx context.Context, s spec, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "shepherd")
	resp, err := f.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return notFound{url}
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s data download failed: HTTP %d", s.kind, resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("%s data is not gzip: %w", s.kind, err)
	}
	tmp := f.path(s) + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, io.LimitReader(gz, 1<<30))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(tmp)
		return fmt.Errorf("%s data download interrupted: %w", s.kind, errors.Join(copyErr, closeErr))
	}
	if err := validateDB(tmp, s); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, f.path(s)); err != nil {
		return err
	}
	return s.load(f.path(s))
}

// validateDB checks that path is a database of the kind s expects before it
// is trusted.
func validateDB(path string, s spec) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("downloaded %s data is not a GeoIP database: %w", s.kind, err)
	}
	defer r.Close()
	md := r.Metadata
	if !strings.Contains(strings.ToLower(md.DatabaseType), s.typeWord) || md.NodeCount == 0 {
		return fmt.Errorf("downloaded %s data is not a %s database (%q)", s.kind, s.label, md.DatabaseType)
	}
	return nil
}

// run ensures the database now and re-checks on an interval until ctx ends.
func (f *feed) run(ctx context.Context, s spec) {
	f.defaults()
	_ = f.ensure(ctx, s)
	t := time.NewTicker(f.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = f.ensure(ctx, s)
		}
	}
}

// Manager keeps a Locator supplied with a fresh city-level database. A failed
// or invalid download never replaces a working database.
type Manager struct {
	Loc *Locator
	feed
}

// NewManager returns a Manager whose database lives under dir.
func NewManager(loc *Locator, dir string) *Manager {
	return &Manager{Loc: loc, feed: feed{Dir: dir}}
}

func (m *Manager) spec() spec {
	return spec{file: dbName, prefix: "dbip-city-lite", kind: "map", label: "city", typeWord: "city",
		attribution: Attribution, load: m.Loc.Open}
}

func (m *Manager) path() string { return m.feed.path(m.spec()) }

// Status returns the current state of the map data.
func (m *Manager) Status() Status { return m.statusOf(m.spec()) }

// Ensure loads the database on disk and refreshes it when it is missing or old.
func (m *Manager) Ensure(ctx context.Context) error { return m.ensure(ctx, m.spec()) }

// Run ensures the database now and re-checks on an interval until ctx ends.
func (m *Manager) Run(ctx context.Context) { m.run(ctx, m.spec()) }

// ASNManager keeps an ASNLocator supplied with the free monthly DB-IP "IP to
// ASN Lite" database, with exactly the guarantees of Manager: this month's
// file with a fall back to last month's, a database type that must mention
// ASN before it is trusted, and a failed or invalid download that never
// replaces a working database. The file is stored beside the city database.
type ASNManager struct {
	ASN *ASNLocator
	feed
}

// NewASNManager returns an ASNManager whose database lives under dir.
func NewASNManager(loc *ASNLocator, dir string) *ASNManager {
	return &ASNManager{ASN: loc, feed: feed{Dir: dir}}
}

func (m *ASNManager) spec() spec {
	return spec{file: asnDBName, prefix: "dbip-asn-lite", kind: "ASN", label: "ASN", typeWord: "asn",
		attribution: ASNAttribution, load: m.ASN.Open}
}

func (m *ASNManager) path() string { return m.feed.path(m.spec()) }

// Status returns the current state of the ASN data.
func (m *ASNManager) Status() Status { return m.statusOf(m.spec()) }

// Ensure loads the database on disk and refreshes it when it is missing or old.
func (m *ASNManager) Ensure(ctx context.Context) error { return m.ensure(ctx, m.spec()) }

// Run ensures the database now and re-checks on an interval until ctx ends.
func (m *ASNManager) Run(ctx context.Context) { m.run(ctx, m.spec()) }
