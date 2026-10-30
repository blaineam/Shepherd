// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultProtected are apex domains no blocklist may ever contain. A list that
// does is rejected whole: it is far more likely broken than intentional.
var DefaultProtected = []string{
	"google.com", "apple.com", "icloud.com", "microsoft.com", "amazon.com",
	"cloudflare.com", "github.com", "tailscale.com", "ts.net", "wikipedia.org",
	"mozilla.org", "debian.org", "ubuntu.com", "windowsupdate.com",
}

// ValidDomain reports whether s looks like a hostname with at least two labels.
func ValidDomain(s string) bool {
	if len(s) < 3 || len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// ParseList reads hosts-file, plain-domain and simple adblock (||domain^) lines.
// Comments, cosmetic rules and anything unrecognised are skipped.
func ParseList(r io.Reader) (map[string]struct{}, error) {
	set := make(map[string]struct{})
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
			continue
		}
		if i := strings.IndexByte(line, '#'); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		var domain string
		switch {
		case strings.HasPrefix(line, "||"):
			rest := line[2:]
			end := strings.IndexAny(rest, "^$/*|")
			if end < 0 {
				end = len(rest)
			} else if tail := rest[end:]; tail != "^" && tail != "^|" {
				continue // has options or wildcards we cannot honour at DNS level
			}
			domain = rest[:end]
		default:
			f := strings.Fields(line)
			switch {
			case len(f) == 1:
				domain = f[0]
			case len(f) >= 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::" || f[0] == "::1"):
				domain = f[1]
			default:
				continue
			}
		}
		domain = normalize(domain)
		if domain != "localhost" && ValidDomain(domain) {
			set[domain] = struct{}{}
		}
	}
	return set, sc.Err()
}

// Guard rejects a freshly downloaded list that looks broken, so a bad update
// can never take over the filter. prev may be nil for a first load.
func Guard(prev, next map[string]struct{}, protected []string) error {
	return guardCount(len(prev), next, protected)
}

// guardCount is Guard given only the previous entry count, so the manager
// need not keep the previous set in memory.
func guardCount(prevN int, next map[string]struct{}, protected []string) error {
	if len(next) == 0 {
		return errors.New("list is empty")
	}
	for _, p := range protected {
		if _, bad := next[p]; bad {
			return fmt.Errorf("list blocks protected domain %s", p)
		}
	}
	if n := prevN; n > 0 {
		if len(next)*2 < n {
			return fmt.Errorf("list shrank from %d to %d entries", n, len(next))
		}
		if n >= 1000 && len(next) > n*3 {
			return fmt.Errorf("list grew from %d to %d entries", n, len(next))
		}
	}
	return nil
}

// ListConfig is the legacy way to name a list: a name and one URL.
type ListConfig struct{ Name, URL string }

// ListSource is one input of a list: a URL (http, https or file) or inline text.
type ListSource struct {
	URL    string
	Format string // informational; parsing auto-detects
	Inline string
}

// ListSpec is a list the manager should keep loaded, under the item ID the
// filter knows it by. Several sources are merged into one item.
type ListSpec struct {
	ID      string
	Name    string
	Sources []ListSource
}

// ListStatus is the per-item state shown in the UI.
type ListStatus struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Count   int       `json:"count"`
	Size    int64     `json:"size_bytes"`
	Updated time.Time `json:"updated"`
	Error   string    `json:"error,omitempty"`
}

// DefaultMaxListBytes caps one downloaded source. A source over the cap is
// rejected, never silently truncated.
const DefaultMaxListBytes = 128 << 20

// ListManager downloads, guards, caches and applies the lists that are
// switched on somewhere, and only those.
type ListManager struct {
	filter    *Filter
	dir       string
	specs     func() []ListSpec
	protected []string
	client    *http.Client
	// MaxBytes caps each downloaded source; set before Run.
	MaxBytes int64

	refreshMu sync.Mutex // one refresh at a time, to bound memory
	mu        sync.Mutex
	status    map[string]*ListStatus
	loaded    map[string]bool // item has data in the filter
	kick      chan struct{}
}

func newManager(f *Filter, dataDir string, specs func() []ListSpec, extraProtected []string) *ListManager {
	return &ListManager{
		filter:    f,
		dir:       filepath.Join(dataDir, "lists"),
		specs:     specs,
		protected: append(append([]string(nil), DefaultProtected...), extraProtected...),
		client:    &http.Client{Timeout: 2 * time.Minute},
		MaxBytes:  DefaultMaxListBytes,
		status:    map[string]*ListStatus{},
		loaded:    map[string]bool{},
		kick:      make(chan struct{}, 1),
	}
}

// NewListManager manages a fixed set of named URL lists, all applied network
// wide (legacy mode).
func NewListManager(f *Filter, dataDir string, lists []ListConfig, extraProtected []string) *ListManager {
	specs := make([]ListSpec, 0, len(lists))
	for _, l := range lists {
		specs = append(specs, ListSpec{ID: l.Name, Name: l.Name, Sources: []ListSource{{URL: l.URL}}})
	}
	return newManager(f, dataDir, func() []ListSpec { return specs }, extraProtected)
}

// NewScopedListManager manages exactly the lists the store has switched on
// at some scope, and re-syncs whenever the store changes.
func NewScopedListManager(f *Filter, store *PolicyStore, dataDir string, extraProtected []string) *ListManager {
	m := newManager(f, dataDir, store.WantedLists, extraProtected)
	store.OnChange(m.Kick)
	return m
}

// Kick asks a running Run loop to re-sync and fetch anything newly wanted.
// It never blocks.
func (m *ListManager) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// fileSafe maps an item ID to a name that cannot escape the cache directory.
func fileSafe(id string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, id)
}

// cachePath is the cache file of source i of item id. Source 0 keeps the
// historic <id>.txt name.
func (m *ListManager) cachePath(id string, i int) string {
	if i == 0 {
		return filepath.Join(m.dir, fileSafe(id)+".txt")
	}
	return filepath.Join(m.dir, fmt.Sprintf("%s.%d.txt", fileSafe(id), i))
}

func specURL(sp ListSpec) string {
	if len(sp.Sources) > 0 {
		if sp.Sources[0].URL != "" {
			return sp.Sources[0].URL
		}
		return "(inline)"
	}
	return ""
}

func (m *ListManager) statusLocked(sp ListSpec) *ListStatus {
	st := m.status[sp.ID]
	if st == nil {
		st = &ListStatus{ID: sp.ID}
		m.status[sp.ID] = st
	}
	st.Name, st.URL = sp.Name, specURL(sp)
	return st
}

// Status returns per-item state for every wanted list, in spec order.
func (m *ListManager) Status() []ListStatus {
	specs := m.specs()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ListStatus, 0, len(specs))
	for _, sp := range specs {
		out = append(out, *m.statusLocked(sp))
	}
	return out
}

// Sync unloads items that are no longer wanted and deletes their cache.
func (m *ListManager) Sync() {
	wanted := map[string]bool{}
	for _, sp := range m.specs() {
		wanted[sp.ID] = true
	}
	m.mu.Lock()
	var drop []string
	for id := range m.loaded {
		if !wanted[id] {
			drop = append(drop, id)
		}
	}
	for id := range m.status {
		if !wanted[id] {
			delete(m.status, id)
		}
	}
	for _, id := range drop {
		delete(m.loaded, id)
	}
	m.mu.Unlock()
	for _, id := range drop {
		m.filter.SetList(id, nil)
	}
	m.pruneCache()
}

// pruneCache removes cache files that belong to no wanted item.
func (m *ListManager) pruneCache() {
	keep := map[string]bool{}
	for _, sp := range m.specs() {
		for i := range max(len(sp.Sources), 1) {
			keep[filepath.Base(m.cachePath(sp.ID, i))] = true
		}
	}
	files, _ := os.ReadDir(m.dir)
	for _, f := range files {
		if n := f.Name(); !f.IsDir() && strings.HasSuffix(n, ".txt") && !keep[n] {
			os.Remove(filepath.Join(m.dir, n))
		}
	}
}

// LoadCached applies lists saved by earlier runs, so filtering works offline
// and immediately at startup. Inline lists need no cache. Items already
// loaded are left alone.
func (m *ListManager) LoadCached() {
	for _, sp := range m.specs() {
		m.mu.Lock()
		done := m.loaded[sp.ID]
		m.mu.Unlock()
		if done {
			continue
		}
		set := map[string]struct{}{}
		var size int64
		var newest time.Time
		for i, src := range sp.Sources {
			if src.Inline != "" {
				if got, err := ParseList(strings.NewReader(src.Inline)); err == nil {
					maps.Copy(set, got)
					size += int64(len(src.Inline))
					newest = time.Now()
				}
				continue
			}
			f, err := os.Open(m.cachePath(sp.ID, i))
			if err != nil {
				continue
			}
			got, err := ParseList(f)
			info, _ := f.Stat()
			f.Close()
			if err != nil {
				continue
			}
			maps.Copy(set, got)
			size += info.Size()
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
		if len(set) > 0 {
			m.apply(sp, set, size, newest, nil)
		}
	}
}

// apply records the outcome of a load. On error the previous data stays.
func (m *ListManager) apply(sp ListSpec, set map[string]struct{}, size int64, updated time.Time, err error) {
	m.mu.Lock()
	st := m.statusLocked(sp)
	if err != nil {
		st.Error = err.Error()
		m.mu.Unlock()
		return
	}
	st.Count, st.Size, st.Updated, st.Error = len(set), size, updated, ""
	m.loaded[sp.ID] = true
	m.mu.Unlock()
	m.filter.SetList(sp.ID, set)
}

// Refresh fetches every wanted list. A failing or rejected list keeps its
// previous contents and records the error.
func (m *ListManager) Refresh(ctx context.Context) { m.refresh(ctx, nil) }

// RefreshItem fetches one wanted list by ID.
func (m *ListManager) RefreshItem(ctx context.Context, id string) {
	m.refresh(ctx, func(sp ListSpec, _ bool) bool { return sp.ID == id })
}

// RefreshMissing fetches wanted lists that have no data loaded yet.
func (m *ListManager) RefreshMissing(ctx context.Context) {
	m.refresh(ctx, func(_ ListSpec, loaded bool) bool { return !loaded })
}

func (m *ListManager) refresh(ctx context.Context, pick func(ListSpec, bool) bool) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	m.Sync()
	specs := m.specs()
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		for _, sp := range specs {
			m.apply(sp, nil, 0, time.Time{}, err)
		}
		return
	}
	for _, sp := range specs {
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		loaded := m.loaded[sp.ID]
		m.mu.Unlock()
		if pick != nil && !pick(sp, loaded) {
			continue
		}
		m.refreshOne(ctx, sp)
	}
}

func (m *ListManager) refreshOne(ctx context.Context, sp ListSpec) {
	set := map[string]struct{}{}
	var size int64
	var tmps []string
	fail := func(err error) {
		for _, t := range tmps {
			os.Remove(t)
		}
		m.apply(sp, nil, 0, time.Time{}, err)
	}
	for i, src := range sp.Sources {
		if src.Inline != "" {
			got, err := ParseList(strings.NewReader(src.Inline))
			if err != nil {
				fail(err)
				return
			}
			maps.Copy(set, got)
			size += int64(len(src.Inline))
			continue
		}
		tmp := m.cachePath(sp.ID, i) + ".tmp"
		tmps = append(tmps, tmp)
		got, n, err := m.fetch(ctx, src.URL, tmp)
		if err != nil {
			fail(err)
			return
		}
		maps.Copy(set, got)
		size += n
	}
	m.mu.Lock()
	prev := 0
	if m.loaded[sp.ID] {
		prev = m.status[sp.ID].Count
	}
	m.mu.Unlock()
	if err := guardCount(prev, set, m.protected); err != nil {
		fail(err)
		return
	}
	for i, src := range sp.Sources {
		if src.Inline != "" {
			continue
		}
		if err := os.Rename(m.cachePath(sp.ID, i)+".tmp", m.cachePath(sp.ID, i)); err != nil {
			fail(err)
			return
		}
	}
	m.apply(sp, set, size, time.Now(), nil)
}

// fetch downloads url into tmp while parsing it, and returns the bytes read.
func (m *ListManager) fetch(ctx context.Context, url, tmp string) (map[string]struct{}, int64, error) {
	var src io.ReadCloser
	if path, ok := strings.CutPrefix(url, "file://"); ok {
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		src = f
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", "shepherd")
		resp, err := m.client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
		}
		src = resp.Body
	}
	defer src.Close()

	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, 0, err
	}
	defer out.Close()
	lr := &io.LimitedReader{R: src, N: m.MaxBytes + 1}
	set, err := ParseList(io.TeeReader(lr, out))
	n := m.MaxBytes + 1 - lr.N
	switch {
	case n > m.MaxBytes:
		return nil, 0, fmt.Errorf("list is larger than the %d MiB cap", m.MaxBytes>>20)
	case err != nil:
		return nil, 0, err
	}
	return set, n, out.Sync()
}

// Run syncs, loads the cache, refreshes now, then refreshes on every interval
// and whenever Kick is called (the store changed).
func (m *ListManager) Run(ctx context.Context, every time.Duration) {
	m.Sync()
	m.LoadCached()
	m.Refresh(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Refresh(ctx)
		case <-m.kick:
			m.Sync()
			m.LoadCached()
			m.RefreshMissing(ctx)
		}
	}
}
