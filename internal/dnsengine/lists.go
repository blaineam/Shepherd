// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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
	if len(next) == 0 {
		return errors.New("list is empty")
	}
	for _, p := range protected {
		if _, bad := next[p]; bad {
			return fmt.Errorf("list blocks protected domain %s", p)
		}
	}
	if n := len(prev); n > 0 {
		if len(next)*2 < n {
			return fmt.Errorf("list shrank from %d to %d entries", n, len(next))
		}
		if n >= 1000 && len(next) > n*3 {
			return fmt.Errorf("list grew from %d to %d entries", n, len(next))
		}
	}
	return nil
}

type ListConfig struct{ Name, URL string }

type ListStatus struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Count   int       `json:"count"`
	Updated time.Time `json:"updated"`
	Error   string    `json:"error,omitempty"`
}

// ListManager downloads, guards, caches and applies blocklists.
type ListManager struct {
	filter    *Filter
	dir       string
	lists     []ListConfig
	protected []string
	client    *http.Client

	mu     sync.Mutex
	status map[string]*ListStatus
	sets   map[string]map[string]struct{}
}

func NewListManager(f *Filter, dataDir string, lists []ListConfig, extraProtected []string) *ListManager {
	m := &ListManager{
		filter:    f,
		dir:       filepath.Join(dataDir, "lists"),
		lists:     lists,
		protected: append(append([]string(nil), DefaultProtected...), extraProtected...),
		client:    &http.Client{Timeout: 2 * time.Minute},
		status:    map[string]*ListStatus{},
		sets:      map[string]map[string]struct{}{},
	}
	for _, l := range lists {
		m.status[l.Name] = &ListStatus{Name: l.Name, URL: l.URL}
	}
	return m
}

func (m *ListManager) cachePath(name string) string { return filepath.Join(m.dir, name+".txt") }

// Status returns per-list state in configuration order.
func (m *ListManager) Status() []ListStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ListStatus, 0, len(m.lists))
	for _, l := range m.lists {
		out = append(out, *m.status[l.Name])
	}
	return out
}

// LoadCached applies lists saved by earlier runs, so filtering works offline
// and immediately at startup.
func (m *ListManager) LoadCached() {
	for _, l := range m.lists {
		f, err := os.Open(m.cachePath(l.Name))
		if err != nil {
			continue
		}
		set, err := ParseList(f)
		f.Close()
		if err != nil || len(set) == 0 {
			continue
		}
		info, _ := os.Stat(m.cachePath(l.Name))
		m.apply(l.Name, set, info.ModTime(), nil)
	}
}

func (m *ListManager) apply(name string, set map[string]struct{}, updated time.Time, err error) {
	m.mu.Lock()
	st := m.status[name]
	if err != nil {
		st.Error = err.Error()
		m.mu.Unlock()
		return
	}
	m.sets[name] = set
	st.Count, st.Updated, st.Error = len(set), updated, ""
	m.mu.Unlock()
	m.filter.SetList(name, set)
}

// Refresh fetches every list. A failing or rejected list keeps its previous
// contents and records the error.
func (m *ListManager) Refresh(ctx context.Context) {
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		for _, l := range m.lists {
			m.apply(l.Name, nil, time.Time{}, err)
		}
		return
	}
	for _, l := range m.lists {
		if ctx.Err() != nil {
			return
		}
		set, err := m.fetch(ctx, l)
		if err == nil {
			m.mu.Lock()
			prev := m.sets[l.Name]
			m.mu.Unlock()
			err = Guard(prev, set, m.protected)
		}
		if err != nil {
			os.Remove(m.cachePath(l.Name) + ".tmp")
			m.apply(l.Name, nil, time.Time{}, err)
			continue
		}
		if err := os.Rename(m.cachePath(l.Name)+".tmp", m.cachePath(l.Name)); err != nil {
			m.apply(l.Name, nil, time.Time{}, err)
			continue
		}
		m.apply(l.Name, set, time.Now(), nil)
	}
}

// fetch downloads l into <cache>.tmp while parsing it.
func (m *ListManager) fetch(ctx context.Context, l ListConfig) (map[string]struct{}, error) {
	var src io.ReadCloser
	if path, ok := strings.CutPrefix(l.URL, "file://"); ok {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		src = f
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "shepherd")
		resp, err := m.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
		}
		src = resp.Body
	}
	defer src.Close()

	tmp, err := os.Create(m.cachePath(l.Name) + ".tmp")
	if err != nil {
		return nil, err
	}
	defer tmp.Close()
	set, err := ParseList(io.TeeReader(io.LimitReader(src, 256<<20), tmp))
	if err != nil {
		return nil, err
	}
	return set, tmp.Sync()
}

// Run loads the cache, refreshes now, then refreshes on every interval.
func (m *ListManager) Run(ctx context.Context, every time.Duration) {
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
		}
	}
}
