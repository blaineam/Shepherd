// SPDX-License-Identifier: AGPL-3.0-or-later

package reverseproxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

var (
	// ErrNotFound means no host has the given id.
	ErrNotFound = errors.New("no such proxy host")
	// ErrDuplicate means another host already answers for that domain:
	// two backends for one name would make routing a coin toss.
	ErrDuplicate = errors.New("another proxy host already uses that domain")
)

const fileVersion = 1

type file struct {
	Version int    `json:"version"`
	Hosts   []Host `json:"hosts"`
}

// Store owns the proxied hosts. The portal is their only editor: nothing is
// seeded from shepherd.toml (these are live deployment details, the kind of
// thing a config file in a repository should never carry), and nothing is
// written until the first edit, the same way GeoBlockStore treats
// geoblock.json. Every edit is validated, saved atomically (mode 0600) and
// only then made visible to the proxy, so routing and disk never disagree.
// An empty path keeps everything in memory.
type Store struct {
	path string

	mu       sync.RWMutex
	hosts    []Host          // sorted by domain
	byDomain map[string]Host // the routing index Lookup reads
}

// Open loads path. A missing file starts empty. A file that cannot be read
// or validated is an error rather than a fresh start: carrying on with an
// empty list would let the first edit from the portal overwrite every host
// the owner had.
func Open(path string) (*Store, error) {
	s := &Store{path: path, byDomain: map[string]Host{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("%s: unsupported version %d", path, f.Version)
	}
	ids := map[string]bool{}
	var hosts []Host
	for _, h := range f.Hosts {
		n, err := h.Normalize()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if n.ID == "" || ids[n.ID] {
			return nil, fmt.Errorf("%s: host %s has a missing or repeated id", path, n.Domain)
		}
		ids[n.ID] = true
		hosts = append(hosts, n)
	}
	byDomain, err := index(hosts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.install(hosts, byDomain)
	return s, nil
}

// List returns every host, sorted by domain.
func (s *Store) List() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.hosts)
}

// Get returns the host with id.
func (s *Store) Get(id string) (Host, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := s.indexOf(id)
	if i < 0 {
		return Host{}, false
	}
	return s.hosts[i], true
}

// Lookup finds the host for a request's Host header, spelled however a
// client sends it: any case, an optional port, an optional trailing dot.
// Disabled hosts are returned too; the proxy decides what that means.
func (s *Store) Lookup(hostHeader string) (Host, bool) {
	d := hostHeader
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.byDomain[d]
	return h, ok
}

// Add validates h, gives it a new id, and saves it.
func (s *Store) Add(h Host) (Host, error) {
	n, err := h.Normalize()
	if err != nil {
		return Host{}, err
	}
	n.ID = newID()
	return n, s.mutate(func(hosts []Host) ([]Host, error) { return append(hosts, n), nil })
}

// Update replaces the host with id by h (whose own ID is ignored).
func (s *Store) Update(id string, h Host) (Host, error) {
	n, err := h.Normalize()
	if err != nil {
		return Host{}, err
	}
	n.ID = id
	return n, s.mutate(func(hosts []Host) ([]Host, error) {
		i := slices.IndexFunc(hosts, func(x Host) bool { return x.ID == id })
		if i < 0 {
			return nil, ErrNotFound
		}
		hosts[i] = n
		return hosts, nil
	})
}

// Remove deletes the host with id; requests for its domain get a 404 from
// the very next request on.
func (s *Store) Remove(id string) error {
	return s.mutate(func(hosts []Host) ([]Host, error) {
		i := slices.IndexFunc(hosts, func(x Host) bool { return x.ID == id })
		if i < 0 {
			return nil, ErrNotFound
		}
		return slices.Delete(hosts, i, i+1), nil
	})
}

// mutate applies fn to a copy, saves the result, and only then swaps it in.
func (s *Store) mutate(fn func([]Host) ([]Host, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := fn(slices.Clone(s.hosts))
	if err != nil {
		return err
	}
	byDomain, err := index(next)
	if err != nil {
		return err
	}
	if s.path != "" {
		if err := s.save(next); err != nil {
			return err
		}
	}
	s.install(next, byDomain)
	return nil
}

// install makes hosts the live set. The caller holds mu (or, in Open, owns
// a Store nobody else can see yet).
func (s *Store) install(hosts []Host, byDomain map[string]Host) {
	slices.SortFunc(hosts, func(a, b Host) int { return strings.Compare(a.Domain, b.Domain) })
	s.hosts, s.byDomain = hosts, byDomain
}

func index(hosts []Host) (map[string]Host, error) {
	m := make(map[string]Host, len(hosts))
	for _, h := range hosts {
		if _, dup := m[h.Domain]; dup {
			return nil, fmt.Errorf("%w: %s", ErrDuplicate, h.Domain)
		}
		m[h.Domain] = h
	}
	return m, nil
}

func (s *Store) indexOf(id string) int {
	return slices.IndexFunc(s.hosts, func(h Host) bool { return h.ID == id })
}

func (s *Store) save(hosts []Host) error {
	b, _ := json.MarshalIndent(file{Version: fileVersion, Hosts: append([]Host{}, hosts...)}, "", "  ") // strings, ints and bools only: cannot fail
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b)
}
