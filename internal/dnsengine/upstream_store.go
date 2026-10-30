// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const upstreamsFileVersion = 1

// upstreamsFile is the persisted form of the runtime upstream choices
// (<data_dir>/upstreams.json).
type upstreamsFile struct {
	Version   int      `json:"version"`
	Upstreams []string `json:"upstreams"`
	Bootstrap []string `json:"bootstrap"`
}

// SaveError means an edit was valid but could not be written to disk (and was
// undone); it is the server's problem, not the caller's.
type SaveError struct{ Err error }

func (e *SaveError) Error() string { return "saving upstreams: " + e.Err.Error() }
func (e *SaveError) Unwrap() error { return e.Err }

// UpstreamStore persists runtime edits to a Pool. The configuration file seeds
// the pool; the first edit made through the store writes the file, and from
// then on the file wins over the configuration. An empty path keeps edits in
// memory only.
type UpstreamStore struct {
	path string
	pool *Pool

	mu       sync.Mutex
	problem  error
	restored bool
}

// OpenUpstreamStore wraps pool. When path exists it is validated and applied
// over the pool's current (configured) upstreams; an invalid or unreadable file
// is ignored, the configured upstreams stay in force, and LoadProblem says why.
func OpenUpstreamStore(path string, pool *Pool) *UpstreamStore {
	s := &UpstreamStore{path: path, pool: pool}
	if path != "" {
		s.problem = s.load()
	}
	return s
}

func (s *UpstreamStore) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f upstreamsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("parsing %s: %w", s.path, err)
	}
	if f.Version != upstreamsFileVersion {
		return fmt.Errorf("%s: unsupported version %d", s.path, f.Version)
	}
	// Validate both halves before touching the pool, so a bad file changes nothing.
	if _, err := s.pool.parseAll(f.Upstreams); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	if err := newBootstrap().setServers(f.Bootstrap); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	_ = s.pool.SetBootstrap(f.Bootstrap) // both halves were validated above
	_ = s.pool.Set(f.Upstreams)
	s.restored = true
	return nil
}

// LoadProblem is why a saved upstreams.json was ignored at startup, or nil.
func (s *UpstreamStore) LoadProblem() error { return s.problem }

// Restored reports whether the pool was configured from the saved file.
func (s *UpstreamStore) Restored() bool { return s.restored }

func (s *UpstreamStore) current() (addrs, boot []string) {
	for _, u := range s.pool.List() {
		addrs = append(addrs, u.Config)
	}
	return addrs, s.pool.Bootstrap()
}

func (s *UpstreamStore) save() error {
	if s.path == "" {
		return nil
	}
	addrs, boot := s.current()
	b, _ := json.MarshalIndent(upstreamsFile{Version: upstreamsFileVersion, Upstreams: addrs, Bootstrap: boot}, "", "  ") // strings only: cannot fail
	return writeAtomic(s.path, b)
}

// edit applies fn to the pool, saves, and undoes fn when the save fails so
// memory and disk never disagree.
func (s *UpstreamStore) edit(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prevAddrs, prevBoot := s.current()
	if err := fn(); err != nil {
		return err
	}
	if err := s.save(); err != nil {
		_ = s.pool.Set(prevAddrs)
		_ = s.pool.SetBootstrap(prevBoot)
		return &SaveError{err}
	}
	return nil
}

// Set replaces and reorders the upstreams.
func (s *UpstreamStore) Set(addrs []string) error {
	return s.edit(func() error { return s.pool.Set(addrs) })
}

// Add appends an upstream; probing starts at once.
func (s *UpstreamStore) Add(addr string) error {
	return s.edit(func() error { return s.pool.Add(addr) })
}

// Remove deletes an upstream by its configuration string.
func (s *UpstreamStore) Remove(addr string) error {
	return s.edit(func() error { return s.pool.Remove(addr) })
}

// SetBootstrap replaces the bootstrap resolvers.
func (s *UpstreamStore) SetBootstrap(servers []string) error {
	return s.edit(func() error { return s.pool.SetBootstrap(servers) })
}

// Pool is the pool being managed (reads, tests, probing).
func (s *UpstreamStore) Pool() *Pool { return s.pool }

// writeAtomic writes data to path through a temporary file, mode 0600.
func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
