// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
)

const geoBlockFileVersion = 1

// validCountry reports whether code has the shape of an ISO 3166-1 alpha-2
// country code: exactly two uppercase ASCII letters. It is a format check
// only — Shepherd ships no canonical list of assigned codes here, so a
// well-formed but unassigned code is accepted and simply never matches a
// resolved country (see docs/GEOBLOCK.md).
func validCountry(code string) bool {
	return len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z'
}

// normalizeCountries upper-cases, trims, dedupes and sorts codes, rejecting
// anything that is not a two-letter code.
func normalizeCountries(codes []string) ([]string, error) {
	out := make([]string, 0, len(codes))
	seen := map[string]bool{}
	for _, c := range codes {
		u := strings.ToUpper(strings.TrimSpace(c))
		if !validCountry(u) {
			return nil, fmt.Errorf("%q is not a two-letter ISO country code", c)
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	slices.Sort(out)
	return out, nil
}

// GeoBlockData is the persisted document for per-scope country blocking
// (<data_dir>/geoblock.json). It is kept deliberately separate from
// policy.json: country blocking is an additive check layered on top of the
// Filter's own decision (see Engine.CountryBlock), never one of the
// Filter's own rules, so editing it never touches Filter, CheckFor or
// policy.json.
type GeoBlockData struct {
	Version int                 `json:"version"`
	Network []string            `json:"network,omitempty"`
	Groups  map[string][]string `json:"groups,omitempty"`
	Devices map[string][]string `json:"devices,omitempty"`
}

func (d GeoBlockData) clone() GeoBlockData {
	out := GeoBlockData{Version: d.Version, Network: slices.Clone(d.Network), Groups: map[string][]string{}, Devices: map[string][]string{}}
	for k, v := range d.Groups {
		out.Groups[k] = slices.Clone(v)
	}
	for k, v := range d.Devices {
		out.Devices[k] = slices.Clone(v)
	}
	return out
}

func (d *GeoBlockData) get(sc Scope) []string {
	switch sc.Kind {
	case ScopeNetwork:
		return d.Network
	case ScopeGroup:
		return d.Groups[sc.ID]
	case ScopeDevice:
		return d.Devices[sc.ID]
	}
	return nil
}

// put stores codes for sc, removing the scope's entry entirely once it is
// empty so the persisted document and the API stay sparse.
func (d *GeoBlockData) put(sc Scope, codes []string) {
	switch sc.Kind {
	case ScopeNetwork:
		d.Network = codes
	case ScopeGroup:
		if len(codes) == 0 {
			delete(d.Groups, sc.ID)
		} else {
			d.Groups[sc.ID] = codes
		}
	case ScopeDevice:
		if len(codes) == 0 {
			delete(d.Devices, sc.ID)
		} else {
			d.Devices[sc.ID] = codes
		}
	}
}

func (d *GeoBlockData) validate() error {
	if d.Version != geoBlockFileVersion {
		return fmt.Errorf("unsupported geoblock version %d", d.Version)
	}
	if d.Groups == nil {
		d.Groups = map[string][]string{}
	}
	if d.Devices == nil {
		d.Devices = map[string][]string{}
	}
	if _, err := normalizeCountries(d.Network); err != nil {
		return err
	}
	for _, m := range []map[string][]string{d.Groups, d.Devices} {
		for id, codes := range m {
			if !validScopeID(id) {
				return fmt.Errorf("invalid scope id %q", id)
			}
			if _, err := normalizeCountries(codes); err != nil {
				return err
			}
		}
	}
	return nil
}

// GeoBlockStore owns the per-scope lists of blocked ISO country codes. It
// validates edits and persists them atomically to geoblock.json (mode
// 0600), the same way PolicyStore persists policy.json, but it never
// touches the Filter: evaluation happens outside it, in the additive check
// wired to Engine.CountryBlock (see docs/GEOBLOCK.md). An empty path keeps
// edits in memory only, and nothing is written to disk until the first
// country is blocked anywhere.
type GeoBlockStore struct {
	path string
	mu   sync.Mutex
	data GeoBlockData
}

// OpenGeoBlockStore loads path (a missing file, or an empty path, is fine
// and starts with nothing blocked anywhere).
func OpenGeoBlockStore(path string) (*GeoBlockStore, error) {
	s := &GeoBlockStore{path: path, data: GeoBlockData{Version: geoBlockFileVersion, Groups: map[string][]string{}, Devices: map[string][]string{}}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		if err := s.data.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		// fresh install: nothing blocked, nothing written until the first edit
	default:
		return nil, err
	}
	return s, nil
}

func writeGeoBlockFile(path string, d GeoBlockData) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}

// mutate runs fn on a copy of the data, persists it (unless the store is
// memory-only), and only then commits it in memory, so a failed save
// changes nothing.
func (s *GeoBlockStore) mutate(fn func(d *GeoBlockData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.clone()
	if err := fn(&next); err != nil {
		return err
	}
	if s.path != "" {
		if err := writeGeoBlockFile(s.path, next); err != nil {
			return err
		}
	}
	s.data = next
	return nil
}

func scopeErr(sc Scope) error {
	switch sc.Kind {
	case ScopeNetwork:
		return nil
	case ScopeGroup, ScopeDevice:
		if !validScopeID(sc.ID) {
			return fmt.Errorf("invalid %s id %q", sc.Kind, sc.ID)
		}
		return nil
	}
	return fmt.Errorf("invalid scope kind %q", sc.Kind)
}

// SetCountries replaces the whole list of blocked countries at sc. An empty
// list is the same as ClearCountries.
func (s *GeoBlockStore) SetCountries(sc Scope, codes []string) error {
	norm, err := normalizeCountries(codes)
	if err != nil {
		return err
	}
	if err := scopeErr(sc); err != nil {
		return err
	}
	return s.mutate(func(d *GeoBlockData) error {
		d.put(sc, norm)
		return nil
	})
}

// ClearCountries removes every blocked country set directly at sc.
func (s *GeoBlockStore) ClearCountries(sc Scope) error { return s.SetCountries(sc, nil) }

// Countries returns the codes blocked directly at sc (not its union with
// other scopes — see BlockedFor for that).
func (s *GeoBlockStore) Countries(sc Scope) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.data.get(sc))
}

// DeleteScope forgets everything configured at a group or device, for when
// the registry deletes it. The network scope cannot be deleted.
func (s *GeoBlockStore) DeleteScope(sc Scope) error {
	switch sc.Kind {
	case ScopeGroup, ScopeDevice:
		return s.mutate(func(d *GeoBlockData) error { d.put(sc, nil); return nil })
	default:
		return errors.New("the network scope cannot be deleted")
	}
}

// GeoBlockSnapshot is a deep copy of the state for the UI.
type GeoBlockSnapshot struct {
	Network []string            `json:"network"`
	Groups  map[string][]string `json:"groups"`
	Devices map[string][]string `json:"devices"`
}

// Snapshot returns the current settings.
func (s *GeoBlockStore) Snapshot() GeoBlockSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.data.clone()
	return GeoBlockSnapshot{Network: d.Network, Groups: d.Groups, Devices: d.Devices}
}

// BlockedFor returns the set of ISO country codes blocked for the client:
// the union of the network's list and whatever applies to the client's
// device and groups (like Filter.CheckFor, blocks only ever add up — there
// is no allow override here, because there is nothing to allow: a country
// not listed is never blocked). It returns nil when nothing is configured
// anywhere, the common case, without allocating. cs may be nil (network
// scope only).
func (s *GeoBlockStore) BlockedFor(clientIP string, cs ClientScopes) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Network) == 0 && len(s.data.Groups) == 0 && len(s.data.Devices) == 0 {
		return nil
	}
	out := make(map[string]bool, len(s.data.Network))
	for _, c := range s.data.Network {
		out[c] = true
	}
	if cs != nil {
		dev, groups := cs.ScopesFor(clientIP)
		for _, g := range groups {
			for _, c := range s.data.Groups[g] {
				out[c] = true
			}
		}
		if dev != "" {
			for _, c := range s.data.Devices[dev] {
				out[c] = true
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
