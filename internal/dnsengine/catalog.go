// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Kind says what a catalog entry is.
type Kind string

const (
	// KindList is a general DNS blocklist (ads, malware, adult content, ...).
	KindList Kind = "list"
	// KindApp is one app or service, or an umbrella of several (Includes).
	KindApp Kind = "app"
	// KindCategory groups apps and lists so one switch covers all of them.
	KindCategory Kind = "category"
)

// Source is one downloadable file of an entry.
type Source struct {
	URL    string `json:"url"`
	Format string `json:"format"` // "hosts", "domains" or "adblock"; parsing auto-detects, this is informational
	Size   int64  `json:"size_bytes,omitempty"`
}

// CatalogEntry is one thing a user can switch on or off at some scope.
type CatalogEntry struct {
	ID            string   `json:"id"`
	Kind          Kind     `json:"kind"`
	Name          string   `json:"name"`
	Category      string   `json:"category"` // ID of the category entry this belongs to, for display
	Description   string   `json:"description"`
	Sources       []Source `json:"sources"`
	Includes      []string `json:"includes,omitempty"` // member IDs of a category or umbrella app
	License       string   `json:"license"`
	Homepage      string   `json:"homepage"`
	ApproxEntries int      `json:"approx_entries"`
	Recommended   bool     `json:"recommended"` // on by default at network scope
	VerifiedAt    string   `json:"verified_at"` // date the source URLs last resolved
}

// CatalogSet is an indexed, validated set of entries.
type CatalogSet struct {
	entries []CatalogEntry
	byID    map[string]int
}

// validItemID restricts IDs to a file-name-safe alphabet; IDs name cache files.
func validItemID(id string) bool {
	if id == "" || len(id) > 64 || id[0] == '.' || id[0] == '-' {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// NewCatalogSet validates entries: unique file-safe IDs, a known kind, http(s)
// sources on lists, sources or includes on apps, resolvable includes without
// cycles, and categories that only compose other entries.
func NewCatalogSet(entries []CatalogEntry) (*CatalogSet, error) {
	c := &CatalogSet{entries: slices.Clone(entries), byID: map[string]int{}}
	for i, e := range c.entries {
		if !validItemID(e.ID) {
			return nil, fmt.Errorf("catalog: invalid id %q", e.ID)
		}
		if _, dup := c.byID[e.ID]; dup {
			return nil, fmt.Errorf("catalog: duplicate id %q", e.ID)
		}
		c.byID[e.ID] = i
		switch e.Kind {
		case KindList, KindApp, KindCategory:
		default:
			return nil, fmt.Errorf("catalog: %s has unknown kind %q", e.ID, e.Kind)
		}
		if e.Name == "" {
			return nil, fmt.Errorf("catalog: %s has no name", e.ID)
		}
		for _, s := range e.Sources {
			if !strings.HasPrefix(s.URL, "https://") && !strings.HasPrefix(s.URL, "http://") {
				return nil, fmt.Errorf("catalog: %s has a non-http source %q", e.ID, s.URL)
			}
		}
		switch {
		case e.Kind == KindCategory && (len(e.Sources) > 0 || len(e.Includes) == 0):
			return nil, fmt.Errorf("catalog: category %s must only include other entries", e.ID)
		case e.Kind == KindList && (len(e.Sources) == 0 || len(e.Includes) > 0):
			return nil, fmt.Errorf("catalog: list %s needs sources and no includes", e.ID)
		case e.Kind == KindApp && len(e.Sources) == 0 && len(e.Includes) == 0:
			return nil, fmt.Errorf("catalog: app %s needs sources or includes", e.ID)
		}
	}
	for _, e := range c.entries {
		for _, inc := range e.Includes {
			if _, ok := c.byID[inc]; !ok {
				return nil, fmt.Errorf("catalog: %s includes unknown %q", e.ID, inc)
			}
		}
	}
	for _, e := range c.entries {
		if err := c.cycleFree(e.ID, nil); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *CatalogSet) cycleFree(id string, path []string) error {
	if slices.Contains(path, id) {
		return fmt.Errorf("catalog: include cycle through %q", id)
	}
	for _, inc := range c.entries[c.byID[id]].Includes {
		if err := c.cycleFree(inc, append(path, id)); err != nil {
			return err
		}
	}
	return nil
}

// Entries returns a copy of every entry in catalog order.
func (c *CatalogSet) Entries() []CatalogEntry { return slices.Clone(c.entries) }

// ByID looks an entry up.
func (c *CatalogSet) ByID(id string) (CatalogEntry, bool) {
	i, ok := c.byID[id]
	if !ok {
		return CatalogEntry{}, false
	}
	return c.entries[i], true
}

// Leaves expands id into the IDs of the entries that actually carry sources:
// the entry itself when it has any, plus the leaves of everything it includes.
// An unknown id expands to nothing.
func (c *CatalogSet) Leaves(id string) []string {
	var out []string
	var walkIDs func(string)
	walkIDs = func(id string) {
		e, ok := c.ByID(id)
		if !ok {
			return
		}
		if len(e.Sources) > 0 && !slices.Contains(out, id) {
			out = append(out, id)
		}
		for _, inc := range e.Includes {
			walkIDs(inc)
		}
	}
	walkIDs(id)
	return out
}

// Recommended returns the IDs switched on by default at network scope.
func (c *CatalogSet) Recommended() []string {
	var out []string
	for _, e := range c.entries {
		if e.Recommended {
			out = append(out, e.ID)
		}
	}
	return out
}

//go:embed catalog.json
var catalogJSON []byte

var (
	defaultCatalogOnce sync.Once
	defaultCatalog     *CatalogSet
	defaultCatalogErr  error
)

// DefaultCatalog is the catalog shipped inside the binary.
func DefaultCatalog() (*CatalogSet, error) {
	defaultCatalogOnce.Do(func() { defaultCatalog, defaultCatalogErr = loadCatalog(catalogJSON) })
	return defaultCatalog, defaultCatalogErr
}

func loadCatalog(data []byte) (*CatalogSet, error) {
	var entries []CatalogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("catalog.json: %w", err)
	}
	return NewCatalogSet(entries)
}

// Catalog returns the shipped entries. The embedded file is checked by tests,
// so an error here is a build defect and yields an empty catalog.
func Catalog() []CatalogEntry {
	c, err := DefaultCatalog()
	if err != nil {
		return nil
	}
	return c.Entries()
}

// CatalogByID looks an ID up in the shipped catalog.
func CatalogByID(id string) (CatalogEntry, bool) {
	c, err := DefaultCatalog()
	if err != nil {
		return CatalogEntry{}, false
	}
	return c.ByID(id)
}
