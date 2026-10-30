// SPDX-License-Identifier: AGPL-3.0-or-later

// Package settings stores small user preferences that the portal changes at
// runtime, such as where "home" is on the globe.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Home sources: the user's choice always beats the detected one.
const (
	SourceUser = "user"
	SourceAuto = "auto"
)

// Home is where arcs start on the globe.
type Home struct {
	Lat    float64   `json:"lat"`
	Lon    float64   `json:"lon"`
	Label  string    `json:"label,omitempty"`
	Source string    `json:"source,omitempty"` // "user" or "auto"
	At     time.Time `json:"at,omitempty"`     // when an automatic home was detected
}

type file struct {
	User *Home `json:"home,omitempty"`      // set by the user
	Auto *Home `json:"auto_home,omitempty"` // detected from the network's public address
}

// Store persists settings to one JSON file (mode 0600). It stores where home
// is, never the public IP address it was worked out from.
type Store struct {
	path string
	mu   sync.Mutex
	data file
}

// Open loads path; a missing file is an empty store.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	return s, nil
}

func copyOf(h *Home, source string) *Home {
	if h == nil {
		return nil
	}
	c := *h
	c.Source = source
	return &c
}

// Home returns the effective home: the user's choice if there is one,
// otherwise the detected location, otherwise nil.
func (s *Store) Home() *Home {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.User != nil {
		return copyOf(s.data.User, SourceUser)
	}
	return copyOf(s.data.Auto, SourceAuto)
}

// UserHome returns the user's override, or nil when home is automatic.
func (s *Store) UserHome() *Home {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyOf(s.data.User, SourceUser)
}

func validate(h *Home) error {
	if math.IsNaN(h.Lat) || math.IsNaN(h.Lon) || h.Lat < -90 || h.Lat > 90 || h.Lon < -180 || h.Lon > 180 {
		return errors.New("latitude must be between -90 and 90 and longitude between -180 and 180")
	}
	h.Label = strings.TrimSpace(h.Label)
	if utf8.RuneCountInString(h.Label) > 80 {
		return errors.New("label is limited to 80 characters")
	}
	return nil
}

func (s *Store) saveLocked(next file) error {
	b, _ := json.MarshalIndent(next, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.data = next
	return nil
}

// SetHome validates and saves the user's override.
func (s *Store) SetHome(h Home) error {
	if err := validate(&h); err != nil {
		return err
	}
	h.Source, h.At = SourceUser, time.Time{}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data
	next.User = &h
	return s.saveLocked(next)
}

// ClearHome removes the user's override so home follows the detected location again.
func (s *Store) ClearHome() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data
	next.User = nil
	return s.saveLocked(next)
}

// SetAuto records a detected location. It never touches the user's override.
func (s *Store) SetAuto(h Home) error {
	if err := validate(&h); err != nil {
		return err
	}
	h.Source = SourceAuto
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data
	next.Auto = &h
	return s.saveLocked(next)
}
