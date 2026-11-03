// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Reservation is the operator's statement that one piece of hardware gets a
// particular address, and optionally a particular name.
//
// Address is allowed to be unset. A reservation with no address is still
// worth having: it is where a chosen hostname lives for a device that does
// not need a fixed address, and it is a place to write a note about a device
// before it ever appears.
type Reservation struct {
	MAC      string     `json:"mac"`
	IP       netip.Addr `json:"ip,omitempty"`
	Hostname string     `json:"hostname,omitempty"`
	Note     string     `json:"note,omitempty"`
	Created  time.Time  `json:"created"`
	Updated  time.Time  `json:"updated"`
}

const maxNote = 200
const maxHostname = 63 // one DNS label, RFC 1035

// ErrReservation is the base for every rejected reservation, so a caller can
// report the reason as a bad request rather than a server error.
var ErrReservation = errors.New("dhcp: reservation")

// Validate normalizes a reservation and reports why it cannot be stored.
//
// A reserved address inside the dynamic pool is **allowed**. An earlier
// version of this refused one, on the grounds that handing the same address
// out twice is the commonest way to break a DHCP server. That reasoning was
// right about the danger and wrong about where it is handled: the allocator
// already takes somebody else's reservation out of the pool walk
// (Allocator.free), so an in-pool reservation can only ever go to the device
// it names. Refusing one instead made the ordinary thing — pinning a device
// to the address it already has, which is nearly always a pool address —
// impossible, which is worse than untidy.
//
// The portal still says when a reserved address sits inside the pool,
// because shrinking the pool past it is tidier and because an operator
// should know. It says it as a note, not a refusal.
func (r *Reservation) Validate(subnet netip.Prefix, pool Pool) error {
	r.MAC = NormalizeMAC(r.MAC)
	if r.MAC == "" {
		return fmt.Errorf("%w: a MAC address is required, as six hex pairs", ErrReservation)
	}
	r.Hostname = strings.TrimSpace(r.Hostname)
	if utf8.RuneCountInString(r.Hostname) > maxHostname {
		return fmt.Errorf("%w: a hostname is limited to %d characters", ErrReservation, maxHostname)
	}
	if r.Hostname != "" && !validHostname(r.Hostname) {
		return fmt.Errorf("%w: a hostname may hold letters, digits and hyphens only", ErrReservation)
	}
	r.Note = strings.TrimSpace(r.Note)
	if utf8.RuneCountInString(r.Note) > maxNote {
		return fmt.Errorf("%w: a note is limited to %d characters", ErrReservation, maxNote)
	}
	if !r.IP.IsValid() {
		return nil
	}
	if !r.IP.Is4() {
		return fmt.Errorf("%w: the address must be IPv4; DHCP mode does not touch IPv6 (docs/DHCP.md)", ErrReservation)
	}
	if subnet.IsValid() && !subnet.Contains(r.IP) {
		return fmt.Errorf("%w: %s is not inside the LAN %s", ErrReservation, r.IP, subnet)
	}
	return nil
}

// InPool reports whether a reservation sits inside the dynamic range. It is
// a note for the portal, not a refusal: see Validate.
func (r Reservation) InPool(pool Pool) bool { return r.IP.IsValid() && pool.Contains(r.IP) }

func validHostname(s string) bool {
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

const stateVersion = 1

type stateFile struct {
	Version int `json:"version"`
	// Reservations is the operator's intent, and the reason this file is
	// separate from the leases.
	Reservations []*Reservation `json:"reservations,omitempty"`
	// Range is the addressing the operator chose in the portal, which
	// overrides what the configuration file and the interface say. It is
	// stored rather than configured because choosing it is a decision
	// taken against the live network -- Check compares it with what is
	// actually in use -- and because changing it should not need a
	// restart.
	Range *Range `json:"range,omitempty"`
	// Confirmed records that someone typed the confirmation in the portal.
	// It is stored rather than held in memory because the whole point is
	// that a restart must not quietly start serving DHCP for a household
	// that never agreed to it.
	Confirmed   bool      `json:"confirmed,omitempty"`
	ConfirmedAt time.Time `json:"confirmed_at,omitempty"`
	// Disarmed is the kill switch. It stays set across restarts, the same
	// way Watch mode's does, so that pressing it is a decision rather than
	// a pause until the next deploy.
	Disarmed   bool      `json:"disarmed,omitempty"`
	DisarmedAt time.Time `json:"disarmed_at,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

// State is the operator's side of DHCP mode: the reservations, the typed
// confirmation, and the kill switch. One JSON file, rarely written.
type State struct {
	path string
	now  func() time.Time
	mu   sync.RWMutex
	data stateFile
}

// OpenState loads path. A missing file is an empty state. A file that exists
// and cannot be parsed is an error and the caller should refuse to start:
// unlike the leases, there is nothing here that any client will re-send, and
// silently dropping a reservation is how a printer changes address.
func OpenState(path string, now func() time.Time) (*State, error) {
	if now == nil {
		now = time.Now
	}
	s := &State{path: path, now: now, data: stateFile{Version: stateVersion}}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("dhcp: parsing %s: %w", path, err)
	}
	if f.Version != stateVersion {
		return nil, fmt.Errorf("dhcp: %s has version %d, which this build does not know", path, f.Version)
	}
	for _, r := range f.Reservations {
		if r != nil {
			r.MAC = NormalizeMAC(r.MAC)
		}
	}
	f.Reservations = slices.DeleteFunc(f.Reservations, func(r *Reservation) bool { return r == nil || r.MAC == "" })
	s.data = f
	return s, nil
}

func (s *State) saveLocked() error {
	s.data.Version = stateVersion
	slices.SortFunc(s.data.Reservations, func(a, b *Reservation) int { return strings.Compare(a.MAC, b.MAC) })
	data, err := json.MarshalIndent(s.data, "", " ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data)
}

// Reservations returns every reservation, by MAC.
func (s *State) Reservations() []Reservation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Reservation, 0, len(s.data.Reservations))
	for _, r := range s.data.Reservations {
		out = append(out, *r)
	}
	return out
}

// Reservation returns the reservation for mac.
func (s *State) Reservation(mac string) (Reservation, bool) {
	mac = NormalizeMAC(mac)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.data.Reservations {
		if r.MAC == mac {
			return *r, true
		}
	}
	return Reservation{}, false
}

// SetReservation adds or replaces one reservation. It validates against the
// LAN and the pool, and refuses an address another reservation already holds.
func (s *State) SetReservation(r Reservation, subnet netip.Prefix, pool Pool) error {
	if err := r.Validate(subnet, pool); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.data.Reservations {
		if o.MAC != r.MAC && r.IP.IsValid() && o.IP == r.IP {
			return fmt.Errorf("%w: %s is already reserved for %s", ErrReservation, r.IP, o.MAC)
		}
	}
	now := s.now()
	r.Updated = now
	prev := s.data.Reservations
	for i, o := range prev {
		if o.MAC == r.MAC {
			r.Created = o.Created
			c := r
			// A fresh slice, not an in-place write: s.data.Reservations
			// and prev would otherwise share one backing array, and the
			// rollback below would not undo anything.
			next := slices.Clone(prev)
			next[i] = &c
			s.data.Reservations = next
			if err := s.saveLocked(); err != nil {
				s.data.Reservations = prev
				return err
			}
			return nil
		}
	}
	r.Created = now
	c := r
	s.data.Reservations = append(slices.Clone(prev), &c)
	if err := s.saveLocked(); err != nil {
		s.data.Reservations = prev
		return err
	}
	return nil
}

// DeleteReservation removes one and reports whether there was one. The
// device's current lease is left alone: it expires on its own, and taking an
// address away from a running device is not what deleting a reservation asks
// for.
func (s *State) DeleteReservation(mac string) (bool, error) {
	mac = NormalizeMAC(mac)
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.data.Reservations)
	kept := slices.DeleteFunc(slices.Clone(s.data.Reservations), func(r *Reservation) bool { return r.MAC == mac })
	if len(kept) == before {
		return false, nil
	}
	prev := s.data.Reservations
	s.data.Reservations = kept
	if err := s.saveLocked(); err != nil {
		s.data.Reservations = prev
		return false, err
	}
	return true, nil
}

// Range returns the operator's chosen addressing, or the zero Range when
// they have not chosen one and the configuration file is the truth.
func (s *State) Range() Range {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.Range == nil {
		return Range{}
	}
	return *s.data.Range
}

// SetRange stores a chosen range, or clears it when r is not set, which puts
// the configuration file and the interface back in charge.
//
// It validates the range on its own terms and nothing more: whether it fits
// the network as it is now is Check's question, and the answer changes as
// the operator works through it. Refusing to *store* a range that does not
// fit yet would make it impossible to write down where you are going before
// you get there.
func (s *State) SetRange(r Range) error {
	if r.Set() {
		if err := r.Validate(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.data.Range
	if r.Set() {
		c := r
		s.data.Range = &c
	} else {
		s.data.Range = nil
	}
	if err := s.saveLocked(); err != nil {
		s.data.Range = prev
		return err
	}
	return nil
}

// Confirmed reports whether the typed portal confirmation has been given.
func (s *State) Confirmed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Confirmed
}

// SetConfirmed records or withdraws the confirmation that Shepherd may serve
// DHCP for this network.
func (s *State) SetConfirmed(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.data
	s.data.Confirmed = on
	if on {
		s.data.ConfirmedAt = s.now()
	} else {
		s.data.ConfirmedAt = time.Time{}
	}
	if err := s.saveLocked(); err != nil {
		s.data = prev
		return err
	}
	return nil
}

// Disarmed reports whether the kill switch has been pulled, and why.
func (s *State) Disarmed() (bool, string, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Disarmed, s.data.Reason, s.data.DisarmedAt
}

// SetDisarmed pulls or re-arms the kill switch. Pulling it stops routing —
// not leasing — so devices keep getting addresses, with the gateway's own
// address in option 3.
func (s *State) SetDisarmed(off bool, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.data
	s.data.Disarmed = off
	s.data.Reason = strings.TrimSpace(reason)
	if off {
		s.data.DisarmedAt = s.now()
	} else {
		s.data.DisarmedAt, s.data.Reason = time.Time{}, ""
	}
	if err := s.saveLocked(); err != nil {
		s.data = prev
		return err
	}
	return nil
}
