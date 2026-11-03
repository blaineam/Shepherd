// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Origin says who handed a lease out.
type Origin string

// Lease origins.
const (
	// OriginShepherd is a lease Shepherd allocated and acknowledged.
	OriginShepherd Origin = "shepherd"
	// OriginObserved is a lease another DHCP server handed out, which
	// observe mode learned by watching the segment. It is the picture of
	// what the router is doing, and it is never renewed or expired by
	// Shepherd's own allocator.
	OriginObserved Origin = "observed"
)

// Lease is one address Shepherd has handed out, or watched another server
// hand out.
//
// The key is the MAC address. A client identifier (option 61) is recorded
// when one was sent, because it is what RFC 2131 says a server should key on,
// but it is not the key here: a MAC is what the device registry indexes, what
// the portal shows and what a person reads off a label, and a home LAN has no
// clients that share a MAC across identifiers.
type Lease struct {
	MAC      string     `json:"mac"`
	ClientID string     `json:"client_id,omitempty"`
	IP       netip.Addr `json:"ip"`
	Hostname string     `json:"hostname,omitempty"`
	// VendorClass is option 60 and Fingerprint is option 55, the list of
	// options the client asked for. Both are identity evidence a passive
	// listener cannot get any other way, and both go to the device
	// registry rather than being interpreted here.
	VendorClass string `json:"vendor_class,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Router is the address that actually went out in option 3, which is
	// the record of whether this device was routed through Shepherd. It is
	// stored rather than recomputed because the question the portal asks is
	// "what is this device doing now", not "what would we decide now".
	Router netip.Addr `json:"router,omitempty"`
	// Reserved marks a lease that came from a reservation rather than the
	// dynamic pool.
	Reserved bool `json:"reserved,omitempty"`
	// DeviceID is the registry's device, when the observation resolved to
	// one. It is what lets the lease list and the device list be the same
	// list.
	DeviceID string `json:"device_id,omitempty"`

	Origin    Origin    `json:"origin,omitempty"`
	Allocated time.Time `json:"allocated"`
	Renewed   time.Time `json:"renewed,omitempty"`
	Expires   time.Time `json:"expires"`
	// Declines counts DHCPDECLINEs seen for this address. A client that
	// declines has found the address already in use by something Shepherd
	// cannot see, so the allocator avoids it afterwards.
	Declines int `json:"declines,omitempty"`
}

// Routed reports whether this lease sent the device through Shepherd, which
// is true exactly when option 3 named one of Shepherd's own addresses.
func (l Lease) Routed(own []netip.Addr) bool {
	return l.Router.IsValid() && slices.Contains(own, l.Router)
}

// Active reports whether the lease has not expired by now.
func (l Lease) Active(now time.Time) bool { return l.Expires.After(now) }

// NormalizeMAC lowercases and colon-separates a MAC address so the same
// hardware always hashes to one key, whatever spelling it arrived in.
func NormalizeMAC(s string) string {
	var b strings.Builder
	b.Grow(17)
	n := 0
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			if n > 0 && n%2 == 0 {
				b.WriteByte(':')
			}
			b.WriteRune(r)
			n++
		}
	}
	if n != 12 {
		return ""
	}
	return b.String()
}

const leasesVersion = 1

type leaseFile struct {
	Version int      `json:"version"`
	Leases  []*Lease `json:"leases"`
}

// Leases is the lease store: every address Shepherd has handed out or
// watched, in memory, persisted to one JSON file.
//
// It is a separate file from the reservations (see State) on purpose. Leases
// churn — every renewal is a write — and reservations are typed by a person
// and must not be at risk from a renewal storm or from a half-written file.
type Leases struct {
	mu     sync.RWMutex
	byMAC  map[string]*Lease
	dirty  bool
	loaded bool
}

// NewLeases returns an empty store.
func NewLeases() *Leases { return &Leases{byMAC: map[string]*Lease{}} }

// Len is how many leases are stored, expired ones included.
func (s *Leases) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byMAC)
}

// Get returns the lease for mac.
func (s *Leases) Get(mac string) (Lease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.byMAC[NormalizeMAC(mac)]
	if !ok {
		return Lease{}, false
	}
	return *l, true
}

// ByIP returns the lease holding ip, if any.
func (s *Leases) ByIP(ip netip.Addr) (Lease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range s.byMAC {
		if l.IP == ip {
			return *l, true
		}
	}
	return Lease{}, false
}

// All returns every lease, newest allocation first, so the portal's list is
// stable without sorting it again.
func (s *Leases) All() []Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Lease, 0, len(s.byMAC))
	for _, l := range s.byMAC {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b Lease) int {
		if c := b.Allocated.Compare(a.Allocated); c != 0 {
			return c
		}
		return strings.Compare(a.MAC, b.MAC)
	})
	return out
}

// Put stores a lease, replacing any for the same MAC. A lease with an
// unparseable MAC is ignored rather than stored under an empty key.
func (s *Leases) Put(l Lease) {
	mac := NormalizeMAC(l.MAC)
	if mac == "" {
		return
	}
	l.MAC = mac
	s.mu.Lock()
	defer s.mu.Unlock()
	// Carry the decline count forward: it is the store's own memory of an
	// address that turned out to be in use, and a fresh allocation for the
	// same device must not forget it.
	if old, ok := s.byMAC[mac]; ok && old.IP == l.IP {
		l.Declines += old.Declines
	}
	s.byMAC[mac] = &l
	s.dirty = true
}

// Delete removes a lease and reports whether there was one.
func (s *Leases) Delete(mac string) bool {
	mac = NormalizeMAC(mac)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byMAC[mac]; !ok {
		return false
	}
	delete(s.byMAC, mac)
	s.dirty = true
	return true
}

// Decline records that the client holding this address found it already in
// use, and drops the lease so the allocator offers something else.
func (s *Leases) Decline(mac string, ip netip.Addr) {
	mac = NormalizeMAC(mac)
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.byMAC[mac]
	if !ok || l.IP != ip {
		return
	}
	l.Declines++
	l.Expires = time.Time{}
	s.dirty = true
}

// Purge drops leases that expired more than grace ago, and returns how many
// went. Expired leases are kept for a while on purpose: a device that comes
// back after a weekend away should get the address it had, which matters most
// for the devices nobody has reserved an address for.
func (s *Leases) Purge(now time.Time, grace time.Duration) int {
	cutoff := now.Add(-grace)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for mac, l := range s.byMAC {
		if !l.Expires.IsZero() && l.Expires.Before(cutoff) {
			delete(s.byMAC, mac)
			n++
		}
	}
	if n > 0 {
		s.dirty = true
	}
	return n
}

// Routed returns the addresses of every active, Shepherd-issued lease whose
// option 3 named one of own: exactly the set the NAT rules must cover.
func (s *Leases) Routed(now time.Time, own []netip.Addr) []netip.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []netip.Addr
	for _, l := range s.byMAC {
		if l.Origin == OriginShepherd && l.Active(now) && l.IP.IsValid() && l.Routed(own) {
			out = append(out, l.IP)
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}

// Dirty reports whether anything has changed since the last Save, so a
// periodic saver can skip a write.
func (s *Leases) Dirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

// Save writes the store to path atomically, mode 0600.
func (s *Leases) Save(path string) error {
	s.mu.Lock()
	f := leaseFile{Version: leasesVersion}
	for _, l := range s.byMAC {
		c := *l
		f.Leases = append(f.Leases, &c)
	}
	s.mu.Unlock()
	slices.SortFunc(f.Leases, func(a, b *Lease) int { return strings.Compare(a.MAC, b.MAC) })
	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, data); err != nil {
		return err
	}
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	return nil
}

// ErrBadLeases means the lease file could not be read as one.
var ErrBadLeases = errors.New("dhcp: unreadable lease file")

// Load reads path into the store. A missing file is not an error and leaves
// the store empty: there is nothing to recover and every device will ask
// again within a renewal interval.
//
// A file that exists but cannot be parsed returns an error wrapping
// ErrBadLeases, and the caller moves it aside and carries on — see
// LoadOrReset. Refusing to start over a corrupt cache of something every
// client re-asks for would turn a small problem into an outage.
func (s *Leases) Load(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		s.loaded = true
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	var f leaseFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("%w: %v", ErrBadLeases, err)
	}
	if f.Version != leasesVersion {
		return fmt.Errorf("%w: version %d", ErrBadLeases, f.Version)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range f.Leases {
		if l == nil {
			continue
		}
		mac := NormalizeMAC(l.MAC)
		if mac == "" {
			continue
		}
		c := *l
		c.MAC = mac
		s.byMAC[mac] = &c
	}
	s.loaded = true
	return nil
}

// LoadOrReset loads path, and on a parse failure renames the bad file to
// path+".bad" and starts empty. It reports whether the file had to be set
// aside, so the caller can say so loudly rather than losing it quietly.
func (s *Leases) LoadOrReset(path string) (reset bool, err error) {
	err = s.Load(path)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ErrBadLeases) {
		return false, err
	}
	if rerr := os.Rename(path, path+".bad"); rerr != nil {
		return false, fmt.Errorf("dhcp: setting aside %s: %w", path, rerr)
	}
	s.mu.Lock()
	s.loaded = true
	s.mu.Unlock()
	return true, nil
}

// Loaded reports whether a load has happened. Serving is gated on it: a
// server that answers before it knows what it has already handed out will
// hand the same address to two devices.
func (s *Leases) Loaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loaded
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory, so a crash leaves either the old file or the new one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
