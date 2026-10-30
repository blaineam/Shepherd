// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Errors returned by registry operations.
var (
	ErrNotFound      = errors.New("devices: device not found")
	ErrGroupNotFound = errors.New("devices: group not found")
	ErrDuplicateName = errors.New("devices: a group with that name already exists")
	ErrInvalid       = errors.New("devices: invalid argument")
	ErrEmptySplit    = errors.New("devices: split would leave the device without an address")
	ErrReservedGroup = errors.New("devices: quarantine is a reserved group and cannot be deleted")
)

// QuarantineGroupID is the reserved group every newly discovered device joins
// automatically. It cannot be deleted; assigning a device to any other group
// removes it from quarantine (see BulkAssignGroup). Call EnsureQuarantineGroup
// once at startup so it always exists, even for a data file from before this
// feature existed.
const QuarantineGroupID = "quarantine"

const (
	maxCurrentV6 = 8
	maxPastIPs   = 16
	maxServices  = 32
	maxHints     = 16
	// restampAfter bounds how often a device that is merely seen again
	// (nothing else changed) gets a new sync stamp.
	restampAfter = 5 * time.Minute
)

// Options configures a Registry. The zero value is usable.
type Options struct {
	NodeID string                  // writer identity stamped on records; default "local"
	Now    func() time.Time        // test clock
	Vendor func(mac string) string // MAC -> vendor; default the embedded OUI table
	NewID  func() string           // device ID source for IP-only devices; default random
	Codec  Codec                   // persistence codec; default plain JSON
	// AllowLoopback lets loopback addresses become devices. Only tests and
	// local development need it; a real network never has loopback clients.
	AllowLoopback bool
}

// Registry is the device registry. It is safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	node     string
	now      func() time.Time
	vendorOf func(string) string
	newID    func() string
	codec    Codec
	loopback bool

	clock   HLC
	devices map[string]*Device // live devices and tombstones
	groups  map[string]*Group
	byMAC   map[string]*Device
	byIP    map[netip.Addr]*Device
	dirty   bool

	scope atomic.Pointer[scopeSnap]

	subMu  sync.RWMutex
	subSeq int
	subs   map[int]func(Event)
}

// New creates an empty registry.
func New(opts Options) *Registry {
	r := &Registry{
		node:     opts.NodeID,
		now:      opts.Now,
		vendorOf: opts.Vendor,
		newID:    opts.NewID,
		codec:    opts.Codec,
		loopback: opts.AllowLoopback,
		devices:  map[string]*Device{},
		groups:   map[string]*Group{},
		byMAC:    map[string]*Device{},
		byIP:     map[netip.Addr]*Device{},
		subs:     map[int]func(Event){},
	}
	if r.node == "" {
		r.node = "local"
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.vendorOf == nil {
		r.vendorOf = LookupVendor
	}
	if r.newID == nil {
		r.newID = randomID
	}
	if r.codec == nil {
		r.codec = PlainCodec{}
	}
	r.rebuildScopes()
	return r
}

func randomID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "d-" + hex.EncodeToString(b[:])
}

// do runs fn under the write lock, refreshes the scope index if fn changed
// it, and emits the events fn returns after unlocking.
func (r *Registry) do(fn func() []Event) {
	r.mu.Lock()
	evs := fn()
	if r.dirty {
		r.rebuildScopes()
		r.dirty = false
	}
	r.mu.Unlock()
	now := r.now()
	for i := range evs {
		evs[i].Time = now
	}
	r.emit(evs)
}

// tick returns a fresh, strictly increasing HLC stamp. Callers hold r.mu.
func (r *Registry) tick() HLC {
	w := r.now().UnixMilli()
	if w > r.clock.Wall {
		r.clock = HLC{Wall: w}
	} else {
		r.clock.Counter++
	}
	return r.clock
}

func (r *Registry) stamp(d *Device) {
	d.Updated = r.tick()
	d.Node = r.node
}

// ---- observation ----------------------------------------------------------

// Observe merges one piece of identity evidence and returns the ID of the
// device it landed on ("" when the observation carries neither a usable MAC
// nor a usable IP).
func (r *Registry) Observe(o Observation) string {
	var id string
	r.do(func() []Event {
		var evs []Event
		id, evs = r.observeLocked(o)
		return evs
	})
	return id
}

func parseIP(s string) (netip.Addr, bool) { return parseIPOpt(s, false) }

func parseIPOpt(s string, allowLoopback bool) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap().WithZone("")
	if a.IsUnspecified() || a.IsMulticast() || (a.IsLoopback() && !allowLoopback) {
		return netip.Addr{}, false
	}
	return a, true
}

func (r *Registry) observeLocked(o Observation) (string, []Event) {
	mac, _ := NormalizeMAC(o.MAC)
	ip, hasIP := parseIPOpt(o.IP, r.loopback)
	if mac == "" && !hasIP {
		return "", nil
	}
	host := cleanName(o.Hostname)
	now := o.Time
	if now.IsZero() {
		now = r.now()
	}
	strongName := (o.Source == SourceMDNS || o.Source == SourceDHCP) && usableName(host)

	var d *Device
	created, learned := false, false
	if mac != "" {
		d = r.byMAC[mac]
		var holder *Device
		if hasIP {
			holder = r.byIP[ip]
		}
		if d == nil {
			switch {
			case holder != nil && len(holder.MACs) == 0:
				d = holder // MAC learned late for an IP-only device
			case holder != nil && IsLocallyAdministered(mac) && holder.Randomized() && !nameConflict(holder, host):
				d = holder // rotated private address, same place on the network
			case IsLocallyAdministered(mac) && strongName:
				d = r.findByName(host, true)
			}
			if d != nil {
				d.MACs = append(d.MACs, mac)
				r.byMAC[mac] = d
				learned = true
			} else {
				d, created = r.newDevice(mac, now), true
			}
		} else if holder != nil && holder != d && len(holder.MACs) == 0 {
			r.mergeLocked(d, holder, now)
			learned = true
		}
	} else {
		d = r.byIP[ip]
		if d == nil && strongName {
			d = r.findByName(host, false)
		}
		if d == nil && o.Source == SourceReverseDNS {
			return "", nil // a PTR name never justifies a new device
		}
		if d == nil {
			d, created = r.newDevice("", now), true
		}
	}

	before := d.DisplayName()
	changed := created || learned
	if hasIP && r.addIP(d, ip, now) {
		changed = true
	}
	if r.applyEvidence(d, o, host, now) {
		changed = true
	}
	if changed || now.Sub(time.UnixMilli(d.Updated.Wall)) >= restampAfter {
		r.stamp(d)
	}

	var evs []Event
	switch {
	case created:
		evs = append(evs, Event{Kind: EventNewDevice, DeviceID: d.ID, NewName: d.DisplayName(), Device: r.copyOut(d)})
	case d.DisplayName() != before:
		evs = append(evs, Event{Kind: EventRenamed, DeviceID: d.ID, OldName: before, NewName: d.DisplayName()})
	}
	return d.ID, evs
}

// newDevice creates and indexes a device. Devices with a MAC get a
// deterministic ID derived from it so replicas that discover the same device
// independently converge on one record.
func (r *Registry) newDevice(mac string, now time.Time) *Device {
	var id string
	if mac != "" {
		sum := sha256.Sum256([]byte("mac:" + mac))
		id = "d-" + hex.EncodeToString(sum[:6])
		if old := r.devices[id]; old != nil && !old.Deleted {
			id = ""
		}
	}
	for id == "" || r.devices[id] != nil && !r.devices[id].Deleted {
		id = r.newID()
	}
	d := &Device{ID: id, FirstSeen: now, LastSeen: now, Type: TypeUnknown}
	if mac != "" {
		d.MACs = []string{mac}
		r.byMAC[mac] = d
	}
	r.devices[id] = d
	r.stamp(d)
	r.dirty = true
	return d
}

// findByName returns a live device already known by the given hostname.
// With randomizedOnly it considers only devices whose MACs are all
// randomized (the rotating-address case).
func (r *Registry) findByName(host string, randomizedOnly bool) *Device {
	key := nameKey(host)
	ids := make([]string, 0, len(r.devices))
	for id := range r.devices {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic when two devices share a name
	for _, id := range ids {
		d := r.devices[id]
		if d.Deleted || randomizedOnly && !d.Randomized() {
			continue
		}
		if nameKey(d.MDNSName) == key || nameKey(d.Hostname) == key {
			return d
		}
	}
	return nil
}

func nameConflict(d *Device, host string) bool {
	if !usableName(host) {
		return false
	}
	key := nameKey(host)
	var have bool
	for _, n := range []string{d.MDNSName, d.Hostname} {
		if usableName(n) {
			have = true
			if nameKey(n) == key {
				return false
			}
		}
	}
	return have
}

// genericNames are hostnames shared by many unrelated devices; they never
// justify merging two devices.
var genericNames = map[string]bool{
	"localhost": true, "iphone": true, "ipad": true, "android": true, "unknown": true,
	"mac": true, "macbook": true, "galaxy": true, "pixel": true, "windows": true,
	"desktop": true, "laptop": true, "ipod": true, "phone": true, "tablet": true,
	"raspberrypi": true, "esp": true, "chromecast": true,
}

func usableName(s string) bool {
	k := nameKey(s)
	return k != "" && !genericNames[k]
}

func nameKey(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(s), "."), ".local"))
}

// cleanName tidies a hostname for display: trailing dot and ".local" go.
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSuffix(s, ".local")
	return s
}

func isV4(s string) bool { return !strings.Contains(s, ":") }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func remove(list []string, s string) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

func union(a []string, b []string, limit int) []string {
	for _, s := range b {
		if s != "" && !contains(a, s) && (limit <= 0 || len(a) < limit) {
			a = append(a, s)
		}
	}
	return a
}

// addIP makes ip a current address of d, displacing it from any other
// device. It reports whether d's address lists changed.
func (r *Registry) addIP(d *Device, ip netip.Addr, now time.Time) bool {
	s := ip.String()
	if h := r.byIP[ip]; h != nil && h != d {
		r.demoteIP(h, s)
		r.stamp(h)
	}
	if d.IPSeen == nil {
		d.IPSeen = map[string]time.Time{}
	}
	if now.After(d.IPSeen[s]) {
		d.IPSeen[s] = now
	}
	if contains(d.IPs, s) {
		return false
	}
	d.IPs = append(d.IPs, s)
	d.PastIPs = remove(d.PastIPs, s)
	r.byIP[ip] = d
	r.dirty = true
	r.trimIPs(d, s)
	return true
}

// demoteIP moves s from a device's current to its past addresses.
func (r *Registry) demoteIP(d *Device, s string) {
	d.IPs = remove(d.IPs, s)
	d.PastIPs = append([]string{s}, remove(d.PastIPs, s)...)
	if len(d.PastIPs) > maxPastIPs {
		d.PastIPs = d.PastIPs[:maxPastIPs]
	}
	if a, err := netip.ParseAddr(s); err == nil && r.byIP[a] == d {
		delete(r.byIP, a)
	}
	r.dirty = true
}

// v4Limit is how many current IPv4 addresses a device may hold: one per
// hardware MAC, and one in total for all its randomized MACs (they are the
// same radio rotating its identity).
func v4Limit(d *Device) int {
	n, rnd := 0, false
	for _, m := range d.MACs {
		if IsLocallyAdministered(m) {
			rnd = true
		} else {
			n++
		}
	}
	if rnd {
		n++
	}
	return max(1, n)
}

// trimIPs enforces the per-family cap on current addresses: one IPv4 per
// MAC (DHCP churn replaces rather than accumulates) and a handful of IPv6
// addresses (privacy addresses rotate). The oldest-seen address goes first.
func (r *Registry) trimIPs(d *Device, keep string) {
	for _, v4 := range []bool{true, false} {
		limit := maxCurrentV6
		if v4 {
			limit = v4Limit(d)
		}
		for {
			var cur []string
			for _, s := range d.IPs {
				if isV4(s) == v4 {
					cur = append(cur, s)
				}
			}
			if len(cur) <= limit {
				break
			}
			oldest := ""
			for _, s := range cur {
				if s != keep && (oldest == "" || d.IPSeen[s].Before(d.IPSeen[oldest])) {
					oldest = s
				}
			}
			r.demoteIP(d, oldest)
		}
	}
}

// applyEvidence folds names, vendor, services and hints into d and refreshes
// the type guess. It reports whether anything other than timestamps changed.
func (r *Registry) applyEvidence(d *Device, o Observation, host string, now time.Time) bool {
	changed := false
	if now.After(d.LastSeen) {
		d.LastSeen = now
	}
	if d.FirstSeen.IsZero() || now.Before(d.FirstSeen) {
		d.FirstSeen = now
	}
	set := func(dst *string, v string) {
		if v != "" && *dst != v {
			*dst, changed = v, true
		}
	}
	switch o.Source {
	case SourceMDNS:
		set(&d.MDNSName, host)
	case SourceReverseDNS:
		set(&d.ReverseName, host)
	default:
		set(&d.Hostname, host)
	}
	if d.Vendor == "" {
		v := strings.TrimSpace(o.VendorHint)
		for _, m := range d.MACs {
			if v == "" {
				v = r.vendorOf(m)
			}
		}
		set(&d.Vendor, v)
	}
	if n := union(d.Services, normServices(o.Services), maxServices); len(n) != len(d.Services) {
		d.Services, changed = n, true
	}
	if n := union(d.Hints, o.Hints, maxHints); len(n) != len(d.Hints) {
		d.Hints, changed = n, true
	}
	if r.retype(d) {
		changed = true
	}
	return changed
}

func normServices(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(s), "."), ".local")
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// retype refreshes the guessed type unless the user set one.
func (r *Registry) retype(d *Device) bool {
	if d.TypeUser || d.TypeAuto {
		return false // the user's choice, or the classifier's, stands
	}
	t, reason := GuessType(Evidence{
		Vendor: d.Vendor, Services: d.Services, Hints: d.Hints,
		Names: []string{d.Alias, d.MDNSName, d.Hostname, d.ReverseName},
	})
	if t == TypeUnknown && d.Randomized() {
		reason = "randomized private address (likely a phone, tablet or laptop)"
	}
	if d.Type == t && d.TypeReason == reason {
		return false
	}
	d.Type, d.TypeReason = t, reason
	return true
}

// mergeLocked folds src into dst and tombstones src. Callers hold r.mu.
func (r *Registry) mergeLocked(dst, src *Device, now time.Time) {
	r.unindex(src)
	r.unindex(dst)
	dst.MACs = union(dst.MACs, src.MACs, 0)
	dst.IPs = union(dst.IPs, src.IPs, 0)
	for _, s := range src.PastIPs {
		if !contains(dst.IPs, s) {
			dst.PastIPs = union(dst.PastIPs, []string{s}, maxPastIPs)
		}
	}
	for _, s := range dst.IPs {
		dst.PastIPs = remove(dst.PastIPs, s)
	}
	if dst.IPSeen == nil {
		dst.IPSeen = map[string]time.Time{}
	}
	for k, v := range src.IPSeen {
		if v.After(dst.IPSeen[k]) {
			dst.IPSeen[k] = v
		}
	}
	fill := func(a *string, b string) {
		if *a == "" {
			*a = b
		}
	}
	fill(&dst.Alias, src.Alias)
	fill(&dst.MDNSName, src.MDNSName)
	fill(&dst.Hostname, src.Hostname)
	fill(&dst.ReverseName, src.ReverseName)
	fill(&dst.Vendor, src.Vendor)
	if src.TypeUser && !dst.TypeUser {
		dst.Type, dst.TypeReason, dst.TypeUser = src.Type, src.TypeReason, true
	}
	dst.Services = union(dst.Services, src.Services, maxServices)
	dst.Hints = union(dst.Hints, src.Hints, maxHints)
	if !src.FirstSeen.IsZero() && (dst.FirstSeen.IsZero() || src.FirstSeen.Before(dst.FirstSeen)) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	dst.Groups = sortedUnion(dst.Groups, src.Groups)
	dst.Tags = sortedUnion(dst.Tags, src.Tags)
	if src.Notes != "" && src.Notes != dst.Notes {
		if dst.Notes == "" {
			dst.Notes = src.Notes
		} else {
			dst.Notes += "\n" + src.Notes
		}
	}
	// An explicit opt-out survives a merge.
	dst.Excluded = dst.Excluded || src.Excluded
	// Wandering survives a merge, and for the longest time either side asked for;
	// an open-ended one wins over a timed one.
	if src.Wandering {
		switch {
		case !dst.Wandering:
			dst.Wandering, dst.WanderingUntil = true, src.WanderingUntil
		case dst.WanderingUntil.IsZero() || src.WanderingUntil.IsZero():
			dst.WanderingUntil = time.Time{}
		case src.WanderingUntil.After(dst.WanderingUntil):
			dst.WanderingUntil = src.WanderingUntil
		}
	}
	r.retype(dst)

	id := src.ID
	*src = Device{ID: id, MergedInto: dst.ID, Deleted: true}
	r.stamp(src)
	r.index(dst)
	r.trimIPs(dst, "")
	r.stamp(dst)
	r.dirty = true
}

func sortedUnion(a, b []string) []string {
	out := union(append([]string(nil), a...), b, 0)
	sort.Strings(out)
	return out
}

func (r *Registry) index(d *Device) {
	for _, m := range d.MACs {
		r.byMAC[m] = d
	}
	for _, s := range d.IPs {
		if a, err := netip.ParseAddr(s); err == nil {
			r.byIP[a] = d
		}
	}
}

func (r *Registry) unindex(d *Device) {
	for _, m := range d.MACs {
		if r.byMAC[m] == d {
			delete(r.byMAC, m)
		}
	}
	for _, s := range d.IPs {
		if a, err := netip.ParseAddr(s); err == nil && r.byIP[a] == d {
			delete(r.byIP, a)
		}
	}
}

// liveGroups filters ids to groups that exist (replicas can lag behind on
// group definitions), sorted.
func (r *Registry) liveGroups(ids []string) []string {
	var out []string
	for _, id := range ids {
		if g := r.groups[id]; g != nil && !g.Deleted {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// copyOut returns a caller-owned copy of d with stale group references
// removed.
func (r *Registry) copyOut(d *Device) *Device {
	c := d.clone()
	c.Groups = r.liveGroups(d.Groups)
	return c
}
