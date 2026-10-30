// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"sort"
	"strings"
	"time"
)

// ---- reading --------------------------------------------------------------

// Get returns a copy of a live device.
func (r *Registry) Get(id string) (Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d := r.devices[id]
	if d == nil || d.Deleted {
		return Device{}, false
	}
	return *r.copyOut(d), true
}

// FindByIP returns the device currently holding ip.
func (r *Registry) FindByIP(ip string) (Device, bool) {
	a, ok := parseIP(ip)
	if !ok {
		return Device{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if d := r.byIP[a]; d != nil {
		return *r.copyOut(d), true
	}
	return Device{}, false
}

// FindByMAC returns the device that owns mac.
func (r *Registry) FindByMAC(mac string) (Device, bool) {
	m, ok := NormalizeMAC(mac)
	if !ok {
		return Device{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if d := r.byMAC[m]; d != nil {
		return *r.copyOut(d), true
	}
	return Device{}, false
}

// Len is the number of live devices.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, d := range r.devices {
		if !d.Deleted {
			n++
		}
	}
	return n
}

// List returns every live device, sorted by display name.
func (r *Registry) List() []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Device, 0, len(r.devices))
	for _, d := range r.devices {
		if !d.Deleted {
			out = append(out, *r.copyOut(d))
		}
	}
	sortDevices(out, SortName)
	return out
}

// ---- device edits ---------------------------------------------------------

// mutate applies fn to each id under one lock and one stamp per changed
// device. It returns the changed and the missing IDs, and the display-name
// changes for rename events.
type renamed struct{ id, old, new string }

func (r *Registry) mutate(ids []string, fn func(*Device) bool) (changed, missing []string, names []renamed) {
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		d := r.devices[id]
		if d == nil || d.Deleted {
			missing = append(missing, id)
			continue
		}
		before := d.DisplayName()
		if fn(d) {
			r.stamp(d)
			changed = append(changed, id)
			if after := d.DisplayName(); !d.Deleted && after != before {
				names = append(names, renamed{id, before, after})
			}
		}
	}
	return
}

func renameEvents(names []renamed) []Event {
	var evs []Event
	for _, n := range names {
		evs = append(evs, Event{Kind: EventRenamed, DeviceID: n.id, OldName: n.old, NewName: n.new})
	}
	return evs
}

// BulkResult reports a bulk operation: how many devices changed and which
// requested IDs did not exist.
type BulkResult struct {
	Changed int
	Missing []string
}

func (r *Registry) bulk(ids []string, kind EventKind, groupID string, fn func(*Device) bool) BulkResult {
	var res BulkResult
	r.do(func() []Event {
		changed, missing, names := r.mutate(ids, fn)
		res = BulkResult{Changed: len(changed), Missing: missing}
		evs := renameEvents(names)
		if len(changed) > 0 {
			if kind != "" {
				evs = append(evs, Event{Kind: kind, DeviceIDs: changed, GroupID: groupID})
			}
			r.dirty = true
		}
		return evs
	})
	return res
}

// Rename sets or clears (empty alias) the user's name for a device.
func (r *Registry) Rename(id, alias string) error {
	alias = strings.TrimSpace(alias)
	if len(alias) > 128 {
		return ErrInvalid
	}
	return r.single(id, func() BulkResult {
		return r.bulk([]string{id}, "", "", func(d *Device) bool {
			if d.Alias == alias {
				return false
			}
			d.Alias = alias
			r.retype(d)
			return true
		})
	})
}

func (r *Registry) single(id string, fn func() BulkResult) error {
	if res := fn(); len(res.Missing) > 0 {
		return ErrNotFound
	}
	return nil
}

// SetNotes replaces a device's free-text notes.
func (r *Registry) SetNotes(id, notes string) error {
	return r.single(id, func() BulkResult {
		return r.bulk([]string{id}, EventUpdated, "", func(d *Device) bool {
			if d.Notes == notes {
				return false
			}
			d.Notes = notes
			return true
		})
	})
}

// SetType overrides the guessed type. An empty or "auto" type clears the
// override and returns to guessing.
func (r *Registry) SetType(id string, typ string) error {
	var t DeviceType
	auto := typ == "" || strings.EqualFold(typ, "auto")
	if !auto {
		var ok bool
		if t, ok = ParseType(typ); !ok {
			return ErrInvalid
		}
	}
	return r.single(id, func() BulkResult {
		return r.bulk([]string{id}, EventUpdated, "", func(d *Device) bool {
			if auto {
				was := d.TypeUser
				d.TypeUser = false
				return r.retype(d) || was
			}
			if d.TypeUser && d.Type == t {
				return false
			}
			d.Type, d.TypeUser, d.TypeReason = t, true, "set by you"
			return true
		})
	})
}

// SetExcluded opts one device in or out of protection and traffic steering.
func (r *Registry) SetExcluded(id string, excluded bool) error {
	return r.single(id, func() BulkResult { return r.BulkSetExcluded([]string{id}, excluded) })
}

// SetWandering puts one device in or out of wandering mode: no filtering at all,
// every request still watched. until ends it automatically; the zero time keeps
// it on until it is turned off.
func (r *Registry) SetWandering(id string, on bool, until time.Time) error {
	return r.single(id, func() BulkResult { return r.BulkSetWandering([]string{id}, on, until) })
}

// SetTags replaces a device's tags.
func (r *Registry) SetTags(id string, tags []string) error {
	want := normTags(tags)
	return r.single(id, func() BulkResult {
		return r.bulk([]string{id}, EventUpdated, "", func(d *Device) bool {
			if strings.Join(d.Tags, "\x00") == strings.Join(want, "\x00") {
				return false
			}
			d.Tags = append([]string(nil), want...)
			return true
		})
	})
}

func normTags(in []string) []string {
	var out []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && !contains(out, t) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// Delete forgets a device (it reappears as a new device if seen again).
func (r *Registry) Delete(id string) error {
	return r.single(id, func() BulkResult { return r.BulkDelete([]string{id}) })
}

// ---- bulk operations ------------------------------------------------------

// BulkAssignGroup adds every listed device to a group.
func (r *Registry) BulkAssignGroup(ids []string, groupID string) (BulkResult, error) {
	if !r.groupExists(groupID) {
		return BulkResult{}, ErrGroupNotFound
	}
	return r.bulk(ids, EventGroupMembers, groupID, func(d *Device) bool {
		if contains(d.Groups, groupID) {
			return false
		}
		d.Groups = sortedUnion(d.Groups, []string{groupID})
		return true
	}), nil
}

// BulkRemoveGroup removes every listed device from a group.
func (r *Registry) BulkRemoveGroup(ids []string, groupID string) (BulkResult, error) {
	if !r.groupExists(groupID) {
		return BulkResult{}, ErrGroupNotFound
	}
	return r.bulk(ids, EventGroupMembers, groupID, func(d *Device) bool {
		if !contains(d.Groups, groupID) {
			return false
		}
		d.Groups = remove(d.Groups, groupID)
		return true
	}), nil
}

// BulkSetExcluded opts every listed device in or out of protection.
func (r *Registry) BulkSetExcluded(ids []string, excluded bool) BulkResult {
	return r.bulk(ids, EventUpdated, "", func(d *Device) bool {
		if d.Excluded == excluded {
			return false
		}
		d.Excluded = excluded
		return true
	})
}

// BulkSetWandering puts every listed device in or out of wandering mode. Turning
// it off also clears the timer.
func (r *Registry) BulkSetWandering(ids []string, on bool, until time.Time) BulkResult {
	return r.bulk(ids, EventUpdated, "", func(d *Device) bool {
		if !on {
			if !d.Wandering && d.WanderingUntil.IsZero() {
				return false
			}
			d.Wandering, d.WanderingUntil = false, time.Time{}
			return true
		}
		if d.Wandering && d.WanderingUntil.Equal(until) {
			return false
		}
		d.Wandering, d.WanderingUntil = true, until
		return true
	})
}

// ExpireWandering ends every wandering timer that has run out by now and returns
// how many devices changed. The DNS engine already stops honouring an expired
// timer on its own; this keeps the stored state and the UI in step.
func (r *Registry) ExpireWandering(now time.Time) int {
	var ids []string
	for _, d := range r.List() {
		if d.Wandering && !d.WanderingUntil.IsZero() && !d.WanderingUntil.After(now) {
			ids = append(ids, d.ID)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	return r.BulkSetWandering(ids, false, time.Time{}).Changed
}

// BulkSetTags adds and removes tags on every listed device.
func (r *Registry) BulkSetTags(ids []string, add, rm []string) BulkResult {
	add, rm = normTags(add), normTags(rm)
	return r.bulk(ids, EventUpdated, "", func(d *Device) bool {
		next := union(append([]string(nil), d.Tags...), add, 0)
		for _, t := range rm {
			next = remove(next, t)
		}
		sort.Strings(next)
		if strings.Join(next, "\x00") == strings.Join(d.Tags, "\x00") {
			return false
		}
		d.Tags = next
		return true
	})
}

// BulkDelete forgets every listed device.
func (r *Registry) BulkDelete(ids []string) BulkResult {
	return r.bulk(ids, EventDeleted, "", func(d *Device) bool {
		r.unindex(d)
		id := d.ID
		*d = Device{ID: id, Deleted: true}
		return true
	})
}

// ---- merge and split ------------------------------------------------------

// Merge folds the source devices into target (their addresses, names,
// groups and tags combine; the sources become tombstones).
func (r *Registry) Merge(targetID string, sourceIDs ...string) error {
	var err error
	r.do(func() []Event {
		dst := r.devices[targetID]
		if dst == nil || dst.Deleted {
			err = ErrNotFound
			return nil
		}
		var srcs []*Device
		for _, id := range sourceIDs {
			s := r.devices[id]
			if s == nil || s.Deleted {
				err = ErrNotFound
				return nil
			}
			if id != targetID {
				srcs = append(srcs, s)
			}
		}
		if len(srcs) == 0 {
			err = ErrInvalid
			return nil
		}
		before := dst.DisplayName()
		var merged []string
		for _, s := range srcs {
			if s.Deleted { // listed twice
				continue
			}
			merged = append(merged, s.ID)
			r.mergeLocked(dst, s, r.now())
		}
		evs := []Event{{Kind: EventMerged, DeviceID: dst.ID, DeviceIDs: merged}}
		if after := dst.DisplayName(); after != before {
			evs = append(evs, Event{Kind: EventRenamed, DeviceID: dst.ID, OldName: before, NewName: after})
		}
		return evs
	})
	return err
}

// Split moves one MAC and/or some IPs of a device onto a new device (for
// example two phones wrongly merged). The new device inherits the group,
// tag and exclusion settings of the original.
func (r *Registry) Split(id, mac string, ips ...string) (string, error) {
	var newID string
	var err error
	r.do(func() []Event {
		d := r.devices[id]
		if d == nil || d.Deleted {
			err = ErrNotFound
			return nil
		}
		m := ""
		if mac != "" {
			var ok bool
			if m, ok = NormalizeMAC(mac); !ok || !contains(d.MACs, m) {
				err = ErrInvalid
				return nil
			}
		}
		moveIPs := map[string]bool{}
		for _, s := range ips {
			a, ok := parseIP(s)
			if !ok || !contains(d.IPs, a.String()) {
				err = ErrInvalid
				return nil
			}
			moveIPs[a.String()] = true
		}
		if m == "" && len(moveIPs) == 0 {
			err = ErrInvalid
			return nil
		}
		leftMACs := len(d.MACs)
		if m != "" {
			leftMACs--
		}
		if leftMACs+len(d.IPs)-len(moveIPs) == 0 {
			err = ErrEmptySplit
			return nil
		}

		now := r.now()
		r.unindex(d)
		nd := r.newDevice(m, now)
		if m != "" {
			d.MACs = remove(d.MACs, m)
		}
		for s := range moveIPs {
			d.IPs = remove(d.IPs, s)
			nd.IPs = append(nd.IPs, s)
			if nd.IPSeen == nil {
				nd.IPSeen = map[string]time.Time{}
			}
			nd.IPSeen[s] = d.IPSeen[s]
			delete(d.IPSeen, s)
		}
		sort.Strings(nd.IPs)
		nd.FirstSeen, nd.LastSeen = d.FirstSeen, d.LastSeen
		nd.Groups = append([]string(nil), d.Groups...)
		nd.Tags = append([]string(nil), d.Tags...)
		nd.Excluded = d.Excluded
		nd.Wandering, nd.WanderingUntil = d.Wandering, d.WanderingUntil
		r.applyEvidence(nd, Observation{}, "", d.LastSeen)
		r.retype(d)
		r.index(d)
		r.index(nd)
		r.stamp(d)
		r.stamp(nd)
		newID = nd.ID
		return []Event{{Kind: EventSplit, DeviceID: id, DeviceIDs: []string{nd.ID}}}
	})
	return newID, err
}

// ---- groups ---------------------------------------------------------------

func (r *Registry) groupExists(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g := r.groups[id]
	return g != nil && !g.Deleted
}

func slug(name string) string {
	var b strings.Builder
	dash := false
	for _, c := range strings.ToLower(name) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if s == "" {
		return "group"
	}
	return s
}

// CreateGroup adds a group. Names are unique, case-insensitively.
func (r *Registry) CreateGroup(name, color string) (Group, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return Group{}, ErrInvalid
	}
	var out Group
	var err error
	r.do(func() []Event {
		for _, g := range r.groups {
			if !g.Deleted && strings.EqualFold(g.Name, name) {
				err = ErrDuplicateName
				return nil
			}
		}
		id := slug(name)
		for n := 2; r.groups[id] != nil && !r.groups[id].Deleted; n++ {
			id = slug(name) + "-" + itoa(n)
		}
		g := &Group{ID: id, Name: name, Color: color, Updated: r.tick(), Node: r.node}
		r.groups[id] = g
		r.dirty = true
		out = *g
		return []Event{{Kind: EventGroupCreated, GroupID: id, NewName: name}}
	})
	return out, err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func (r *Registry) editGroup(id string, fn func(*Group) (bool, error)) error {
	var err error
	r.do(func() []Event {
		g := r.groups[id]
		if g == nil || g.Deleted {
			err = ErrGroupNotFound
			return nil
		}
		old := g.Name
		var changed bool
		if changed, err = fn(g); err != nil || !changed {
			return nil
		}
		g.Updated, g.Node = r.tick(), r.node
		r.dirty = true
		return []Event{{Kind: EventGroupUpdated, GroupID: id, OldName: old, NewName: g.Name}}
	})
	return err
}

// RenameGroup changes a group's name (its ID stays).
func (r *Registry) RenameGroup(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return ErrInvalid
	}
	return r.editGroup(id, func(g *Group) (bool, error) {
		for _, o := range r.groups {
			if o != g && !o.Deleted && strings.EqualFold(o.Name, name) {
				return false, ErrDuplicateName
			}
		}
		if g.Name == name {
			return false, nil
		}
		g.Name = name
		return true, nil
	})
}

// SetGroupColor changes a group's color.
func (r *Registry) SetGroupColor(id, color string) error {
	return r.editGroup(id, func(g *Group) (bool, error) {
		if g.Color == color {
			return false, nil
		}
		g.Color = color
		return true, nil
	})
}

// DeleteGroup removes a group and takes its devices out of it.
func (r *Registry) DeleteGroup(id string) error {
	var err error
	r.do(func() []Event {
		g := r.groups[id]
		if g == nil || g.Deleted {
			err = ErrGroupNotFound
			return nil
		}
		var members []string
		for _, d := range r.devices {
			if !d.Deleted && contains(d.Groups, id) {
				d.Groups = remove(d.Groups, id)
				r.stamp(d)
				members = append(members, d.ID)
			}
		}
		sort.Strings(members)
		*g = Group{ID: id, Deleted: true, Updated: r.tick(), Node: r.node}
		r.dirty = true
		evs := []Event{{Kind: EventGroupDeleted, GroupID: id}}
		if len(members) > 0 {
			evs = append(evs, Event{Kind: EventGroupMembers, GroupID: id, DeviceIDs: members})
		}
		return evs
	})
	return err
}

// GetGroup returns a group with its member device IDs.
func (r *Registry) GetGroup(id string) (Group, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g := r.groups[id]
	if g == nil || g.Deleted {
		return Group{}, false
	}
	return r.groupView(g), true
}

// GroupByName finds a group by name, ignoring case.
func (r *Registry) GroupByName(name string) (Group, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, g := range r.groups {
		if !g.Deleted && strings.EqualFold(g.Name, strings.TrimSpace(name)) {
			return r.groupView(g), true
		}
	}
	return Group{}, false
}

// Groups lists every group sorted by name.
func (r *Registry) Groups() []Group {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Group
	for _, g := range r.groups {
		if !g.Deleted {
			out = append(out, r.groupView(g))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func (r *Registry) groupView(g *Group) Group {
	c := *g
	c.Members = nil
	for _, d := range r.devices {
		if !d.Deleted && contains(d.Groups, g.ID) {
			c.Members = append(c.Members, d.ID)
		}
	}
	sort.Strings(c.Members)
	return c
}
