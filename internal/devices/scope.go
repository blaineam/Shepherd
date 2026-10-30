// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import "net/netip"

type scopeEntry struct {
	id     string
	groups []string
}

// scopeSnap is an immutable IP index published atomically, so the policy
// engine's per-query lookups take no lock.
type scopeSnap struct {
	byIP map[string]*scopeEntry
}

// rebuildScopes publishes a fresh index. Callers hold r.mu (or are
// constructing the registry).
func (r *Registry) rebuildScopes() {
	snap := &scopeSnap{byIP: make(map[string]*scopeEntry, len(r.byIP))}
	entries := map[*Device]*scopeEntry{}
	for ip, d := range r.byIP {
		e := entries[d]
		if e == nil {
			e = &scopeEntry{id: d.ID, groups: r.liveGroups(d.Groups)}
			entries[d] = e
		}
		snap.byIP[ip.String()] = e
	}
	r.scope.Store(snap)
}

// ScopesFor resolves a client IP to its device and that device's groups, for
// the policy engine. It is called for every DNS query: it reads an atomic
// snapshot and takes no lock. An unknown IP returns "" and nil. The returned
// slice is shared and must not be modified.
func (r *Registry) ScopesFor(clientIP string) (deviceID string, groupIDs []string) {
	s := r.scope.Load()
	if e := s.byIP[clientIP]; e != nil {
		return e.id, e.groups
	}
	a, err := netip.ParseAddr(clientIP)
	if err != nil {
		return "", nil
	}
	if e := s.byIP[a.Unmap().WithZone("").String()]; e != nil {
		return e.id, e.groups
	}
	return "", nil
}

// IsExcluded reports whether a device has opted out of protection and
// traffic steering.
func (r *Registry) IsExcluded(deviceID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d := r.devices[deviceID]
	return d != nil && !d.Deleted && d.Excluded
}
