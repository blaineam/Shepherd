// SPDX-License-Identifier: AGPL-3.0-or-later

package hub

import (
	"encoding/json"
	"os"
	"sort"

	"shepherd/internal/backends"
)

// A blocked client vanishes from the product's own client list (UniFi lists
// only what is connected), so a device Shepherd blocked would otherwise be
// impossible to find again for unblocking. The hub remembers each one it
// blocked, keeps it on the device list marked Blocked until it is
// unblocked, and stores the set so a restart does not lose it.

func blockedKey(box, native string) string { return box + "|" + native }

func (h *Hub) loadBlocked() {
	if h.o.BlockedPath == "" {
		return
	}
	b, err := os.ReadFile(h.o.BlockedPath)
	if err != nil {
		return
	}
	var list []backends.Device
	if json.Unmarshal(b, &list) != nil {
		return
	}
	for _, d := range list {
		if d.Native != "" {
			d.Blocked, d.Online = true, false
			h.blocked[blockedKey(d.Box, d.Native)] = d
		}
	}
}

// saveBlockedLocked must be called with h.mu held. A failed write is
// logged: the block itself already happened and must not be reported as
// failed.
func (h *Hub) saveBlockedLocked() {
	if h.o.BlockedPath == "" {
		return
	}
	list := make([]backends.Device, 0, len(h.blocked))
	for _, d := range h.blocked {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool {
		return blockedKey(list[i].Box, list[i].Native) < blockedKey(list[j].Box, list[j].Native)
	})
	b, _ := json.Marshal(list)
	tmp := h.o.BlockedPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		h.o.Logf("backend: keeping blocked devices: %v", err)
		return
	}
	if err := os.Rename(tmp, h.o.BlockedPath); err != nil {
		h.o.Logf("backend: keeping blocked devices: %v", err)
	}
}

// noteBlockedLocked records a successful block or unblock of ref.
func (h *Hub) noteBlockedLocked(ref backends.DeviceRef, block bool) {
	key := blockedKey(ref.Box, ref.Native)
	if !block {
		if _, had := h.blocked[key]; had {
			delete(h.blocked, key)
			h.saveBlockedLocked()
		}
		return
	}
	d := backends.Device{Box: ref.Box, Native: ref.Native, Name: ref.Native}
	for _, k := range h.devices {
		if k.Native == ref.Native && (ref.Box == "" || k.Box == ref.Box) {
			d = k
			break
		}
	}
	d.Blocked, d.Online = true, false
	h.blocked[key] = d
	h.saveBlockedLocked()
}

// forgetOnlineBlockedLocked drops a remembered block once the product
// lists that client as connected: a blocked client cannot be, so it was
// unblocked elsewhere (the console's own client list).
func (h *Hub) forgetOnlineBlockedLocked() {
	changed := false
	for _, d := range h.devices {
		if !d.Online || d.Native == "" {
			continue
		}
		for key, b := range h.blocked {
			if b.Native == d.Native && (b.Box == "" || b.Box == d.Box) {
				delete(h.blocked, key)
				changed = true
			}
		}
	}
	if changed {
		h.saveBlockedLocked()
	}
}

// devicesWithBlockedLocked is the device list with every remembered block
// on it: marked in place when the product still lists the client, appended
// when it does not.
func (h *Hub) devicesWithBlockedLocked() []backends.Device {
	out := append([]backends.Device(nil), h.devices...)
	if len(h.blocked) == 0 {
		return out
	}
	listed := map[string]bool{}
	for i, d := range out {
		for key, b := range h.blocked {
			if b.Native == d.Native && (b.Box == "" || b.Box == d.Box) {
				out[i].Blocked = true
				listed[key] = true
			}
		}
	}
	var extra []backends.Device
	for key, b := range h.blocked {
		if !listed[key] {
			extra = append(extra, b)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i].Name < extra[j].Name })
	return append(out, extra...)
}
