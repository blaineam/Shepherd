// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Codec transforms the serialized registry on its way to and from disk, so a
// caller can plug in encryption later.
type Codec interface {
	Encode(plain []byte) ([]byte, error)
	Decode(stored []byte) ([]byte, error)
}

// PlainCodec stores bytes unchanged.
type PlainCodec struct{}

func (PlainCodec) Encode(b []byte) ([]byte, error) { return b, nil }
func (PlainCodec) Decode(b []byte) ([]byte, error) { return b, nil }

const snapshotVersion = 1

// Snapshot is the replicable form of the registry: every record, tombstones
// included, each stamped with its HLC and writer.
type Snapshot struct {
	Version int       `json:"version"`
	Node    string    `json:"node"`
	Clock   HLC       `json:"clock"`
	Devices []*Device `json:"devices"`
	Groups  []*Group  `json:"groups"`
}

// Export returns a deep copy of every record for persistence or sync.
func (r *Registry) Export() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := Snapshot{Version: snapshotVersion, Node: r.node, Clock: r.clock}
	for _, d := range r.devices {
		s.Devices = append(s.Devices, d.clone())
	}
	for _, g := range r.groups {
		c := *g
		c.Members = nil
		s.Groups = append(s.Groups, &c)
	}
	sort.Slice(s.Devices, func(i, j int) bool { return s.Devices[i].ID < s.Devices[j].ID })
	sort.Slice(s.Groups, func(i, j int) bool { return s.Groups[i].ID < s.Groups[j].ID })
	return s
}

// newer reports whether remote beats local under last-writer-wins: higher
// HLC, node ID as the tie-break.
func newer(rUpd HLC, rNode string, lUpd HLC, lNode string) bool {
	if c := rUpd.Compare(lUpd); c != 0 {
		return c > 0
	}
	return rNode > lNode
}

// Import merges a snapshot, last-writer-wins per record, and returns how many
// records changed. It is idempotent and order-independent. Imported changes
// emit no events.
func (r *Registry) Import(s Snapshot) int {
	n := 0
	r.do(func() []Event {
		for _, g := range s.Groups {
			if g == nil || g.ID == "" {
				continue
			}
			r.witness(g.Updated)
			if l := r.groups[g.ID]; l == nil || newer(g.Updated, g.Node, l.Updated, l.Node) {
				c := *g
				c.Members = nil
				r.groups[g.ID] = &c
				n++
			}
		}
		for _, d := range s.Devices {
			if d == nil || d.ID == "" {
				continue
			}
			r.witness(d.Updated)
			if l := r.devices[d.ID]; l == nil || newer(d.Updated, d.Node, l.Updated, l.Node) {
				r.devices[d.ID] = d.clone()
				n++
			}
		}
		if n > 0 {
			r.reindexAll()
		}
		return nil
	})
	return n
}

func (r *Registry) witness(h HLC) {
	if h.Compare(r.clock) > 0 {
		r.clock = h
	}
}

// reindexAll rebuilds the MAC and IP indexes from the records. Conflicts are
// resolved deterministically so replicas converge: two live devices sharing a
// MAC merge into the one with the lower ID; an IP claimed by two devices stays
// with the one that saw it last.
func (r *Registry) reindexAll() {
	r.byMAC = map[string]*Device{}
	r.byIP = map[netip.Addr]*Device{}
	ids := make([]string, 0, len(r.devices))
	for id := range r.devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	type pair struct{ win, lose *Device }
	var merges []pair
	for _, id := range ids {
		d := r.devices[id]
		if d.Deleted {
			continue
		}
		clash := false
		for _, m := range d.MACs {
			if o := r.byMAC[m]; o != nil && o != d {
				merges = append(merges, pair{o, d})
				clash = true
				break
			}
		}
		if clash {
			continue
		}
		for _, m := range d.MACs {
			r.byMAC[m] = d
		}
		for _, s := range append([]string(nil), d.IPs...) {
			a, err := netip.ParseAddr(s)
			if err != nil {
				r.demoteIP(d, s)
				continue
			}
			if o := r.byIP[a]; o != nil && o != d {
				if o.IPSeen[s].After(d.IPSeen[s]) {
					r.demoteIP(d, s)
					continue
				}
				r.demoteIP(o, s)
			}
			r.byIP[a] = d
		}
	}
	for _, p := range merges {
		if !p.lose.Deleted && !p.win.Deleted {
			r.mergeLocked(p.win, p.lose, r.now())
		}
	}
	r.dirty = true
}

// PurgeTombstones drops tombstones older than age. Only do this once every
// replica has seen them.
func (r *Registry) PurgeTombstones(age time.Duration) int {
	cutoff := r.now().Add(-age).UnixMilli()
	n := 0
	r.do(func() []Event {
		for id, d := range r.devices {
			if d.Deleted && d.Updated.Wall < cutoff {
				delete(r.devices, id)
				n++
			}
		}
		for id, g := range r.groups {
			if g.Deleted && g.Updated.Wall < cutoff {
				delete(r.groups, id)
				n++
			}
		}
		return nil
	})
	return n
}

// Save writes the registry to path atomically with mode 0600.
func (r *Registry) Save(path string) error {
	plain, err := json.MarshalIndent(r.Export(), "", " ")
	if err != nil {
		return err
	}
	data, err := r.codec.Encode(plain)
	if err != nil {
		return fmt.Errorf("devices: encode: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".devices-*.tmp")
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

// ErrBadSnapshot is returned by Load for unreadable or unsupported files.
var ErrBadSnapshot = errors.New("devices: unreadable snapshot")

// Load merges the file at path into the registry (last-writer-wins, so
// loading into a fresh registry restores it). A missing file returns an
// error satisfying errors.Is(err, os.ErrNotExist).
func (r *Registry) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plain, err := r.codec.Decode(data)
	if err != nil {
		return fmt.Errorf("devices: decode: %w", err)
	}
	var s Snapshot
	if err := json.Unmarshal(plain, &s); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSnapshot, err)
	}
	if s.Version != snapshotVersion {
		return fmt.Errorf("%w: version %d", ErrBadSnapshot, s.Version)
	}
	r.Import(s)
	return nil
}
