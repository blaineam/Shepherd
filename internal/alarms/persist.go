// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Codec transforms the serialized files on their way to and from disk, so a
// caller can plug in encryption later. It is the same shape as the Codec in
// internal/devices, so one implementation serves every store.
type Codec interface {
	Encode(plain []byte) ([]byte, error)
	Decode(stored []byte) ([]byte, error)
}

// PlainCodec stores bytes unchanged.
type PlainCodec struct{}

// Encode returns b unchanged.
func (PlainCodec) Encode(b []byte) ([]byte, error) { return b, nil }

// Decode returns b unchanged.
func (PlainCodec) Decode(b []byte) ([]byte, error) { return b, nil }

// File names inside Options.Dir.
const (
	AlarmsFile     = "alarms.json"      // alarms and mute rules
	PrefsFile      = "alarm-prefs.json" // preferences and learning state
	DeliveriesFile = "deliveries.json"  // the Router's log, retries and digest queue
)

const snapshotVersion = 1

// ErrBadSnapshot is returned by Load for unreadable or unsupported files.
var ErrBadSnapshot = errors.New("alarms: unreadable snapshot")

// Snapshot is the replicable form of the alarm store: every alarm and rule,
// tombstones included, each stamped with its HLC and writer.
type Snapshot struct {
	Version int      `json:"version"`
	Node    string   `json:"node"`
	Clock   HLC      `json:"clock"`
	Alarms  []*Alarm `json:"alarms"`
	Rules   []*Rule  `json:"rules"`
}

// prefsDoc is the preferences file.
type prefsDoc struct {
	Version     int                  `json:"version"`
	Node        string               `json:"node"`
	Updated     HLC                  `json:"updated"`
	Preferences Preferences          `json:"preferences"`
	InstalledAt time.Time            `json:"installed_at"`
	DeviceSeen  map[string]time.Time `json:"device_seen,omitempty"`
}

// writeFileAtomic writes data to path through a temp file in the same
// directory (mode 0600, fsync, rename) so a crash never leaves half a file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".alarms-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	err = errors.Join(tmp.Chmod(0o600), werr, tmp.Sync(), tmp.Close())
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// saveJSON encodes v through the codec and writes it atomically.
func saveJSON(codec Codec, path string, v any) error {
	plain, _ := json.MarshalIndent(v, "", " ") // plain structs: cannot fail
	data, err := codec.Encode(plain)
	if err != nil {
		return fmt.Errorf("alarms: encode: %w", err)
	}
	return writeFileAtomic(path, data)
}

// loadJSON reads path through the codec into v. A missing file returns an
// error satisfying errors.Is(err, os.ErrNotExist).
func loadJSON(codec Codec, path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plain, err := codec.Decode(data)
	if err != nil {
		return fmt.Errorf("alarms: decode: %w", err)
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSnapshot, err)
	}
	return nil
}

// Export returns a deep copy of every alarm and rule for persistence or sync.
func (e *Engine) Export() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exportLocked()
}

func (e *Engine) exportLocked() Snapshot {
	s := Snapshot{Version: snapshotVersion, Node: e.node, Clock: e.hlc}
	for _, a := range e.alarms {
		c := a.clone()
		s.Alarms = append(s.Alarms, &c)
	}
	for _, r := range e.rules {
		c := r.clone()
		s.Rules = append(s.Rules, &c)
	}
	sort.Slice(s.Alarms, func(i, j int) bool { return s.Alarms[i].ID < s.Alarms[j].ID })
	sort.Slice(s.Rules, func(i, j int) bool { return s.Rules[i].ID < s.Rules[j].ID })
	return s
}

func newer(rUpd HLC, rNode string, lUpd HLC, lNode string) bool {
	if c := rUpd.Compare(lUpd); c != 0 {
		return c > 0
	}
	return rNode > lNode
}

// Import merges a snapshot, last-writer-wins per record, and returns how many
// records changed. It is idempotent and order-independent. Imported records
// produce no changes and no notifications, so a synced replica does not
// re-announce what its peers already announced.
func (e *Engine) Import(s Snapshot) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := e.importLocked(s)
	if n > 0 {
		e.dirty = true
	}
	return n
}

func (e *Engine) importLocked(s Snapshot) int {
	n := 0
	for _, r := range s.Rules {
		if r == nil || r.ID == "" {
			continue
		}
		e.witness(r.Updated)
		if l := e.rules[r.ID]; l == nil || newer(r.Updated, r.Node, l.Updated, l.Node) {
			c := r.clone()
			e.rules[r.ID] = &c
			n++
		}
	}
	for _, a := range s.Alarms {
		if a == nil || a.ID == "" {
			continue
		}
		e.witness(a.Updated)
		if l := e.alarms[a.ID]; l == nil || newer(a.Updated, a.Node, l.Updated, l.Node) {
			c := a.clone()
			e.alarms[a.ID] = &c
			n++
		}
	}
	if n > 0 {
		e.reindex()
	}
	return n
}

func (e *Engine) witness(h HLC) {
	if h.Compare(e.hlc) > 0 {
		e.hlc = h
	}
}

// reindex rebuilds the key and parent indexes from the records.
func (e *Engine) reindex() {
	e.byKey = map[string]string{}
	e.children = map[string][]string{}
	for id, a := range e.alarms {
		if a.Deleted {
			continue
		}
		if cur, ok := e.alarms[e.byKey[a.Key]]; !ok || a.FirstSeen.After(cur.FirstSeen) || (a.FirstSeen.Equal(cur.FirstSeen) && id > cur.ID) {
			e.byKey[a.Key] = id
		}
		if a.ParentID != "" {
			e.children[a.ParentID] = append(e.children[a.ParentID], id)
		}
	}
	for _, ids := range e.children {
		sort.Strings(ids)
	}
}

// Save writes the alarms, rules, preferences and learning state into
// Options.Dir. It is a no-op for an engine without a directory.
func (e *Engine) Save() error {
	if e.dir == "" {
		return nil
	}
	e.mu.Lock()
	snap := e.exportLocked()
	pd := prefsDoc{Version: snapshotVersion, Node: e.node, Updated: e.prefsUpdated, Preferences: e.prefs.Clone(),
		InstalledAt: e.installedAt, DeviceSeen: make(map[string]time.Time, len(e.deviceSeen))}
	for k, v := range e.deviceSeen {
		pd.DeviceSeen[k] = v
	}
	e.dirty = false
	e.lastSave = e.clock.Now()
	e.mu.Unlock()
	err := errors.Join(saveJSON(e.codec, filepath.Join(e.dir, AlarmsFile), snap),
		saveJSON(e.codec, filepath.Join(e.dir, PrefsFile), pd))
	if err != nil {
		e.mu.Lock()
		e.dirty = true
		e.mu.Unlock()
	}
	return err
}

// load reads the files in Options.Dir; missing files are fine (a first run).
func (e *Engine) load() error {
	var s Snapshot
	switch err := loadJSON(e.codec, filepath.Join(e.dir, AlarmsFile), &s); {
	case err == nil:
		if s.Version != snapshotVersion {
			return fmt.Errorf("%w: version %d", ErrBadSnapshot, s.Version)
		}
		e.importLocked(s)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	var pd prefsDoc
	switch err := loadJSON(e.codec, filepath.Join(e.dir, PrefsFile), &pd); {
	case err == nil:
		if pd.Version != snapshotVersion {
			return fmt.Errorf("%w: version %d", ErrBadSnapshot, pd.Version)
		}
		if err := pd.Preferences.Validate(); err != nil {
			return err
		}
		e.prefs = pd.Preferences.Clone()
		e.prefsUpdated = pd.Updated
		e.witness(pd.Updated)
		e.installedAt = pd.InstalledAt
		for k, v := range pd.DeviceSeen {
			e.deviceSeen[k] = v
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	return nil
}
