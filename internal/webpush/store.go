// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Codec transforms the serialized store on its way to and from disk, so a
// caller can plug in encryption later. It is the same shape as the Codec in
// internal/devices, so one implementation serves both.
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

// HLC is a hybrid logical clock stamp, wire-compatible with the one in
// internal/devices: wall-clock milliseconds plus a counter that orders events
// within the same millisecond.
type HLC struct {
	Wall    int64  `json:"w"`
	Counter uint32 `json:"c"`
}

// Compare orders two stamps (-1, 0, +1).
func (a HLC) Compare(b HLC) int {
	switch {
	case a.Wall < b.Wall:
		return -1
	case a.Wall > b.Wall:
		return 1
	case a.Counter < b.Counter:
		return -1
	case a.Counter > b.Counter:
		return 1
	}
	return 0
}

// Errors returned by the Store.
var (
	ErrNotFound = errors.New("webpush: subscription not found")
	ErrTooMany  = errors.New("webpush: too many subscriptions")
	ErrInvalid  = errors.New("webpush: invalid argument")
	// ErrBadSnapshot is returned by Load for unreadable or unsupported files.
	ErrBadSnapshot = errors.New("webpush: unreadable snapshot")
)

const (
	maxName         = 64
	maxUserAgent    = 200
	maxLastError    = 300
	maxSubs         = 64
	snapshotVersion = 1
)

// Record is one subscription as stored and synced: the secrets, the
// bookkeeping, and the HLC stamp, writer and tombstone every replicated
// record in Shepherd carries.
type Record struct {
	ID          string    `json:"id"`
	Endpoint    string    `json:"endpoint"`
	P256dh      string    `json:"p256dh"`
	Auth        string    `json:"auth"`
	Name        string    `json:"name,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Created     time.Time `json:"created"`
	LastOK      time.Time `json:"last_ok,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	Failures    int       `json:"failures,omitempty"` // consecutive failures since the last success

	Updated HLC    `json:"updated"`
	Node    string `json:"node"`
	Deleted bool   `json:"deleted,omitempty"`
	// RetiredReason is set when the push service retired the subscription
	// ("gone"), as opposed to the user removing it.
	RetiredReason string `json:"retired_reason,omitempty"`
}

// Subscription returns the sending view of the record.
func (r Record) Subscription() Subscription {
	return Subscription{Endpoint: r.Endpoint, P256dh: r.P256dh, Auth: r.Auth}
}

// Device is the safe, list-friendly view of a subscription: no endpoint and no
// keys, so it can be shown in the portal and logged.
type Device struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Service     string    `json:"service"` // push service host, e.g. push.example.com
	Created     time.Time `json:"created"`
	LastOK      time.Time `json:"last_ok,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	Failures    int       `json:"failures,omitempty"`
}

// BrowserSubscription is the JSON a browser's PushSubscription.toJSON()
// produces, which the portal posts to the server.
type BrowserSubscription struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

// DeviceID derives the stable short device ID from an endpoint: the first 12
// hex characters of its SHA-256. The same browser always gets the same ID, and
// the ID reveals nothing usable about the endpoint.
func DeviceID(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:])[:12]
}

// StoreOptions configures a Store. The zero value is usable.
type StoreOptions struct {
	NodeID   string                      // writer identity stamped on records; default "local"
	Now      func() time.Time            // test clock; default time.Now
	Codec    Codec                       // persistence codec; default plain JSON
	Validate func(endpoint string) error // endpoint check; default ValidateEndpoint
}

// Store holds the push subscriptions. It is safe for concurrent use.
type Store struct {
	mu       sync.RWMutex
	node     string
	now      func() time.Time
	codec    Codec
	validate func(string) error
	clock    HLC
	recs     map[string]*Record
}

// NewStore creates an empty store.
func NewStore(o StoreOptions) *Store {
	s := &Store{node: o.NodeID, now: o.Now, codec: o.Codec, validate: o.Validate, recs: map[string]*Record{}}
	if s.node == "" {
		s.node = "local"
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.codec == nil {
		s.codec = PlainCodec{}
	}
	if s.validate == nil {
		s.validate = ValidateEndpoint
	}
	return s
}

func (s *Store) tick() HLC {
	w := s.now().UnixMilli()
	if w > s.clock.Wall {
		s.clock = HLC{Wall: w}
	} else {
		s.clock.Counter++
	}
	return s.clock
}

func (s *Store) stamp(r *Record) {
	r.Updated = s.tick()
	r.Node = s.node
}

// clean strips control characters and bounds the length of user text.
func clean(v string, max int) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	if len(v) > max {
		v = strings.ToValidUTF8(v[:max], "")
	}
	return v
}

func (s *Store) liveCount() int {
	n := 0
	for _, r := range s.recs {
		if !r.Deleted {
			n++
		}
	}
	return n
}

// Add stores a browser's subscription. The endpoint must pass the validator
// and the keys must be a real P-256 point and a 16-byte secret. Adding an
// endpoint that exists (or was removed or retired) updates it and revives it:
// browsers re-subscribe with fresh keys. The returned Device carries the
// stable ID.
func (s *Store) Add(sub BrowserSubscription, name, userAgent string) (Device, error) {
	if err := s.validate(sub.Endpoint); err != nil {
		return Device{}, err
	}
	if _, _, err := ParseKeys(sub.Keys.P256dh, sub.Keys.Auth); err != nil {
		return Device{}, err
	}
	id := DeviceID(sub.Endpoint)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.recs[id]
	if r == nil || r.Deleted {
		if s.liveCount() >= maxSubs {
			return Device{}, ErrTooMany
		}
	}
	if r == nil {
		r = &Record{ID: id, Created: s.now()}
		s.recs[id] = r
	} else if r.Deleted {
		r.Created = s.now()
		r.Deleted = false
		r.RetiredReason = ""
		r.LastError, r.LastErrorAt, r.Failures = "", time.Time{}, 0
	}
	r.Endpoint, r.P256dh, r.Auth = sub.Endpoint, strings.TrimRight(sub.Keys.P256dh, "="), strings.TrimRight(sub.Keys.Auth, "=")
	if n := clean(name, maxName); n != "" {
		r.Name = n
	} else if r.Name == "" {
		r.Name = "Device " + id[:4]
	}
	if ua := clean(userAgent, maxUserAgent); ua != "" {
		r.UserAgent = ua
	}
	s.stamp(r)
	return deviceOf(r), nil
}

func deviceOf(r *Record) Device {
	svc := ""
	if u, err := url.Parse(r.Endpoint); err == nil {
		svc = u.Hostname()
	}
	return Device{ID: r.ID, Name: r.Name, UserAgent: r.UserAgent, Service: svc, Created: r.Created,
		LastOK: r.LastOK, LastError: r.LastError, LastErrorAt: r.LastErrorAt, Failures: r.Failures}
}

// List returns the live subscriptions as safe Device views, oldest first.
func (s *Store) List() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Device
	for _, r := range s.recs {
		if !r.Deleted {
			out = append(out, deviceOf(r))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Records returns copies of the live subscriptions with their secrets, for
// sending. Callers must not log them.
func (s *Store) Records() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Record
	for _, r := range s.recs {
		if !r.Deleted {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Count returns the number of live subscriptions.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.liveCount()
}

// Get returns one live subscription's safe view.
func (s *Store) Get(id string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.recs[id]
	if r == nil || r.Deleted {
		return Device{}, false
	}
	return deviceOf(r), true
}

func (s *Store) live(id string) (*Record, error) {
	r := s.recs[id]
	if r == nil || r.Deleted {
		return nil, ErrNotFound
	}
	return r, nil
}

// Rename changes a device's display name.
func (s *Store) Rename(id, name string) error {
	name = clean(name, maxName)
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.live(id)
	if err != nil {
		return err
	}
	r.Name = name
	s.stamp(r)
	return nil
}

// Remove deletes a subscription (a tombstone, so the removal replicates).
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.live(id)
	if err != nil {
		return err
	}
	r.Deleted = true
	s.stamp(r)
	return nil
}

// MarkOK records a successful push.
func (s *Store) MarkOK(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, err := s.live(id); err == nil {
		r.LastOK, r.LastError, r.LastErrorAt, r.Failures = s.now(), "", time.Time{}, 0
		s.stamp(r)
	}
}

// MarkError records a failed push; the message is bounded and never contains
// the endpoint when produced by this package.
func (s *Store) MarkError(id string, err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, e := s.live(id); e == nil {
		r.LastError, r.LastErrorAt = clean(err.Error(), maxLastError), s.now()
		r.Failures++
		s.stamp(r)
	}
}

// Retire tombstones a subscription the push service reported gone (404 or
// 410). A browser that subscribes again revives it.
func (s *Store) Retire(id, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, err := s.live(id); err == nil {
		r.Deleted, r.RetiredReason = true, clean(reason, 40)
		s.stamp(r)
	}
}

// PurgeTombstones drops tombstones older than age. Only do this once every
// replica has seen them.
func (s *Store) PurgeTombstones(age time.Duration) int {
	cutoff := s.now().Add(-age).UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, r := range s.recs {
		if r.Deleted && r.Updated.Wall < cutoff {
			delete(s.recs, id)
			n++
		}
	}
	return n
}

// ---- persistence and sync ---------------------------------------------------

// Snapshot is the replicable form of the store: every record, tombstones
// included, each stamped with its HLC and writer.
type Snapshot struct {
	Version       int       `json:"version"`
	Node          string    `json:"node"`
	Clock         HLC       `json:"clock"`
	Subscriptions []*Record `json:"subscriptions"`
}

// Export returns a copy of every record for persistence or sync.
func (s *Store) Export() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{Version: snapshotVersion, Node: s.node, Clock: s.clock}
	for _, r := range s.recs {
		c := *r
		snap.Subscriptions = append(snap.Subscriptions, &c)
	}
	sort.Slice(snap.Subscriptions, func(i, j int) bool { return snap.Subscriptions[i].ID < snap.Subscriptions[j].ID })
	return snap
}

func newer(rUpd HLC, rNode string, lUpd HLC, lNode string) bool {
	if c := rUpd.Compare(lUpd); c != 0 {
		return c > 0
	}
	return rNode > lNode
}

// Import merges a snapshot, last-writer-wins per record, and returns how many
// records changed. It is idempotent and order-independent.
func (s *Store) Import(snap Snapshot) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range snap.Subscriptions {
		if r == nil || r.ID == "" || r.ID != DeviceID(r.Endpoint) {
			continue
		}
		if r.Updated.Compare(s.clock) > 0 {
			s.clock = r.Updated
		}
		if l := s.recs[r.ID]; l == nil || newer(r.Updated, r.Node, l.Updated, l.Node) {
			c := *r
			s.recs[r.ID] = &c
			n++
		}
	}
	return n
}

// Save writes the store to path atomically with mode 0600.
func (s *Store) Save(path string) error {
	plain, _ := json.MarshalIndent(s.Export(), "", " ") // plain structs: cannot fail
	data, err := s.codec.Encode(plain)
	if err != nil {
		return fmt.Errorf("webpush: encode: %w", err)
	}
	return writeFileAtomic(path, data)
}

// Load merges the file at path into the store. A missing file returns an
// error satisfying errors.Is(err, os.ErrNotExist).
func (s *Store) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plain, err := s.codec.Decode(data)
	if err != nil {
		return fmt.Errorf("webpush: decode: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSnapshot, err)
	}
	if snap.Version != snapshotVersion {
		return fmt.Errorf("%w: version %d", ErrBadSnapshot, snap.Version)
	}
	s.Import(snap)
	return nil
}
