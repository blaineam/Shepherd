// SPDX-License-Identifier: AGPL-3.0-or-later

// Package traffic keeps the bandwidth history: how many bytes each device
// sent and (by estimate) received, per minute, hour and day, rolled up as
// it ages so months of history fit in a few megabytes. See
// docs/TRAFFIC.md.
//
// The numbers come from Watch mode (internal/watch): the relayed bytes
// are a device's upload, measured exactly; the received bytes are the
// TCP-acknowledgement estimate (intercept.AckMeter), which never
// over-counts and is blind to QUIC, UDP and tunnels. Bytes are additive,
// so unlike internal/nethealth's averaged rollups every fold here is
// exact: a day's total is the sum of its hours whatever order they
// arrived in.
//
// Groups and the network as a whole are sums over devices, computed at
// query time from the registry's current membership rather than stored,
// so moving a device between groups moves its history with it.
package traffic

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

// Bucket names a resolution to query at.
type Bucket string

const (
	BucketMinute Bucket = "minute"
	BucketHour   Bucket = "hour"
	BucketDay    Bucket = "day"
)

// ParseBucket accepts the three bucket names; anything else is not ok.
func ParseBucket(s string) (Bucket, bool) {
	switch Bucket(s) {
	case BucketMinute, BucketHour, BucketDay:
		return Bucket(s), true
	}
	return "", false
}

// DefaultBucket picks the resolution a chart over [from, to] wants: minute
// detail for anything up to a day, hourly out to two months, daily beyond.
// Matched to DefaultRetention so a request never asks for a resolution
// that has been rolled away for most of its range.
func DefaultBucket(from, to time.Time) Bucket {
	span := to.Sub(from)
	switch {
	case span <= 24*time.Hour:
		return BucketMinute
	case span <= 60*24*time.Hour:
		return BucketHour
	default:
		return BucketDay
	}
}

// Point is one bucket's totals: bytes sent (exact) and bytes received
// (estimated) during the bucket that starts at Time.
type Point struct {
	Time time.Time `json:"time"`
	Up   uint64    `json:"up"`
	Down uint64    `json:"down"`
}

// Delta is a count of bytes to credit: sent and received.
type Delta struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

func (d Delta) zero() bool { return d.Up == 0 && d.Down == 0 }

// Retention is how long each resolution is kept before being folded into
// the next (minute -> hour -> day) or, for daily, dropped. MaxBytes caps
// the marshaled store; past it the oldest daily points go first.
type Retention struct {
	Minute   time.Duration // default 48 hours
	Hour     time.Duration // default 90 days
	Day      time.Duration // default 0: keep forever, bounded by MaxBytes
	MaxBytes int           // default 8 MiB; 0 means no cap
}

// DefaultRetention is what NewStore uses when Options.Retention is unset.
func DefaultRetention() Retention {
	return Retention{
		Minute:   48 * time.Hour,
		Hour:     90 * 24 * time.Hour,
		Day:      0,
		MaxBytes: 8 << 20,
	}
}

// Options configures a Store. The zero value is usable.
type Options struct {
	Retention Retention
	// Path, when set, is where Record saves the store (atomically, mode
	// 0600) at most once per SaveEvery. Load reads it back.
	Path      string
	SaveEvery time.Duration // default one minute
	// OnSaveError receives a failed save's error; default: ignored.
	OnSaveError func(error)
}

// series is one device's history at the three resolutions, each sorted
// by time with at most one point per bucket.
type series struct {
	Minute []Point `json:"minute,omitempty"`
	Hour   []Point `json:"hour,omitempty"`
	Day    []Point `json:"day,omitempty"`
}

func (s *series) empty() bool { return len(s.Minute)+len(s.Hour)+len(s.Day) == 0 }

// Store is the bandwidth history for every device. Safe for concurrent
// use: Watch mode records into it from its own goroutine while the portal
// queries it.
type Store struct {
	opt Options

	mu       sync.Mutex
	devices  map[string]*series
	lastSave time.Time
	dirty    bool
}

// NewStore creates an empty Store from opts.
func NewStore(opts Options) *Store {
	if opts.Retention == (Retention{}) {
		opts.Retention = DefaultRetention()
	}
	if opts.SaveEvery <= 0 {
		opts.SaveEvery = time.Minute
	}
	return &Store{opt: opts, devices: map[string]*series{}}
}

// Retention reports the windows in effect.
func (s *Store) Retention() Retention { return s.opt.Retention }

// Record credits each device with its bytes since the previous call, as
// of now, then rolls up whatever has aged out of its resolution and saves
// if a Path is set and SaveEvery has passed. Zero deltas are ignored, so a
// device that is steered but idle leaves no trace until it moves.
func (s *Store) Record(now time.Time, rows map[string]Delta) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, d := range rows {
		if id == "" || d.zero() {
			continue
		}
		ser := s.devices[id]
		if ser == nil {
			ser = &series{}
			s.devices[id] = ser
		}
		ser.Minute = addTo(ser.Minute, minuteStart(now), d)
		s.dirty = true
	}
	s.rollupLocked(now)
	if s.opt.Path != "" && s.dirty && now.Sub(s.lastSave) >= s.opt.SaveEvery {
		s.lastSave = now
		if err := s.saveLocked(s.opt.Path); err != nil && s.opt.OnSaveError != nil {
			s.opt.OnSaveError(err)
		}
	}
}

// addTo folds d into the point for bucket in pts (sorted by time), adding
// a point if there is none. Points arrive in time order in practice, so
// the common case is the last element.
func addTo(pts []Point, bucket time.Time, d Delta) []Point {
	if n := len(pts); n > 0 && pts[n-1].Time.Equal(bucket) {
		pts[n-1].Up += d.Up
		pts[n-1].Down += d.Down
		return pts
	}
	i := sort.Search(len(pts), func(i int) bool { return !pts[i].Time.Before(bucket) })
	if i < len(pts) && pts[i].Time.Equal(bucket) {
		pts[i].Up += d.Up
		pts[i].Down += d.Down
		return pts
	}
	pts = append(pts, Point{})
	copy(pts[i+1:], pts[i:])
	pts[i] = Point{Time: bucket, Up: d.Up, Down: d.Down}
	return pts
}

func minuteStart(t time.Time) time.Time { return t.UTC().Truncate(time.Minute) }
func hourStart(t time.Time) time.Time   { return t.UTC().Truncate(time.Hour) }
func dayStart(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func bucketStart(t time.Time, b Bucket) time.Time {
	switch b {
	case BucketHour:
		return hourStart(t)
	case BucketDay:
		return dayStart(t)
	}
	return minuteStart(t)
}

// rollupLocked folds minute points older than Retention.Minute into the
// hourly series, hourly points older than Retention.Hour into the daily
// series, drops daily points older than Retention.Day, then enforces
// MaxBytes.
func (s *Store) rollupLocked(now time.Time) {
	r := s.opt.Retention
	for id, ser := range s.devices {
		if r.Minute > 0 {
			cutoff := now.Add(-r.Minute)
			ser.Minute, ser.Hour = fold(ser.Minute, ser.Hour, cutoff, hourStart)
		}
		if r.Hour > 0 {
			cutoff := now.Add(-r.Hour)
			ser.Hour, ser.Day = fold(ser.Hour, ser.Day, cutoff, dayStart)
		}
		if r.Day > 0 {
			cutoff := dayStart(now.Add(-r.Day))
			ser.Day = dropBefore(ser.Day, cutoff)
		}
		if ser.empty() {
			delete(s.devices, id)
		}
	}
	s.enforceMaxBytesLocked()
}

// fold moves every point of fine older than cutoff into coarse, bucketed
// by start. Both slices are sorted, so the aged points are a prefix.
func fold(fine, coarse []Point, cutoff time.Time, start func(time.Time) time.Time) ([]Point, []Point) {
	n := 0
	for n < len(fine) && fine[n].Time.Before(cutoff) {
		coarse = addTo(coarse, start(fine[n].Time), Delta{Up: fine[n].Up, Down: fine[n].Down})
		n++
	}
	if n == 0 {
		return fine, coarse
	}
	return append(fine[:0:0], fine[n:]...), coarse
}

func dropBefore(pts []Point, cutoff time.Time) []Point {
	n := 0
	for n < len(pts) && pts[n].Time.Before(cutoff) {
		n++
	}
	if n == 0 {
		return pts
	}
	return append(pts[:0:0], pts[n:]...)
}

// enforceMaxBytesLocked drops the globally oldest daily point, one at a
// time, until the marshaled store fits. Minute and hourly data are already
// bounded by their own retention and are small next to years of daily
// points for every device that ever appeared.
func (s *Store) enforceMaxBytesLocked() {
	max := s.opt.Retention.MaxBytes
	if max <= 0 {
		return
	}
	for {
		b, err := json.Marshal(s.devices)
		if err != nil || len(b) <= max {
			return
		}
		oldestID := ""
		var oldest time.Time
		for id, ser := range s.devices {
			if len(ser.Day) > 0 && (oldestID == "" || ser.Day[0].Time.Before(oldest)) {
				oldestID, oldest = id, ser.Day[0].Time
			}
		}
		if oldestID == "" {
			return
		}
		ser := s.devices[oldestID]
		ser.Day = append(ser.Day[:0:0], ser.Day[1:]...)
		if ser.empty() {
			delete(s.devices, oldestID)
		}
	}
}

// Devices lists every device ID with any history, sorted.
func (s *Store) Devices() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.devices))
	for id := range s.devices {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Series returns the summed history of the given devices (every device
// when ids is nil) over [from, to] at bucket resolution, oldest first,
// with one point per bucket that had any traffic. Finer data is folded up
// into the requested resolution, so an hourly series over the last week
// includes the minutes not yet rolled up; coarser data cannot be split
// and is left out, which only matters for a minute-level query reaching
// further back than the minute retention.
func (s *Store) Series(ids []string, from, to time.Time, bucket Bucket) []Point {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Point
	add := func(pts []Point) {
		for _, p := range pts {
			if p.Time.Before(from) || p.Time.After(to) {
				continue
			}
			out = addTo(out, bucketStart(p.Time, bucket), Delta{Up: p.Up, Down: p.Down})
		}
	}
	for _, ser := range s.selectLocked(ids) {
		add(ser.Minute)
		if bucket != BucketMinute {
			add(ser.Hour)
		}
		if bucket == BucketDay {
			add(ser.Day)
		}
	}
	if out == nil {
		out = []Point{}
	}
	return out
}

// Totals returns each device's bytes over [from, to] at the finest
// resolution available, for a "who used the most" ranking. Devices with
// nothing in the range are left out.
func (s *Store) Totals(from, to time.Time) map[string]Delta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]Delta{}
	for id, ser := range s.devices {
		var d Delta
		for _, pts := range [][]Point{ser.Minute, ser.Hour, ser.Day} {
			for _, p := range pts {
				if p.Time.Before(from) || p.Time.After(to) {
					continue
				}
				d.Up += p.Up
				d.Down += p.Down
			}
		}
		if !d.zero() {
			out[id] = d
		}
	}
	return out
}

func (s *Store) selectLocked(ids []string) []*series {
	if ids == nil {
		out := make([]*series, 0, len(s.devices))
		for _, ser := range s.devices {
			out = append(out, ser)
		}
		return out
	}
	out := make([]*series, 0, len(ids))
	for _, id := range ids {
		if ser, ok := s.devices[id]; ok {
			out = append(out, ser)
		}
	}
	return out
}

// Save writes the store to path (mode 0600), atomically.
func (s *Store) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(path)
}

func (s *Store) saveLocked(path string) error {
	b, err := json.Marshal(s.devices)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// Load replaces the store's history with what is saved at path. A missing
// file is reported through the usual os.IsNotExist error.
func (s *Store) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	devices := map[string]*series{}
	if err := json.Unmarshal(b, &devices); err != nil {
		return err
	}
	for id, ser := range devices {
		if ser == nil || ser.empty() {
			delete(devices, id)
			continue
		}
		for _, pts := range []*[]Point{&ser.Minute, &ser.Hour, &ser.Day} {
			sort.Slice(*pts, func(i, j int) bool { return (*pts)[i].Time.Before((*pts)[j].Time) })
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = devices
	s.dirty = false
	return nil
}
