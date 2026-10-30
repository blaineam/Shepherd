// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"encoding/json"
	"math"
	"os"
	"sort"
	"time"
)

// Bucket names a resolution to query or roll samples up to.
type Bucket string

const (
	BucketRaw  Bucket = "raw"  // full-resolution samples, one per probe cycle
	BucketHour Bucket = "hour" // one point per hour
	BucketDay  Bucket = "day"  // one point per day
)

// Point is one plotted value at some resolution: a raw Sample's own fields
// when Bucket is raw, or an Aggregate's rolled-up fields otherwise. Latency,
// jitter and loss are always present; Min/Max are only meaningful for a
// rolled-up bucket (both equal Avg for a raw point).
type Point struct {
	Time             time.Time `json:"time"`
	Count            int       `json:"count"`
	AvgLatencyMS     float64   `json:"avg_latency_ms,omitempty"`
	MinLatencyMS     float64   `json:"min_latency_ms,omitempty"`
	MaxLatencyMS     float64   `json:"max_latency_ms,omitempty"`
	AvgJitterMS      float64   `json:"avg_jitter_ms,omitempty"`
	AvgLossPct       float64   `json:"avg_loss_pct"`
	ReachableTargets int       `json:"reachable_targets,omitempty"`
	TotalTargets     int       `json:"total_targets,omitempty"`
}

func pointFromSample(s Sample) Point {
	return Point{
		Time: s.Time, Count: 1,
		AvgLatencyMS: s.LatencyMS, MinLatencyMS: s.LatencyMS, MaxLatencyMS: s.LatencyMS,
		AvgJitterMS: s.JitterMS, AvgLossPct: s.LossPct,
		ReachableTargets: s.ReachableTargets, TotalTargets: s.TotalTargets,
	}
}

// aggregate is one rolled-up bucket (an hour or a day): the running,
// count-weighted mean of every sample folded into it, plus the min/max
// latency actually observed. Weighting every merge by how many raw samples
// are behind each side keeps repeated rollups (raw -> hour -> day) exact
// rather than drifting toward an unweighted average of averages.
type aggregate struct {
	Bucket           time.Time `json:"bucket"`
	Count            int       `json:"count"`
	AvgLatencyMS     float64   `json:"avg_latency_ms"`
	MinLatencyMS     float64   `json:"min_latency_ms"`
	MaxLatencyMS     float64   `json:"max_latency_ms"`
	AvgJitterMS      float64   `json:"avg_jitter_ms"`
	AvgLossPct       float64   `json:"avg_loss_pct"`
	ReachableTargets float64   `json:"reachable_targets"` // mean, kept as float for exact re-merging
	TotalTargets     float64   `json:"total_targets"`
}

func (a *aggregate) toPoint() Point {
	return Point{
		Time: a.Bucket, Count: a.Count,
		AvgLatencyMS: a.AvgLatencyMS, MinLatencyMS: a.MinLatencyMS, MaxLatencyMS: a.MaxLatencyMS,
		AvgJitterMS: a.AvgJitterMS, AvgLossPct: a.AvgLossPct,
		ReachableTargets: int(math.Round(a.ReachableTargets)), TotalTargets: int(math.Round(a.TotalTargets)),
	}
}

// mergeSample folds one raw Sample into the aggregate (count weight 1).
func (a *aggregate) mergeSample(s Sample, bucketStart time.Time) {
	a.mergeWeighted(bucketStart, 1, s.LatencyMS, s.LatencyMS, s.LatencyMS, s.JitterMS, s.LossPct, float64(s.ReachableTargets), float64(s.TotalTargets))
}

// mergeAggregate folds another aggregate (e.g. an hour into a day) in,
// weighted by its own count.
func (a *aggregate) mergeAggregate(o aggregate, bucketStart time.Time) {
	if o.Count == 0 {
		return
	}
	a.mergeWeighted(bucketStart, o.Count, o.AvgLatencyMS, o.MinLatencyMS, o.MaxLatencyMS, o.AvgJitterMS, o.AvgLossPct, o.ReachableTargets, o.TotalTargets)
}

func (a *aggregate) mergeWeighted(bucketStart time.Time, n int, avgLat, minLat, maxLat, avgJit, avgLoss, reach, total float64) {
	if a.Count == 0 {
		a.Bucket = bucketStart
		a.MinLatencyMS, a.MaxLatencyMS = minLat, maxLat
	} else {
		if minLat < a.MinLatencyMS {
			a.MinLatencyMS = minLat
		}
		if maxLat > a.MaxLatencyMS {
			a.MaxLatencyMS = maxLat
		}
	}
	prev := float64(a.Count)
	next := prev + float64(n)
	a.AvgLatencyMS = (a.AvgLatencyMS*prev + avgLat*float64(n)) / next
	a.AvgJitterMS = (a.AvgJitterMS*prev + avgJit*float64(n)) / next
	a.AvgLossPct = (a.AvgLossPct*prev + avgLoss*float64(n)) / next
	a.ReachableTargets = (a.ReachableTargets*prev + reach*float64(n)) / next
	a.TotalTargets = (a.TotalTargets*prev + total*float64(n)) / next
	a.Count += n
}

func hourStart(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) }
func dayStart(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Retention is how long each resolution is kept before being rolled up (raw
// -> hourly, hourly -> daily) or, for daily, dropped entirely. See
// docs/NETHEALTH.md's "Retention" section for the reasoning behind the
// defaults: full resolution for a few days (enough to look at "what happened
// this morning"), hourly for a couple of months, daily indefinitely by
// default so "is this getting worse over the year" always has an answer,
// bounded by MaxBytes so a years-old install cannot grow without limit.
type Retention struct {
	Raw  time.Duration // default 3 days
	Hour time.Duration // default 60 days
	Day  time.Duration // default 0 (keep forever)
	// MaxBytes caps the on-disk size of the daily series; once the
	// marshaled store would exceed it, the oldest daily points are dropped
	// first (raw and hourly are already bounded by their own retention and
	// are tiny by comparison). 0 means no cap.
	MaxBytes int
}

// DefaultRetention is what Store uses when StoreOptions.Retention is unset.
func DefaultRetention() Retention {
	return Retention{
		Raw:      3 * 24 * time.Hour,
		Hour:     60 * 24 * time.Hour,
		Day:      0,
		MaxBytes: 8 << 20, // 8 MiB: tens of thousands of daily points, far more than a year needs
	}
}

// StoreOptions configures a Store. The zero value is usable.
type StoreOptions struct {
	Retention Retention
	Now       func() time.Time
}

// Store keeps nethealth's history at three resolutions and rolls data from
// one resolution to the next as it ages out, so size never grows without
// bound while months of trend data stay available (see Retention). It also
// keeps the separate, much sparser Bufferbloat series (store_bufferbloat.go).
// Safe for concurrent use only via its caller's own locking (Prober already
// serializes access); Store itself takes no lock.
type Store struct {
	opt StoreOptions

	Raw         []Sample      `json:"raw"`
	Hourly      []aggregate   `json:"hourly"`
	Daily       []aggregate   `json:"daily"`
	Bufferbloat []Bufferbloat `json:"bufferbloat"`
}

// NewStore creates an empty Store from opts.
func NewStore(opts StoreOptions) *Store {
	if opts.Retention == (Retention{}) {
		opts.Retention = DefaultRetention()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{opt: opts}
}

// Add records a fresh sample and rolls up anything that has aged out of its
// current resolution.
func (st *Store) Add(s Sample) {
	st.Raw = append(st.Raw, s)
	sortSamples(st.Raw)
	st.rollup()
}

// AddBufferbloat records a fresh bufferbloat reading and prunes old ones by
// the same daily retention window (bufferbloat runs rarely, so it is never
// itself large enough to need rollup — see docs/NETHEALTH.md).
func (st *Store) AddBufferbloat(b Bufferbloat) {
	st.Bufferbloat = append(st.Bufferbloat, b)
	sortBufferbloat(st.Bufferbloat)
	if st.opt.Retention.Day > 0 {
		cutoff := st.opt.Now().Add(-st.opt.Retention.Day)
		st.Bufferbloat = dropBufferbloatBefore(st.Bufferbloat, cutoff)
	}
}

func sortSamples(xs []Sample) {
	sort.Slice(xs, func(i, j int) bool { return xs[i].Time.Before(xs[j].Time) })
}

// rollup folds any raw sample older than Retention.Raw into the hourly
// series, then any hourly bucket older than Retention.Hour into the daily
// series, then drops daily buckets older than Retention.Day (if set), then
// enforces MaxBytes by dropping the oldest daily buckets.
func (st *Store) rollup() {
	now := st.opt.Now()

	if st.opt.Retention.Raw > 0 {
		cutoff := now.Add(-st.opt.Retention.Raw)
		kept := st.Raw[:0:0]
		for _, s := range st.Raw {
			if s.Time.Before(cutoff) {
				st.foldIntoHourly(s)
				continue
			}
			kept = append(kept, s)
		}
		st.Raw = kept
	}

	if st.opt.Retention.Hour > 0 {
		cutoff := now.Add(-st.opt.Retention.Hour)
		kept := st.Hourly[:0:0]
		for _, h := range st.Hourly {
			if h.Bucket.Before(cutoff) {
				st.foldIntoDaily(h)
				continue
			}
			kept = append(kept, h)
		}
		st.Hourly = kept
	}

	if st.opt.Retention.Day > 0 {
		cutoff := dayStart(now.Add(-st.opt.Retention.Day))
		kept := st.Daily[:0:0]
		for _, d := range st.Daily {
			if d.Bucket.Before(cutoff) {
				continue
			}
			kept = append(kept, d)
		}
		st.Daily = kept
	}

	st.enforceMaxBytes()
}

func (st *Store) foldIntoHourly(s Sample) {
	bucket := hourStart(s.Time)
	for i := range st.Hourly {
		if st.Hourly[i].Bucket.Equal(bucket) {
			st.Hourly[i].mergeSample(s, bucket)
			return
		}
	}
	var a aggregate
	a.mergeSample(s, bucket)
	st.Hourly = append(st.Hourly, a)
	sort.Slice(st.Hourly, func(i, j int) bool { return st.Hourly[i].Bucket.Before(st.Hourly[j].Bucket) })
}

func (st *Store) foldIntoDaily(h aggregate) {
	bucket := dayStart(h.Bucket)
	for i := range st.Daily {
		if st.Daily[i].Bucket.Equal(bucket) {
			st.Daily[i].mergeAggregate(h, bucket)
			return
		}
	}
	var a aggregate
	a.mergeAggregate(h, bucket)
	st.Daily = append(st.Daily, a)
	sort.Slice(st.Daily, func(i, j int) bool { return st.Daily[i].Bucket.Before(st.Daily[j].Bucket) })
}

// enforceMaxBytes drops the oldest daily points, one at a time, until the
// marshaled store fits under the cap. Raw and hourly are already bounded by
// their own age-based retention, so only the unbounded-by-default daily
// series is ever trimmed this way.
func (st *Store) enforceMaxBytes() {
	if st.opt.Retention.MaxBytes <= 0 {
		return
	}
	for len(st.Daily) > 0 {
		b, err := json.Marshal(st)
		if err != nil || len(b) <= st.opt.Retention.MaxBytes {
			return
		}
		st.Daily = st.Daily[1:]
	}
}

// Latest returns the most recently recorded raw sample.
func (st *Store) Latest() (Sample, bool) {
	if len(st.Raw) == 0 {
		return Sample{}, false
	}
	return st.Raw[len(st.Raw)-1], true
}

// Query returns every point at the given bucket resolution whose time falls
// in [from, to]. Raw returns Sample-derived points from the raw series only
// (a query that reaches further back than Retention.Raw will not find
// anything there — ask for hour or day instead); hour and day return the
// corresponding rolled-up series.
func (st *Store) Query(from, to time.Time, bucket Bucket) []Point {
	var out []Point
	switch bucket {
	case BucketHour:
		for _, a := range st.Hourly {
			if inRange(a.Bucket, from, to) {
				out = append(out, a.toPoint())
			}
		}
	case BucketDay:
		for _, a := range st.Daily {
			if inRange(a.Bucket, from, to) {
				out = append(out, a.toPoint())
			}
		}
	default: // BucketRaw and anything unrecognized
		for _, s := range st.Raw {
			if inRange(s.Time, from, to) {
				out = append(out, pointFromSample(s))
			}
		}
	}
	return out
}

func inRange(t, from, to time.Time) bool {
	return !t.Before(from) && !t.After(to)
}

type persistedFile struct {
	Raw         []Sample      `json:"raw"`
	Hourly      []aggregate   `json:"hourly"`
	Daily       []aggregate   `json:"daily"`
	Bufferbloat []Bufferbloat `json:"bufferbloat"`
}

// Save writes the store to path (mode 0600), atomically.
func (p *Prober) Save(path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	f := persistedFile{Raw: p.store.Raw, Hourly: p.store.Hourly, Daily: p.store.Daily, Bufferbloat: p.store.Bufferbloat}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load replaces the store's history with what is saved at path. A missing
// file is reported through the usual os.IsNotExist error.
func (p *Prober) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f persistedFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.store.Raw = f.Raw
	p.store.Hourly = f.Hourly
	p.store.Daily = f.Daily
	p.store.Bufferbloat = f.Bufferbloat
	return nil
}
