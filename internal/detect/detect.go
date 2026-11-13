// SPDX-License-Identifier: AGPL-3.0-or-later

// Package detect notices behaviour worth a look from data Shepherd already
// has: the DNS queries it answers and the per-device byte counts it reads
// from the router. Nothing here is in the path of anyone's traffic and
// nothing inspects a packet. Seven checks, each one cheap:
//
//   - a device looked up a public encrypted-DNS resolver (it may be about
//     to take its lookups somewhere Shepherd cannot see);
//   - a device moves real traffic but asks Shepherd nothing (it already
//     has);
//   - a burst of lookups for names that do not exist and look machine-made
//     (the way malware hunts for its controller);
//   - many long, distinct names under one domain (data carried in DNS);
//   - one device asking for a name nobody else asks for, new to the
//     network, on a metronome (a beacon);
//   - a single-purpose device reaching a country it never has;
//   - an upload far larger than the device has ever made.
//
// A finding names the device and raises an alarm; it blocks nothing. See
// docs/DETECT.md.
package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"shepherd/internal/dnsengine"
	"shepherd/internal/traffic"
)

// Kind is which check produced a finding.
type Kind string

const (
	KindEncryptedDNS Kind = "encrypted-dns"
	KindSilentDNS    Kind = "dns-silent"
	KindRandomNames  Kind = "dns-random-names"
	KindTunnel       Kind = "dns-tunnel"
	KindBeacon       Kind = "dns-beacon"
	KindNewCountry   Kind = "new-country"
	KindUploadSpike  Kind = "upload-spike"
)

// Evidence is one labelled fact behind a finding.
type Evidence struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Finding is one thing a check noticed.
type Finding struct {
	Time     time.Time `json:"time"`
	Kind     Kind      `json:"kind"`
	DeviceID string    `json:"device_id,omitempty"`
	Device   string    `json:"device,omitempty"`
	Client   string    `json:"client,omitempty"`
	// Subject is what the finding is about besides the device: a resolver,
	// a domain, a country code. Empty for the traffic checks.
	Subject string `json:"subject,omitempty"`
	// Summary is one sentence for a person.
	Summary  string     `json:"summary"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// DeviceInfo is what a check needs to know about a device.
type DeviceInfo struct {
	Name string
	// Skip leaves the device out of the traffic checks: the host Shepherd
	// runs on, the router, a device its owner excluded from protection.
	Skip bool
	// Narrow marks a device that does one job (a camera, a plug, a TV) and
	// so talks to a small, steady set of places. Only these get the
	// new-country check; a laptop reaches a new country every week.
	Narrow bool
}

// Traffic is the per-device byte history (internal/traffic.Store).
type Traffic interface {
	Totals(from, to time.Time) map[string]traffic.Delta
	Series(ids []string, from, to time.Time, bucket traffic.Bucket) []traffic.Point
}

// Limits are the thresholds. A zero field takes its default.
type Limits struct {
	// Learning is how long after the first start, and after a device is
	// first seen, the checks that compare against the past only watch.
	Learning time.Duration
	// Window is the span the burst checks count over.
	Window time.Duration
	// RandomNames is how many distinct registrable domains that do not
	// exist one device must ask for in a Window, at least half of them
	// machine-looking.
	RandomNames int
	// TunnelNames is how many distinct names, each carrying at least
	// TunnelBytes of subdomain, one device must ask for under one domain in
	// a Window.
	TunnelNames int
	TunnelBytes int
	// BeaconIntervals is how many evenly spaced lookups make a beacon, and
	// BeaconMaxCV how even (standard deviation over mean). BeaconNewFor is
	// how long a domain counts as new to the network.
	BeaconIntervals int
	BeaconMaxCV     float64
	BeaconNewFor    time.Duration
	// MatureQueries is how many lookups a device must have made before a
	// new country is news.
	MatureQueries uint64
	// SilentBytes of traffic over SilentFor with no lookup at all is a
	// device resolving names somewhere else.
	SilentBytes uint64
	SilentFor   time.Duration
	// An upload in the last hour of at least UploadFloor bytes that is
	// UploadFactor times the device's busiest hour on record. A device with
	// under a day of history needs UploadColdFloor instead.
	UploadFloor     uint64
	UploadFactor    float64
	UploadColdFloor uint64
}

// DefaultLimits are the thresholds Shepherd ships with.
func DefaultLimits() Limits {
	return Limits{
		Learning:        7 * 24 * time.Hour,
		Window:          10 * time.Minute,
		RandomNames:     20,
		TunnelNames:     40,
		TunnelBytes:     30,
		BeaconIntervals: 20,
		BeaconMaxCV:     0.1,
		BeaconNewFor:    7 * 24 * time.Hour,
		MatureQueries:   200,
		SilentBytes:     200 << 20,
		SilentFor:       24 * time.Hour,
		UploadFloor:     1 << 30,
		UploadFactor:    3,
		UploadColdFloor: 10 << 30,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.Learning <= 0 {
		l.Learning = d.Learning
	}
	if l.Window <= 0 {
		l.Window = d.Window
	}
	if l.RandomNames <= 0 {
		l.RandomNames = d.RandomNames
	}
	if l.TunnelNames <= 0 {
		l.TunnelNames = d.TunnelNames
	}
	if l.TunnelBytes <= 0 {
		l.TunnelBytes = d.TunnelBytes
	}
	if l.BeaconIntervals <= 0 {
		l.BeaconIntervals = d.BeaconIntervals
	}
	if l.BeaconMaxCV <= 0 {
		l.BeaconMaxCV = d.BeaconMaxCV
	}
	if l.BeaconNewFor <= 0 {
		l.BeaconNewFor = d.BeaconNewFor
	}
	if l.MatureQueries == 0 {
		l.MatureQueries = d.MatureQueries
	}
	if l.SilentBytes == 0 {
		l.SilentBytes = d.SilentBytes
	}
	if l.SilentFor <= 0 {
		l.SilentFor = d.SilentFor
	}
	if l.UploadFloor == 0 {
		l.UploadFloor = d.UploadFloor
	}
	if l.UploadFactor <= 0 {
		l.UploadFactor = d.UploadFactor
	}
	if l.UploadColdFloor == 0 {
		l.UploadColdFloor = d.UploadColdFloor
	}
	return l
}

// Options configures an Engine.
type Options struct {
	// Dir holds detect.json, what the checks have learned. Empty keeps it
	// in memory, which restarts the learning period on every start.
	Dir string
	// Now is the clock.
	Now func() time.Time
	// OnFinding hears every finding after it is recorded. It is called
	// from the DNS path, so it must not block.
	OnFinding func(Finding)
	// Resolvers are the encrypted-DNS resolver names to report a lookup
	// of; nil uses dnsengine.EncryptedDNSResolvers.
	Resolvers []string
	// Traffic is the byte history; nil turns the two traffic checks off.
	Traffic Traffic
	// Device describes a device by ID; nil means every device is unknown,
	// which turns off the checks that need to know one.
	Device func(id string) (DeviceInfo, bool)
	Limits Limits
}

const (
	stateVersion  = 1
	stateFile     = "detect.json"
	recentMax     = 200
	maxDomains    = 200_000
	maxDevices    = 5_000
	maxCountries  = 64
	maxWindowKeys = 512
	maxBeats      = 5_000
	// Lookups closer together than this are one event, not a rhythm; a gap
	// longer than beatMaxGap is the rhythm stopping.
	beatMinGap = 20 * time.Second
	beatMaxGap = 2 * time.Hour

	quietResolver = 24 * time.Hour
	quietBeacon   = 24 * time.Hour
	quietSilent   = 7 * 24 * time.Hour
	quietUpload   = 6 * time.Hour
	uploadHistory = 15 * 24 * time.Hour
)

// devState is what is remembered about one device.
type devState struct {
	First     time.Time `json:"first"`
	Queries   uint64    `json:"queries"`
	LastQuery time.Time `json:"last_query,omitzero"`
	// Countries the device's lookups have resolved to.
	Countries []string `json:"countries,omitempty"`
	// When the traffic checks last reported it, so each stays quiet for a
	// while afterwards.
	SilentReported time.Time `json:"silent_reported,omitzero"`
	UploadReported time.Time `json:"upload_reported,omitzero"`
}

// state is detect.json.
type state struct {
	Version int       `json:"version"`
	Started time.Time `json:"started"`
	// Domains is every registrable domain the network has looked up and
	// when it first did, in Unix seconds.
	Domains map[string]int64     `json:"domains"`
	Devices map[string]*devState `json:"devices"`
}

// window is one device's burst counters for the current Window.
type window struct {
	start time.Time
	// nx is the registrable domains that did not exist, and whether each
	// looked machine-made.
	nx         map[string]bool
	nxReported bool
	// tun is, per registrable domain, the distinct long names asked for.
	tun         map[string]map[string]struct{}
	tunReported map[string]bool
}

// beat is the rhythm of one device's lookups of one name (Welford's
// running mean and variance of the gaps).
type beat struct {
	last time.Time
	n    int
	mean float64
	m2   float64
}

// Status is the engine's state for the portal.
type Status struct {
	Started       time.Time `json:"started"`
	LearningUntil time.Time `json:"learning_until"`
	Learning      bool      `json:"learning"`
	Devices       int       `json:"devices"`
	Domains       int       `json:"domains"`
	// Traffic says whether the two traffic checks have a byte history to
	// read.
	Traffic  bool `json:"traffic"`
	Findings int  `json:"findings"`
}

// Engine runs the checks. It is safe for concurrent use.
type Engine struct {
	opt       Options
	lim       Limits
	resolvers map[string]struct{}

	mu     sync.Mutex
	st     state
	dirty  bool
	wins   map[string]*window
	beats  map[string]*beat
	askers map[string]string // new domain -> the one device asking, or "*"
	quiet  map[string]time.Time
	recent []Finding
	total  int
}

// New builds an Engine and loads what an earlier run learned. An unreadable
// detect.json is reported and replaced by a fresh start: the engine is
// usable either way.
func New(opt Options) (*Engine, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	names := opt.Resolvers
	if names == nil {
		names = dnsengine.EncryptedDNSResolvers()
	}
	e := &Engine{
		opt: opt, lim: opt.Limits.withDefaults(),
		resolvers: map[string]struct{}{},
		wins:      map[string]*window{}, beats: map[string]*beat{},
		askers: map[string]string{}, quiet: map[string]time.Time{},
	}
	for _, n := range names {
		e.resolvers[normalize(n)] = struct{}{}
	}
	err := e.load()
	if e.st.Started.IsZero() {
		e.st = state{Version: stateVersion, Started: opt.Now().UTC(), Domains: map[string]int64{}, Devices: map[string]*devState{}}
		e.dirty = true
	}
	return e, err
}

func (e *Engine) path() string {
	if e.opt.Dir == "" {
		return ""
	}
	return filepath.Join(e.opt.Dir, stateFile)
}

func (e *Engine) load() error {
	p := e.path()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("parsing %s: %w", p, err)
	}
	if st.Version != stateVersion || st.Started.IsZero() {
		return fmt.Errorf("%s: unsupported version %d", p, st.Version)
	}
	if st.Domains == nil {
		st.Domains = map[string]int64{}
	}
	if st.Devices == nil {
		st.Devices = map[string]*devState{}
	}
	for id, d := range st.Devices {
		if d == nil {
			delete(st.Devices, id)
		}
	}
	e.st = st
	return nil
}

// Save writes what the checks have learned, when it has changed.
func (e *Engine) Save() error {
	p := e.path()
	e.mu.Lock()
	if p == "" || !e.dirty {
		e.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(e.st)
	e.dirty = false
	e.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(e.opt.Dir, 0o750); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Run ticks the traffic checks and saves on the interval until ctx ends,
// then saves once more.
func (e *Engine) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = e.Save()
			return
		case <-t.C:
			e.Tick(e.opt.Now())
			_ = e.Save()
		}
	}
}

// Status reports the engine's state.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	until := e.st.Started.Add(e.lim.Learning)
	return Status{
		Started: e.st.Started, LearningUntil: until, Learning: e.opt.Now().Before(until),
		Devices: len(e.st.Devices), Domains: len(e.st.Domains),
		Traffic: e.opt.Traffic != nil, Findings: e.total,
	}
}

// Recent returns the latest findings, newest first.
func (e *Engine) Recent() []Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := slices.Clone(e.recent)
	slices.Reverse(out)
	if out == nil {
		out = []Finding{}
	}
	return out
}

// emit records findings and hands them to OnFinding. Callers must not hold
// e.mu.
func (e *Engine) emit(fs []Finding) {
	if len(fs) == 0 {
		return
	}
	e.mu.Lock()
	for _, f := range fs {
		e.recent = append(e.recent, f)
		e.total++
	}
	if over := len(e.recent) - recentMax; over > 0 {
		e.recent = slices.Clone(e.recent[over:])
	}
	e.mu.Unlock()
	if e.opt.OnFinding != nil {
		for _, f := range fs {
			e.opt.OnFinding(f)
		}
	}
}

// quietLocked reports whether key was reported within d, and marks it
// reported now when it was not.
func (e *Engine) quietLocked(key string, now time.Time, d time.Duration) bool {
	if last, ok := e.quiet[key]; ok && now.Sub(last) < d {
		return true
	}
	if len(e.quiet) >= maxBeats {
		for k, t := range e.quiet {
			if now.Sub(t) > quietSilent {
				delete(e.quiet, k)
			}
		}
	}
	e.quiet[key] = now
	return false
}

func (e *Engine) deviceLocked(id string, now time.Time) *devState {
	if d, ok := e.st.Devices[id]; ok {
		return d
	}
	if len(e.st.Devices) >= maxDevices {
		return nil
	}
	d := &devState{First: now.UTC()}
	e.st.Devices[id] = d
	e.dirty = true
	return d
}

func (e *Engine) info(id string) (DeviceInfo, bool) {
	if e.opt.Device == nil || id == "" {
		return DeviceInfo{}, false
	}
	return e.opt.Device(id)
}

// Observe is the DNS engine's hook: every recorded query, whatever was done
// with it.
func (e *Engine) Observe(q dnsengine.Entry) {
	name := normalize(q.Name)
	if name == "" || localName(name) {
		return
	}
	now := q.Time
	if now.IsZero() {
		now = e.opt.Now()
	}
	key := q.DeviceID
	if key == "" {
		key = "ip:" + q.Client
	}
	who := q.Device
	if who == "" {
		who = q.Client
	}
	reg := registrable(name)
	base := Finding{Time: now, DeviceID: q.DeviceID, Device: who, Client: q.Client}
	var out []Finding

	e.mu.Lock()
	var ds *devState
	if q.DeviceID != "" {
		if ds = e.deviceLocked(q.DeviceID, now); ds != nil {
			ds.Queries++
			ds.LastQuery = now.UTC()
			e.dirty = true
		}
	}

	if r := e.resolverFor(name); r != "" && !e.quietLocked("r|"+key+"|"+r, now, quietResolver) {
		f := base
		f.Kind, f.Subject = KindEncryptedDNS, r
		f.Summary = who + " looked up " + name + ", a public encrypted-DNS resolver. A device that uses one sends its lookups where Shepherd cannot filter or see them."
		f.Evidence = []Evidence{{"Looked up", name}, {"Resolver", r}, {"The lookup was", q.Action}}
		out = append(out, f)
	}

	w := e.windowLocked(key, now)
	if q.Rcode == "NXDOMAIN" && q.Action != "blocked" && len(w.nx) < maxWindowKeys {
		w.nx[reg] = looksRandom(firstLabel(reg))
		if !w.nxReported && len(w.nx) >= e.lim.RandomNames {
			random := 0
			for _, r := range w.nx {
				if r {
					random++
				}
			}
			if random*2 >= len(w.nx) {
				w.nxReported = true
				f := base
				f.Kind, f.Subject = KindRandomNames, reg
				f.Summary = fmt.Sprintf("%s asked for %d different domains that do not exist within %s, most of them machine-made names. Malware hunting for its controller looks like this.", who, len(w.nx), span(e.lim.Window))
				f.Evidence = []Evidence{{"Domains that did not exist", fmt.Sprint(len(w.nx))}, {"Machine-looking", fmt.Sprint(random)}, {"Examples", sample(w.nx, 5)}}
				out = append(out, f)
			}
		}
	}

	if sub := len(name) - len(reg) - 1; sub >= e.lim.TunnelBytes && !w.tunReported[reg] {
		names := w.tun[reg]
		if names == nil && len(w.tun) < maxWindowKeys {
			names = map[string]struct{}{}
			w.tun[reg] = names
		}
		if names != nil {
			names[name] = struct{}{}
			if len(names) >= e.lim.TunnelNames {
				w.tunReported[reg] = true
				delete(w.tun, reg)
				f := base
				f.Kind, f.Subject = KindTunnel, reg
				f.Summary = fmt.Sprintf("%s asked for %d different long names under %s within %s. Names like that can carry data out through DNS; some security and telemetry products also work this way.", who, e.lim.TunnelNames, reg, span(e.lim.Window))
				f.Evidence = []Evidence{{"Domain", reg}, {"Distinct long names", fmt.Sprint(e.lim.TunnelNames)}, {"Example", name}}
				out = append(out, f)
			}
		}
	}

	first, known := e.st.Domains[reg]
	if !known {
		first = now.Unix()
		if len(e.st.Domains) < maxDomains {
			e.st.Domains[reg] = first
			e.dirty = true
		}
	}
	learned := e.st.Started.Add(e.lim.Learning)
	if q.Action != "blocked" && !now.Before(learned) && first >= learned.Unix() && now.Sub(time.Unix(first, 0)) <= e.lim.BeaconNewFor {
		if f, ok := e.beatLocked(key, name, reg, now); ok {
			f.Time, f.DeviceID, f.Device, f.Client = base.Time, base.DeviceID, base.Device, base.Client
			f.Summary = who + f.Summary
			out = append(out, f)
		}
	}

	if ds != nil && (q.Action == "allowed" || q.Action == "cached") {
		for _, d := range q.Dests {
			c := strings.ToUpper(d.Country)
			if c == "" || slices.Contains(ds.Countries, c) || len(ds.Countries) >= maxCountries {
				continue
			}
			mature := now.Sub(ds.First) >= e.lim.Learning && ds.Queries >= e.lim.MatureQueries
			had := strings.Join(ds.Countries, ", ")
			ds.Countries = append(ds.Countries, c)
			e.dirty = true
			if !mature {
				continue
			}
			e.mu.Unlock()
			info, ok := e.info(q.DeviceID)
			e.mu.Lock()
			if !ok || !info.Narrow {
				continue
			}
			f := base
			f.Kind, f.Subject = KindNewCountry, c
			f.Summary = who + " looked up " + name + ", which resolved to an address in " + c + ". Until now its lookups have only ever resolved to " + had + "."
			f.Evidence = []Evidence{{"Looked up", name}, {"Address", d.IP}, {"Country", c}, {"Seen before", had}}
			out = append(out, f)
		}
	}
	e.mu.Unlock()
	e.emit(out)
}

func (e *Engine) windowLocked(key string, now time.Time) *window {
	w := e.wins[key]
	if w == nil || now.Sub(w.start) >= e.lim.Window || now.Before(w.start) {
		if w == nil && len(e.wins) >= maxDevices {
			for k, old := range e.wins {
				if now.Sub(old.start) >= e.lim.Window {
					delete(e.wins, k)
				}
			}
		}
		w = &window{start: now, nx: map[string]bool{}, tun: map[string]map[string]struct{}{}, tunReported: map[string]bool{}}
		e.wins[key] = w
	}
	return w
}

// beatLocked feeds one lookup of a new-to-the-network name into its rhythm
// and returns a finding when the rhythm is a beacon. The returned Summary
// starts after the device's name.
func (e *Engine) beatLocked(key, name, reg string, now time.Time) (Finding, bool) {
	switch a := e.askers[reg]; {
	case a == "":
		if len(e.askers) >= maxBeats {
			clear(e.askers)
			clear(e.beats)
		}
		e.askers[reg] = key
	case a != key:
		// A name several devices ask for is a service, not an implant.
		e.askers[reg] = "*"
		return Finding{}, false
	}
	bk := key + "|" + name
	b := e.beats[bk]
	if b == nil {
		if len(e.beats) >= maxBeats {
			clear(e.beats)
		}
		e.beats[bk] = &beat{last: now}
		return Finding{}, false
	}
	gap := now.Sub(b.last)
	switch {
	case gap < beatMinGap:
		return Finding{}, false
	case gap > beatMaxGap:
		*b = beat{last: now}
		return Finding{}, false
	}
	b.last = now
	b.n++
	g := gap.Seconds()
	delta := g - b.mean
	b.mean += delta / float64(b.n)
	b.m2 += delta * (g - b.mean)
	if b.n < e.lim.BeaconIntervals {
		return Finding{}, false
	}
	cv := math.Sqrt(b.m2/float64(b.n-1)) / b.mean
	if cv > e.lim.BeaconMaxCV || e.quietLocked("b|"+bk, now, quietBeacon) {
		return Finding{}, false
	}
	every := time.Duration(b.mean * float64(time.Second)).Round(time.Second)
	return Finding{
		Kind: KindBeacon, Subject: name,
		Summary: fmt.Sprintf(" has looked up %s every %s, %d times in a row. No other device asks for %s and the network first saw it %s. Software checking in with a server looks like this; so does a new app or a firmware update.",
			name, every, b.n+1, reg, time.Unix(e.st.Domains[reg], 0).UTC().Format("2 Jan 2006")),
		Evidence: []Evidence{{"Name", name}, {"Every", every.String()}, {"Lookups in a row", fmt.Sprint(b.n + 1)}, {"Evenness", fmt.Sprintf("%.0f%% variation", cv*100)}},
	}, true
}

// Tick runs the two traffic checks. It is called on an interval by Run.
func (e *Engine) Tick(now time.Time) {
	if e.opt.Traffic == nil {
		return
	}
	var out []Finding
	out = append(out, e.silent(now)...)
	out = append(out, e.uploads(now)...)
	e.emit(out)
}

func sortedIDs(m map[string]traffic.Delta) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// silent finds devices that moved real traffic over SilentFor without one
// lookup reaching Shepherd.
func (e *Engine) silent(now time.Time) []Finding {
	e.mu.Lock()
	started := e.st.Started
	e.mu.Unlock()
	if now.Sub(started) < e.lim.SilentFor {
		return nil // not yet watched for long enough to say "nothing"
	}
	totals := e.opt.Traffic.Totals(now.Add(-e.lim.SilentFor), now)
	var out []Finding
	for _, id := range sortedIDs(totals) {
		d := totals[id]
		if d.Up+d.Down < e.lim.SilentBytes {
			continue
		}
		info, ok := e.info(id)
		if !ok || info.Skip {
			continue
		}
		e.mu.Lock()
		ds := e.deviceLocked(id, now)
		report := ds != nil && now.Sub(ds.First) >= e.lim.SilentFor &&
			(ds.LastQuery.IsZero() || now.Sub(ds.LastQuery) >= e.lim.SilentFor) &&
			(ds.SilentReported.IsZero() || now.Sub(ds.SilentReported) >= quietSilent)
		var last time.Time
		if report {
			last = ds.LastQuery
			ds.SilentReported = now.UTC()
			e.dirty = true
		}
		e.mu.Unlock()
		if !report {
			continue
		}
		asked := "never"
		if !last.IsZero() {
			asked = last.UTC().Format("2 Jan 2006 15:04 UTC")
		}
		out = append(out, Finding{
			Time: now, Kind: KindSilentDNS, DeviceID: id, Device: info.Name,
			Summary: fmt.Sprintf("%s moved %s in the last %s without one lookup reaching Shepherd. It is resolving names somewhere else, a resolver built into it or an encrypted one, so nothing it does is filtered. Lookups arriving from an address Shepherd has not tied to the device would look the same.",
				info.Name, bytesText(d.Up+d.Down), span(e.lim.SilentFor)),
			Evidence: []Evidence{{"Traffic", bytesText(d.Up + d.Down)}, {"Over", span(e.lim.SilentFor)}, {"Last lookup", asked}},
		})
	}
	return out
}

// uploads finds a device whose last hour of upload dwarfs its own record.
func (e *Engine) uploads(now time.Time) []Finding {
	hour := e.opt.Traffic.Totals(now.Add(-time.Hour), now)
	var out []Finding
	for _, id := range sortedIDs(hour) {
		up := hour[id].Up
		if up < e.lim.UploadFloor {
			continue
		}
		info, ok := e.info(id)
		if !ok || info.Skip {
			continue
		}
		// The hour buckets that ended before the hour being judged.
		hist := e.opt.Traffic.Series([]string{id}, now.Add(-uploadHistory), now.Add(-2*time.Hour), traffic.BucketHour)
		var busiest uint64
		for _, p := range hist {
			busiest = max(busiest, p.Up)
		}
		known := len(hist) >= 24
		if known && float64(up) < e.lim.UploadFactor*float64(busiest) {
			continue
		}
		if !known && up < e.lim.UploadColdFloor {
			continue
		}
		e.mu.Lock()
		ds := e.deviceLocked(id, now)
		report := ds != nil && (ds.UploadReported.IsZero() || now.Sub(ds.UploadReported) >= quietUpload)
		if report {
			ds.UploadReported = now.UTC()
			e.dirty = true
		}
		e.mu.Unlock()
		if !report {
			continue
		}
		compare := "It has under a day of history to compare against."
		ev := []Evidence{{"Uploaded in the last hour", bytesText(up)}}
		if known {
			compare = fmt.Sprintf("Its busiest hour on record before this was %s.", bytesText(busiest))
			ev = append(ev, Evidence{"Busiest hour before", bytesText(busiest)}, Evidence{"Hours on record", fmt.Sprint(len(hist))})
		}
		out = append(out, Finding{
			Time: now, Kind: KindUploadSpike, DeviceID: id, Device: info.Name,
			Summary:  fmt.Sprintf("%s uploaded %s in the last hour. %s A backup or a large share does this; so does data leaving that should not.", info.Name, bytesText(up), compare),
			Evidence: ev,
		})
	}
	return out
}

// resolverFor returns the resolver name covering name, or "".
func (e *Engine) resolverFor(name string) string {
	for n := name; ; {
		if _, ok := e.resolvers[n]; ok {
			return n
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return ""
		}
		n = n[i+1:]
	}
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// localName reports names that say nothing about the internet: a bare
// label, reverse lookups and the local-network suffixes.
func localName(name string) bool {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return true
	}
	switch name[i+1:] {
	case "arpa", "local", "lan", "home", "internal", "localdomain", "localhost", "invalid", "test":
		return true
	}
	return false
}

// registrable returns the domain a name belongs to (example.co.uk for
// a.b.example.co.uk), or the name itself when the suffix list has no
// answer.
func registrable(name string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return d
	}
	return name
}

func firstLabel(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// looksRandom reports whether a label reads as machine-made: long enough,
// high in entropy, and either short of vowels or salted with digits. Words
// people pick fail it; the output of a domain-generation algorithm passes.
func looksRandom(label string) bool {
	label = strings.ReplaceAll(label, "-", "")
	n := len(label)
	if n < 8 {
		return false
	}
	var counts [256]int
	vowels, digits := 0, 0
	for i := 0; i < n; i++ {
		c := label[i]
		counts[c]++
		switch {
		case strings.IndexByte("aeiou", c) >= 0:
			vowels++
		case c >= '0' && c <= '9':
			digits++
		}
	}
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / float64(n)
			h -= p * math.Log2(p)
		}
	}
	return h >= 3.0 && (float64(vowels)/float64(n) < 0.3 || digits >= 2)
}

// sample returns up to n keys of m, sorted, joined for display.
func sample(m map[string]bool, n int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > n {
		keys = keys[:n]
	}
	return strings.Join(keys, ", ")
}

// span words a duration the way a person would: "10 minutes", "24 hours".
func span(d time.Duration) string {
	unit := func(n int, s string) string {
		if n == 1 {
			return "1 " + s
		}
		return fmt.Sprintf("%d %ss", n, s)
	}
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return unit(int(d/time.Hour), "hour")
	case d >= time.Minute && d%time.Minute == 0:
		return unit(int(d/time.Minute), "minute")
	}
	return d.String()
}

// bytesText words a byte count in binary units.
func bytesText(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
