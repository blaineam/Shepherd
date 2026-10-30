// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shepherd/internal/devices"
)

// Defaults. Each can be changed through Options.
const (
	DefaultThreshold    = 0.5  // the least confidence that names a class
	DefaultRelease      = 0.35 // a guess is withdrawn only when its own evidence falls below this
	DefaultSwitchMargin = 0.12 // a challenger must beat the current guess by this much
	DefaultHalfLife     = 7 * 24 * time.Hour
	DefaultIdleTTL      = 30 * 24 * time.Hour
	DefaultMaxDevices   = 1024
	DefaultMaxDomains   = 24
	DefaultMaxASNs      = 16
	DefaultMinGroupSize = 2
	// minEvidence is how many (decayed) lookups a device must have shown
	// before "the evidence no longer supports the guess" can withdraw it:
	// having no evidence at all (a restart) is not evidence against.
	minEvidence = 5
)

// Options configures a Classifier. The zero value is usable.
type Options struct {
	// Rules defaults to the embedded rule files.
	Rules *RuleSet
	// ASN looks up the network of an answer address. Optional: without it
	// the ASN family simply contributes nothing.
	ASN ASNFunc
	// Resolve maps a client IP to the device it belongs to ("" if unknown).
	// Optional; UseRegistry sets it from the registry's lock-free scope
	// index. Evidence for unresolved IPs is kept under the IP and folded
	// into the device by Apply.
	Resolve func(clientIP string) string
	// NonBlocking makes Observe drop an observation rather than wait when
	// its lock is busy. The DNS engine should set it.
	NonBlocking bool

	Now func() time.Time

	HalfLife time.Duration // evidence halves every HalfLife (default 7 days)
	IdleTTL  time.Duration // a device not heard from for this long is forgotten (default 30 days)

	MaxDevices int // devices tracked at once (default 1024)
	MaxDomains int // registrable domains retained per device (default 24)
	MaxASNs    int // ASNs retained per device (default 16)

	Threshold    float64 // default 0.5
	Release      float64 // default 0.35
	SwitchMargin float64 // default 0.12
	MinGroupSize int     // smallest group worth suggesting (default 2)
}

// Classifier collects evidence and classifies devices. It is safe for
// concurrent use.
type Classifier struct {
	rs  *RuleSet
	cfg *config
	st  *store

	resolver atomic.Pointer[func(string) string]
	asnFn    atomic.Pointer[ASNFunc]

	threshold, release, margin float64
	minGroup                   int

	mu       sync.Mutex
	assigned map[string]devices.DeviceType // effective type per device, as of the last Apply
	existing map[string]bool               // lower-cased names of groups that already exist
}

// New creates a Classifier.
func New(opts Options) (*Classifier, error) {
	rs := opts.Rules
	if rs == nil {
		var err error
		if rs, err = DefaultRuleSet(); err != nil {
			return nil, fmt.Errorf("classify: embedded rules: %w", err)
		}
	}
	cfg := &config{
		halfLife: orDur(opts.HalfLife, DefaultHalfLife), idleTTL: orDur(opts.IdleTTL, DefaultIdleTTL),
		maxDomains: orInt(opts.MaxDomains, DefaultMaxDomains), maxASNs: orInt(opts.MaxASNs, DefaultMaxASNs),
		nonBlock: opts.NonBlocking, now: opts.Now,
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	c := &Classifier{
		rs: rs, cfg: cfg,
		st:        newStore(rs, cfg, orInt(opts.MaxDevices, DefaultMaxDevices)),
		threshold: orFloat(opts.Threshold, DefaultThreshold), release: orFloat(opts.Release, DefaultRelease),
		margin: orFloat(opts.SwitchMargin, DefaultSwitchMargin), minGroup: orInt(opts.MinGroupSize, DefaultMinGroupSize),
		assigned: map[string]devices.DeviceType{},
		existing: map[string]bool{},
	}
	if opts.Resolve != nil {
		c.SetResolver(opts.Resolve)
	}
	if opts.ASN != nil {
		c.SetASN(opts.ASN)
	}
	return c, nil
}

func orDur(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}
func orInt(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}
func orFloat(f, def float64) float64 {
	if f <= 0 {
		return def
	}
	return f
}

// Rules returns the rule set in use.
func (c *Classifier) Rules() *RuleSet { return c.rs }

// SetResolver sets (or, with nil, clears) the client-IP-to-device mapping.
func (c *Classifier) SetResolver(fn func(clientIP string) string) {
	if fn == nil {
		c.resolver.Store(nil)
		return
	}
	c.resolver.Store(&fn)
}

// SetASN sets (or, with nil, clears) the ASN lookup, for example once the
// monthly database has loaded.
func (c *Classifier) SetASN(fn ASNFunc) {
	if fn == nil {
		c.asnFn.Store(nil)
		return
	}
	c.asnFn.Store(&fn)
}

// UseRegistry resolves client IPs to devices with the registry's lock-free
// scope index, so evidence lands on the right device as soon as the registry
// knows the address.
func (c *Classifier) UseRegistry(r *devices.Registry) {
	c.SetResolver(func(ip string) string {
		id, _ := r.ScopesFor(ip)
		return id
	})
}

// Dropped counts observations discarded because the classifier was busy
// (non-blocking mode only).
func (c *Classifier) Dropped() uint64 { return c.st.dropped.Load() }

// Stats describes the classifier's memory use.
type Stats struct {
	Devices int    // devices with evidence
	Domains int    // retained domains across all devices
	Dropped uint64 // observations dropped under load
}

// Stats returns a snapshot of the table sizes.
func (c *Classifier) Stats() Stats {
	st := Stats{Dropped: c.Dropped()}
	for i := range c.st.shards {
		sh := &c.st.shards[i]
		sh.mu.Lock()
		st.Devices += len(sh.m)
		for _, e := range sh.m {
			st.Domains += len(e.domains)
		}
		sh.mu.Unlock()
	}
	return st
}

// Retained is everything the classifier keeps about one device, for the
// portal's "what do you know about this device" and for the privacy tests.
// There is nothing else: no query log, no timestamps of lookups, no full
// host names, no answer addresses.
type Retained struct {
	Key        string
	Vendor     string
	Randomized bool
	Services   []string
	Domains    []RetainedDomain // registrable domains only, busiest first
	ASNs       []uint32
	Lookups    float64 // decayed number of lookups behind the scores
	LastSeen   time.Time
}

// RetainedDomain is one registrable domain and its decayed lookup count.
type RetainedDomain struct {
	Domain string
	Count  float64
}

// Retained returns what is kept about key.
func (c *Classifier) Retained(key string) (Retained, bool) {
	sh := c.st.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[key]
	if e == nil {
		return Retained{}, false
	}
	e.decay(c.cfg.now(), c.cfg.halfLife)
	r := Retained{Key: e.key, Vendor: e.info.vendor, Randomized: e.info.randomized,
		Services: append([]string(nil), e.info.services...), Lookups: float64(e.lookups), LastSeen: e.last}
	for _, d := range e.domains {
		r.Domains = append(r.Domains, RetainedDomain{d.name, float64(d.count)})
	}
	sort.Slice(r.Domains, func(i, j int) bool { return r.Domains[i].Count > r.Domains[j].Count })
	for _, a := range e.asns {
		r.ASNs = append(r.ASNs, a.num)
	}
	return r, true
}

// Classify scores one device. A device with no evidence is unknown.
func (c *Classifier) Classify(key string) Result {
	sh := c.st.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[key]
	if e == nil {
		r := Result{Type: devices.TypeUnknown, Reasons: []string{"Not enough evidence yet to tell what this is"}}
		r.stable = r.Reasons
		return r
	}
	return c.classify(e, c.cfg.now())
}

// Forget drops everything kept about key.
func (c *Classifier) Forget(key string) {
	sh := c.st.shardFor(key)
	sh.mu.Lock()
	delete(sh.m, key)
	sh.mu.Unlock()
	c.mu.Lock()
	delete(c.assigned, key)
	c.mu.Unlock()
}

// Prune forgets devices not heard from for IdleTTL and returns how many.
func (c *Classifier) Prune() int {
	cutoff := c.cfg.now().Add(-c.cfg.idleTTL)
	n := 0
	for i := range c.st.shards {
		sh := &c.st.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e.last.Before(cutoff) {
				delete(sh.m, k)
				n++
			}
		}
		sh.mu.Unlock()
	}
	return n
}

// Target is what Apply needs from the device registry; *devices.Registry
// satisfies it. A target may also provide FindByIP (to fold evidence kept
// under an IP into the device that now holds it) and Groups (so Suggestions
// skips groups that already exist).
type Target interface {
	List() []devices.Device
	SetGuessedType(id string, typ devices.DeviceType, reason string, confidence float64) (bool, error)
	ClearGuessedType(id string) (bool, error)
}

type ipFinder interface {
	FindByIP(ip string) (devices.Device, bool)
}

type groupLister interface {
	Groups() []devices.Group
}

// Report says what an Apply pass did.
type Report struct {
	Examined int // devices looked at
	Changed  int // guesses written or updated
	Cleared  int // guesses withdrawn
	Skipped  int // devices the user typed themselves
}

// Apply classifies every device in the registry and records the guesses. It
// sets a device's GUESSED type, reason and confidence only when the user has
// not set a type, and a type the user sets always wins and survives every
// later guess. It is idempotent: with no new evidence a second pass changes
// nothing. A change of mind needs real evidence: a device keeps its guess
// until a challenger beats it by the switch margin, and a guess is withdrawn
// only when its own evidence has fallen below the release level while there
// is evidence to judge by. Safe to call from a timer and on demand.
func (c *Classifier) Apply(t Target) Report {
	var rep Report
	list := t.List()
	finder, _ := t.(ipFinder)
	assigned := make(map[string]devices.DeviceType, len(list))
	for _, d := range list {
		rep.Examined++
		c.ObserveDevice(d.ID, d.Vendor, d.Services, d.Randomized())
		c.ObserveNames(d.ID, []string{d.Alias, d.MDNSName, d.Hostname, d.ReverseName}, d.Hints)
		if finder != nil {
			for _, ip := range d.IPs {
				c.fold(ip, d.ID)
			}
		}
		if d.TypeUser {
			rep.Skipped++
			assigned[d.ID] = d.Type
			continue
		}
		res := c.Classify(d.ID)
		set, clear := c.decide(d, res)
		switch {
		case set != "":
			if ok, err := t.SetGuessedType(d.ID, set, res.Summary(), res.Confidence); err == nil && ok {
				rep.Changed++
			}
			assigned[d.ID] = set
		case clear:
			if ok, err := t.ClearGuessedType(d.ID); err == nil && ok {
				rep.Cleared++
			}
			assigned[d.ID] = devices.TypeUnknown
		default:
			assigned[d.ID] = d.Type
		}
	}
	c.mu.Lock()
	c.assigned = assigned
	if g, ok := t.(groupLister); ok {
		c.existing = map[string]bool{}
		for _, grp := range g.Groups() {
			c.existing[strings.ToLower(grp.Name)] = true
		}
	}
	c.mu.Unlock()
	return rep
}

// decide applies the thresholds and hysteresis to a fresh result. It returns
// the type to record, or clear=true to withdraw the current guess, or
// neither to leave things alone.
func (c *Classifier) decide(d devices.Device, res Result) (set devices.DeviceType, clear bool) {
	var incumbent devices.DeviceType
	if d.TypeAuto && !d.TypeUser {
		incumbent = d.Type
	}
	if res.Type != devices.TypeUnknown {
		if incumbent != "" && incumbent != res.Type {
			inc := res.Score(incumbent)
			if inc >= c.release && res.Score(res.Type) < inc+c.margin {
				return "", false // not convincing enough to change its mind
			}
		}
		return res.Type, false
	}
	if incumbent != "" && res.lookups >= minEvidence && res.Score(incumbent) < c.release {
		return "", true
	}
	return "", false
}

// fold moves evidence kept under a bare client IP onto the device that now
// holds that address.
func (c *Classifier) fold(ip, id string) {
	if ip == id {
		return
	}
	src := c.st.shardFor(ip)
	src.mu.Lock()
	e := src.m[ip]
	if e == nil {
		src.mu.Unlock()
		return
	}
	delete(src.m, ip)
	src.mu.Unlock()

	now := c.cfg.now()
	dst := c.st.shardFor(id)
	dst.mu.Lock()
	defer dst.mu.Unlock()
	d := c.st.get(dst, id, now)
	d.decay(now, c.cfg.halfLife)
	e.decay(now, c.cfg.halfLife)
	d.merge(e, c.cfg)
}

func (d *devEvidence) merge(o *devEvidence, cfg *config) {
	d.lookups += o.lookups
	d.matched += o.matched
	d.shared += o.shared
	for i := range d.dom {
		d.dom[i] += o.dom[i]
		d.asn[i] += o.asn[i]
	}
	for i := range d.labelHits {
		d.labelHits[i] += o.labelHits[i]
		d.asnLabelHits[i] += o.asnLabelHits[i]
	}
	for _, x := range o.domains {
		if e := d.touchDomain(x.name, cfg.maxDomains, x.count > 1.5); e != nil {
			e.count += x.count - 1
			e.credit += x.credit
		}
	}
	for _, x := range o.asns {
		if e := d.touchASN(x.num, cfg.maxASNs); e != nil {
			e.count += x.count - 1
			e.credit += x.credit
		}
	}
	if o.last.After(d.last) {
		d.last = o.last
	}
}

// Run applies the classifier to the registry now and then every interval
// until ctx ends, pruning idle devices as it goes.
func (c *Classifier) Run(ctx context.Context, t Target, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Minute
	}
	c.Apply(t)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.Apply(t)
			c.Prune()
		}
	}
}

// Suggestion is a group the portal can offer to create with one click.
type Suggestion struct {
	Name      string               `json:"name"`  // "Cameras"
	Label     string               `json:"label"` // "Cameras (4 devices)"
	Count     int                  `json:"count"` // devices that would join
	DeviceIDs []string             `json:"device_ids"`
	Types     []devices.DeviceType `json:"types"` // the classes folded into the group
}

// Suggestions proposes groups from the classes assigned at the last Apply:
// cameras with doorbells, TVs with streaming boxes, and so on. Groups with
// fewer than MinGroupSize devices are not worth a click, and a group the user
// already has (by name) is not suggested again. Types the user set count the
// same as guessed ones. Unknown devices are never grouped.
func (c *Classifier) Suggestions() []Suggestion {
	c.mu.Lock()
	defer c.mu.Unlock()
	groups := map[string]*Suggestion{}
	var order []string
	for _, cl := range c.rs.classes {
		if _, ok := groups[cl.Group]; !ok {
			groups[cl.Group] = &Suggestion{Name: cl.Group}
			order = append(order, cl.Group)
		}
	}
	groupOf := map[devices.DeviceType]string{}
	for _, cl := range c.rs.classes {
		groupOf[cl.ID] = cl.Group
	}
	ids := make([]string, 0, len(c.assigned))
	for id := range c.assigned {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t := c.assigned[id]
		g, ok := groupOf[t]
		if !ok {
			continue
		}
		s := groups[g]
		s.DeviceIDs = append(s.DeviceIDs, id)
		if !containsType(s.Types, t) {
			s.Types = append(s.Types, t)
		}
	}
	var out []Suggestion
	for _, name := range order {
		s := groups[name]
		s.Count = len(s.DeviceIDs)
		if s.Count < c.minGroup || c.existing[strings.ToLower(name)] {
			continue
		}
		s.Label = fmt.Sprintf("%s (%d %s)", name, s.Count, plural(s.Count, "device", "devices"))
		out = append(out, *s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func containsType(list []devices.DeviceType, t devices.DeviceType) bool {
	for _, x := range list {
		if x == t {
			return true
		}
	}
	return false
}
