// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shepherd/internal/devices"
)

const (
	shardCount = 16
	// domainCreditCap and asnCreditCap bound how many lookups of one
	// registrable domain (or ASN) can count toward a class: a camera
	// heartbeating every ten seconds proves its class once, not a thousand
	// times, and one chatty domain cannot drown out the rest.
	domainCreditCap = 5
	asnCreditCap    = 5
	maxAnswersSeen  = 3  // answer addresses looked up per query
	maxServices     = 16 // mDNS service labels kept per device
	maxNames        = 8  // names and hints kept per device
	decayEvery      = time.Minute
)

// ASNInfo is the network an address belongs to.
type ASNInfo struct {
	Number uint
	Org    string
}

// ASNFunc looks up the network of an address; ok is false when unknown. The
// wiring code adapts geo.ASNLocator to it, so this package does not depend on
// geo (and geo does not depend on the DNS engine that will call us).
type ASNFunc func(netip.Addr) (ASNInfo, bool)

type domEntry struct {
	name          string
	count, credit float32
}

type asnEntry struct {
	num           uint32
	count, credit float32
}

// devInfo is what the registry told us about a device.
type devInfo struct {
	vendor     string
	vrule      *vendorRule
	services   []string // first labels of mDNS service types, lower case
	nameType   devices.DeviceType
	nameReason string
	randomized bool
}

// devEvidence is everything retained about one device. See docs/CLASSIFY.md
// for the retention contract: class scores, a few counters and capped sets,
// never a query history.
type devEvidence struct {
	key     string
	last    time.Time // last observation of any kind
	decayAt time.Time

	lookups float32 // all answered lookups (decayed)
	matched float32 // lookups that matched a domain rule
	shared  float32 // answers on shared CDN, cloud or backbone networks

	dom, asn     vec
	labelHits    [maxLabels]float32
	asnLabelHits [maxLabels]float32

	domains []domEntry
	asns    []asnEntry
	info    devInfo
}

type shard struct {
	mu sync.Mutex
	m  map[string]*devEvidence
}

// store is the sharded, bounded evidence table.
type store struct {
	shards   [shardCount]shard
	perShard int
	rs       *RuleSet
	cfg      *config
	dropped  atomic.Uint64
}

type config struct {
	halfLife   time.Duration
	idleTTL    time.Duration
	maxDomains int
	maxASNs    int
	nonBlock   bool
	now        func() time.Time
}

func newStore(rs *RuleSet, cfg *config, maxDevices int) *store {
	s := &store{rs: rs, cfg: cfg, perShard: max(1, (maxDevices+shardCount-1)/shardCount)}
	for i := range s.shards {
		s.shards[i].m = make(map[string]*devEvidence)
	}
	return s
}

// shardFor hashes a key (FNV-1a, no allocation).
func (s *store) shardFor(key string) *shard {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &s.shards[h%shardCount]
}

// lock takes the shard lock. In non-blocking mode a busy shard means the
// observation is dropped, never waited for.
func (s *store) lock(sh *shard) bool {
	if !s.cfg.nonBlock {
		sh.mu.Lock()
		return true
	}
	if sh.mu.TryLock() {
		return true
	}
	s.dropped.Add(1)
	return false
}

// get returns the entry for key, creating it (and evicting the least
// recently seen entry of a full shard) when absent. The shard lock is held.
func (s *store) get(sh *shard, key string, now time.Time) *devEvidence {
	if e := sh.m[key]; e != nil {
		return e
	}
	if len(sh.m) >= s.perShard {
		var oldest string
		var oldestT time.Time
		first := true
		for k, e := range sh.m {
			if first || e.last.Before(oldestT) {
				oldest, oldestT, first = k, e.last, false
			}
		}
		delete(sh.m, oldest)
	}
	e := &devEvidence{key: strings.Clone(key), last: now, decayAt: now}
	sh.m[e.key] = e
	return e
}

// decay ages the counters by the time since they were last aged. Cheap calls
// (under a minute apart) are skipped so the hot path pays almost nothing.
func (e *devEvidence) decay(now time.Time, halfLife time.Duration) {
	dt := now.Sub(e.decayAt)
	if dt < decayEvery {
		return
	}
	e.decayAt = now
	f := float32(math.Exp2(-float64(dt) / float64(halfLife)))
	e.lookups *= f
	e.matched *= f
	e.shared *= f
	for i := range e.dom {
		e.dom[i] *= f
		e.asn[i] *= f
	}
	for i := range e.labelHits {
		e.labelHits[i] *= f
		e.asnLabelHits[i] *= f
	}
	kept := e.domains[:0]
	for _, d := range e.domains {
		d.count *= f
		d.credit *= f
		if d.count >= 0.2 {
			kept = append(kept, d)
		}
	}
	clear(e.domains[len(kept):]) // let dropped names be collected
	e.domains = kept
	keptA := e.asns[:0]
	for _, a := range e.asns {
		a.count *= f
		a.credit *= f
		if a.count >= 0.2 {
			keptA = append(keptA, a)
		}
	}
	e.asns = keptA
}

// asnHit is one answer address resolved to a network, computed before any
// lock is taken.
type asnHit struct {
	num    uint32
	shared bool
	label  int
	w      *vec
}

// Observe records that clientIP asked for qname and was answered with
// answers. The DNS engine calls it for every answered query, so it is built
// to be cheap: it allocates nothing for a name it has seen before, touches
// one of sixteen locks, does a bounded amount of work, and in NonBlocking
// mode drops the observation instead of waiting if that lock is busy.
func (c *Classifier) Observe(clientIP, qname string, answers []net.IP) {
	host := lowerTrim(qname)
	if clientIP == "" || !observable(host) {
		return
	}
	reg := registrable(host)
	if reg == "" {
		return
	}
	key := clientIP
	if r := c.resolver.Load(); r != nil {
		if id := (*r)(clientIP); id != "" {
			key = id
		}
	}
	rule := c.rs.matchDomain(host)

	var hits [maxAnswersSeen]asnHit
	nh := 0
	if f := c.asnFn.Load(); f != nil {
		if len(answers) > maxAnswersSeen {
			answers = answers[:maxAnswersSeen] // bounded work per query
		}
		for _, ip := range answers {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			info, ok := (*f)(addr.Unmap())
			if !ok || info.Number == 0 || info.Number > math.MaxUint32 {
				continue
			}
			dup := false
			for _, h := range hits[:nh] {
				dup = dup || h.num == uint32(info.Number)
			}
			if dup {
				continue
			}
			h := asnHit{num: uint32(info.Number)}
			if r, ok := c.rs.asns[info.Number]; ok {
				h.shared, h.label, h.w = r.Shared, r.LabelIdx, &r.W
			} else if r := c.rs.matchOrg(info.Org); r != nil {
				h.shared, h.label, h.w = r.Shared, r.LabelIdx, &r.W
			}
			hits[nh] = h
			nh++
		}
	}

	now := c.cfg.now()
	sh := c.st.shardFor(key)
	if !c.st.lock(sh) {
		return
	}
	defer sh.mu.Unlock()
	e := c.st.get(sh, key, now)
	e.decay(now, c.cfg.halfLife)
	e.last = now
	e.lookups++

	if rule != nil {
		e.matched++
		e.labelHits[rule.LabelIdx]++
	}
	// A recognised domain always earns a place in the capped set (it is the
	// evidence); an unrecognised one only if there is room or the entry it
	// would replace is a one-off.
	de := e.touchDomain(reg, c.cfg.maxDomains, rule != nil)
	if rule != nil && de.credit < domainCreditCap {
		de.credit++
		for i, w := range rule.W {
			e.dom[i] += w
		}
	}
	for _, h := range hits[:nh] {
		ae := e.touchASN(h.num, c.cfg.maxASNs)
		if h.shared {
			e.shared++
			continue
		}
		if h.w == nil || ae == nil || ae.credit >= asnCreditCap {
			continue
		}
		ae.credit++
		e.asnLabelHits[h.label]++
		for i, w := range h.w {
			e.asn[i] += w
		}
	}
}

// touchDomain counts a lookup of reg in the capped set. It returns the entry,
// or nil when the set is full of better-established domains and force is not
// set.
func (e *devEvidence) touchDomain(reg string, limit int, force bool) *domEntry {
	for i := range e.domains {
		if e.domains[i].name == reg {
			e.domains[i].count++
			return &e.domains[i]
		}
	}
	if len(e.domains) < limit {
		e.domains = append(e.domains, domEntry{name: strings.Clone(reg), count: 1})
		return &e.domains[len(e.domains)-1]
	}
	// Full: a newcomer only displaces an entry that is itself just a
	// one-off, so a flood of random names cannot push out what the device
	// really talks to.
	lowest := 0
	for i := range e.domains {
		if e.domains[i].count < e.domains[lowest].count {
			lowest = i
		}
	}
	if e.domains[lowest].count > 1.5 && !force {
		return nil
	}
	e.domains[lowest] = domEntry{name: strings.Clone(reg), count: 1}
	return &e.domains[lowest]
}

func (e *devEvidence) touchASN(num uint32, limit int) *asnEntry {
	for i := range e.asns {
		if e.asns[i].num == num {
			e.asns[i].count++
			return &e.asns[i]
		}
	}
	if len(e.asns) < limit {
		e.asns = append(e.asns, asnEntry{num: num, count: 1})
		return &e.asns[len(e.asns)-1]
	}
	lowest := 0
	for i := range e.asns {
		if e.asns[i].count < e.asns[lowest].count {
			lowest = i
		}
	}
	if e.asns[lowest].count > 1.5 {
		return nil
	}
	e.asns[lowest] = asnEntry{num: num, count: 1}
	return &e.asns[lowest]
}

// ObserveDevice tells the classifier what the registry knows about a device:
// its manufacturer (from the MAC prefix), the mDNS service types it
// advertises, and whether its MAC address is randomized (a private address,
// whose prefix says nothing about the manufacturer, so the vendor is then
// ignored). key is the device ID or MAC; it must be the key Observe resolves
// to, which Apply arranges.
func (c *Classifier) ObserveDevice(key, vendor string, services []string, randomized bool) {
	if key == "" {
		return
	}
	now := c.cfg.now()
	sh := c.st.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := c.st.get(sh, key, now)
	e.last = now
	e.info.vendor = strings.TrimSpace(vendor)
	e.info.vrule = nil
	if e.info.vendor != "" {
		e.info.vrule = c.rs.matchVendor(e.info.vendor)
	}
	e.info.randomized = randomized
	e.info.services = e.info.services[:0]
	for _, s := range services {
		l := strings.ToLower(strings.SplitN(strings.TrimPrefix(strings.TrimSpace(s), "."), ".", 2)[0])
		if l == "" || len(e.info.services) >= maxServices || containsStr(e.info.services, l) {
			continue
		}
		e.info.services = append(e.info.services, l)
	}
}

// ObserveNames gives the classifier a device's names and model strings (alias,
// mDNS name, hostname, reverse name, hints). A name like "front-door-camera"
// is strong evidence; the registry's keyword table decides what counts.
func (c *Classifier) ObserveNames(key string, names, hints []string) {
	if key == "" {
		return
	}
	var clean []string
	for _, group := range [][]string{hints, names} {
		for _, n := range group {
			if n = strings.TrimSpace(n); n != "" && len(clean) < maxNames {
				clean = append(clean, n)
			}
		}
	}
	t, why := devices.GuessType(devices.Evidence{Names: clean})
	now := c.cfg.now()
	sh := c.st.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := c.st.get(sh, key, now)
	e.last = now
	e.info.nameType, e.info.nameReason = t, why
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// lowerTrim lower-cases a host name and drops a trailing dot, without
// allocating when it is already lower case.
func lowerTrim(s string) string {
	s = strings.TrimSuffix(s, ".")
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}

// observable filters names that say nothing about the device: reverse
// lookups, local names and single labels.
func observable(host string) bool {
	if len(host) < 3 || len(host) > 253 || strings.IndexByte(host, '.') < 0 {
		return false
	}
	i := strings.LastIndexByte(host, '.')
	switch host[i+1:] {
	case "arpa", "local", "lan", "localdomain", "internal", "home", "invalid", "localhost":
		return false
	}
	return true
}
