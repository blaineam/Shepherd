// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScopeKind is how widely a set of settings applies.
type ScopeKind string

const (
	ScopeNetwork ScopeKind = "network"
	ScopeGroup   ScopeKind = "group"
	ScopeDevice  ScopeKind = "device"
)

// Scope names where a setting lives. Specificity grows network < group < device.
type Scope struct {
	Kind ScopeKind
	ID   string // empty for the network
}

func NetworkScope() Scope         { return Scope{Kind: ScopeNetwork} }
func GroupScope(id string) Scope  { return Scope{Kind: ScopeGroup, ID: id} }
func DeviceScope(id string) Scope { return Scope{Kind: ScopeDevice, ID: id} }
func (s Scope) level() int {
	return map[ScopeKind]int{ScopeNetwork: 0, ScopeGroup: 1, ScopeDevice: 2}[s.Kind]
}
func (s Scope) String() string {
	if s.Kind == ScopeNetwork {
		return string(ScopeNetwork)
	}
	return string(s.Kind) + ":" + s.ID
}

// ParseScope is the inverse of Scope.String.
func ParseScope(s string) (Scope, error) {
	if s == string(ScopeNetwork) {
		return NetworkScope(), nil
	}
	kind, id, ok := strings.Cut(s, ":")
	sc := Scope{Kind: ScopeKind(kind), ID: id}
	if !ok || (sc.Kind != ScopeGroup && sc.Kind != ScopeDevice) || !validScopeID(id) {
		return Scope{}, fmt.Errorf("invalid scope %q: want \"network\", \"group:<id>\" or \"device:<id>\"", s)
	}
	return sc, nil
}

func validScopeID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

// ClientScopes is implemented by the devices registry. ScopesFor maps a
// client address to its device ID and the IDs of the groups it belongs to; an
// unknown client returns "" and nil and gets network scope only. It runs on
// every query, so it must be fast and safe for concurrent use.
type ClientScopes interface {
	ScopesFor(clientIP string) (deviceID string, groupIDs []string)
}

// ScopeConfig is what one scope switches on and off. Items holds list item IDs
// (leaf items; the PolicyStore expands apps and categories): true enables the
// item at this scope, false opts out of it here and below. Policies work the
// same way for built-in policy switches.
//
// Mode is this scope's own block/allow default ("" means inherit; see
// effectiveMode). AllowSchedules and BlockSchedules optionally limit when a
// domain in Allow or Block applies; a domain absent from the map always
// applies when it matches. A domain's entry is meaningless unless that same
// domain is also in Allow or Block.
type ScopeConfig struct {
	Items          map[string]bool
	Policies       map[string]bool
	Allow          []string
	Block          []string
	Mode           Mode
	AllowSchedules map[string]Schedule
	BlockSchedules map[string]Schedule
}

// Mode is a scope's default action for a name nothing else decides. "block"
// (the zero value behaves the same way) leaves a name that matches no item,
// policy, list or rule unblocked. "allow" inverts that default: a name that
// matches no item, policy, list or rule is blocked instead. See
// docs/POLICY.md's "Allowlist mode".
type Mode string

const (
	ModeBlock Mode = "block"
	ModeAllow Mode = "allow"
)

func (m Mode) valid() bool { return m == "" || m == ModeBlock || m == ModeAllow }

func ruleItem(kind string, s Scope) string { return kind + ":" + s.String() }

type atomicPolicy = atomic.Pointer[policyState]

// policyState is an immutable snapshot of the scope configuration plus the
// cache of effective masks derived from it. A configuration change swaps in
// a new snapshot, which drops the cache.
type policyState struct {
	configured     bool
	scopes         map[string]ScopeConfig
	legacyPolicies map[string]bool

	cache sync.Map // sigKey -> *effective
	n     atomic.Int32
}

func (p *policyState) clone() *policyState {
	return &policyState{configured: p.configured, scopes: p.scopes, legacyPolicies: maps.Clone(p.legacyPolicies)}
}

// maxCachedSignatures bounds the effective-mask cache. Real installs have one
// signature per device at most; the bound only guards against a misbehaving
// ClientScopes inventing IDs.
const maxCachedSignatures = 8192

// SetScopes replaces the whole scoped configuration, keyed by Scope.String(),
// and switches the filter out of legacy mode. Rule sets for scopes that
// disappeared are dropped.
func (f *Filter) SetScopes(cfgs map[string]ScopeConfig) {
	f.pmu.Lock()
	defer f.pmu.Unlock()
	sets := map[string]map[string]struct{}{}
	for name := range f.rules.load().bits {
		if strings.HasPrefix(name, "allow:") || strings.HasPrefix(name, "block:") {
			sets[name] = nil
		}
	}
	for key, c := range cfgs {
		sets["allow:"+key] = domainSet(c.Allow)
		sets["block:"+key] = domainSet(c.Block)
	}
	for name, domains := range policyDomains {
		if _, ok := f.rules.load().bits[policyItem(name)]; !ok {
			sets[policyItem(name)] = domainSet(domains)
		}
	}
	f.rules.setMany(sets)
	f.pol.Store(&policyState{configured: true, scopes: maps.Clone(cfgs), legacyPolicies: map[string]bool{}})
}

// sigKey identifies a distinct (device, groups) combination without
// allocating in the common cases of zero or one group.
type sigKey struct{ dev, g0, rest string }

func makeSigKey(dev string, groups []string) sigKey {
	k := sigKey{dev: dev}
	if len(groups) > 0 {
		k.g0 = groups[0]
		if len(groups) > 1 {
			k.rest = strings.Join(groups[1:], "\x00")
		}
	}
	return k
}

// effScope is one scope's precomputed contribution for a signature.
type effScope struct {
	key    string
	level  int
	list   []uint64 // list items that block here, after opt-outs from more specific scopes
	policy []uint64 // policy items that block here, after opt-outs
	block  []uint64 // this scope's own block-rule item (coarse: any of its domains)
	allow  []uint64 // this scope's own allow-rule item (coarse: any of its domains)
	// blockRule and allowRule narrow block/allow to the specific domain that
	// matched, and apply its schedule, if it has one. Nil when the scope has
	// no rules of that kind.
	blockRule, allowRule *ruleSet
}

// effective holds the scopes that apply to one signature, most specific
// first, plus the effective Mode for this signature (most-specific-set-wins;
// ModeBlock when nothing set one, which is today's only behavior).
type effective struct {
	listVer, ruleVer uint64
	scopes           []effScope
	mode             Mode
	modeScope        string // the scope that set mode; "" when mode is the default
}

func (p *policyState) effectiveFor(dev string, groups []string, li, ri *indexState) *effective {
	key := makeSigKey(dev, groups)
	if v, ok := p.cache.Load(key); ok {
		if e := v.(*effective); e.listVer == li.ver && e.ruleVer == ri.ver {
			return e
		}
	}
	e := p.compute(dev, groups, li, ri)
	if p.n.Load() < maxCachedSignatures {
		if _, replaced := p.cache.Swap(key, e); !replaced {
			p.n.Add(1)
		}
	}
	return e
}

type rawScope struct {
	sc                             Scope
	listOn, listOff, polOn, polOff []uint64
	allow, block                   []uint64
	allowRule, blockRule           *ruleSet
}

func (p *policyState) compute(dev string, groups []string, li, ri *indexState) *effective {
	order := make([]Scope, 0, len(groups)+2)
	if dev != "" {
		order = append(order, DeviceScope(dev))
	}
	for _, g := range groups {
		order = append(order, GroupScope(g))
	}
	order = append(order, NetworkScope())

	mode, modeScope := ModeBlock, ""
	var raws []rawScope
	for _, sc := range order {
		r := rawScope{sc: sc}
		if !p.configured {
			if sc.Kind != ScopeNetwork {
				continue
			}
			for b, n := range li.names {
				if n != "" {
					r.listOn = setBitIn(r.listOn, b)
				}
			}
			pol := make([]string, 0, len(p.legacyPolicies))
			for name := range p.legacyPolicies {
				pol = append(pol, policyItem(name))
			}
			r.polOn = ri.maskOf(pol)
		} else {
			c, ok := p.scopes[sc.String()]
			if !ok {
				continue
			}
			r.listOn, r.listOff = splitMask(li, c.Items, "")
			r.polOn, r.polOff = splitMask(ri, c.Policies, "policy:")
			r.allowRule = newRuleSet(c.Allow, c.AllowSchedules)
			r.blockRule = newRuleSet(c.Block, c.BlockSchedules)
			// The effective Mode is the most specific scope's own explicit
			// choice, exactly the same most-specific-wins lookup compute()
			// already walks order for everything else; an unset scope (""
			// here, or no entry at all for this scope) falls through to the
			// next less specific one, and ModeBlock when none ever sets it.
			if modeScope == "" && c.Mode != "" {
				mode, modeScope = c.Mode, sc.String()
			}
		}
		r.allow = ri.maskOf([]string{ruleItem("allow", sc)})
		r.block = ri.maskOf([]string{ruleItem("block", sc)})
		raws = append(raws, r)
	}

	e := &effective{listVer: li.ver, ruleVer: ri.ver, mode: mode, modeScope: modeScope}
	for _, r := range raws {
		es := effScope{key: r.sc.String(), level: r.sc.level(), list: r.listOn, policy: r.polOn,
			block: r.block, allow: r.allow, blockRule: r.blockRule, allowRule: r.allowRule}
		for _, o := range raws {
			if o.sc.level() > es.level { // opt-outs only reach less specific scopes
				es.list = clearBitsIn(es.list, o.listOff)
				es.policy = clearBitsIn(es.policy, o.polOff)
			}
		}
		e.scopes = append(e.scopes, es)
	}
	return e
}

// splitMask turns an on/off map into masks over idx's item bits.
func splitMask(idx *indexState, m map[string]bool, prefix string) (on, off []uint64) {
	for name, v := range m {
		b, ok := idx.bits[prefix+name]
		if !ok {
			continue
		}
		if v {
			on = setBitIn(on, b)
		} else {
			off = setBitIn(off, b)
		}
	}
	return on, off
}

// CheckFor decides name for the client behind clientIP. Blocks union across
// the client's scopes. An allow rule at a more specific scope, or at the same
// scope, overrides a block from a less specific one; allows at sibling groups
// do not cancel each other's blocks. When the effective Mode (see
// docs/POLICY.md's "Allowlist mode") is "allow", a catalog or custom item
// switched on at a scope is that scope's allowlist instead of its blocklist,
// and a name nothing decides is blocked instead of let through. Built-in
// policy switches always block, in both modes. cs may be nil (network scope
// only).
func (f *Filter) CheckFor(clientIP, name string, cs ClientScopes) Decision {
	name = normalize(name)
	var dev string
	var groups []string
	if cs != nil {
		dev, groups = cs.ScopesFor(clientIP)
	}
	li, ri := f.lists.load(), f.rules.load()
	e := f.pol.Load().effectiveFor(dev, groups, li, ri)
	var lb, rb [4]uint64
	hl, hr := li.match(name, lb[:0]), ri.match(name, rb[:0])
	if len(hl) == 0 && len(hr) == 0 {
		return e.defaultDecision()
	}
	return e.decide(li, ri, hl, hr, name, f.now())
}

// defaultDecision is what CheckFor returns when nothing in any index even
// mentions name: not blocked, unless the effective mode is "allow".
func (e *effective) defaultDecision() Decision {
	if e.mode == ModeAllow {
		return Decision{Blocked: true, Reason: "default deny: allowlist mode", Scope: e.modeScope}
	}
	return Decision{}
}

func (e *effective) decide(li, ri *indexState, hl, hr []uint64, name string, now time.Time) Decision {
	// In allow mode an item (catalog or custom list) switched on at a scope
	// is that scope's allowlist, not its blocklist; ruleAllow and itemAllow
	// are tracked apart only to report which one matched. Both are computed
	// once: decide() needs them both to find the most specific allow (below)
	// and to skip a scope they override (in the main loop), and
	// activeRuleMatch walks name's ancestors, so it is worth not repeating
	// per scope.
	listAllows := e.mode == ModeAllow
	ruleAllow := make([]bool, len(e.scopes))
	itemAllow := make([]bool, len(e.scopes))
	maxAllow, allowAt := -1, -1
	for i, s := range e.scopes {
		ruleAllow[i] = intersects(hr, s.allow) && activeRuleMatch(s.allowRule, name, now)
		itemAllow[i] = listAllows && intersects(hl, s.list)
		if ruleAllow[i] || itemAllow[i] {
			if allowAt < 0 {
				allowAt = i
			}
			maxAllow = max(maxAllow, s.level)
		}
	}
	for i, s := range e.scopes {
		if maxAllow > s.level || ruleAllow[i] || itemAllow[i] {
			continue // overridden by an allow (rule, or in allow mode an item) here or at a more specific scope
		}
		if intersects(hr, s.policy) { // policies always block, in both modes
			names := ri.commonNames(hr, s.policy)
			return Decision{Blocked: true, Reason: strings.TrimPrefix(slices.Min(names), "policy:"), NXDOMAIN: true, Scope: s.key}
		}
		if intersects(hr, s.block) && activeRuleMatch(s.blockRule, name, now) {
			return Decision{Blocked: true, Reason: "custom rule", Scope: s.key}
		}
		if !listAllows && intersects(hl, s.list) {
			return Decision{Blocked: true, Reason: slices.Min(li.commonNames(hl, s.list)), Scope: s.key}
		}
	}
	if allowAt >= 0 {
		reason := "allowlist"
		if !ruleAllow[allowAt] && itemAllow[allowAt] {
			reason = slices.Min(li.commonNames(hl, e.scopes[allowAt].list))
		}
		return Decision{Reason: reason, Scope: e.scopes[allowAt].key}
	}
	return e.defaultDecision()
}
