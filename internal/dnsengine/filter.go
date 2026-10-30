// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dnsengine is Shepherd's DNS filtering resolver: blocklist matching,
// upstream health probing with failover, a TTL cache and a query log.
package dnsengine

import (
	"slices"
	"strings"
	"sync"
)

// Decision is the outcome of checking a name against the filter.
type Decision struct {
	Blocked bool
	// Reason names what matched: a catalog or custom list ID, "custom rule",
	// "allowlist", or a policy name.
	Reason string
	// NXDOMAIN is set for policy blocks that must answer NXDOMAIN, not 0.0.0.0.
	NXDOMAIN bool
	// Scope says where the decision was made: "network", "group:<id>" or
	// "device:<id>". Empty when nothing matched.
	Scope string
}

// Filter matches names and all their parent domains against blocklists, user
// rules and policies, per scope (network, group, device).
//
// Blocklists and rules live in two membership bitset indexes (see index.go),
// so one domain can belong to many items. Which items apply to a client is a
// precomputed mask per distinct (device, groups) signature (see policy.go).
//
// Until SetScopes is called the filter runs in legacy mode: every loaded list
// applies network wide, and SetRules and SetPolicy edit the network scope.
type Filter struct {
	lists *memberIndex // catalog and custom list items
	rules *memberIndex // "allow:<scope>", "block:<scope>" and "policy:<name>" items

	pmu sync.Mutex // serialises writers of pol
	pol atomicPolicy
}

// NewFilter returns an empty filter in legacy mode.
func NewFilter() *Filter {
	f := &Filter{lists: newMemberIndex(), rules: newMemberIndex()}
	f.pol.Store(&policyState{legacyPolicies: map[string]bool{}})
	f.loadKnownPolicies()
	return f
}

func (f *Filter) loadKnownPolicies() {
	sets := map[string]map[string]struct{}{}
	for name, domains := range policyDomains {
		if _, ok := f.rules.load().bits[policyItem(name)]; !ok {
			sets[policyItem(name)] = domainSet(domains)
		}
	}
	if len(sets) > 0 {
		f.rules.setMany(sets)
	}
}

func policyItem(name string) string { return "policy:" + name }

func domainSet(domains []string) map[string]struct{} {
	if len(domains) == 0 {
		return nil
	}
	s := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		s[normalize(d)] = struct{}{}
	}
	return s
}

// SetPolicy enables a built-in policy for domains (and their subdomains), or
// disables it when domains is empty. Policy blocks answer NXDOMAIN. This is
// the legacy network-wide switch; it is ignored once SetScopes has been used.
func (f *Filter) SetPolicy(label string, domains []string) {
	f.pmu.Lock()
	defer f.pmu.Unlock()
	old := f.pol.Load()
	if old.configured {
		return
	}
	f.rules.set(policyItem(label), domainSet(domains))
	next := old.clone()
	if len(domains) == 0 {
		delete(next.legacyPolicies, label)
	} else {
		next.legacyPolicies[label] = true
	}
	f.pol.Store(next)
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// walk calls fn with name, then each parent that still has two or more labels.
// Single-label parents (TLDs) are never visited.
func walk(name string, fn func(string)) {
	for {
		fn(name)
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return
		}
		name = name[i+1:]
		if !strings.Contains(name, ".") {
			return
		}
	}
}

// Check reports whether name should be blocked network wide.
func (f *Filter) Check(name string) Decision { return f.CheckFor("", name, nil) }

// ItemsFor returns the IDs of every loaded list item that contains name or
// any of its parent domains, sorted. It ignores scopes: it answers "what
// would match", not "what is enabled".
func (f *Filter) ItemsFor(name string) []string {
	li := f.lists.load()
	var buf [4]uint64
	hit := li.match(normalize(name), buf[:0])
	out := li.commonNames(hit, hit)
	slices.Sort(out)
	return out
}

// SetList replaces one named blocklist item. A nil set removes it.
func (f *Filter) SetList(name string, set map[string]struct{}) { f.lists.set(name, set) }

// SetRules replaces the network scope's allow and block rules. This is the
// legacy entry point; it is ignored once SetScopes has been used.
func (f *Filter) SetRules(allow, block []string) {
	f.pmu.Lock()
	defer f.pmu.Unlock()
	if f.pol.Load().configured {
		return
	}
	f.rules.setMany(map[string]map[string]struct{}{
		ruleItem("allow", NetworkScope()): domainSet(allow),
		ruleItem("block", NetworkScope()): domainSet(block),
	})
}

// Counts returns the number of listed domains and network scope rules.
func (f *Filter) Counts() (listed, allow, block int) {
	ri := f.rules.load()
	return len(f.lists.load().dom), ri.size[ruleItem("allow", NetworkScope())], ri.size[ruleItem("block", NetworkScope())]
}

// ItemSize returns how many domains the named list item holds, and whether
// it is loaded.
func (f *Filter) ItemSize(name string) (int, bool) {
	st := f.lists.load()
	_, ok := st.bits[name]
	return st.size[name], ok
}
