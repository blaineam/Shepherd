// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dnsengine is Shepherd's DNS filtering resolver: blocklist matching,
// upstream health probing with failover, a TTL cache and a query log.
package dnsengine

import (
	"sort"
	"strings"
	"sync"
)

// Decision is the outcome of checking a name against the filter.
type Decision struct {
	Blocked bool
	// Reason names the matching list, "custom rule", "allowlist", or a policy.
	Reason string
	// NXDOMAIN is set for policy blocks that must answer NXDOMAIN, not 0.0.0.0.
	NXDOMAIN bool
}

// Filter matches names and all their parent domains against blocklists and
// user rules. Allow rules win over every block source.
type Filter struct {
	mu        sync.RWMutex
	lists     map[string]map[string]struct{}
	listNames []string
	listed    map[string]uint16 // domain -> index into listNames
	allow     map[string]struct{}
	block     map[string]struct{}
	policies  map[string][]string // policy label -> domains
	policy    map[string]string   // domain -> policy label
}

func NewFilter() *Filter {
	return &Filter{
		lists:    map[string]map[string]struct{}{},
		listed:   map[string]uint16{},
		allow:    map[string]struct{}{},
		block:    map[string]struct{}{},
		policies: map[string][]string{},
		policy:   map[string]string{},
	}
}

// SetPolicy enables a built-in policy for domains (and their subdomains), or
// disables it when domains is empty. Policy blocks answer NXDOMAIN.
func (f *Filter) SetPolicy(label string, domains []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(domains) == 0 {
		delete(f.policies, label)
	} else {
		f.policies[label] = domains
	}
	f.policy = map[string]string{}
	for l, ds := range f.policies {
		for _, d := range ds {
			f.policy[normalize(d)] = l
		}
	}
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// walk calls fn with name, then each parent that still has two or more labels,
// stopping when fn returns true. Single-label parents (TLDs) are never matched.
func walk(name string, fn func(string) bool) {
	for {
		if fn(name) {
			return
		}
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

// Check reports whether name should be blocked.
func (f *Filter) Check(name string) Decision {
	name = normalize(name)
	f.mu.RLock()
	defer f.mu.RUnlock()

	var d Decision
	walk(name, func(s string) bool {
		if _, ok := f.allow[s]; ok {
			d = Decision{Reason: "allowlist"}
			return true
		}
		return false
	})
	if d.Reason != "" {
		return d
	}
	walk(name, func(s string) bool {
		if label, ok := f.policy[s]; ok {
			d = Decision{Blocked: true, Reason: label, NXDOMAIN: true}
			return true
		}
		if _, ok := f.block[s]; ok {
			d = Decision{Blocked: true, Reason: "custom rule"}
			return true
		}
		if i, ok := f.listed[s]; ok {
			d = Decision{Blocked: true, Reason: f.listNames[i]}
			return true
		}
		return false
	})
	return d
}

// SetList replaces one named blocklist. A nil set removes it.
func (f *Filter) SetList(name string, set map[string]struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if set == nil {
		delete(f.lists, name)
	} else {
		f.lists[name] = set
	}
	names := make([]string, 0, len(f.lists))
	for n := range f.lists {
		names = append(names, n)
	}
	sort.Strings(names)
	listed := make(map[string]uint16)
	for i, n := range names {
		for d := range f.lists[n] {
			if _, dup := listed[d]; !dup {
				listed[d] = uint16(i)
			}
		}
	}
	f.listNames, f.listed = names, listed
}

// SetRules replaces the user allow and block rules.
func (f *Filter) SetRules(allow, block []string) {
	a := make(map[string]struct{}, len(allow))
	for _, d := range allow {
		a[normalize(d)] = struct{}{}
	}
	b := make(map[string]struct{}, len(block))
	for _, d := range block {
		b[normalize(d)] = struct{}{}
	}
	f.mu.Lock()
	f.allow, f.block = a, b
	f.mu.Unlock()
}

// Counts returns the number of listed domains and user rules.
func (f *Filter) Counts() (listed, allow, block int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.listed), len(f.allow), len(f.block)
}
