// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
)

// PolicyPrivateRelay makes the resolver answer NXDOMAIN for the hostnames
// Apple devices use to reach iCloud Private Relay, which is Apple's documented
// way for a network to signal that it does not allow the relay.
const PolicyPrivateRelay = "apple-private-relay"

var policyDomains = map[string][]string{
	PolicyPrivateRelay: {"mask.icloud.com", "mask-h2.icloud.com", "mask-api.icloud.com"},
}

// KnownPolicies lists every built-in policy name.
func KnownPolicies() []string {
	out := make([]string, 0, len(policyDomains))
	for k := range policyDomains {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

type rulesFile struct {
	Allow    []string        `json:"allow"`
	Block    []string        `json:"block"`
	Policies map[string]bool `json:"policies"`
}

// Rules are the user's allow and block rules and policy switches, persisted
// to one JSON file and applied to the Filter.
type Rules struct {
	path   string
	filter *Filter
	mu     sync.Mutex
	data   rulesFile
}

// LoadRules reads path (a missing file is fine) and applies it. defaults sets
// policies the file does not mention yet.
func LoadRules(path string, f *Filter, defaults map[string]bool) (*Rules, error) {
	r := &Rules{path: path, filter: f}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &r.data); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	if r.data.Policies == nil {
		r.data.Policies = map[string]bool{}
	}
	for name := range policyDomains {
		if _, set := r.data.Policies[name]; !set {
			r.data.Policies[name] = defaults[name]
		}
	}
	r.applyLocked()
	return r, nil
}

func (r *Rules) applyLocked() {
	r.filter.SetRules(r.data.Allow, r.data.Block)
	for name, domains := range policyDomains {
		if r.data.Policies[name] {
			r.filter.SetPolicy(name, domains)
		} else {
			r.filter.SetPolicy(name, nil)
		}
	}
}

func (r *Rules) saveLocked() error {
	b, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

func (r *Rules) commitLocked() error {
	r.applyLocked()
	return r.saveLocked()
}

func (r *Rules) Snapshot() (allow, block []string, policies map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	policies = make(map[string]bool, len(r.data.Policies))
	for k, v := range r.data.Policies {
		policies[k] = v
	}
	return slices.Clone(r.data.Allow), slices.Clone(r.data.Block), policies
}

func (r *Rules) lists(kind string) (*[]string, *[]string, error) {
	switch kind {
	case "allow":
		return &r.data.Allow, &r.data.Block, nil
	case "block":
		return &r.data.Block, &r.data.Allow, nil
	}
	return nil, nil, fmt.Errorf("rule kind must be \"allow\" or \"block\", got %q", kind)
}

// Add puts domain on the kind list, removing it from the opposite one.
func (r *Rules) Add(kind, domain string) error {
	domain = normalize(domain)
	if !ValidDomain(domain) {
		return fmt.Errorf("%q is not a valid domain", domain)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	same, other, err := r.lists(kind)
	if err != nil {
		return err
	}
	*other = slices.DeleteFunc(*other, func(d string) bool { return d == domain })
	if !slices.Contains(*same, domain) {
		*same = append(*same, domain)
		slices.Sort(*same)
	}
	return r.commitLocked()
}

func (r *Rules) Remove(kind, domain string) error {
	domain = normalize(domain)
	r.mu.Lock()
	defer r.mu.Unlock()
	same, _, err := r.lists(kind)
	if err != nil {
		return err
	}
	*same = slices.DeleteFunc(*same, func(d string) bool { return d == domain })
	return r.commitLocked()
}

// SetPolicy switches a built-in policy on or off.
func (r *Rules) SetPolicy(name string, on bool) error {
	if _, ok := policyDomains[name]; !ok {
		return fmt.Errorf("unknown policy %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data.Policies[name] = on
	return r.commitLocked()
}
