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
// way for a network to signal that it does not allow the relay. Only the two
// names Apple documents belong here: Siri looks up mask-api.icloud.com on
// every request, so a broader list can break more than the relay.
const PolicyPrivateRelay = "apple-private-relay"

// PolicyDoHCanary answers NXDOMAIN for use-application-dns.net, the canary
// name a browser looks up before it switches itself to DNS over HTTPS. A
// negative answer is the documented way for a network to say "keep using
// the resolver you were given", so the browser's lookups stay where the
// blocklists and the history can see them. It breaks nothing: the name
// exists only to be asked about. On by default. See docs/DETECT.md.
const PolicyDoHCanary = "doh-canary"

// PolicyEncryptedDNS answers NXDOMAIN for the host names of the well-known
// public encrypted-DNS resolvers (EncryptedDNSResolvers), so an app or a
// device set to use one by name cannot find it and falls back to the
// network's resolver. Off by default: a phone whose owner set a private DNS
// provider by name in strict mode loses its lookups entirely until that
// setting is cleared, which is the owner's call to make. It does nothing
// about a device that reaches a resolver by address. See docs/DETECT.md.
const PolicyEncryptedDNS = "encrypted-dns"

// encryptedDNSResolvers are the host names of public resolvers that answer
// DNS over HTTPS or TLS. A name here also covers its subdomains. The list
// is short on purpose: the providers a browser, a phone's private-DNS
// setting or an app actually ships with, not every resolver that exists.
var encryptedDNSResolvers = []string{
	"dns.google", "dns64.dns.google",
	"cloudflare-dns.com", "one.one.one.one",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	"doh.opendns.com", "dns.opendns.com", "dns.umbrella.com",
	"dns.adguard-dns.com", "dns.adguard.com", "dns-family.adguard.com", "dns-unfiltered.adguard.com",
	"unfiltered.adguard-dns.com", "family.adguard-dns.com",
	"dns.nextdns.io",
	"doh.cleanbrowsing.org",
	"dns.mullvad.net", "doh.mullvad.net",
	"dns.controld.com", "freedns.controld.com",
	"doh.dns.sb", "dns.sb",
	"doh.libredns.gr",
	"dns.alidns.com", "doh.pub", "dot.pub", "doh.360.cn",
	"dns.switch.ch",
	"doh.xfinity.com", "dot.xfinity.com",
}

// EncryptedDNSResolvers returns the resolver names PolicyEncryptedDNS
// covers, for the detector that reports a device looking one up
// (internal/detect).
func EncryptedDNSResolvers() []string { return slices.Clone(encryptedDNSResolvers) }

var policyDomains = map[string][]string{
	PolicyPrivateRelay: {"mask.icloud.com", "mask-h2.icloud.com"},
	PolicyDoHCanary:    {"use-application-dns.net"},
	PolicyEncryptedDNS: encryptedDNSResolvers,
}

// policyDefaults is what a policy is at network scope when the owner has
// never chosen: on a fresh install, and on an existing one the first time
// it runs a version that knows the policy.
var policyDefaults = map[string]bool{
	PolicyPrivateRelay: true,
	PolicyDoHCanary:    true,
	PolicyEncryptedDNS: false,
}

// fillPolicyDefaults gives every built-in policy the network scope has no
// choice for its default, and reports whether it changed anything. It is
// how a policy added in a later version reaches an install whose
// policy.json predates it.
func fillPolicyDefaults(d *PolicyData) bool {
	if d.Network.Policies == nil {
		d.Network.Policies = map[string]bool{}
	}
	changed := false
	for name := range policyDomains {
		if _, set := d.Network.Policies[name]; !set {
			d.Network.Policies[name] = policyDefaults[name]
			changed = true
		}
	}
	return changed
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
