// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	policyFileVersion = 1
	maxInlineBytes    = 1 << 20
	maxRulesPerKind   = 5000
)

// ScopeSettings is what the user chose at one scope. Items maps a catalog or
// custom item ID (a list, an app or a whole category) to true (on here) or
// false (off here and below); an ID that is absent inherits from less
// specific scopes. Policies work the same way for built-in policy switches.
type ScopeSettings struct {
	Items    map[string]bool `json:"items,omitempty"`
	Policies map[string]bool `json:"policies,omitempty"`
	Allow    []string        `json:"allow,omitempty"`
	Block    []string        `json:"block,omitempty"`
}

// CustomList is a user-defined blocklist, fetched from URL or given inline.
type CustomList struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description,omitempty"`
	URL         string    `json:"url,omitempty"`
	Inline      string    `json:"inline,omitempty"`
	Added       time.Time `json:"added"`
}

// PolicyData is the persisted document (<data_dir>/policy.json).
type PolicyData struct {
	Version int                      `json:"version"`
	Network ScopeSettings            `json:"network"`
	Groups  map[string]ScopeSettings `json:"groups,omitempty"`
	Devices map[string]ScopeSettings `json:"devices,omitempty"`
	Custom  []CustomList             `json:"custom_lists,omitempty"`
}

func (s ScopeSettings) clone() ScopeSettings {
	return ScopeSettings{Items: maps.Clone(s.Items), Policies: maps.Clone(s.Policies), Allow: slices.Clone(s.Allow), Block: slices.Clone(s.Block)}
}

func (d PolicyData) clone() PolicyData {
	out := PolicyData{Version: d.Version, Network: d.Network.clone(), Custom: slices.Clone(d.Custom),
		Groups: map[string]ScopeSettings{}, Devices: map[string]ScopeSettings{}}
	for k, v := range d.Groups {
		out.Groups[k] = v.clone()
	}
	for k, v := range d.Devices {
		out.Devices[k] = v.clone()
	}
	return out
}

// settings returns a pointer to the settings of sc inside d, creating the
// entry when needed. The network always exists.
func (d *PolicyData) settings(sc Scope) (*ScopeSettings, error) {
	switch sc.Kind {
	case ScopeNetwork:
		return &d.Network, nil
	case ScopeGroup, ScopeDevice:
		if !validScopeID(sc.ID) {
			return nil, fmt.Errorf("invalid %s id %q", sc.Kind, sc.ID)
		}
		m := d.Groups
		if sc.Kind == ScopeDevice {
			m = d.Devices
		}
		s := m[sc.ID]
		return &s, nil
	}
	return nil, fmt.Errorf("invalid scope kind %q", sc.Kind)
}

// put stores s back after settings() edited the copy.
func (d *PolicyData) put(sc Scope, s ScopeSettings) {
	switch sc.Kind {
	case ScopeNetwork:
		d.Network = s
	case ScopeGroup:
		d.Groups[sc.ID] = s
	case ScopeDevice:
		d.Devices[sc.ID] = s
	}
}

// LegacyConfig carries what predates policy.json so a first run can adopt it.
type LegacyConfig struct {
	RulesPath         string       // old rules.json (a missing file is fine)
	Lists             []ListConfig // the config's [[lists]]
	BlockPrivateRelay bool         // the config's privacy default
}

// PolicyOptions configures OpenPolicyStore.
type PolicyOptions struct {
	Catalog        *CatalogSet   // nil means the shipped catalog
	Legacy         *LegacyConfig // nil means a fresh install
	ExtraProtected []string      // extra apex domains inline lists may not contain
	// NoRecommended leaves the catalog's recommended items off when the file
	// is first created. A migrated install keeps exactly the lists it had.
	NoRecommended bool
}

// PolicyStore owns the scoped configuration: it validates edits, persists
// them atomically to policy.json (mode 0600) and pushes them into the Filter.
type PolicyStore struct {
	path      string
	filter    *Filter
	cat       *CatalogSet
	protected []string

	mu   sync.Mutex
	data PolicyData
	subs []func()
}

func freshPolicy(cat *CatalogSet) PolicyData {
	d := PolicyData{Version: policyFileVersion, Groups: map[string]ScopeSettings{}, Devices: map[string]ScopeSettings{}}
	d.Network.Items = map[string]bool{}
	for _, id := range cat.Recommended() {
		d.Network.Items[id] = true
	}
	d.Network.Policies = map[string]bool{}
	for name := range policyDomains {
		d.Network.Policies[name] = true
	}
	return d
}

// MigrateLegacy builds the first policy.json for an install that predates it:
// the recommended catalog items at network scope, the old rules.json allow,
// block and policy switches, and each configured list (as the catalog item
// with the same URL when there is one, otherwise as a custom list).
func MigrateLegacy(cat *CatalogSet, l LegacyConfig) (PolicyData, error) {
	d := freshPolicy(cat)
	d.Network.Policies[PolicyPrivateRelay] = l.BlockPrivateRelay
	if l.RulesPath != "" {
		b, err := os.ReadFile(l.RulesPath)
		switch {
		case err == nil:
			var rf rulesFile
			if err := json.Unmarshal(b, &rf); err != nil {
				return PolicyData{}, fmt.Errorf("parsing %s: %w", l.RulesPath, err)
			}
			for _, a := range rf.Allow {
				d.Network.Allow = addDomain(d.Network.Allow, a)
			}
			for _, a := range rf.Block {
				d.Network.Block = addDomain(d.Network.Block, a)
			}
			for name, on := range rf.Policies {
				if _, known := policyDomains[name]; known {
					d.Network.Policies[name] = on
				}
			}
		case !errors.Is(err, os.ErrNotExist):
			return PolicyData{}, err
		}
	}
	for _, lc := range l.Lists {
		if id, ok := cat.listByURL(lc.URL); ok {
			d.Network.Items[id] = true
			continue
		}
		cl := CustomList{ID: uniqueCustomID(d.Custom, lc.Name), Name: lc.Name, Category: "custom", URL: lc.URL, Added: time.Now().UTC().Truncate(time.Second)}
		d.Custom = append(d.Custom, cl)
		d.Network.Items[cl.ID] = true
	}
	return d, nil
}

// addDomain appends the normalized domain when valid and new.
func addDomain(list []string, d string) []string {
	d = normalize(d)
	if !ValidDomain(d) || slices.Contains(list, d) {
		return list
	}
	list = append(list, d)
	slices.Sort(list)
	return list
}

// withoutRecommended returns a copy of the catalog with nothing recommended.
func (c *CatalogSet) withoutRecommended() *CatalogSet {
	out := &CatalogSet{entries: slices.Clone(c.entries), byID: c.byID}
	for i := range out.entries {
		out.entries[i].Recommended = false
	}
	return out
}

func (c *CatalogSet) listByURL(u string) (string, bool) {
	for _, e := range c.entries {
		if e.Kind == KindList && len(e.Sources) == 1 && e.Sources[0].URL == u {
			return e.ID, true
		}
	}
	return "", false
}

func slug(s string) string {
	var b strings.Builder
	dash := true
	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = strings.Trim(out[:40], "-")
	}
	if out == "" {
		out = "list"
	}
	return out
}

func uniqueCustomID(existing []CustomList, name string) string {
	base := "custom-" + slug(name)
	id := base
	for n := 2; slices.ContainsFunc(existing, func(c CustomList) bool { return c.ID == id }); n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	return id
}

// OpenPolicyStore loads path, or on first run seeds it (see MigrateLegacy),
// writes it, and applies the result to f.
func OpenPolicyStore(path string, f *Filter, opts PolicyOptions) (*PolicyStore, error) {
	cat := opts.Catalog
	if cat == nil {
		var err error
		if cat, err = DefaultCatalog(); err != nil {
			return nil, err
		}
	}
	s := &PolicyStore{path: path, filter: f, cat: cat,
		protected: append(slices.Clone(DefaultProtected), opts.ExtraProtected...)}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		if err := s.data.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		seed := cat
		if opts.NoRecommended {
			seed = cat.withoutRecommended()
		}
		s.data = freshPolicy(seed)
		if opts.Legacy != nil {
			if s.data, err = MigrateLegacy(seed, *opts.Legacy); err != nil {
				return nil, err
			}
		}
		if err := writePolicyFile(path, s.data); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	s.apply()
	return s, nil
}

// validate checks a loaded document and fills in nil maps.
func (d *PolicyData) validate() error {
	if d.Version != policyFileVersion {
		return fmt.Errorf("unsupported policy version %d", d.Version)
	}
	if d.Groups == nil {
		d.Groups = map[string]ScopeSettings{}
	}
	if d.Devices == nil {
		d.Devices = map[string]ScopeSettings{}
	}
	for _, m := range []map[string]ScopeSettings{d.Groups, d.Devices} {
		for id := range m {
			if !validScopeID(id) {
				return fmt.Errorf("invalid scope id %q", id)
			}
		}
	}
	for _, c := range d.Custom {
		if !validItemID(c.ID) {
			return fmt.Errorf("invalid custom list id %q", c.ID)
		}
	}
	return nil
}

func writePolicyFile(path string, d PolicyData) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}

// OnChange registers fn to run after every successful edit, outside the
// store's lock. The ListManager uses it to fetch newly enabled lists.
func (s *PolicyStore) OnChange(fn func()) {
	s.mu.Lock()
	s.subs = append(s.subs, fn)
	s.mu.Unlock()
}

// Catalog returns the catalog this store validates against.
func (s *PolicyStore) Catalog() *CatalogSet { return s.cat }

func (s *PolicyStore) customIDs() map[string]bool {
	m := make(map[string]bool, len(s.data.Custom))
	for _, c := range s.data.Custom {
		m[c.ID] = true
	}
	return m
}

// expandItems turns a scope's item switches into switches on leaf items. A
// switch on a leaf beats the switch of a category or umbrella that contains
// it, and off beats on between two containers.
func (s *PolicyStore) expandItems(items map[string]bool, custom map[string]bool) map[string]bool {
	out := map[string]bool{}
	var offs []string
	direct := map[string]bool{}
	for id, v := range items {
		e, isCat := s.cat.ByID(id)
		if custom[id] || (isCat && len(e.Includes) == 0) {
			direct[id] = v
			continue
		}
		for _, l := range s.cat.Leaves(id) {
			if v {
				out[l] = true
			} else {
				offs = append(offs, l)
			}
		}
	}
	for _, l := range offs {
		out[l] = false
	}
	for id, v := range direct {
		out[id] = v
	}
	return out
}

// scopeConfigs builds the Filter configuration. Callers hold s.mu.
func (s *PolicyStore) scopeConfigs() map[string]ScopeConfig {
	custom := s.customIDs()
	cfg := func(ss ScopeSettings) ScopeConfig {
		return ScopeConfig{Items: s.expandItems(ss.Items, custom), Policies: maps.Clone(ss.Policies), Allow: ss.Allow, Block: ss.Block}
	}
	out := map[string]ScopeConfig{NetworkScope().String(): cfg(s.data.Network)}
	for id, ss := range s.data.Groups {
		out[GroupScope(id).String()] = cfg(ss)
	}
	for id, ss := range s.data.Devices {
		out[DeviceScope(id).String()] = cfg(ss)
	}
	return out
}

func (s *PolicyStore) apply() { s.filter.SetScopes(s.scopeConfigs()) }

// mutate runs fn on a copy of the data, persists it, and only then commits it
// in memory and in the filter, so a failed save changes nothing.
func (s *PolicyStore) mutate(fn func(d *PolicyData) error) error {
	s.mu.Lock()
	next := s.data.clone()
	if err := fn(&next); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := writePolicyFile(s.path, next); err != nil {
		s.mu.Unlock()
		return err
	}
	s.data = next
	s.apply()
	subs := slices.Clone(s.subs)
	s.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
	return nil
}

// knownItem reports whether id is a catalog entry or a custom list in d.
func (s *PolicyStore) knownItem(d *PolicyData, id string) bool {
	if _, ok := s.cat.ByID(id); ok {
		return true
	}
	return slices.ContainsFunc(d.Custom, func(c CustomList) bool { return c.ID == id })
}

// SetItem switches a catalog or custom item on or off at a scope.
func (s *PolicyStore) SetItem(sc Scope, id string, enabled bool) error {
	return s.mutate(func(d *PolicyData) error {
		if !s.knownItem(d, id) {
			return fmt.Errorf("unknown item %q", id)
		}
		ss, err := d.settings(sc)
		if err != nil {
			return err
		}
		if ss.Items == nil {
			ss.Items = map[string]bool{}
		}
		ss.Items[id] = enabled
		d.put(sc, *ss)
		return nil
	})
}

// ClearItem removes the scope's own choice for id so it inherits again.
func (s *PolicyStore) ClearItem(sc Scope, id string) error {
	return s.mutate(func(d *PolicyData) error {
		ss, err := d.settings(sc)
		if err != nil {
			return err
		}
		delete(ss.Items, id)
		d.put(sc, *ss)
		return nil
	})
}

// SetPolicy switches a built-in policy on or off at a scope.
func (s *PolicyStore) SetPolicy(sc Scope, name string, enabled bool) error {
	if _, ok := policyDomains[name]; !ok {
		return fmt.Errorf("unknown policy %q", name)
	}
	return s.mutate(func(d *PolicyData) error {
		ss, err := d.settings(sc)
		if err != nil {
			return err
		}
		if ss.Policies == nil {
			ss.Policies = map[string]bool{}
		}
		ss.Policies[name] = enabled
		d.put(sc, *ss)
		return nil
	})
}

// ClearPolicy removes the scope's own choice for a policy so it inherits.
func (s *PolicyStore) ClearPolicy(sc Scope, name string) error {
	return s.mutate(func(d *PolicyData) error {
		ss, err := d.settings(sc)
		if err != nil {
			return err
		}
		delete(ss.Policies, name)
		d.put(sc, *ss)
		return nil
	})
}

func ruleLists(ss *ScopeSettings, kind string) (same, other *[]string, err error) {
	switch kind {
	case "allow":
		return &ss.Allow, &ss.Block, nil
	case "block":
		return &ss.Block, &ss.Allow, nil
	}
	return nil, nil, fmt.Errorf("rule kind must be \"allow\" or \"block\", got %q", kind)
}

// AddRule puts domain on the scope's allow or block rules, removing it from
// the opposite kind at that scope.
func (s *PolicyStore) AddRule(sc Scope, kind, domain string) error {
	domain = normalize(domain)
	if !ValidDomain(domain) {
		return fmt.Errorf("%q is not a valid domain", domain)
	}
	return s.mutate(func(d *PolicyData) error {
		ss, err := d.settings(sc)
		if err != nil {
			return err
		}
		same, other, err := ruleLists(ss, kind)
		if err != nil {
			return err
		}
		if len(*same) >= maxRulesPerKind && !slices.Contains(*same, domain) {
			return fmt.Errorf("too many %s rules at this scope (limit %d)", kind, maxRulesPerKind)
		}
		*other = slices.DeleteFunc(*other, func(x string) bool { return x == domain })
		*same = addDomain(*same, domain)
		d.put(sc, *ss)
		return nil
	})
}

// RemoveRule deletes domain from the scope's allow or block rules.
func (s *PolicyStore) RemoveRule(sc Scope, kind, domain string) error {
	domain = normalize(domain)
	return s.mutate(func(d *PolicyData) error {
		ss, err := d.settings(sc)
		if err != nil {
			return err
		}
		same, _, err := ruleLists(ss, kind)
		if err != nil {
			return err
		}
		*same = slices.DeleteFunc(*same, func(x string) bool { return x == domain })
		d.put(sc, *ss)
		return nil
	})
}

// DeleteScope forgets everything configured at a group or device, for when
// the registry deletes it. The network scope cannot be deleted.
func (s *PolicyStore) DeleteScope(sc Scope) error {
	return s.mutate(func(d *PolicyData) error {
		switch sc.Kind {
		case ScopeGroup:
			delete(d.Groups, sc.ID)
		case ScopeDevice:
			delete(d.Devices, sc.ID)
		default:
			return errors.New("the network scope cannot be deleted")
		}
		return nil
	})
}

// CustomListInput describes a custom list to add. Give URL or Inline, not both.
type CustomListInput struct {
	Name        string
	Category    string
	Description string
	URL         string // http or https
	Inline      string // pasted text in hosts, domain-per-line or adblock form
	Scope       Scope  // where to enable it; the zero value means the network
}

// AddCustomList validates and stores a custom list and enables it at in.Scope.
func (s *PolicyStore) AddCustomList(in CustomListInput) (CustomList, error) {
	name := strings.TrimSpace(in.Name)
	cat := strings.TrimSpace(in.Category)
	switch {
	case name == "" || len(name) > 80:
		return CustomList{}, errors.New("name must be 1 to 80 characters")
	case len(cat) > 40 || len(in.Description) > 500:
		return CustomList{}, errors.New("category or description too long")
	case (in.URL == "") == (in.Inline == ""):
		return CustomList{}, errors.New("give either a url or inline text")
	}
	if cat == "" {
		cat = "custom"
	}
	if in.Scope.Kind == "" {
		in.Scope = NetworkScope()
	}
	if in.URL != "" {
		u, err := url.Parse(in.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return CustomList{}, fmt.Errorf("%q is not an http or https URL", in.URL)
		}
	} else {
		if len(in.Inline) > maxInlineBytes {
			return CustomList{}, fmt.Errorf("inline list is over %d bytes", maxInlineBytes)
		}
		set, err := ParseList(strings.NewReader(in.Inline))
		if err != nil {
			return CustomList{}, err
		}
		if err := Guard(nil, set, s.protected); err != nil {
			return CustomList{}, err
		}
	}
	var created CustomList
	err := s.mutate(func(d *PolicyData) error {
		ss, err := d.settings(in.Scope)
		if err != nil {
			return err
		}
		created = CustomList{ID: uniqueCustomID(d.Custom, name), Name: name, Category: cat, Description: in.Description,
			URL: in.URL, Inline: in.Inline, Added: time.Now().UTC().Truncate(time.Second)}
		d.Custom = append(d.Custom, created)
		if ss.Items == nil {
			ss.Items = map[string]bool{}
		}
		ss.Items[created.ID] = true
		d.put(in.Scope, *ss)
		return nil
	})
	return created, err
}

// RemoveCustomList deletes a custom list and every switch that referred to it.
func (s *PolicyStore) RemoveCustomList(id string) error {
	return s.mutate(func(d *PolicyData) error {
		i := slices.IndexFunc(d.Custom, func(c CustomList) bool { return c.ID == id })
		if i < 0 {
			return fmt.Errorf("unknown custom list %q", id)
		}
		d.Custom = slices.Delete(d.Custom, i, i+1)
		delete(d.Network.Items, id)
		for _, m := range []map[string]ScopeSettings{d.Groups, d.Devices} {
			for _, ss := range m {
				delete(ss.Items, id)
			}
		}
		return nil
	})
}

// PolicySnapshot is a deep copy of the state for the UI.
type PolicySnapshot struct {
	Network  ScopeSettings            `json:"network"`
	Groups   map[string]ScopeSettings `json:"groups"`
	Devices  map[string]ScopeSettings `json:"devices"`
	Custom   []CustomList             `json:"custom_lists"`
	Catalog  []CatalogEntry           `json:"catalog"`
	Policies []string                 `json:"known_policies"`
}

// Snapshot returns the current settings together with the catalog.
func (s *PolicyStore) Snapshot() PolicySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.data.clone()
	return PolicySnapshot{Network: d.Network, Groups: d.Groups, Devices: d.Devices,
		Custom: d.Custom, Catalog: s.cat.Entries(), Policies: KnownPolicies()}
}

// WantedLists returns every list item switched on at some scope, with its
// sources. Items that are off everywhere are never listed, so never fetched.
func (s *PolicyStore) WantedLists() []ListSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	custom := s.customIDs()
	wanted := map[string]bool{}
	collect := func(ss ScopeSettings) {
		for id, on := range s.expandItems(ss.Items, custom) {
			if on {
				wanted[id] = true
			}
		}
	}
	collect(s.data.Network)
	for _, ss := range s.data.Groups {
		collect(ss)
	}
	for _, ss := range s.data.Devices {
		collect(ss)
	}
	ids := slices.Sorted(maps.Keys(wanted))
	specs := make([]ListSpec, 0, len(ids))
	for _, id := range ids {
		if e, ok := s.cat.ByID(id); ok {
			sp := ListSpec{ID: id, Name: e.Name}
			for _, src := range e.Sources {
				sp.Sources = append(sp.Sources, ListSource{URL: src.URL, Format: src.Format})
			}
			specs = append(specs, sp)
			continue
		}
		for _, c := range s.data.Custom {
			if c.ID == id {
				sp := ListSpec{ID: id, Name: c.Name, Sources: []ListSource{{URL: c.URL, Inline: c.Inline}}}
				specs = append(specs, sp)
			}
		}
	}
	return specs
}
