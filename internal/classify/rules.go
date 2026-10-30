// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"shepherd/internal/devices"
)

//go:embed rules/classes.json rules/domains.json rules/vendors.json rules/asn.json rules/services.json
var dataFS embed.FS

const (
	// maxClasses bounds the class vector so per-device state is a fixed size.
	maxClasses = 32
	// maxLabels bounds the distinct reason labels (what lookups are "to").
	maxLabels = 64
	// asnMaxWeight is the strongest hint a single ASN rule may carry. ASNs
	// are weak evidence by design.
	asnMaxWeight = 0.4
)

// vec holds one number per class.
type vec [maxClasses]float32

// RuleFiles are the raw bytes of the five rule files.
type RuleFiles struct {
	Classes, Domains, Vendors, ASN, Services []byte
}

type classInfo struct {
	ID      devices.DeviceType
	Group   string
	Related []int
}

type domainRule struct {
	Suffix, Label, Vendor, Evidence string
	W                               vec
	Top                             int // class index of the largest weight
	LabelIdx                        int
}

type vendorRule struct {
	Match, KnownFor string
	W               vec
	Neutral         bool
}

type asnRule struct {
	ASN      uint
	Holder   string
	Label    string
	W        vec
	Shared   bool
	LabelIdx int
}

type orgRule struct {
	Keyword  string
	Label    string
	W        vec
	Shared   bool
	LabelIdx int
}

type serviceRule struct {
	Service, Label string
	W              vec
	LabelIdx       int
}

// RuleSet is the validated, indexed rule data. It is immutable once built
// and safe to share.
type RuleSet struct {
	// Version of the rule files (the maximum of their version fields) and
	// the date their contents were last verified against public sources.
	Version  int
	Verified string

	classes  []classInfo
	classIdx map[devices.DeviceType]int
	related  [maxClasses][maxClasses]bool

	domains  map[string]*domainRule
	vendors  []vendorRule
	asns     map[uint]*asnRule
	orgs     []orgRule
	services map[string]*serviceRule

	labels   []string // reason labels, index = label id
	labelIdx map[string]int
	// labelW[l][c] is the strongest weight any rule with label l gives class c.
	labelW [maxLabels]vec
}

// Classes lists the classes in rule order.
func (rs *RuleSet) Classes() []devices.DeviceType {
	out := make([]devices.DeviceType, len(rs.classes))
	for i, c := range rs.classes {
		out[i] = c.ID
	}
	return out
}

// Counts reports how many rules of each kind are loaded.
func (rs *RuleSet) Counts() (domains, vendors, asns, orgs, services int) {
	return len(rs.domains), len(rs.vendors), len(rs.asns), len(rs.orgs), len(rs.services)
}

var (
	defaultOnce sync.Once
	defaultSet  *RuleSet
	defaultErr  error
)

// DefaultRuleSet returns the rules embedded in the binary.
func DefaultRuleSet() (*RuleSet, error) {
	defaultOnce.Do(func() {
		read := func(name string) []byte {
			b, err := dataFS.ReadFile("rules/" + name)
			if err != nil {
				defaultErr = errors.Join(defaultErr, err)
			}
			return b
		}
		f := RuleFiles{read("classes.json"), read("domains.json"), read("vendors.json"), read("asn.json"), read("services.json")}
		if defaultErr != nil {
			return
		}
		defaultSet, defaultErr = ParseRules(f)
	})
	return defaultSet, defaultErr
}

type jsonClasses struct {
	Version int `json:"version"`
	Classes []struct {
		ID      string   `json:"id"`
		Group   string   `json:"group"`
		Related []string `json:"related"`
	} `json:"classes"`
}

type jsonDomains struct {
	Version  int    `json:"version"`
	Verified string `json:"verified"`
	Rules    []struct {
		Suffix   string             `json:"suffix"`
		Classes  map[string]float64 `json:"classes"`
		Label    string             `json:"label"`
		Vendor   string             `json:"vendor"`
		Evidence string             `json:"evidence"`
	} `json:"rules"`
}

type jsonVendors struct {
	Version  int    `json:"version"`
	Verified string `json:"verified"`
	Rules    []struct {
		Match    string             `json:"match"`
		Classes  map[string]float64 `json:"classes"`
		Neutral  bool               `json:"neutral"`
		KnownFor string             `json:"known_for"`
		Evidence string             `json:"evidence"`
	} `json:"rules"`
}

type jsonASN struct {
	Version  int    `json:"version"`
	Verified string `json:"verified"`
	ASNs     []struct {
		ASN      uint               `json:"asn"`
		Holder   string             `json:"holder"`
		Classes  map[string]float64 `json:"classes"`
		Label    string             `json:"label"`
		Shared   bool               `json:"shared"`
		Evidence string             `json:"evidence"`
	} `json:"asns"`
	Orgs []struct {
		Keyword  string             `json:"keyword"`
		Classes  map[string]float64 `json:"classes"`
		Label    string             `json:"label"`
		Shared   bool               `json:"shared"`
		Evidence string             `json:"evidence"`
	} `json:"orgs"`
}

type jsonServices struct {
	Version int `json:"version"`
	Rules   []struct {
		Service string             `json:"service"`
		Classes map[string]float64 `json:"classes"`
		Label   string             `json:"label"`
	} `json:"rules"`
}

func strict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

// ParseRules parses and validates rule files. Every problem is reported at
// once so a contributor can fix a whole file in one pass. The checks are the
// same ones the embedded data is held to in tests: valid, lower-case
// suffixes and keywords, known classes, weights in range, no duplicates, no
// parent and child suffix that disagree about the class, shared networks
// that carry no weight, and evidence recorded for every rule.
func ParseRules(f RuleFiles) (*RuleSet, error) {
	rs := &RuleSet{
		classIdx: map[devices.DeviceType]int{},
		domains:  map[string]*domainRule{},
		asns:     map[uint]*asnRule{},
		services: map[string]*serviceRule{},
		labelIdx: map[string]int{},
	}
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	// ---- classes
	var jc jsonClasses
	if err := strict(f.Classes, &jc); err != nil {
		return nil, fmt.Errorf("classes.json: %w", err)
	}
	rs.Version = max(rs.Version, jc.Version)
	if len(jc.Classes) > maxClasses {
		bad("classes.json: at most %d classes", maxClasses)
	}
	for _, c := range jc.Classes {
		t, ok := devices.ParseType(c.ID)
		switch {
		case !ok || t == devices.TypeUnknown || string(t) != c.ID:
			bad("classes.json: %q is not a registry device type", c.ID)
			continue
		case c.Group == "":
			bad("classes.json: class %q has no group", c.ID)
		}
		if _, dup := rs.classIdx[t]; dup {
			bad("classes.json: class %q listed twice", c.ID)
			continue
		}
		rs.classIdx[t] = len(rs.classes)
		rs.classes = append(rs.classes, classInfo{ID: t, Group: c.Group})
	}
	for i, c := range jc.Classes {
		if i >= len(rs.classes) || string(rs.classes[i].ID) != c.ID {
			continue // a bad or duplicate entry, already reported
		}
		for _, r := range c.Related {
			j, ok := rs.classIdx[devices.DeviceType(r)]
			if !ok || j == i {
				bad("classes.json: class %q lists an unknown or self relation %q", c.ID, r)
				continue
			}
			rs.classes[i].Related = append(rs.classes[i].Related, j)
			rs.related[i][j] = true
		}
	}
	weights := func(where string, in map[string]float64, hi float64) (vec, int, bool) {
		var v vec
		top, topW := -1, 0.0
		if len(in) == 0 {
			bad("%s: no classes", where)
			return v, -1, false
		}
		ok := true
		for name, w := range in {
			i, known := rs.classIdx[devices.DeviceType(name)]
			if !known {
				bad("%s: unknown class %q", where, name)
				ok = false
				continue
			}
			if !(w > 0 && w <= hi) {
				bad("%s: weight %v for %q must be above 0 and at most %v", where, w, name, hi)
				ok = false
				continue
			}
			v[i] = float32(w)
			if w > topW || (w == topW && i < top) {
				top, topW = i, w
			}
		}
		return v, top, ok
	}
	label := func(where, l string, w vec) int {
		if strings.TrimSpace(l) == "" || l != strings.TrimSpace(l) {
			bad("%s: label must be non-empty plain text", where)
			return 0
		}
		i, ok := rs.labelIdx[l]
		if !ok {
			if len(rs.labels) >= maxLabels {
				bad("%s: more than %d distinct labels", where, maxLabels)
				return 0
			}
			i = len(rs.labels)
			rs.labelIdx[l] = i
			rs.labels = append(rs.labels, l)
		}
		for c := range w {
			rs.labelW[i][c] = max(rs.labelW[i][c], w[c])
		}
		return i
	}

	// ---- domains
	var jd jsonDomains
	if err := strict(f.Domains, &jd); err != nil {
		return nil, fmt.Errorf("domains.json: %w", err)
	}
	rs.Version = max(rs.Version, jd.Version)
	rs.Verified = jd.Verified
	for _, d := range jd.Rules {
		where := "domains.json: " + d.Suffix
		if !validHost(d.Suffix) || strings.Count(d.Suffix, ".") < 1 {
			bad("%s: not a valid lower-case domain suffix with at least two labels", where)
			continue
		}
		if _, dup := rs.domains[d.Suffix]; dup {
			bad("%s: duplicate rule", where)
			continue
		}
		if d.Vendor == "" || d.Evidence == "" {
			bad("%s: vendor and evidence are required", where)
		}
		w, top, ok := weights(where, d.Classes, 1)
		if !ok {
			continue
		}
		rs.domains[d.Suffix] = &domainRule{Suffix: d.Suffix, Label: d.Label, Vendor: d.Vendor,
			Evidence: d.Evidence, W: w, Top: top, LabelIdx: label(where, d.Label, w)}
	}
	for suffix, r := range rs.domains {
		for parent := parentOf(suffix); parent != ""; parent = parentOf(parent) {
			if p, ok := rs.domains[parent]; ok && p.Top != r.Top {
				bad("domains.json: %s (%s) contradicts its parent %s (%s)", suffix, rs.classes[r.Top].ID, parent, rs.classes[p.Top].ID)
			}
		}
	}

	// ---- vendors
	var jv jsonVendors
	if err := strict(f.Vendors, &jv); err != nil {
		return nil, fmt.Errorf("vendors.json: %w", err)
	}
	rs.Version = max(rs.Version, jv.Version)
	seenVendor := map[string]bool{}
	for _, v := range jv.Rules {
		where := "vendors.json: " + v.Match
		if v.Match == "" || v.Match != strings.ToLower(strings.TrimSpace(v.Match)) {
			bad("%s: match must be non-empty lower-case text", where)
			continue
		}
		if seenVendor[v.Match] {
			bad("%s: duplicate rule", where)
			continue
		}
		seenVendor[v.Match] = true
		if v.Evidence == "" {
			bad("%s: evidence is required", where)
		}
		r := vendorRule{Match: v.Match, KnownFor: v.KnownFor, Neutral: v.Neutral}
		switch {
		case v.Neutral && len(v.Classes) > 0:
			bad("%s: a neutral rule carries no classes", where)
			continue
		case v.Neutral:
		default:
			w, _, ok := weights(where, v.Classes, 1)
			if !ok {
				continue
			}
			if v.KnownFor == "" {
				bad("%s: known_for is required", where)
			}
			r.W = w
		}
		rs.vendors = append(rs.vendors, r)
	}

	// ---- ASNs and organization keywords
	var ja jsonASN
	if err := strict(f.ASN, &ja); err != nil {
		return nil, fmt.Errorf("asn.json: %w", err)
	}
	rs.Version = max(rs.Version, ja.Version)
	for _, a := range ja.ASNs {
		where := fmt.Sprintf("asn.json: AS%d", a.ASN)
		if a.ASN == 0 || a.ASN > 4294967295 {
			bad("%s: not a valid AS number", where)
			continue
		}
		if _, dup := rs.asns[a.ASN]; dup {
			bad("%s: duplicate entry", where)
			continue
		}
		if a.Holder == "" || a.Evidence == "" {
			bad("%s: holder and evidence are required", where)
		}
		r := &asnRule{ASN: a.ASN, Holder: a.Holder, Shared: a.Shared, Label: a.Label}
		if a.Shared {
			if len(a.Classes) > 0 || a.Label != "" {
				bad("%s: a shared network carries no classes and no label", where)
				continue
			}
		} else {
			w, _, ok := weights(where, a.Classes, asnMaxWeight)
			if !ok {
				continue
			}
			r.W, r.LabelIdx = w, label(where, a.Label, w)
		}
		rs.asns[a.ASN] = r
	}
	seenOrg := map[string]bool{}
	for _, o := range ja.Orgs {
		where := "asn.json: org " + o.Keyword
		if o.Keyword == "" || o.Keyword != strings.ToLower(strings.TrimSpace(o.Keyword)) {
			bad("%s: keyword must be non-empty lower-case text", where)
			continue
		}
		if seenOrg[o.Keyword] {
			bad("%s: duplicate keyword", where)
			continue
		}
		seenOrg[o.Keyword] = true
		if o.Evidence == "" {
			bad("%s: evidence is required", where)
		}
		r := orgRule{Keyword: o.Keyword, Shared: o.Shared, Label: o.Label}
		if o.Shared {
			if len(o.Classes) > 0 || o.Label != "" {
				bad("%s: a shared network carries no classes and no label", where)
				continue
			}
		} else {
			w, _, ok := weights(where, o.Classes, asnMaxWeight)
			if !ok {
				continue
			}
			r.W, r.LabelIdx = w, label(where, o.Label, w)
		}
		rs.orgs = append(rs.orgs, r)
	}

	// ---- mDNS services
	var js jsonServices
	if err := strict(f.Services, &js); err != nil {
		return nil, fmt.Errorf("services.json: %w", err)
	}
	rs.Version = max(rs.Version, js.Version)
	for _, s := range js.Rules {
		where := "services.json: " + s.Service
		if !strings.HasPrefix(s.Service, "_") || len(s.Service) < 2 || s.Service != strings.ToLower(s.Service) || strings.ContainsAny(s.Service, ". ") {
			bad("%s: a service is the first label of an mDNS type, like _ipp", where)
			continue
		}
		if _, dup := rs.services[s.Service]; dup {
			bad("%s: duplicate rule", where)
			continue
		}
		w, _, ok := weights(where, s.Classes, 1)
		if !ok {
			continue
		}
		rs.services[s.Service] = &serviceRule{Service: s.Service, Label: s.Label, W: w, LabelIdx: label(where, s.Label, w)}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return rs, nil
}

// parentOf returns the suffix one label up ("a.b.com" -> "b.com"), or "" when
// only a single label would remain.
func parentOf(s string) string {
	i := strings.IndexByte(s, '.')
	if i < 0 || strings.IndexByte(s[i+1:], '.') < 0 {
		return ""
	}
	return s[i+1:]
}

// validHost reports whether s is a lower-case host name of letters, digits,
// hyphens and dots with sane labels.
func validHost(s string) bool {
	if s == "" || len(s) > 253 || s != strings.ToLower(s) {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// matchDomain finds the most specific domain rule for a lower-case host name.
func (rs *RuleSet) matchDomain(host string) *domainRule {
	for s := host; s != ""; {
		if r, ok := rs.domains[s]; ok {
			return r
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	return nil
}

// matchVendor picks the longest vendor rule whose text appears as whole words
// in the manufacturer name, so "tcl" never matches "NETCLEUS" and a specific
// rule ("hewlett packard enterprise") beats a general one ("hewlett packard").
func (rs *RuleSet) matchVendor(vendor string) *vendorRule {
	lv := strings.ToLower(vendor)
	var best *vendorRule
	for i := range rs.vendors {
		v := &rs.vendors[i]
		if (best == nil || len(v.Match) > len(best.Match)) && containsWord(lv, v.Match) {
			best = v
		}
	}
	return best
}

// containsWord reports whether frag appears in s with a non-alphanumeric
// character (or an edge) on both sides.
func containsWord(s, frag string) bool {
	for from := 0; ; {
		i := strings.Index(s[from:], frag)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(frag)
		if (i == 0 || !isAlnum(s[i-1])) && (end == len(s) || !isAlnum(s[end])) {
			return true
		}
		from = i + 1
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c >= 0x80
}

// matchOrg finds an organization-keyword rule in an ASN holder name.
func (rs *RuleSet) matchOrg(org string) *orgRule {
	lo := strings.ToLower(org)
	for i := range rs.orgs {
		if containsWord(lo, rs.orgs[i].Keyword) {
			return &rs.orgs[i]
		}
	}
	return nil
}
