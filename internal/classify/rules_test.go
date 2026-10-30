// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"shepherd/internal/devices"
)

func defaultRules(t testing.TB) *RuleSet {
	t.Helper()
	rs, err := DefaultRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func readData(t testing.TB, name string) []byte {
	t.Helper()
	b, err := dataFS.ReadFile("rules/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func files(t testing.TB) RuleFiles {
	return RuleFiles{readData(t, "classes.json"), readData(t, "domains.json"), readData(t, "vendors.json"),
		readData(t, "asn.json"), readData(t, "services.json")}
}

func TestEmbeddedRulesAreValid(t *testing.T) {
	rs := defaultRules(t)
	d, v, a, o, s := rs.Counts()
	if d < 60 || v < 30 || a < 30 || o < 10 || s < 15 {
		t.Errorf("rule counts look wrong: domains %d vendors %d asns %d orgs %d services %d", d, v, a, o, s)
	}
	if rs.Version < 1 || rs.Verified != "2026-10-30" {
		t.Errorf("version %d verified %q", rs.Version, rs.Verified)
	}
	// Loading twice is the same cached set.
	again, _ := DefaultRuleSet()
	if again != rs {
		t.Error("the default rule set should be loaded once")
	}
}

// Every registry type except unknown is a class, and every class is a registry type.
func TestClassesCoverTheRegistryTypes(t *testing.T) {
	rs := defaultRules(t)
	have := map[devices.DeviceType]bool{}
	for _, c := range rs.Classes() {
		have[c] = true
	}
	for _, ty := range devices.AllTypes() {
		if ty == devices.TypeUnknown {
			continue
		}
		if !have[ty] {
			t.Errorf("registry type %q has no class", ty)
		}
		delete(have, ty)
	}
	for c := range have {
		t.Errorf("class %q is not a registry type", c)
	}
}

// The classifier and the registry agree on what each mDNS service means.
func TestServiceRulesAgreeWithTheRegistryTable(t *testing.T) {
	rs := defaultRules(t)
	for label, want := range devices.ServiceTypeRules() {
		r := rs.services[label]
		if r == nil {
			t.Errorf("service %s is in the registry table but has no classifier rule", label)
			continue
		}
		best, bw := -1, float32(0)
		for i, w := range r.W {
			if w > bw {
				best, bw = i, w
			}
		}
		if rs.classes[best].ID != want {
			t.Errorf("service %s: classifier says %s, registry says %s", label, rs.classes[best].ID, want)
		}
	}
}

// Every vendor rule must match at least one manufacturer name that really
// exists in the OUI table, so a typo cannot hide a dead rule.
func TestEveryVendorRuleMatchesARealManufacturer(t *testing.T) {
	rs := defaultRules(t)
	known := devices.KnownVendors()
	for _, v := range rs.vendors {
		hit := false
		for _, name := range known {
			if containsWord(strings.ToLower(name), v.Match) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("vendor rule %q matches no manufacturer in the OUI table", v.Match)
		}
	}
}

// Every rule must be justified in rules/README.md, the document reviewers read.
func TestReadmeListsEveryRule(t *testing.T) {
	b, err := os.ReadFile("rules/README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	rs := defaultRules(t)
	for s := range rs.domains {
		if !strings.Contains(readme, "`"+s+"`") {
			t.Errorf("domain rule %s is not in rules/README.md", s)
		}
	}
	for _, v := range rs.vendors {
		if !strings.Contains(readme, "`"+v.Match+"`") {
			t.Errorf("vendor rule %s is not in rules/README.md", v.Match)
		}
	}
	for n := range rs.asns {
		if !strings.Contains(readme, fmt.Sprintf("| AS%d |", n)) {
			t.Errorf("AS%d is not in rules/README.md", n)
		}
	}
	for _, o := range rs.orgs {
		if !strings.Contains(readme, "`"+o.Keyword+"`") {
			t.Errorf("org keyword %s is not in rules/README.md", o.Keyword)
		}
	}
	for s := range rs.services {
		if !strings.Contains(readme, "`"+s+"`") {
			t.Errorf("service %s is not in rules/README.md", s)
		}
	}
}

func TestShippedRulesAreSensible(t *testing.T) {
	rs := defaultRules(t)
	// Shared networks carry no weight and ASN hints stay weak.
	shared := 0
	for _, a := range rs.asns {
		if a.Shared {
			shared++
			for _, w := range a.W {
				if w != 0 {
					t.Errorf("shared AS%d carries weight", a.ASN)
				}
			}
			continue
		}
		for _, w := range a.W {
			if w > asnMaxWeight {
				t.Errorf("AS%d hint %v is above the cap", a.ASN, w)
			}
		}
	}
	if shared < 10 {
		t.Errorf("expected the big shared networks to be listed, got %d", shared)
	}
	for _, big := range []uint{15169, 16509, 13335, 8075, 20940, 54113} {
		if r := rs.asns[big]; r == nil || !r.Shared {
			t.Errorf("AS%d must be a zero-weight shared network", big)
		}
	}
	// The brand-new camera cloud suffix really is a camera rule.
	r := rs.matchDomain("ezvizlife.com")
	if r == nil || rs.classes[r.Top].ID != devices.TypeCamera {
		t.Error("ezvizlife.com should be a camera cloud")
	}
	// Hints stay below what a lone domain says.
	for _, a := range rs.asns {
		for _, w := range a.W {
			if w > 0.4 {
				t.Errorf("AS%d too strong", a.ASN)
			}
		}
	}
}

// mutate returns the rule files with fn applied to the named JSON document.
func mutate(t *testing.T, which string, fn func(m map[string]any)) RuleFiles {
	t.Helper()
	f := files(t)
	field := map[string]*[]byte{"classes": &f.Classes, "domains": &f.Domains, "vendors": &f.Vendors, "asn": &f.ASN, "services": &f.Services}[which]
	var m map[string]any
	if err := json.Unmarshal(*field, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	*field = out
	return f
}

func rulesOf(m map[string]any, key string) []any { return m[key].([]any) }

func TestRuleValidationRejectsBadData(t *testing.T) {
	cases := []struct {
		name  string
		which string
		fn    func(m map[string]any)
		want  string
	}{
		{"unknown class in a domain rule", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["classes"] = map[string]any{"toaster": 0.5}
		}, `unknown class "toaster"`},
		{"weight above one", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["classes"] = map[string]any{"tv": 1.5}
		}, "must be above 0"},
		{"zero weight", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["classes"] = map[string]any{"tv": 0}
		}, "must be above 0"},
		{"no classes", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["classes"] = map[string]any{}
		}, "no classes"},
		{"upper-case suffix", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["suffix"] = "Netflix.com"
		}, "not a valid lower-case domain suffix"},
		{"single-label suffix", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["suffix"] = "com"
		}, "not a valid lower-case domain suffix"},
		{"bad characters in suffix", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["suffix"] = "ex ample.com"
		}, "not a valid lower-case domain suffix"},
		{"empty label in suffix", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["suffix"] = "a..com"
		}, "not a valid lower-case domain suffix"},
		{"duplicate domain", "domains", func(m map[string]any) {
			r := rulesOf(m, "rules")
			m["rules"] = append(r, r[0])
		}, "duplicate rule"},
		{"missing evidence", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["evidence"] = ""
		}, "vendor and evidence are required"},
		{"empty label", "domains", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["label"] = " "
		}, "label must be non-empty"},
		{"child contradicts parent", "domains", func(m map[string]any) {
			r := rulesOf(m, "rules")
			m["rules"] = append(r, map[string]any{"suffix": "x.netflix.com", "classes": map[string]any{"camera": 0.9},
				"label": "a camera cloud service", "vendor": "v", "evidence": "e"})
		}, "contradicts its parent netflix.com"},
		{"duplicate vendor", "vendors", func(m map[string]any) {
			r := rulesOf(m, "rules")
			m["rules"] = append(r, r[0])
		}, "duplicate rule"},
		{"upper-case vendor", "vendors", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["match"] = "Sonos"
		}, "lower-case"},
		{"vendor without known_for", "vendors", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["known_for"] = ""
		}, "known_for is required"},
		{"neutral vendor with classes", "vendors", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["neutral"] = true
		}, "neutral rule carries no classes"},
		{"vendor without evidence", "vendors", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["evidence"] = ""
		}, "evidence is required"},
		{"asn zero", "asn", func(m map[string]any) {
			rulesOf(m, "asns")[0].(map[string]any)["asn"] = 0
		}, "not a valid AS number"},
		{"duplicate asn", "asn", func(m map[string]any) {
			r := rulesOf(m, "asns")
			m["asns"] = append(r, r[0])
		}, "duplicate entry"},
		{"asn without holder", "asn", func(m map[string]any) {
			rulesOf(m, "asns")[0].(map[string]any)["holder"] = ""
		}, "holder and evidence are required"},
		{"asn hint too strong", "asn", func(m map[string]any) {
			rulesOf(m, "asns")[0].(map[string]any)["classes"] = map[string]any{"tv": 0.9}
		}, "at most 0.4"},
		{"shared asn with weight", "asn", func(m map[string]any) {
			for _, a := range rulesOf(m, "asns") {
				if a.(map[string]any)["shared"] == true {
					a.(map[string]any)["classes"] = map[string]any{"tv": 0.1}
					return
				}
			}
		}, "shared network carries no classes"},
		{"duplicate org", "asn", func(m map[string]any) {
			r := rulesOf(m, "orgs")
			m["orgs"] = append(r, r[0])
		}, "duplicate keyword"},
		{"org upper case", "asn", func(m map[string]any) {
			rulesOf(m, "orgs")[0].(map[string]any)["keyword"] = "Netflix"
		}, "lower-case"},
		{"org without evidence", "asn", func(m map[string]any) {
			rulesOf(m, "orgs")[0].(map[string]any)["evidence"] = ""
		}, "evidence is required"},
		{"shared org with label", "asn", func(m map[string]any) {
			for _, a := range rulesOf(m, "orgs") {
				if a.(map[string]any)["shared"] == true {
					a.(map[string]any)["label"] = "x"
					return
				}
			}
		}, "shared network carries no classes"},
		{"org hint too strong", "asn", func(m map[string]any) {
			rulesOf(m, "orgs")[0].(map[string]any)["classes"] = map[string]any{"tv": 0.9}
		}, "at most 0.4"},
		{"service without underscore", "services", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["service"] = "ipp"
		}, "first label of an mDNS type"},
		{"service with dots", "services", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["service"] = "_ipp._tcp"
		}, "first label of an mDNS type"},
		{"duplicate service", "services", func(m map[string]any) {
			r := rulesOf(m, "rules")
			m["rules"] = append(r, r[0])
		}, "duplicate rule"},
		{"service unknown class", "services", func(m map[string]any) {
			rulesOf(m, "rules")[0].(map[string]any)["classes"] = map[string]any{"toaster": 0.5}
		}, "unknown class"},
		{"class not a registry type", "classes", func(m map[string]any) {
			rulesOf(m, "classes")[0].(map[string]any)["id"] = "toaster"
		}, "not a registry device type"},
		{"class without group", "classes", func(m map[string]any) {
			rulesOf(m, "classes")[0].(map[string]any)["group"] = ""
		}, "has no group"},
		{"duplicate class", "classes", func(m map[string]any) {
			r := rulesOf(m, "classes")
			m["classes"] = append(r, r[0])
		}, "listed twice"},
		{"unknown relation", "classes", func(m map[string]any) {
			rulesOf(m, "classes")[0].(map[string]any)["related"] = []any{"toaster"}
		}, "unknown or self relation"},
		{"self relation", "classes", func(m map[string]any) {
			c := rulesOf(m, "classes")[0].(map[string]any)
			c["related"] = []any{c["id"]}
		}, "unknown or self relation"},
		{"too many classes", "classes", func(m map[string]any) {
			r := rulesOf(m, "classes")
			for i := 0; i < 40; i++ {
				r = append(r, r[0])
			}
			m["classes"] = r
		}, "at most 32 classes"},
		{"unknown json field", "domains", func(m map[string]any) { m["surprise"] = true }, "unknown field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRules(mutate(t, tc.which, tc.fn))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRuleFilesMustBeJSON(t *testing.T) {
	for _, which := range []string{"classes", "domains", "vendors", "asn", "services"} {
		f := files(t)
		switch which {
		case "classes":
			f.Classes = []byte("{")
		case "domains":
			f.Domains = []byte("[]")
		case "vendors":
			f.Vendors = []byte(`{"version":1} {"x":1}`)
		case "asn":
			f.ASN = []byte("nope")
		case "services":
			f.Services = []byte("")
		}
		if _, err := ParseRules(f); err == nil || !strings.Contains(err.Error(), which+".json") {
			t.Errorf("%s: want an error naming the file, got %v", which, err)
		}
	}
}

func TestTooManyLabelsAreRejected(t *testing.T) {
	f := mutate(t, "services", func(m map[string]any) {
		var rules []any
		for i := 0; i < 70; i++ {
			rules = append(rules, map[string]any{"service": fmt.Sprintf("_s%d", i), "classes": map[string]any{"printer": 0.5}, "label": fmt.Sprintf("label %d", i)})
		}
		m["rules"] = rules
	})
	if _, err := ParseRules(f); err == nil || !strings.Contains(err.Error(), "distinct labels") {
		t.Errorf("got %v", err)
	}
}

func TestMatchVendorWholeWordsAndLongestRule(t *testing.T) {
	rs := defaultRules(t)
	for name, want := range map[string]string{
		"Sonos":                                 "sonos",
		"Arlo Technology":                       "arlo",
		"Hangzhou Hikvision Digital Technology": "hikvision",
		"Huizhou TCL Communication Electron":    "tcl",
		"Hewlett Packard":                       "hewlett packard",
		"Hewlett Packard Enterprise":            "hewlett packard enterprise",
		"Cisco-Linksys":                         "cisco-linksys",
		"TP-Link Systems":                       "tp-link",
	} {
		r := rs.matchVendor(name)
		if r == nil || r.Match != want {
			got := "<none>"
			if r != nil {
				got = r.Match
			}
			t.Errorf("matchVendor(%q) = %s, want %s", name, got, want)
		}
	}
	for _, name := range []string{"Carlo Gavazzi", "NETCLEUS Systems", "Salutron", "Obscure Widgets", "", "Sonosite"} {
		if r := rs.matchVendor(name); r != nil {
			t.Errorf("matchVendor(%q) = %s, want no match (whole words only)", name, r.Match)
		}
	}
	if r := rs.matchVendor("Hewlett Packard Enterprise"); r == nil || !r.Neutral {
		t.Error("the enterprise company must be neutral, not inherit the printer rule")
	}
}

func TestMatchDomainIsMostSpecificSuffix(t *testing.T) {
	rs := defaultRules(t)
	for host, want := range map[string]string{
		"netflix.com": "netflix.com", "www.netflix.com": "netflix.com", "a.b.c.hik-connect.com": "hik-connect.com",
		"push.apple.com": "push.apple.com", "gateway.push.apple.com": "push.apple.com", "www.apple.com": "apple.com",
		"notnetflix.com": "", "example.com": "", "com": "",
	} {
		r := rs.matchDomain(host)
		got := ""
		if r != nil {
			got = r.Suffix
		}
		if got != want {
			t.Errorf("matchDomain(%q) = %q, want %q", host, got, want)
		}
	}
	if r := rs.matchOrg("Netflix Streaming Services Inc."); r == nil || r.Keyword != "netflix" {
		t.Error("org keyword")
	}
	if r := rs.matchOrg("Bovhorn Telecom"); r != nil {
		t.Errorf("org keywords are whole words, matched %q", r.Keyword)
	}
}
