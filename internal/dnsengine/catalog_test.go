// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// testCatalog is a synthetic catalog: two lists, three apps, an umbrella that
// includes two of them, and two categories.
func testCatalog(t testing.TB) *CatalogSet {
	t.Helper()
	src := func(n string) []Source {
		return []Source{{URL: "https://lists.example/" + n + ".txt", Format: "domains"}}
	}
	c, err := NewCatalogSet([]CatalogEntry{
		{ID: "ads-main", Kind: KindList, Name: "Main ads", Category: "ads", Sources: src("ads-main"), Recommended: true},
		{ID: "ads-extra", Kind: KindList, Name: "Extra ads", Category: "ads", Sources: src("ads-extra")},
		{ID: "app-one", Kind: KindApp, Name: "App One", Category: "social", Sources: src("app-one")},
		{ID: "app-two", Kind: KindApp, Name: "App Two", Category: "social", Sources: src("app-two")},
		{ID: "app-three", Kind: KindApp, Name: "App Three", Category: "games", Sources: src("app-three")},
		{ID: "suite", Kind: KindApp, Name: "Suite", Category: "social", Includes: []string{"app-one", "app-two"}},
		{ID: "social", Kind: KindCategory, Name: "Social", Includes: []string{"suite"}},
		{ID: "everything", Kind: KindCategory, Name: "Everything", Includes: []string{"social", "app-three", "ads-extra"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogSetValidation(t *testing.T) {
	good := CatalogEntry{ID: "a", Kind: KindList, Name: "A", Sources: []Source{{URL: "https://x.example/a"}}}
	bad := map[string][]CatalogEntry{
		"invalid id":      {{ID: "Bad Id", Kind: KindList, Name: "x", Sources: good.Sources}},
		"empty id":        {{ID: "", Kind: KindList, Name: "x", Sources: good.Sources}},
		"dot id":          {{ID: ".hidden", Kind: KindList, Name: "x", Sources: good.Sources}},
		"duplicate":       {good, good},
		"unknown kind":    {{ID: "a", Kind: "weird", Name: "x"}},
		"no name":         {{ID: "a", Kind: KindList, Sources: good.Sources}},
		"non-http":        {{ID: "a", Kind: KindList, Name: "x", Sources: []Source{{URL: "file:///etc/hosts"}}}},
		"category source": {{ID: "a", Kind: KindCategory, Name: "x", Sources: good.Sources, Includes: []string{"a"}}},
		"empty category":  {{ID: "a", Kind: KindCategory, Name: "x"}},
		"list no source":  {{ID: "a", Kind: KindList, Name: "x"}},
		"list includes":   {good, {ID: "b", Kind: KindList, Name: "x", Sources: good.Sources, Includes: []string{"a"}}},
		"empty app":       {{ID: "a", Kind: KindApp, Name: "x"}},
		"unknown include": {good, {ID: "b", Kind: KindCategory, Name: "x", Includes: []string{"zzz"}}},
		"cycle": {
			{ID: "a", Kind: KindCategory, Name: "x", Includes: []string{"b"}},
			{ID: "b", Kind: KindCategory, Name: "x", Includes: []string{"a"}},
		},
	}
	for name, entries := range bad {
		if _, err := NewCatalogSet(entries); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewCatalogSet([]CatalogEntry{good}); err != nil {
		t.Errorf("valid catalog rejected: %v", err)
	}
}

func TestCatalogSetLookupsAndLeaves(t *testing.T) {
	c := testCatalog(t)
	if _, ok := c.ByID("nope"); ok {
		t.Error("unknown id found")
	}
	if e, ok := c.ByID("suite"); !ok || e.Name != "Suite" {
		t.Errorf("ByID(suite) = %+v %v", e, ok)
	}
	if got := c.Recommended(); !slices.Equal(got, []string{"ads-main"}) {
		t.Errorf("Recommended = %v", got)
	}
	cases := map[string][]string{
		"app-one":    {"app-one"},
		"suite":      {"app-one", "app-two"},
		"social":     {"app-one", "app-two"},
		"everything": {"app-one", "app-two", "app-three", "ads-extra"},
		"nope":       nil,
	}
	for id, want := range cases {
		if got := c.Leaves(id); !slices.Equal(got, want) {
			t.Errorf("Leaves(%s) = %v, want %v", id, got, want)
		}
	}
	// An umbrella that also carries sources contributes itself once.
	c2, err := NewCatalogSet([]CatalogEntry{
		{ID: "x", Kind: KindApp, Name: "X", Sources: []Source{{URL: "https://x.example/x"}}},
		{ID: "y", Kind: KindApp, Name: "Y", Sources: []Source{{URL: "https://x.example/y"}}, Includes: []string{"x", "x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := c2.Leaves("y"); !slices.Equal(got, []string{"y", "x"}) {
		t.Errorf("Leaves(y) = %v", got)
	}
	// Entries returns a copy.
	es := c.Entries()
	es[0].Name = "changed"
	if e, _ := c.ByID("ads-main"); e.Name == "changed" {
		t.Error("Entries leaked internal storage")
	}
}

func TestShippedCatalog(t *testing.T) {
	c, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[Kind]int{}
	cats := map[string]bool{}
	for _, e := range c.Entries() {
		counts[e.Kind]++
		if e.Kind == KindCategory {
			cats[e.ID] = true
		}
	}
	if counts[KindList] < 20 || counts[KindApp] < 25 || counts[KindCategory] < 8 {
		t.Errorf("catalog too small: %v", counts)
	}
	for _, e := range c.Entries() {
		if e.License == "" || e.Description == "" {
			t.Errorf("%s: license and description are required", e.ID)
		}
		if _, err := time.Parse("2006-01-02", e.VerifiedAt); err != nil {
			t.Errorf("%s: verified_at %q: %v", e.ID, e.VerifiedAt, err)
		}
		if e.Kind != KindCategory && !cats[e.Category] {
			t.Errorf("%s: category %q is not a category entry", e.ID, e.Category)
		}
		if e.Recommended && e.Kind != KindList {
			t.Errorf("%s: only lists may be recommended", e.ID)
		}
		for _, s := range e.Sources {
			if !strings.HasPrefix(s.URL, "https://") || s.Size <= 0 || s.Format == "" {
				t.Errorf("%s: bad source %+v", e.ID, s)
			}
		}
		if len(e.Sources) > 0 && e.ApproxEntries <= 0 {
			t.Errorf("%s: approx_entries missing", e.ID)
		}
		if e.Kind != KindCategory && len(c.Leaves(e.ID)) == 0 {
			t.Errorf("%s expands to nothing", e.ID)
		}
	}
	if len(c.Recommended()) == 0 {
		t.Error("a fresh install needs recommended items")
	}
	// Lists that also need to pass the manager's protected-domain guard must
	// not be recommended by accident: recommended items are plain lists.
	for _, id := range c.Recommended() {
		if e, _ := c.ByID(id); e.Kind != KindList {
			t.Errorf("recommended %s is not a list", id)
		}
	}
}

func TestCatalogAccessors(t *testing.T) {
	all := Catalog()
	if len(all) == 0 {
		t.Fatal("empty catalog")
	}
	if e, ok := CatalogByID(all[0].ID); !ok || e.ID != all[0].ID {
		t.Errorf("CatalogByID = %+v %v", e, ok)
	}
	if _, ok := CatalogByID("definitely-not-an-id"); ok {
		t.Error("unknown id found")
	}
}

func TestCatalogAccessorsWhenEmbeddedCatalogIsBroken(t *testing.T) {
	_, _ = DefaultCatalog() // make sure the Once has run
	oldC, oldErr := defaultCatalog, defaultCatalogErr
	defer func() { defaultCatalog, defaultCatalogErr = oldC, oldErr }()
	defaultCatalog, defaultCatalogErr = nil, errors.New("broken")
	if Catalog() != nil {
		t.Error("Catalog must be empty when the embedded file is broken")
	}
	if _, ok := CatalogByID("x"); ok {
		t.Error("CatalogByID must miss when the embedded file is broken")
	}
}

func TestLoadCatalogRejectsBadJSON(t *testing.T) {
	if _, err := loadCatalog([]byte("not json")); err == nil {
		t.Error("bad JSON accepted")
	}
	if _, err := loadCatalog([]byte(`[{"id":"a","kind":"list","name":"x"}]`)); err == nil {
		t.Error("invalid catalog accepted")
	}
}
