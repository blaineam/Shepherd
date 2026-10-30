// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func openStore(t *testing.T, opts PolicyOptions) (*PolicyStore, *Filter, string) {
	t.Helper()
	if opts.Catalog == nil {
		opts.Catalog = testCatalog(t)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	f := NewFilter()
	s, err := OpenPolicyStore(path, f, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, path
}

func loadTestLists(f *Filter) {
	f.SetList("ads-main", set("ads.example"))
	f.SetList("ads-extra", set("extra.example"))
	f.SetList("app-one", set("one.example"))
	f.SetList("app-two", set("two.example"))
	f.SetList("app-three", set("three.example"))
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestFreshInstallIsProtectedOptOut(t *testing.T) {
	s, f, path := openStore(t, PolicyOptions{})
	loadTestLists(f)
	if !f.Check("ads.example").Blocked {
		t.Error("recommended list must be on at first run")
	}
	if f.Check("extra.example").Blocked || f.Check("one.example").Blocked {
		t.Error("non-recommended items must start off")
	}
	if d := f.Check("mask.icloud.com"); !d.Blocked || !d.NXDOMAIN {
		t.Errorf("private relay policy must default on: %+v", d)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("policy.json mode = %v, %v", info.Mode(), err)
	}
	if want := []string{"ads-main"}; !slices.Equal(idsOf(s.WantedLists()), want) {
		t.Errorf("wanted = %v, want %v", idsOf(s.WantedLists()), want)
	}
	if s.Catalog() == nil {
		t.Error("Catalog accessor")
	}
}

func idsOf(specs []ListSpec) []string {
	var ids []string
	for _, sp := range specs {
		ids = append(ids, sp.ID)
	}
	return ids
}

func TestStoreScenarioMatrix(t *testing.T) {
	s, f, _ := openStore(t, PolicyOptions{})
	loadTestLists(f)
	cs := fakeClients{
		"192.0.2.1": client("console", "teens"),
		"192.0.2.2": client("laptop"),
	}
	net, teens, console := NetworkScope(), GroupScope("teens"), DeviceScope("console")

	// Network blocks one app; a group blocks another.
	mustOK(t, s.SetItem(net, "app-one", true))
	mustOK(t, s.SetItem(teens, "app-two", true))
	expect(t, f, cs, "192.0.2.2", "one.example", true, "app-one", "network")
	expect(t, f, cs, "192.0.2.2", "two.example", false, "", "")
	expect(t, f, cs, "192.0.2.1", "two.example", true, "app-two", "group:teens")

	// An umbrella and a category switch every leaf at that scope.
	mustOK(t, s.SetItem(console, "social", true))
	expect(t, f, cs, "192.0.2.1", "one.example", true, "app-one", "device:console")
	expect(t, f, cs, "192.0.2.2", "two.example", false, "", "")

	// A device is allowed an override: allow rule, then an item opt-out.
	mustOK(t, s.AddRule(console, "allow", "one.example"))
	expect(t, f, cs, "192.0.2.1", "one.example", false, "allowlist", "device:console")
	expect(t, f, cs, "192.0.2.2", "one.example", true, "app-one", "network")
	mustOK(t, s.SetItem(console, "app-two", false)) // leaf off beats the umbrella on
	expect(t, f, cs, "192.0.2.1", "two.example", false, "", "")

	// Disabling an item at one scope does not affect the others.
	mustOK(t, s.SetItem(teens, "app-two", false))
	expect(t, f, cs, "192.0.2.1", "two.example", false, "", "")
	expect(t, f, cs, "192.0.2.2", "one.example", true, "app-one", "network")
	mustOK(t, s.ClearItem(console, "app-two"))
	expect(t, f, cs, "192.0.2.1", "two.example", true, "app-two", "device:console")

	// A scope-level policy switch, then inherit again.
	mustOK(t, s.SetPolicy(console, PolicyPrivateRelay, false))
	if f.CheckFor("192.0.2.1", "mask.icloud.com", cs).Blocked || !f.CheckFor("192.0.2.2", "mask.icloud.com", cs).Blocked {
		t.Error("device policy opt-out wrong")
	}
	mustOK(t, s.ClearPolicy(console, PolicyPrivateRelay))
	if !f.CheckFor("192.0.2.1", "mask.icloud.com", cs).Blocked {
		t.Error("cleared policy must inherit the network switch")
	}

	// Forgetting a device removes its settings.
	mustOK(t, s.DeleteScope(console))
	expect(t, f, cs, "192.0.2.1", "one.example", true, "app-one", "network")
	mustOK(t, s.DeleteScope(teens))
	if err := s.DeleteScope(net); err == nil {
		t.Error("the network scope must not be deletable")
	}
}

func TestStoreCategoryExpansionRules(t *testing.T) {
	s, f, _ := openStore(t, PolicyOptions{})
	loadTestLists(f)
	net := NetworkScope()
	// Off wins between two containers that share a leaf.
	mustOK(t, s.SetItem(net, "everything", true))
	mustOK(t, s.SetItem(net, "suite", false))
	for name, want := range map[string]bool{"one.example": false, "two.example": false, "three.example": true, "extra.example": true} {
		if got := f.Check(name).Blocked; got != want {
			t.Errorf("%s blocked=%v want %v", name, got, want)
		}
	}
	// A leaf beats every container.
	mustOK(t, s.SetItem(net, "app-one", true))
	if !f.Check("one.example").Blocked || f.Check("two.example").Blocked {
		t.Error("leaf switch must beat the umbrella")
	}
	// Stale or unknown IDs in a file are ignored when expanding.
	if got := s.expandItems(map[string]bool{"gone": true}, nil); len(got) != 0 {
		t.Errorf("unknown id expanded to %v", got)
	}
}

func TestCustomInlineListEndToEnd(t *testing.T) {
	s, f, path := openStore(t, PolicyOptions{})
	var changes atomic.Int32
	s.OnChange(func() { changes.Add(1) })
	cl, err := s.AddCustomList(CustomListInput{Name: "My Block List!", Category: " chores ", Inline: "# mine\nbad.example\n0.0.0.0 worse.example\n"})
	mustOK(t, err)
	if cl.ID != "custom-my-block-list" || cl.Category != "chores" || changes.Load() != 1 {
		t.Errorf("created %+v, changes %d", cl, changes.Load())
	}
	specs := s.WantedLists()
	if !slices.Contains(idsOf(specs), cl.ID) {
		t.Fatalf("custom list not wanted: %v", idsOf(specs))
	}
	m := NewScopedListManager(f, s, t.TempDir(), nil)
	m.LoadCached() // inline lists need no download
	if d := f.Check("x.bad.example"); !d.Blocked || d.Reason != cl.ID || d.Scope != "network" {
		t.Errorf("inline list not applied: %+v", d)
	}
	// A second list with the same name gets a distinct ID and a URL source.
	cl2, err := s.AddCustomList(CustomListInput{Name: "My Block List!", URL: "https://lists.example/x.txt", Scope: GroupScope("g1")})
	mustOK(t, err)
	if cl2.ID != "custom-my-block-list-2" || cl2.Category != "custom" {
		t.Errorf("second list = %+v", cl2)
	}
	// Persisted and reloaded.
	s2, err := OpenPolicyStore(path, NewFilter(), PolicyOptions{Catalog: testCatalog(t)})
	mustOK(t, err)
	if snap := s2.Snapshot(); len(snap.Custom) != 2 || !snap.Network.Items[cl.ID] || !snap.Groups["g1"].Items[cl2.ID] {
		t.Errorf("reloaded snapshot wrong: %+v", snap)
	}
	// Removing it clears every switch.
	mustOK(t, s.RemoveCustomList(cl.ID))
	mustOK(t, s.RemoveCustomList(cl2.ID))
	if snap := s.Snapshot(); len(snap.Custom) != 0 || snap.Network.Items[cl.ID] || snap.Groups["g1"].Items[cl2.ID] {
		t.Errorf("custom list traces remain: %+v", snap)
	}
	if err := s.RemoveCustomList(cl.ID); err == nil {
		t.Error("removing an unknown list succeeded")
	}
	m.Sync()
	if f.Check("x.bad.example").Blocked {
		t.Error("removed custom list still blocks after sync")
	}
}

func TestStoreValidation(t *testing.T) {
	s, _, _ := openStore(t, PolicyOptions{ExtraProtected: []string{"home.example"}})
	net := NetworkScope()
	bigInline := strings.Repeat("a.example\n", maxInlineBytes/8)
	errs := map[string]error{
		"unknown item":      s.SetItem(net, "nope", true),
		"bad scope id":      s.SetItem(GroupScope("bad id"), "app-one", true),
		"bad scope kind":    s.SetItem(Scope{Kind: "weird", ID: "x"}, "app-one", true),
		"clear bad scope":   s.ClearItem(Scope{Kind: "weird"}, "app-one"),
		"unknown policy":    s.SetPolicy(net, "nope", true),
		"policy bad scope":  s.SetPolicy(Scope{Kind: "weird"}, PolicyPrivateRelay, true),
		"clear policy bad":  s.ClearPolicy(Scope{Kind: "weird"}, PolicyPrivateRelay),
		"bad domain":        s.AddRule(net, "block", "not a domain"),
		"bad rule kind":     s.AddRule(net, "maybe", "ok.example"),
		"rule bad scope":    s.AddRule(Scope{Kind: "weird"}, "block", "ok.example"),
		"remove bad kind":   s.RemoveRule(net, "maybe", "ok.example"),
		"remove bad scope":  s.RemoveRule(Scope{Kind: "weird"}, "block", "ok.example"),
		"delete bad scope":  s.DeleteScope(Scope{Kind: "weird"}),
		"no name":           addErr(s, CustomListInput{URL: "https://lists.example/x"}),
		"long name":         addErr(s, CustomListInput{Name: strings.Repeat("n", 81), URL: "https://lists.example/x"}),
		"long category":     addErr(s, CustomListInput{Name: "n", Category: strings.Repeat("c", 41), URL: "https://lists.example/x"}),
		"neither":           addErr(s, CustomListInput{Name: "n"}),
		"both":              addErr(s, CustomListInput{Name: "n", URL: "https://lists.example/x", Inline: "a.example"}),
		"file url":          addErr(s, CustomListInput{Name: "n", URL: "file:///etc/hosts"}),
		"junk url":          addErr(s, CustomListInput{Name: "n", URL: "http://[::1"}),
		"no host":           addErr(s, CustomListInput{Name: "n", URL: "https:///x"}),
		"empty inline":      addErr(s, CustomListInput{Name: "n", Inline: "# nothing\n"}),
		"protected inline":  addErr(s, CustomListInput{Name: "n", Inline: "google.com\nfine.example\n"}),
		"extra protected":   addErr(s, CustomListInput{Name: "n", Inline: "home.example\n"}),
		"oversized inline":  addErr(s, CustomListInput{Name: "n", Inline: bigInline + "z"}),
		"unparsable inline": addErr(s, CustomListInput{Name: "n", Inline: strings.Repeat("a", 2<<20)[:maxInlineBytes-1] + "\n"}),
		"custom bad scope":  addErr(s, CustomListInput{Name: "n", Inline: "a.example", Scope: Scope{Kind: "weird"}}),
	}
	for name, err := range errs {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Valid edits still work and rules normalise.
	mustOK(t, s.AddRule(net, "block", "  Mixed.Example. "))
	mustOK(t, s.AddRule(net, "block", "mixed.example"))
	if snap := s.Snapshot(); !slices.Equal(snap.Network.Block, []string{"mixed.example"}) {
		t.Errorf("rules = %v", snap.Network.Block)
	}
	mustOK(t, s.AddRule(net, "allow", "mixed.example")) // moves to allow
	snap := s.Snapshot()
	if len(snap.Network.Block) != 0 || !slices.Equal(snap.Network.Allow, []string{"mixed.example"}) {
		t.Errorf("allow/block = %v / %v", snap.Network.Allow, snap.Network.Block)
	}
	mustOK(t, s.RemoveRule(net, "allow", "MIXED.example"))
	if len(s.Snapshot().Network.Allow) != 0 {
		t.Error("RemoveRule failed")
	}
}

func addErr(s *PolicyStore, in CustomListInput) error {
	_, err := s.AddCustomList(in)
	return err
}

func TestRuleLimit(t *testing.T) {
	s, _, _ := openStore(t, PolicyOptions{})
	d := s.data.clone()
	for i := 0; i < maxRulesPerKind; i++ {
		d.Network.Block = append(d.Network.Block, strings.Repeat("a", 1+i%50)+itoa(i)+".example")
	}
	s.data = d
	if err := s.AddRule(NetworkScope(), "block", "one-too-many.example"); err == nil {
		t.Error("rule limit not enforced")
	}
	// Re-adding an existing rule at the limit is fine.
	if err := s.AddRule(NetworkScope(), "block", d.Network.Block[0]); err != nil {
		t.Errorf("re-adding at the limit: %v", err)
	}
}

func TestStoreRenameFailureChangesNothing(t *testing.T) {
	s, _, path := openStore(t, PolicyOptions{})
	mustOK(t, os.Remove(path))
	mustOK(t, os.MkdirAll(filepath.Join(path, "x"), 0o750)) // a non-empty directory cannot be replaced by rename
	if err := s.SetItem(NetworkScope(), "app-one", true); err == nil {
		t.Error("rename failure not reported")
	}
}

func TestStoreSaveFailureChangesNothing(t *testing.T) {
	s, f, _ := openStore(t, PolicyOptions{})
	loadTestLists(f)
	blocker := filepath.Join(t.TempDir(), "file")
	mustOK(t, os.WriteFile(blocker, []byte("x"), 0o600))
	s.path = filepath.Join(blocker, "policy.json") // a directory cannot be made under a file
	var changes atomic.Int32
	s.OnChange(func() { changes.Add(1) })
	if err := s.SetItem(NetworkScope(), "app-one", true); err == nil {
		t.Fatal("save failure not reported")
	}
	if f.Check("one.example").Blocked || changes.Load() != 0 || s.Snapshot().Network.Items["app-one"] {
		t.Error("a failed save must change nothing")
	}
}

func TestOpenPolicyStoreErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	cases := map[string]string{
		"not json":      "{",
		"wrong version": `{"version": 99}`,
		"bad group id":  `{"version":1,"groups":{"bad id":{}}}`,
		"bad device id": `{"version":1,"devices":{"bad id":{}}}`,
		"bad custom id": `{"version":1,"custom_lists":[{"id":"Bad Id"}]}`,
	}
	for name, body := range cases {
		mustOK(t, os.WriteFile(bad, []byte(body), 0o600))
		if _, err := OpenPolicyStore(bad, NewFilter(), PolicyOptions{Catalog: testCatalog(t)}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A directory where the file should be is a read error, not a fresh install.
	if _, err := OpenPolicyStore(dir, NewFilter(), PolicyOptions{Catalog: testCatalog(t)}); err == nil {
		t.Error("unreadable path accepted")
	}
	// First-run write failure.
	blocker := filepath.Join(dir, "file")
	mustOK(t, os.WriteFile(blocker, []byte("x"), 0o600))
	if _, err := OpenPolicyStore(filepath.Join(blocker, "policy.json"), NewFilter(), PolicyOptions{Catalog: testCatalog(t)}); err == nil {
		t.Error("seed write failure accepted")
	}
	// A broken legacy rules.json fails the migration.
	mustOK(t, os.WriteFile(bad, []byte("{"), 0o600))
	_, err := OpenPolicyStore(filepath.Join(dir, "p.json"), NewFilter(), PolicyOptions{Catalog: testCatalog(t), Legacy: &LegacyConfig{RulesPath: bad}})
	if err == nil {
		t.Error("broken legacy rules accepted")
	}
	// The shipped catalog is the default.
	s, err := OpenPolicyStore(filepath.Join(dir, "shipped.json"), NewFilter(), PolicyOptions{})
	mustOK(t, err)
	if len(s.Snapshot().Catalog) == 0 {
		t.Error("default catalog not used")
	}
}

func TestOpenPolicyStoreDefaultCatalogError(t *testing.T) {
	_, _ = DefaultCatalog()
	oldC, oldErr := defaultCatalog, defaultCatalogErr
	defer func() { defaultCatalog, defaultCatalogErr = oldC, oldErr }()
	defaultCatalog, defaultCatalogErr = nil, os.ErrInvalid
	if _, err := OpenPolicyStore(filepath.Join(t.TempDir(), "p.json"), NewFilter(), PolicyOptions{}); err == nil {
		t.Error("broken catalog accepted")
	}
}

func TestMigrateLegacyRulesJSON(t *testing.T) {
	dir := t.TempDir()
	cat := testCatalog(t)
	rules := filepath.Join(dir, "rules.json")
	mustOK(t, os.WriteFile(rules, []byte(`{
		"allow": ["Allowed.example", "not a domain", "allowed.example"],
		"block": ["blocked.example"],
		"policies": {"apple-private-relay": false, "unknown-policy": true}
	}`), 0o600))
	// One legacy list is a catalog source, one is not.
	known, _ := cat.ByID("ads-extra")
	legacy := LegacyConfig{
		RulesPath:         rules,
		BlockPrivateRelay: true, // the config says on, but rules.json says off and wins
		Lists: []ListConfig{
			{Name: "renamed-extra", URL: known.Sources[0].URL},
			{Name: "Home Brew", URL: "https://lists.example/brew.txt"},
		},
	}
	f := NewFilter()
	path := filepath.Join(dir, "policy.json")
	s, err := OpenPolicyStore(path, f, PolicyOptions{Catalog: cat, Legacy: &legacy})
	mustOK(t, err)
	loadTestLists(f)
	f.SetList("custom-home-brew", set("brew.example"))

	snap := s.Snapshot()
	if !slices.Equal(snap.Network.Allow, []string{"allowed.example"}) || !slices.Equal(snap.Network.Block, []string{"blocked.example"}) {
		t.Errorf("rules lost in migration: allow=%v block=%v", snap.Network.Allow, snap.Network.Block)
	}
	if snap.Network.Policies[PolicyPrivateRelay] {
		t.Error("rules.json policy choice must beat the config default")
	}
	if _, junk := snap.Network.Policies["unknown-policy"]; junk {
		t.Error("unknown policy migrated")
	}
	for _, id := range []string{"ads-main", "ads-extra", "custom-home-brew"} {
		if !snap.Network.Items[id] {
			t.Errorf("%s not enabled after migration", id)
		}
	}
	if len(snap.Custom) != 1 || snap.Custom[0].URL != "https://lists.example/brew.txt" || snap.Custom[0].Name != "Home Brew" {
		t.Errorf("custom lists = %+v", snap.Custom)
	}
	if !f.Check("blocked.example").Blocked || f.Check("allowed.example").Blocked || f.Check("mask.icloud.com").Blocked {
		t.Error("migrated rules not applied")
	}
	if !f.Check("brew.example").Blocked || !f.Check("extra.example").Blocked {
		t.Error("migrated lists not applied")
	}
	if _, err := os.Stat(rules); err != nil {
		t.Error("migration must leave rules.json in place")
	}
	// The second start reads policy.json, not the legacy files: edits stick.
	mustOK(t, os.Remove(rules))
	mustOK(t, s.RemoveRule(NetworkScope(), "block", "blocked.example"))
	s2, err := OpenPolicyStore(path, NewFilter(), PolicyOptions{Catalog: cat, Legacy: &legacy})
	mustOK(t, err)
	if len(s2.Snapshot().Network.Block) != 0 {
		t.Error("legacy data was re-imported over policy.json")
	}
}

func TestMigrateLegacyWithoutRulesFile(t *testing.T) {
	cat := testCatalog(t)
	d, err := MigrateLegacy(cat, LegacyConfig{RulesPath: filepath.Join(t.TempDir(), "absent.json"), BlockPrivateRelay: false})
	mustOK(t, err)
	if d.Network.Policies[PolicyPrivateRelay] || !d.Network.Items["ads-main"] {
		t.Errorf("migration without rules.json: %+v", d.Network)
	}
	// No rules path at all is fine too, and an unreadable one is an error.
	if _, err := MigrateLegacy(cat, LegacyConfig{}); err != nil {
		t.Error(err)
	}
	if _, err := MigrateLegacy(cat, LegacyConfig{RulesPath: t.TempDir()}); err == nil {
		t.Error("a directory as rules.json accepted")
	}
}

func TestSlugAndUniqueIDs(t *testing.T) {
	cases := map[string]string{"Hello World": "hello-world", "  --x--  ": "x", "!!!": "list", strings.Repeat("ab ", 30): "ab-ab-ab-ab-ab-ab-ab-ab-ab-ab-ab-ab-ab-a"}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
	if got := slug(strings.Repeat("a", 39) + " b"); got != strings.Repeat("a", 39) {
		t.Errorf("slug trimmed badly: %q", got)
	}
	existing := []CustomList{{ID: "custom-x"}, {ID: "custom-x-2"}}
	if got := uniqueCustomID(existing, "x"); got != "custom-x-3" {
		t.Errorf("unique id = %q", got)
	}
}

func TestSnapshotIsADeepCopy(t *testing.T) {
	s, _, _ := openStore(t, PolicyOptions{})
	mustOK(t, s.SetItem(GroupScope("g"), "app-one", true))
	snap := s.Snapshot()
	snap.Network.Items["app-three"] = true
	snap.Groups["g"].Items["app-two"] = true
	snap.Catalog[0].Name = "changed"
	again := s.Snapshot()
	if again.Network.Items["app-three"] || again.Groups["g"].Items["app-two"] || again.Catalog[0].Name == "changed" {
		t.Error("snapshot aliases internal state")
	}
	if !slices.Contains(again.Policies, PolicyPrivateRelay) {
		t.Error("known policies missing from the snapshot")
	}
}

func TestWantedListsSkipsDisabledAndMergesScopes(t *testing.T) {
	s, _, _ := openStore(t, PolicyOptions{})
	mustOK(t, s.SetItem(NetworkScope(), "ads-main", false)) // opted out everywhere
	if len(s.WantedLists()) != 0 {
		t.Errorf("a list off at every scope must not be fetched: %v", idsOf(s.WantedLists()))
	}
	mustOK(t, s.SetItem(DeviceScope("d1"), "suite", true))
	mustOK(t, s.SetItem(GroupScope("g1"), "app-two", true))
	mustOK(t, s.SetItem(GroupScope("g2"), "app-three", false))
	specs := s.WantedLists()
	if got := idsOf(specs); !slices.Equal(got, []string{"app-one", "app-two"}) {
		t.Errorf("wanted = %v", got)
	}
	if specs[0].Name != "App One" || len(specs[0].Sources) != 1 || specs[0].Sources[0].Format != "domains" {
		t.Errorf("spec = %+v", specs[0])
	}
	// A custom list that exists in the data but is not enabled anywhere is not wanted.
	cl, err := s.AddCustomList(CustomListInput{Name: "c", Inline: "x.example"})
	mustOK(t, err)
	mustOK(t, s.SetItem(NetworkScope(), cl.ID, false))
	if slices.Contains(idsOf(s.WantedLists()), cl.ID) {
		t.Error("disabled custom list wanted")
	}
}

func TestStoreConcurrentEdits(t *testing.T) {
	s, f, _ := openStore(t, PolicyOptions{})
	loadTestLists(f)
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				_ = s.SetItem(NetworkScope(), "app-one", j%2 == 0)
				_ = s.AddRule(DeviceScope("d"), "block", "r"+itoa(j)+".example")
				_ = s.Snapshot()
				f.Check("one.example")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}
