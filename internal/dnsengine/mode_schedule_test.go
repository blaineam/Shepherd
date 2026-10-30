// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"testing"
	"time"
)

func withClock(f *Filter, now time.Time) *Filter {
	f.clock = func() time.Time { return now }
	return f
}

// ---- Mode: regression (nobody who never touches Mode sees any change) ----

func TestModeDefaultIsBlockRegression(t *testing.T) {
	// A scope that never sets Mode behaves exactly as before: unmatched
	// names are not blocked, and matched ones follow the existing rules.
	f := scopedFilter(t, map[string]ScopeConfig{"network": {Items: on("app-one")}})
	if f.Check("one.example").Blocked == false {
		t.Error("existing block behavior must be unaffected")
	}
	if f.Check("unmatched.example").Blocked {
		t.Error("default mode must not block an unmatched name")
	}
	// The legacy, never-configured filter also defaults to block mode.
	g := NewFilter()
	g.SetList("l", set("a.example"))
	if g.Check("a.example").Blocked == false {
		t.Error("legacy list block must be unaffected")
	}
	if g.Check("unmatched.example").Blocked {
		t.Error("legacy filter must default to block mode")
	}
}

// ---- Mode: allow mode defaults to deny, explicit allow rule still works ----

func TestAllowModeDefaultDeniesEverything(t *testing.T) {
	f := scopedFilter(t, map[string]ScopeConfig{"network": {Mode: ModeAllow}})
	d := f.Check("anything.example")
	if !d.Blocked || d.Scope != "network" || d.Reason == "" {
		t.Errorf("allow mode must default-deny an unmatched name: %+v", d)
	}
	if d.NXDOMAIN {
		t.Error("a default-deny decision need not force NXDOMAIN")
	}
}

func TestAllowModeExplicitAllowRuleWorks(t *testing.T) {
	f := scopedFilter(t, map[string]ScopeConfig{"network": {Mode: ModeAllow, Allow: []string{"ok.example"}}})
	if d := f.Check("ok.example"); d.Blocked {
		t.Errorf("explicit allow must work in allow mode: %+v", d)
	}
	if d := f.Check("deep.sub.ok.example"); d.Blocked {
		t.Error("an allow rule must cover subdomains in allow mode too")
	}
	if d := f.Check("other.example"); !d.Blocked {
		t.Error("everything not explicitly allowed must still be blocked")
	}
}

// ---- Mode: an item or custom list switched on is the allowlist, not the blocklist ----

func TestAllowModeItemSwitchIsTheAllowlist(t *testing.T) {
	f := scopedFilter(t, map[string]ScopeConfig{"network": {Mode: ModeAllow, Items: on("app-one")}})
	if d := f.Check("one.example"); d.Blocked {
		t.Errorf("an item switched on must allow, not block, in allow mode: %+v", d)
	}
	if d := f.Check("two.example"); !d.Blocked {
		t.Error("an item not switched on must still default-deny in allow mode")
	}
	// Opting an item off at a more specific scope still cancels the less
	// specific "on" — the same opt-out mechanism, just read as allow, not block.
	cs := fakeClients{"192.0.2.1": client("kid")}
	g := scopedFilter(t, map[string]ScopeConfig{
		"network":    {Mode: ModeAllow, Items: on("app-one")},
		"device:kid": {Items: map[string]bool{"app-one": false}},
	})
	if d := g.CheckFor("192.0.2.1", "one.example", cs); !d.Blocked {
		t.Error("a device opt-out must still cancel a less specific allow-mode item")
	}
	if d := g.Check("one.example"); d.Blocked {
		t.Error("the opt-out must not leak to a different device")
	}
}

// ---- Mode: scope precedence (device overrides group overrides network) ----

func TestModeScopePrecedence(t *testing.T) {
	cs := fakeClients{
		"192.0.2.1": client("kid", "teens"), // device overrides its own group
		"192.0.2.2": client("", "teens"),    // inherits the group's mode
		"192.0.2.3": client("other"),        // inherits the network's mode
	}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network":     {Mode: ModeBlock, Items: on("app-one")},
		"group:teens": {Mode: ModeAllow, Items: on("app-two")},
		"device:kid":  {Mode: ModeBlock},
	})
	// The device's own Mode wins over its group's.
	if d := f.CheckFor("192.0.2.1", "unmatched.example", cs); d.Blocked {
		t.Errorf("device Mode must override the group's: %+v", d)
	}
	// Without a device override, the group's Mode applies.
	if d := f.CheckFor("192.0.2.2", "unmatched.example", cs); !d.Blocked {
		t.Errorf("group Mode must apply when the device sets none: %+v", d)
	}
	if d := f.CheckFor("192.0.2.2", "two.example", cs); d.Blocked {
		t.Error("group's own item must allow under the group's allow mode")
	}
	// Without any override at all, the network's Mode applies.
	if d := f.CheckFor("192.0.2.3", "unmatched.example", cs); d.Blocked {
		t.Errorf("network Mode must apply with no closer override: %+v", d)
	}
}

func TestModeSiblingGroupTieBreakIsDeterministic(t *testing.T) {
	// A device in two groups with different explicit Mode: the group named
	// first by ClientScopes decides (documented in docs/POLICY.md). This
	// locks in that specific, documented, deterministic choice: "first"'s
	// allow mode wins, so an unmatched name default-denies, scoped to it.
	cs := fakeClients{"192.0.2.1": client("", "first", "second")}
	f := scopedFilter(t, map[string]ScopeConfig{
		"group:first":  {Mode: ModeAllow},
		"group:second": {Mode: ModeBlock},
	})
	d := f.CheckFor("192.0.2.1", "unmatched.example", cs)
	if !d.Blocked || d.Scope != "group:first" {
		t.Errorf("the first-listed group's Mode must win: %+v", d)
	}
	// Reversing the order reverses the winner.
	cs2 := fakeClients{"192.0.2.1": client("", "second", "first")}
	if d := f.CheckFor("192.0.2.1", "unmatched.example", cs2); d.Blocked {
		t.Errorf("with second listed first, its block mode must win: %+v", d)
	}
}

// ---- The preserved block-vs-allow precedence, in both modes ----

func TestPrecedencePreservedInBlockMode(t *testing.T) {
	// Mirrors TestAllowOverridesAndPrecedence's documented rule directly:
	// same scope, allow beats block; a more specific block beats a less
	// specific allow; a more specific allow beats a less specific block.
	cs := fakeClients{"192.0.2.1": client("dev", "g")}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network":    {Allow: []string{"a.example"}},
		"group:g":    {Block: []string{"a.example"}},
		"device:dev": {},
	})
	if d := f.CheckFor("192.0.2.1", "a.example", cs); !d.Blocked || d.Scope != "group:g" {
		t.Errorf("a more specific block must beat a less specific allow: %+v", d)
	}
	g := scopedFilter(t, map[string]ScopeConfig{
		"network": {Allow: []string{"b.example"}, Block: []string{"b.example"}},
	})
	if d := g.Check("b.example"); d.Blocked {
		t.Errorf("an allow must beat a block at the very same scope: %+v", d)
	}
	h := scopedFilter(t, map[string]ScopeConfig{
		"network":    {Block: []string{"c.example"}},
		"device:dev": {Allow: []string{"c.example"}},
	})
	if d := h.CheckFor("192.0.2.1", "c.example", cs); d.Blocked {
		t.Errorf("a more specific allow must beat a less specific block: %+v", d)
	}
}

func TestPrecedencePreservedInAllowMode(t *testing.T) {
	// The same three rules, restated with an item switch standing in for the
	// "block" side at a scope that is itself in allow mode (item on = allow),
	// and an explicit Block rule as the override.
	cs := fakeClients{"192.0.2.1": client("dev", "g")}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network": {Mode: ModeAllow, Items: on("app-one")}, // one.example allowed network-wide
		"group:g": {Block: []string{"one.example"}},        // but the group blocks it
	})
	if d := f.CheckFor("192.0.2.1", "one.example", cs); !d.Blocked || d.Scope != "group:g" {
		t.Errorf("a more specific block must beat a less specific allow-mode item: %+v", d)
	}
	// Same scope: an explicit allow beats a block at that very scope, even
	// though the scope is in allow mode (the item match and the allow rule
	// would agree here, but the rule alone must already be enough).
	g := scopedFilter(t, map[string]ScopeConfig{
		"network": {Mode: ModeAllow, Allow: []string{"x.example"}, Block: []string{"x.example"}},
	})
	if d := g.Check("x.example"); d.Blocked {
		t.Errorf("an allow must beat a block at the very same scope in allow mode too: %+v", d)
	}
	// A more specific allow-mode item beats a less specific block.
	h := scopedFilter(t, map[string]ScopeConfig{
		"network":    {Block: []string{"two.example"}},
		"device:dev": {Mode: ModeAllow, Items: on("app-two")},
	})
	if d := h.CheckFor("192.0.2.1", "two.example", cs); d.Blocked {
		t.Errorf("a more specific allow-mode item must beat a less specific block: %+v", d)
	}
}

// ---- Schedule: validation and Active ----

func TestScheduleValidate(t *testing.T) {
	valid := Schedule{Days: []time.Weekday{time.Monday}, StartMin: 60, EndMin: 120}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid schedule rejected: %v", err)
	}
	cases := map[string]Schedule{
		"no days":        {StartMin: 0, EndMin: 60},
		"repeated day":   {Days: []time.Weekday{time.Monday, time.Monday}, StartMin: 0, EndMin: 60},
		"bad weekday":    {Days: []time.Weekday{7}, StartMin: 0, EndMin: 60},
		"negative start": {Days: []time.Weekday{time.Monday}, StartMin: -1, EndMin: 60},
		"end over 1440":  {Days: []time.Weekday{time.Monday}, StartMin: 0, EndMin: 1441},
		"start == end":   {Days: []time.Weekday{time.Monday}, StartMin: 60, EndMin: 60},
		"start > end (overnight, must split into two)": {Days: []time.Weekday{time.Monday}, StartMin: 120, EndMin: 60},
	}
	for name, sch := range cases {
		if err := sch.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScheduleActive(t *testing.T) {
	sch := Schedule{Days: []time.Weekday{time.Monday, time.Wednesday}, StartMin: 9 * 60, EndMin: 17 * 60}
	cases := []struct {
		name string
		t    time.Time
		want bool
	}{
		{"inside, Monday 10:00", time.Date(2024, 1, 1, 10, 0, 0, 0, time.Local), true}, // 2024-01-01 is a Monday
		{"wrong day, Tuesday 10:00", time.Date(2024, 1, 2, 10, 0, 0, 0, time.Local), false},
		{"before the window", time.Date(2024, 1, 1, 8, 59, 0, 0, time.Local), false},
		{"at the start, inclusive", time.Date(2024, 1, 1, 9, 0, 0, 0, time.Local), true},
		{"at the end, exclusive", time.Date(2024, 1, 1, 17, 0, 0, 0, time.Local), false},
		{"one minute before the end", time.Date(2024, 1, 1, 16, 59, 0, 0, time.Local), true},
		{"a different active day, Wednesday", time.Date(2024, 1, 3, 12, 0, 0, 0, time.Local), true},
	}
	for _, c := range cases {
		if got := sch.Active(c.t); got != c.want {
			t.Errorf("%s: Active = %v, want %v", c.name, got, c.want)
		}
	}
}

// ---- Schedule: in/out of window for a block rule and an allow rule ----

func TestScheduledBlockRuleInAndOutOfWindow(t *testing.T) {
	sch := Schedule{Days: []time.Weekday{time.Monday}, StartMin: 9 * 60, EndMin: 17 * 60}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network": {Block: []string{"scheduled.example"}, BlockSchedules: map[string]Schedule{"scheduled.example": sch}},
	})
	inWindow := time.Date(2024, 1, 1, 10, 0, 0, 0, time.Local)    // Monday 10:00
	outOfWindow := time.Date(2024, 1, 1, 20, 0, 0, 0, time.Local) // Monday 20:00
	withClock(f, inWindow)
	if d := f.Check("scheduled.example"); !d.Blocked || d.Reason != "custom rule" {
		t.Errorf("block rule must apply inside its schedule: %+v", d)
	}
	if d := f.Check("sub.scheduled.example"); !d.Blocked {
		t.Error("a scheduled block rule must still cover subdomains inside its window")
	}
	withClock(f, outOfWindow)
	if d := f.Check("scheduled.example"); d.Blocked {
		t.Errorf("a block rule outside its schedule must be inert: %+v", d)
	}
}

func TestScheduledAllowRuleInAndOutOfWindow(t *testing.T) {
	sch := Schedule{Days: []time.Weekday{time.Monday}, StartMin: 9 * 60, EndMin: 17 * 60}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network": {Block: []string{"scheduled.example"}},
		"device:kid": {
			Allow: []string{"scheduled.example"}, AllowSchedules: map[string]Schedule{"scheduled.example": sch},
		},
	})
	cs := fakeClients{"192.0.2.1": client("kid")}
	inWindow := time.Date(2024, 1, 1, 10, 0, 0, 0, time.Local)
	outOfWindow := time.Date(2024, 1, 1, 20, 0, 0, 0, time.Local)
	withClock(f, inWindow)
	if d := f.CheckFor("192.0.2.1", "scheduled.example", cs); d.Blocked {
		t.Errorf("allow rule must apply inside its schedule: %+v", d)
	}
	withClock(f, outOfWindow)
	if d := f.CheckFor("192.0.2.1", "scheduled.example", cs); !d.Blocked || d.Scope != "network" {
		t.Errorf("outside its schedule the allow rule must be inert, falling back to the network block: %+v", d)
	}
}

// A less specific ancestor rule without a schedule must still apply when a
// more specific ancestor's own schedule is inert right now.
func TestScheduleFallsThroughToLessSpecificAncestorRule(t *testing.T) {
	sch := Schedule{Days: []time.Weekday{time.Monday}, StartMin: 9 * 60, EndMin: 17 * 60}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network": {
			Block:          []string{"example.com", "sub.example.com"},
			BlockSchedules: map[string]Schedule{"sub.example.com": sch}, // example.com itself always blocks
		},
	})
	withClock(f, time.Date(2024, 1, 1, 20, 0, 0, 0, time.Local)) // outside sub.example.com's window
	if d := f.Check("deep.sub.example.com"); !d.Blocked {
		t.Error("the less specific always-on ancestor rule must still apply")
	}
}

// ---- Combined: a scheduled rule inside an allowlist-mode scope ----

func TestScheduledAllowRuleInsideAllowlistModeScope(t *testing.T) {
	sch := Schedule{Days: []time.Weekday{time.Monday}, StartMin: 9 * 60, EndMin: 17 * 60}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network": {
			Mode: ModeAllow, Allow: []string{"homework.example"}, AllowSchedules: map[string]Schedule{"homework.example": sch},
		},
	})
	withClock(f, time.Date(2024, 1, 1, 10, 0, 0, 0, time.Local))
	if d := f.Check("homework.example"); d.Blocked {
		t.Errorf("the scheduled allow must work inside its window in allow mode: %+v", d)
	}
	if d := f.Check("anything-else.example"); !d.Blocked {
		t.Error("allow mode must still default-deny everything else")
	}
	withClock(f, time.Date(2024, 1, 1, 20, 0, 0, 0, time.Local))
	if d := f.Check("homework.example"); !d.Blocked || d.Reason == "" {
		t.Errorf("outside its window the allow is inert, so allow mode's default-deny must apply: %+v", d)
	}
}

func TestScheduledItemInsideAllowlistModeScope(t *testing.T) {
	// A catalog item has no per-domain schedule of its own (v1 scope), but a
	// scheduled allow rule and an always-on allow-mode item must compose:
	// the rule governs its own domain, the item governs everything else it
	// lists, independent of each other.
	sch := Schedule{Days: []time.Weekday{time.Monday}, StartMin: 9 * 60, EndMin: 17 * 60}
	f := scopedFilter(t, map[string]ScopeConfig{
		"network": {
			Mode: ModeAllow, Items: on("app-one"),
			Allow: []string{"homework.example"}, AllowSchedules: map[string]Schedule{"homework.example": sch},
		},
	})
	withClock(f, time.Date(2024, 1, 1, 20, 0, 0, 0, time.Local)) // outside homework's window
	if d := f.Check("one.example"); d.Blocked {
		t.Error("the always-on item allow must be unaffected by the rule's schedule")
	}
	if d := f.Check("homework.example"); !d.Blocked {
		t.Error("the scheduled allow rule must still be inert outside its window")
	}
}
