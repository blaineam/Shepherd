// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestStoreSetAndClearMode(t *testing.T) {
	s, f, _ := openStore(t, PolicyOptions{})
	loadTestLists(f)
	net := NetworkScope()
	mustOK(t, s.SetMode(net, ModeAllow))
	if snap := s.Snapshot(); snap.Network.Mode != ModeAllow {
		t.Errorf("mode = %q, want allow", snap.Network.Mode)
	}
	if d := f.Check("unmatched.example"); !d.Blocked {
		t.Error("allow mode must be applied to the filter")
	}
	mustOK(t, s.ClearMode(net))
	if snap := s.Snapshot(); snap.Network.Mode != "" {
		t.Errorf("mode after clear = %q, want empty", snap.Network.Mode)
	}
	if d := f.Check("unmatched.example"); d.Blocked {
		t.Error("clearing mode must restore block-mode default")
	}
	if err := s.SetMode(net, "sideways"); err == nil {
		t.Error("an invalid mode was accepted")
	}
	if err := s.SetMode(Scope{Kind: "weird"}, ModeAllow); err == nil {
		t.Error("SetMode accepted a bad scope")
	}
	if err := s.ClearMode(Scope{Kind: "weird"}); err == nil {
		t.Error("ClearMode accepted a bad scope")
	}
}

func TestStoreAddScheduledRuleAndClearsOnOverwrite(t *testing.T) {
	s, f, path := openStore(t, PolicyOptions{})
	loadTestLists(f)
	net := NetworkScope()
	sch := Schedule{Days: []time.Weekday{time.Monday}, StartMin: 60, EndMin: 120}
	mustOK(t, s.AddScheduledRule(net, "block", "sched.example", sch))
	snap := s.Snapshot()
	if got, ok := snap.Network.BlockSchedules["sched.example"]; !ok || !slices.Equal(got.Days, sch.Days) {
		t.Errorf("schedule not stored: %+v", snap.Network.BlockSchedules)
	}
	if !slices.Contains(snap.Network.Block, "sched.example") {
		t.Error("the rule itself must also be added")
	}
	// Re-adding plainly (no schedule) must clear the schedule but keep the rule.
	mustOK(t, s.AddRule(net, "block", "sched.example"))
	snap = s.Snapshot()
	if _, ok := snap.Network.BlockSchedules["sched.example"]; ok {
		t.Error("a bare AddRule must clear any existing schedule")
	}
	if !slices.Contains(snap.Network.Block, "sched.example") {
		t.Error("the rule must survive the schedule being cleared")
	}
	// Moving a scheduled rule from block to allow drops the block schedule
	// and does not carry it to the allow side.
	mustOK(t, s.AddScheduledRule(net, "block", "moved.example", sch))
	mustOK(t, s.AddRule(net, "allow", "moved.example"))
	snap = s.Snapshot()
	if _, ok := snap.Network.BlockSchedules["moved.example"]; ok {
		t.Error("the old kind's schedule must be dropped when a rule moves kind")
	}
	if _, ok := snap.Network.AllowSchedules["moved.example"]; ok {
		t.Error("a bare AddRule on the new kind must not invent a schedule")
	}
	// Removing a scheduled rule removes its schedule too.
	mustOK(t, s.AddScheduledRule(net, "allow", "gone.example", sch))
	mustOK(t, s.RemoveRule(net, "allow", "gone.example"))
	snap = s.Snapshot()
	if _, ok := snap.Network.AllowSchedules["gone.example"]; ok {
		t.Error("RemoveRule must also remove the schedule")
	}
	// Validation.
	if err := s.AddScheduledRule(net, "block", "ok.example", Schedule{}); err == nil {
		t.Error("an invalid schedule was accepted")
	}
	if err := s.AddScheduledRule(net, "block", "not a domain", sch); err == nil {
		t.Error("an invalid domain was accepted")
	}
	if err := s.AddScheduledRule(Scope{Kind: "weird"}, "block", "ok.example", sch); err == nil {
		t.Error("AddScheduledRule accepted a bad scope")
	}
	// Persisted and reloaded.
	mustOK(t, s.AddScheduledRule(net, "allow", "persisted.example", sch))
	s2, err := OpenPolicyStore(path, NewFilter(), PolicyOptions{Catalog: testCatalog(t)})
	mustOK(t, err)
	snap2 := s2.Snapshot()
	if got, ok := snap2.Network.AllowSchedules["persisted.example"]; !ok || got.StartMin != sch.StartMin {
		t.Errorf("schedule not persisted: %+v", snap2.Network.AllowSchedules)
	}
}

func TestStoreValidatesModeAndScheduleOnLoad(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	cases := map[string]string{
		"invalid mode":            `{"version":1,"network":{"mode":"sideways"}}`,
		"schedule without rule":   `{"version":1,"network":{"allow_schedules":{"x.example":{"days":[1],"start_min":0,"end_min":60}}}}`,
		"schedule invalid itself": `{"version":1,"network":{"allow":["x.example"],"allow_schedules":{"x.example":{"days":[],"start_min":0,"end_min":60}}}}`,
		"schedule bad day":        `{"version":1,"network":{"block":["x.example"],"block_schedules":{"x.example":{"days":[9],"start_min":0,"end_min":60}}}}`,
	}
	for name, body := range cases {
		mustOK(t, os.WriteFile(bad, []byte(body), 0o600))
		if _, err := OpenPolicyStore(bad, NewFilter(), PolicyOptions{Catalog: testCatalog(t)}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A well-formed one with both a mode and a scheduled rule loads fine.
	good := filepath.Join(dir, "good.json")
	mustOK(t, os.WriteFile(good, []byte(`{"version":1,"network":{"mode":"allow","allow":["x.example"],"allow_schedules":{"x.example":{"days":[1],"start_min":0,"end_min":60}}}}`), 0o600))
	s, err := OpenPolicyStore(good, NewFilter(), PolicyOptions{Catalog: testCatalog(t)})
	mustOK(t, err)
	if s.Snapshot().Network.Mode != ModeAllow {
		t.Error("mode not loaded")
	}
}

func TestScopeSettingsCloneCopiesModeAndSchedules(t *testing.T) {
	ss := ScopeSettings{Mode: ModeAllow, Allow: []string{"a.example"}, AllowSchedules: map[string]Schedule{"a.example": {Days: []time.Weekday{time.Monday}, StartMin: 0, EndMin: 60}}}
	clone := ss.clone()
	clone.AllowSchedules["a.example"] = Schedule{Days: []time.Weekday{time.Tuesday}, StartMin: 0, EndMin: 60}
	if ss.AllowSchedules["a.example"].Days[0] == time.Tuesday {
		t.Error("clone aliases the original schedule map")
	}
	if clone.Mode != ModeAllow {
		t.Error("clone lost Mode")
	}
}
