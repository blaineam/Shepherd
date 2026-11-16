// SPDX-License-Identifier: AGPL-3.0-or-later

package backends

import (
	"context"
	"errors"
	"testing"
)

type stub struct{ ro bool }

func (s stub) Name() string   { return "stub" }
func (s stub) ReadOnly() bool { return s.ro }

type readsOnly struct{ stub }

func (readsOnly) Devices(context.Context) ([]Device, error) { return nil, nil }

type everything struct {
	stub
	readsOnly2
}
type readsOnly2 struct{}

func (readsOnly2) Devices(context.Context) ([]Device, error)          { return nil, nil }
func (readsOnly2) Flows(context.Context, FlowQuery) (FlowPage, error) { return FlowPage{}, nil }
func (readsOnly2) Alarms(context.Context, AlarmQuery) (AlarmPage, error) {
	return AlarmPage{}, nil
}
func (readsOnly2) Rules(context.Context) ([]Rule, error)                 { return nil, nil }
func (readsOnly2) CreateRule(context.Context, RuleSpec) (Rule, error)    { return Rule{}, nil }
func (readsOnly2) SetRulePaused(context.Context, string, bool) error     { return nil }
func (readsOnly2) DeleteRule(context.Context, string) error              { return nil }
func (readsOnly2) RenameDevice(context.Context, DeviceRef, string) error { return nil }
func (readsOnly2) DismissAlarm(context.Context, AlarmRef) error          { return nil }

func TestCapabilitiesAreWhatTheBackendImplements(t *testing.T) {
	got := Capabilities(readsOnly{})
	if len(got) != 1 || got[0] != CapDevices {
		t.Fatalf("a devices-only backend = %v", got)
	}
	if Has(readsOnly{}, CapFlows) || Has(readsOnly{}, CapRuleWrite) {
		t.Fatal("it claims what it does not implement")
	}
}

func TestAReadOnlyConnectionNeverAdvertisesWrites(t *testing.T) {
	full := Capabilities(everything{})
	want := []Capability{CapDevices, CapFlows, CapAlarms, CapRules, CapRuleWrite, CapDeviceRename, CapAlarmDismiss}
	if len(full) != len(want) {
		t.Fatalf("full = %v, want %v", full, want)
	}
	for i := range want {
		if full[i] != want[i] {
			t.Fatalf("full = %v, want %v", full, want)
		}
	}
	ro := Capabilities(everything{stub: stub{ro: true}})
	for _, c := range ro {
		if c == CapRuleWrite || c == CapDeviceRename || c == CapAlarmDismiss {
			t.Fatalf("a read-only backend offers %s", c)
		}
	}
	if !Has(everything{stub: stub{ro: true}}, CapRules) {
		t.Fatal("reading rules is still allowed")
	}
}

func TestRuleSpecValidation(t *testing.T) {
	ok := RuleSpec{Action: "block", TargetType: "domain", Target: "example.com"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	dev := ok
	dev.ScopeType, dev.Scope = "device", "02:00:5e:00:00:01"
	if err := dev.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]RuleSpec{
		"action":        {Action: "drop", TargetType: "domain", Target: "x"},
		"no action":     {TargetType: "domain", Target: "x"},
		"target type":   {Action: "block", TargetType: "port", Target: "x"},
		"no target":     {Action: "block", TargetType: "domain", Target: "  "},
		"scope no type": {Action: "block", TargetType: "domain", Target: "x", Scope: "m"},
		"device no mac": {Action: "block", TargetType: "domain", Target: "x", ScopeType: "device"},
		"unknown scope": {Action: "block", TargetType: "domain", Target: "x", ScopeType: "group", Scope: "kids"},
	}
	for name, s := range bad {
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestRefsCarryWhatAWriteNeeds(t *testing.T) {
	if r := (Device{Box: "b", Native: "d"}).Ref(); r != (DeviceRef{Box: "b", Native: "d"}) {
		t.Fatalf("%+v", r)
	}
	if r := (Alarm{Box: "b", ID: "1"}).Ref(); r != (AlarmRef{Box: "b", ID: "1"}) {
		t.Fatalf("%+v", r)
	}
}
