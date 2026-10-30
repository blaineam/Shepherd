// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDefaultPreferencesAreValid(t *testing.T) {
	p := DefaultPreferences()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.ImmediateMin != SeverityHigh || !p.Digest.Enabled || p.Digest.Every.D() != 6*time.Hour || p.Quiet.Enabled ||
		!p.Learning.Enabled || p.Learning.Period.D() != 72*time.Hour || p.NtfyAlways || !p.Channels[ChannelPush].Enabled {
		t.Fatalf("defaults: %+v", p)
	}
	if loc, err := p.Location(); err != nil || loc != time.Local {
		t.Fatal("empty timezone must be the local zone")
	}
	p.Timezone = "Local"
	if loc, _ := p.Location(); loc != time.Local {
		t.Fatal("Local")
	}
	p.Timezone = "UTC"
	if loc, _ := p.Location(); loc != time.UTC {
		t.Fatal("UTC")
	}
}

func TestPreferencesValidation(t *testing.T) {
	mod := func(f func(*Preferences)) Preferences {
		p := DefaultPreferences()
		f(&p)
		return p
	}
	bad := map[string]Preferences{
		"timezone":         mod(func(p *Preferences) { p.Timezone = "Mars/Olympus" }),
		"channel name":     mod(func(p *Preferences) { p.Channels["fax"] = ChannelPref{Enabled: true, MinSeverity: SeverityLow} }),
		"channel severity": mod(func(p *Preferences) { p.Channels[ChannelPush] = ChannelPref{Enabled: true, MinSeverity: "huge"} }),
		"immediate":        mod(func(p *Preferences) { p.ImmediateMin = "" }),
		"digest time":      mod(func(p *Preferences) { p.Digest.At = "25:00" }),
		"digest interval":  mod(func(p *Preferences) { p.Digest.Every = Duration(time.Second) }),
		"quiet start":      mod(func(p *Preferences) { p.Quiet.Windows[0].Start = "7pm" }),
		"quiet end":        mod(func(p *Preferences) { p.Quiet.Windows[0].End = "7:5" }),
		"quiet allow":      mod(func(p *Preferences) { p.Quiet.Windows[0].Allow = "huge" }),
		"quiet day":        mod(func(p *Preferences) { p.Quiet.Windows[0].Days = []int{7} }),
		"learning":         mod(func(p *Preferences) { p.Learning.Period = -1 }),
		"device learning":  mod(func(p *Preferences) { p.Learning.DevicePeriod = -1 }),
		"morning":          mod(func(p *Preferences) { p.MorningHour = 24 }),
		"type channel":     mod(func(p *Preferences) { p.Types = map[string]TypePref{"x": {Channels: []string{"fax"}}} }),
		"portal url":       mod(func(p *Preferences) { p.PortalURL = "javascript:alert(1)" }),
	}
	for name, p := range bad {
		if err := p.Validate(); !errors.Is(err, ErrBadPreferences) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	ok := mod(func(p *Preferences) {
		p.Digest = DigestPref{Enabled: true, At: "08:30"}
		p.PortalURL = "https://shepherd.example.com"
		p.Types = map[string]TypePref{"new-device": {OffForClasses: []string{"tv"}, Channels: []string{ChannelPush}}}
	})
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	morning := bad["morning"]
	if _, err := New(Options{Preferences: &morning}); err == nil {
		t.Fatal("New accepted invalid preferences")
	}
}

func TestPreferencesJSONRoundTrip(t *testing.T) {
	p := DefaultPreferences()
	p.Types = map[string]TypePref{"new-device": {Off: true, OffForClasses: []string{"tv"}}}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"every":"6h0m0s"`) {
		t.Fatalf("durations should be strings: %s", b)
	}
	var back Preferences
	if err := json.Unmarshal(b, &back); err != nil || back.Digest.Every != p.Digest.Every || !back.Types["new-device"].Off {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	var d Duration
	if json.Unmarshal([]byte(`90`), &d) != nil || d.D() != 90*time.Second {
		t.Fatalf("seconds: %v", d)
	}
	for _, bad := range []string{`"soon"`, `true`, `{`, `[1]`} {
		if err := json.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestPreferencesCloneIsDeep(t *testing.T) {
	p := DefaultPreferences()
	p.Types = map[string]TypePref{"a": {OffForClasses: []string{"tv"}, Channels: []string{ChannelPush}}}
	p.Quiet.Windows[0].Days = []int{1}
	c := p.Clone()
	c.Channels[ChannelPush] = ChannelPref{}
	c.Types["a"].OffForClasses[0] = "changed"
	c.Quiet.Windows[0].Days[0] = 5
	if p.Channels[ChannelPush].Enabled == false || p.Types["a"].OffForClasses[0] != "tv" || p.Quiet.Windows[0].Days[0] != 1 {
		t.Fatal("clone shares memory with the original")
	}
}

func TestSetPreferencesEmitsAndApplies(t *testing.T) {
	e, _, rec := newTestEngine(t)
	p := e.Preferences()
	p.NtfyAlways = true
	if err := e.SetPreferences(p); err != nil {
		t.Fatal(err)
	}
	if !e.Preferences().NtfyAlways || len(rec.kinds(ChangePrefs)) != 1 {
		t.Fatal("set")
	}
	p.MorningHour = 99
	if err := e.SetPreferences(p); !errors.Is(err, ErrBadPreferences) {
		t.Fatal(err)
	}
	if e.Preferences().MorningHour == 99 {
		t.Fatal("invalid preferences stored")
	}
	// The returned copy is detached.
	got := e.Preferences()
	got.Channels[ChannelPush] = ChannelPref{}
	if !e.Preferences().Channels[ChannelPush].Enabled {
		t.Fatal("Preferences leaked internal state")
	}
	// A changed morning hour changes "until tomorrow morning".
	p = e.Preferences()
	p.MorningHour = 6
	e.SetPreferences(p)
	a := mustRaise(t, e, Event{Type: "custom", Key: "m"})
	e.Snooze(a.ID, MuteSpec{Preset: MuteTomorrow})
	if got, _ := e.Get(a.ID); !got.MutedUntil.Equal(time.Date(2030, 3, 5, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("muted until %v", got.MutedUntil)
	}
}

func TestTypeSwitchHelpers(t *testing.T) {
	p := DefaultPreferences()
	if !p.typeOn("x", "camera") {
		t.Fatal("default on")
	}
	p.Types = map[string]TypePref{"x": {OffForClasses: []string{"Camera"}}, "y": {Off: true}}
	if p.typeOn("x", "camera") || !p.typeOn("x", "tv") || !p.typeOn("x", "") || p.typeOn("y", "tv") {
		t.Fatal("switches")
	}
	ty := AlarmType{ID: "x", Channels: []string{ChannelPortal}}
	if got := p.channelsFor(ty); len(got) != 1 {
		t.Fatal("default channels")
	}
	p.Types["x"] = TypePref{Channels: []string{ChannelPush}}
	if got := p.channelsFor(ty); got[0] != ChannelPush {
		t.Fatal("override channels")
	}
}
