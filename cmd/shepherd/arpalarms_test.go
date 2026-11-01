// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/arp"
	"shepherd/internal/config"
	"shepherd/internal/devices"
)

// Every ARP event type either maps to one alarm type or deliberately to
// none; this is docs/ARP.md's table, line by line.
func TestARPEventsMapToAlarmsOrDeliberatelyToNone(t *testing.T) {
	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:00:02", IP: "192.0.2.20", Hostname: "laptop"})
	if _, err := reg.CreateGroup("Kids", ""); err != nil {
		t.Fatal(err)
	}
	g, _ := reg.GroupByName("Kids")
	if _, err := reg.BulkAssignGroup([]string{id}, g.ID); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		ev       arp.Event
		wantType string // "" means no alarm
		wantSev  alarms.Severity
	}{
		{"a new MAC is the registry's new-device alarm, not ours", arp.Event{Type: arp.EventNewMAC, Severity: arp.SeverityInfo, MAC: "02:00:00:00:00:09"}, "", ""},
		{"gateway MAC changed", arp.Event{Type: arp.EventGatewayMACChanged, Severity: arp.SeverityHigh, MAC: "02:00:00:00:00:02", OtherMAC: "02:00:00:00:00:01", IP: "192.0.2.1", Key: "gw|a|b"}, alarms.TypeARPGatewayChanged, alarms.SeverityHigh},
		{"spoofing suspected", arp.Event{Type: arp.EventSpoofingSuspected, Severity: arp.SeverityHigh, MAC: "02:00:00:00:00:02"}, alarms.TypeARPSpoofing, alarms.SeverityHigh},
		{"an IP moved while the old owner was active", arp.Event{Type: arp.EventIPMoved, Severity: arp.SeverityMedium, MAC: "02:00:00:00:00:02", OtherMAC: "02:00:00:00:00:03", IP: "192.0.2.20"}, alarms.TypeARPIPMoved, alarms.SeverityMedium},
		{"a quiet lease handover", arp.Event{Type: arp.EventIPMoved, Severity: arp.SeverityLow, MAC: "02:00:00:00:00:02"}, alarms.TypeARPIPMoved, alarms.SeverityLow},
		{"a private-address rotation is not an alarm", arp.Event{Type: arp.EventIPMoved, Severity: arp.SeverityInfo, MAC: "02:00:00:00:00:02"}, "", ""},
		{"duplicate IP", arp.Event{Type: arp.EventDuplicateIP, Severity: arp.SeverityMedium, IP: "192.0.2.20"}, alarms.TypeARPDuplicateIP, alarms.SeverityMedium},
		{"one MAC claiming many IPs", arp.Event{Type: arp.EventManyIPs, Severity: arp.SeverityMedium, MAC: "02:00:00:00:00:02"}, alarms.TypeARPManyIPs, alarms.SeverityMedium},
		{"gratuitous flood", arp.Event{Type: arp.EventGratuitousFlood, Severity: arp.SeverityLow, MAC: "02:00:00:00:00:02"}, alarms.TypeARPFlood, alarms.SeverityLow},
		{"gratuitous flood for the gateway's address", arp.Event{Type: arp.EventGratuitousFlood, Severity: arp.SeverityMedium, MAC: "02:00:00:00:00:02", IP: "192.0.2.1"}, alarms.TypeARPFlood, alarms.SeverityMedium},
		{"reply storm", arp.Event{Type: arp.EventUnsolicitedStorm, Severity: arp.SeverityMedium, MAC: "02:00:00:00:00:02"}, alarms.TypeARPReplyStorm, alarms.SeverityMedium},
		{"an unknown future type raises nothing", arp.Event{Type: arp.EventType("something-new"), Severity: arp.SeverityHigh}, "", ""},
		{"baseline noise is not an alarm", arp.Event{Type: arp.EventManyIPs, Severity: arp.SeverityMedium, Baseline: true}, "", ""},
		{"a baseline gateway change still is", arp.Event{Type: arp.EventGatewayMACChanged, Severity: arp.SeverityHigh, Baseline: true}, alarms.TypeARPGatewayChanged, alarms.SeverityHigh},
		{"baseline spoofing still is", arp.Event{Type: arp.EventSpoofingSuspected, Severity: arp.SeverityHigh, Baseline: true}, alarms.TypeARPSpoofing, alarms.SeverityHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := arpAlarm(tc.ev, reg)
			if tc.wantType == "" {
				if ok {
					t.Fatalf("raised %+v, want nothing", got)
				}
				return
			}
			if !ok || got.Type != tc.wantType || got.Severity != tc.wantSev || got.Source != "arp" {
				t.Fatalf("got %+v ok=%v, want type %s severity %s", got, ok, tc.wantType, tc.wantSev)
			}
		})
	}

	// Attribution and evidence: the registry's device for the suspect MAC,
	// its groups, and every address the event named, with the monitor's
	// own evidence in a stable order.
	ev, _ := arpAlarm(arp.Event{
		Type: arp.EventGatewayMACChanged, Severity: arp.SeverityHigh, Key: "k",
		MAC: "02:00:00:00:00:02", OtherMAC: "02:00:00:00:00:01", IP: "192.0.2.1",
		Summary: "the gateway moved", Evidence: map[string]string{"z": "last", "a": "first"},
	}, reg)
	if ev.DeviceID != id || len(ev.GroupIDs) != 1 || ev.GroupIDs[0] != g.ID || ev.Body != "the gateway moved" {
		t.Fatalf("attribution = %+v", ev)
	}
	if ev.Key != "gateway-mac-changed|k|" {
		t.Fatalf("key = %q", ev.Key)
	}
	labels := make([]string, 0, len(ev.Evidence))
	for _, e := range ev.Evidence {
		labels = append(labels, e.Label+"="+e.Value)
	}
	want := []string{"MAC=02:00:00:00:00:02", "Device=laptop", "Other MAC=02:00:00:00:00:01", "IP=192.0.2.1", "a=first", "z=last"}
	if len(labels) != len(want) {
		t.Fatalf("evidence = %v, want %v", labels, want)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Fatalf("evidence = %v, want %v", labels, want)
		}
	}
	// A MAC the registry does not know is still evidence, just unattributed.
	ev, _ = arpAlarm(arp.Event{Type: arp.EventManyIPs, Severity: arp.SeverityMedium, MAC: "02:00:00:00:00:77"}, reg)
	if ev.DeviceID != "" || len(ev.Evidence) != 1 {
		t.Fatalf("unknown MAC: %+v", ev)
	}
	// And a nil registry is fine.
	if _, ok := arpAlarm(arp.Event{Type: arp.EventManyIPs, Severity: arp.SeverityMedium, MAC: "02:00:00:00:00:77"}, nil); !ok {
		t.Fatal("nil registry should still map")
	}
}

// reportARPEvent raises the alarm into a real engine and a repeat of the
// same finding folds into it; without an engine it only logs.
func TestReportARPEventRaisesOnceAndFoldsRepeats(t *testing.T) {
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	reg := devices.New(devices.Options{NodeID: "t", AllowLoopback: true})
	ev := arp.Event{Type: arp.EventUnsolicitedStorm, Severity: arp.SeverityMedium, MAC: "02:00:00:00:00:02", Key: "storm|02:00:00:00:00:02", Summary: "storm", Time: time.Now()}
	reportARPEvent(eng, reg, ev)
	reportARPEvent(eng, reg, ev)
	reportARPEvent(eng, reg, arp.Event{Type: arp.EventNewMAC, Severity: arp.SeverityInfo, MAC: "02:00:00:00:00:05"})
	reportARPEvent(nil, reg, ev)

	var page alarms.Page
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeARPReplyStorm}}})
		if page.Total > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Total != 1 {
		t.Fatalf("alarms = %d, want one folded alarm", page.Total)
	}
	if a := page.Alarms[0]; a.RawSeverity != alarms.SeverityMedium || a.Key != "arp-reply-without-request-storm|storm|02:00:00:00:00:02|" {
		t.Fatalf("alarm = %+v", a)
	}
	if n := eng.List(alarms.Query{}).Total; n != 1 {
		t.Fatalf("total alarms = %d, want 1 (new-mac raises none)", n)
	}
}

// The whole path: a real monitor on a fake source feeds reportARPEvent,
// which consults the engine. The monitor's own learning period marks
// everything it sees in the first minutes as baseline and its gateway is
// unknown without /proc/net/route, so what this proves is the wiring: the
// event arrives, is logged, and a new-MAC sighting raises nothing.
func TestARPMonitorEventsReachTheAlarmEngine(t *testing.T) {
	src := arp.NewFakeSource()
	old := arpOpen
	arpOpen = func(string) (arp.Source, string, error) { return src, "test0", nil }
	t.Cleanup(func() { arpOpen = old })

	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	_, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := make(chan arp.Event, 8)
	mon, err := startARP(ctx, config.Default(), reg, func(e arp.Event) { reportARPEvent(eng, reg, e); seen <- e })
	if err != nil || mon == nil {
		t.Fatalf("startARP: %v %v", mon, err)
	}
	mac, _ := arp.ParseMAC("02:00:00:00:00:02")
	src.Push(arp.NewRequest(mac, netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("192.0.2.1")))
	select {
	case e := <-seen:
		if e.Type != arp.EventNewMAC {
			t.Fatalf("first event = %+v, want new-mac-seen", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the monitor's event never reached the callback")
	}
	eng.Drain()
	if n := eng.List(alarms.Query{}).Total; n != 0 {
		t.Fatalf("a new MAC raised %d alarms, want none (the registry's new-device alarm covers it)", n)
	}
}
