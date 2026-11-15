// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/linkwatch"
)

func TestRaiseLinkLostReportsDurationInterfaceAndCause(t *testing.T) {
	raiseLinkLost(nil, linkwatch.Episode{}) // alarms off: no panic

	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	st := time.Date(2026, 11, 13, 4, 2, 38, 0, time.UTC)
	ep := linkwatch.Episode{
		Addr: netip.MustParseAddr("192.0.2.10"), Iface: "eth0",
		Reason: "interface eth0 lost its link (no carrier)", Start: st, End: st.Add(12 * time.Second),
	}
	raiseLinkLost(eng, ep)
	raiseLinkLost(eng, ep) // a flapping link merges into one alarm
	ep.Iface = ""
	ep.Addr = netip.MustParseAddr("198.51.100.7")
	raiseLinkLost(eng, ep)
	eng.Drain()
	got := eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeNetworkLinkLost}}})
	if got.Total != 2 {
		t.Fatalf("total %d, want 2 (one per address)", got.Total)
	}
	var lan, ts alarms.Alarm
	for _, a := range got.Alarms {
		if strings.Contains(a.Title, "192.0.2.10") {
			lan = a
		} else {
			ts = a
		}
	}
	if !strings.Contains(lan.Title, "12s") || !strings.Contains(lan.Title, "eth0") || lan.Count != 2 {
		t.Fatalf("lan alarm = %+v", lan)
	}
	if !strings.Contains(ts.Title, "unknown") {
		t.Fatalf("tailnet alarm = %+v", ts)
	}
}

func TestStartLinkwatchNeedsALANAddress(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:5353"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if w := startLinkwatch(ctx, cfg, nil); w != nil {
		t.Fatal("loopback-only installs have no link to watch")
	}
	cfg.DNS.Listen = []string{"192.0.2.10:53", "[2001:db8::1]:53", "not-an-address"}
	w := startLinkwatch(ctx, cfg, nil)
	if w == nil || w.Watching() != 2 {
		t.Fatalf("watcher = %v", w)
	}
}
