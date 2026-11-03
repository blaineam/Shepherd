// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
	"shepherd/internal/selftest"
)

func TestSkipSet(t *testing.T) {
	var s skipSet
	if len(s.list()) != 0 {
		t.Fatal("not empty")
	}
	s.add("a:53")
	s.add("a:53")
	if got := s.list(); len(got) != 1 || got[0] != "a:53" {
		t.Fatalf("list = %v", got)
	}
}

func TestStartSelftestOffReturnsNil(t *testing.T) {
	cfg := config.Default()
	cfg.Selftest.Enabled = false
	if startSelftest(context.Background(), cfg, &dnsengine.Engine{}, &skipSet{}, nil) != nil {
		t.Fatal("a disabled self-test must not start")
	}
}

func TestStartSelftestRunsAgainstTheEngineAndKeepsCanariesQuiet(t *testing.T) {
	old := selftestDelay
	selftestDelay = time.Millisecond
	t.Cleanup(func() { selftestDelay = old })

	pool, err := dnsengine.NewPool([]string{fakeLiveUpstream(t)})
	if err != nil {
		t.Fatal(err)
	}
	e := &dnsengine.Engine{Filter: dnsengine.NewFilter(), Pool: pool, Cache: dnsengine.NewCache(10), Log: dnsengine.NewQueryLog(50), Stats: dnsengine.NewStats()}
	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.DNS.Listen = []string{"127.0.0.1:" + strconv.Itoa(freePort(t))}
	cfg.DNS.ListenLoopback = new(bool) // false
	// The listen list also names an address that was skipped at startup: it
	// must not be reported as a dead listener.
	cfg.DNS.Listen = append(cfg.DNS.Listen, "192.0.2.99:53")
	var skipped skipSet
	skipped.add("192.0.2.99:53")

	eng, _, _, stop, err := startAlarms(context.Background(), cfg, pool, memSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = dnsengine.Serve(ctx, cfg.DNS.Listen[:1], e) }()
	for i := 0; i < 500; i++ { // up before the first round, which does not retry
		if c, err := net.Dial("tcp", cfg.DNS.Listen[0]); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	st := startSelftest(ctx, cfg, e, &skipped, eng)
	if st == nil || e.Quiet == nil || !e.Quiet("example.com") {
		t.Fatal("the engine was not told which names are canaries")
	}

	var rep selftest.Report
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := st.Latest(); ok && len(r.Listeners) > 0 {
			rep = r
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The status may be "warn": this machine's own LAN addresses are not
	// served by the test listener. What matters is the one listener we run.
	if len(rep.Listeners) != 1 || !rep.Listeners[0].OK || len(rep.Skipped) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if n := len(e.Log.All()); n != 0 {
		t.Errorf("%d canary queries reached the query log", n)
	}
}

func TestRaiseSelftestMapsEachCheckToItsAlarmType(t *testing.T) {
	raiseSelftest(nil, selftest.Problem{Check: selftest.CheckListener}) // alarms off: no panic

	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	for check, want := range map[string]string{
		selftest.CheckListener: alarms.TypeDNSListenerDown,
		selftest.CheckResolve:  alarms.TypeDNSCanaryFailed,
		selftest.CheckBlock:    alarms.TypeDNSCanaryFailed,
		selftest.CheckLAN:      alarms.TypeDNSLANUncovered,
		selftest.CheckUpstream: alarms.TypeDNSUpstreamDegraded,
	} {
		raiseSelftest(eng, selftest.Problem{Check: check, Subject: net.JoinHostPort("10.0.0.20", "53"), Message: check + " problem"})
		eng.Drain()
		if got := eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{want}}}); got.Total == 0 {
			t.Errorf("%s raised no %s alarm", check, want)
		}
	}
}

func TestStartSelftestStopsBeforeItsFirstRoundWhenCancelled(t *testing.T) {
	old := selftestDelay
	selftestDelay = time.Hour
	t.Cleanup(func() { selftestDelay = old })
	pool, err := dnsengine.NewPool([]string{fakeLiveUpstream(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := startSelftest(ctx, config.Default(), &dnsengine.Engine{Pool: pool}, &skipSet{}, nil)
	cancel()
	time.Sleep(20 * time.Millisecond)
	if _, ok := st.Latest(); ok {
		t.Fatal("a round ran although the context ended before the delay")
	}
}
