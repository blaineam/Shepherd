// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log"
	"sync"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
	"shepherd/internal/selftest"
)

// selftestDelay is how long the first round waits, so the listeners
// (bound after this is started) are up before they are asked.
var selftestDelay = 3 * time.Second

// skipSet records the listen addresses Serve could not bind, so the
// self-test does not report a listener it knows was never started.
type skipSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (s *skipSet) add(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]bool{}
	}
	s.m[addr] = true
}

func (s *skipSet) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for a := range s.m {
		out = append(out, a)
	}
	return out
}

// startSelftest builds the DNS self-test, keeps its canary queries out of
// the query log and device list, and, unless cfg turns it off, runs it on
// its interval, raising alarms (with a cooldown) for what it finds.
// docs/DNS-QA.md.
func startSelftest(ctx context.Context, cfg config.Config, engine *dnsengine.Engine, skipped *skipSet, eng *alarms.Engine) *selftest.Tester {
	c := cfg.Selftest
	if !c.Enabled {
		return nil
	}
	skip := func() map[string]bool {
		m := map[string]bool{}
		for _, a := range skipped.list() {
			m[a] = true
		}
		return m
	}
	t := selftest.New(selftest.Options{
		Addrs: func() []string {
			sk := skip()
			var out []string
			for _, a := range cfg.DNS.ListenAddrs() {
				if !sk[a] {
					out = append(out, a)
				}
			}
			return out
		},
		Skipped:        skipped.list,
		Window:         engine.Pool.Window,
		GoodName:       c.GoodName,
		BlockedName:    c.BlockedName,
		NotServed:      c.NotServed,
		MaxErrorPct:    c.MaxErrorPercent,
		UpstreamWindow: time.Duration(c.WindowMinutes) * time.Minute,
	})
	engine.Quiet = t.IsCanary
	al := &selftest.Alerter{Cooldown: time.Duration(c.AlarmCooldownMinutes) * time.Minute, Raise: func(p selftest.Problem) {
		log.Printf("selftest: %s: %s", p.Check, p.Message)
		raiseSelftest(eng, p)
	}}
	delay := selftestDelay
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		t.Run(ctx, time.Duration(c.IntervalSeconds)*time.Second, al.Observe)
	}()
	return t
}

// raiseSelftest maps one finding to its alarm type. eng may be nil (alarms
// off); the finding is logged by the caller either way.
func raiseSelftest(eng *alarms.Engine, p selftest.Problem) {
	if eng == nil {
		return
	}
	typ, sev := alarms.TypeDNSCanaryFailed, alarms.Severity("")
	switch p.Check {
	case selftest.CheckListener:
		typ = alarms.TypeDNSListenerDown
	case selftest.CheckLAN:
		typ = alarms.TypeDNSLANUncovered
	case selftest.CheckUpstream:
		typ = alarms.TypeDNSUpstreamDegraded
	}
	eng.Raise(alarms.Event{
		Type: typ, Severity: sev, Source: "selftest", Title: p.Message,
		Key:      p.Check + "|" + p.Subject + "|",
		Evidence: []alarms.Evidence{{Label: "Subject", Value: p.Subject}},
	})
}
