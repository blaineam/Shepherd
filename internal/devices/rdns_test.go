// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type lookupLog struct {
	mu    sync.Mutex
	calls []string
	names map[string][]string
	err   map[string]error
}

func (l *lookupLog) lookup(_ context.Context, ip string) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, ip)
	return l.names[ip], l.err[ip]
}

func TestReverseDNSCacheAndQueue(t *testing.T) {
	r, clk := newReg(t)
	id := r.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	ll := &lookupLog{
		names: map[string][]string{"192.0.2.1": {"host1.example.org."}, "192.0.2.2": {}},
		err:   map[string]error{"192.0.2.3": errors.New("SERVFAIL")},
	}
	rd := NewReverseDNS(ll.lookup, r, ReverseDNSOptions{Now: clk.Now, MaxQueue: 3, TTL: time.Hour, NegativeTTL: time.Minute})

	if rd.Step(context.Background()) {
		t.Fatal("empty queue stepped")
	}
	if rd.Submit("bogus") {
		t.Fatal("bogus ip queued")
	}
	if !rd.Submit("192.0.2.1") || rd.Submit("192.0.2.1") {
		t.Fatal("dedupe")
	}
	rd.Submit("192.0.2.2")
	rd.Submit("192.0.2.3")
	if rd.Submit("192.0.2.4") {
		t.Fatal("queue should be full")
	}
	eq(t, rd.Pending(), 3)
	for rd.Step(context.Background()) {
	}
	eq(t, len(ll.calls), 3)
	eq(t, mustDevice(t, r, id).ReverseName, "host1.example.org")
	if r.Len() != 1 {
		t.Fatal("PTR created a device")
	}

	// Cached: not re-queued inside the TTL; failures retried after the shorter TTL.
	if rd.Submit("192.0.2.1") || rd.Submit("192.0.2.2") || rd.Submit("192.0.2.3") {
		t.Fatal("cache ignored")
	}
	clk.Advance(2 * time.Minute)
	if rd.Submit("192.0.2.1") {
		t.Fatal("positive answer expired early")
	}
	if !rd.Submit("192.0.2.2") || !rd.Submit("192.0.2.3") {
		t.Fatal("negative cache did not expire")
	}
	clk.Advance(2 * time.Hour)
	if !rd.Submit("192.0.2.1") {
		t.Fatal("positive cache did not expire")
	}
}

func TestReverseDNSEmptyName(t *testing.T) {
	r, _ := newReg(t)
	r.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	rd := NewReverseDNS(func(context.Context, string) ([]string, error) { return []string{"."}, nil }, r, ReverseDNSOptions{})
	rd.Submit("192.0.2.1")
	rd.Step(context.Background())
	d, _ := r.FindByIP("192.0.2.1")
	if d.ReverseName != "" {
		t.Fatal("root name stored")
	}
}

func TestReverseDNSRunRateLimitedAndAttached(t *testing.T) {
	r, _ := newReg(t)
	ll := &lookupLog{names: map[string][]string{"192.0.2.1": {"a.example.org"}, "192.0.2.2": {"b.example.org"}}}
	rd := NewReverseDNS(ll.lookup, r, ReverseDNSOptions{Interval: time.Millisecond})
	unsub := AttachReverseDNS(r, rd)
	defer unsub()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- rd.Run(ctx) }()

	// New devices trigger lookups; the run loop wakes from idle on Submit.
	r.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	time.Sleep(20 * time.Millisecond)
	r.Observe(Observation{MAC: macB, IP: "192.0.2.2"})
	r.Observe(Observation{MAC: macB, Hostname: "no-event-no-lookup"}) // not a new device
	deadline := time.After(2 * time.Second)
	for {
		a, _ := r.FindByIP("192.0.2.1")
		b, _ := r.FindByIP("192.0.2.2")
		if a.ReverseName != "" && b.ReverseName != "" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reverse names never arrived")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Cancellation while idle-waiting for work.
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error)
	rd2 := NewReverseDNS(ll.lookup, r, ReverseDNSOptions{Interval: time.Millisecond})
	go func() { done2 <- rd2.Run(ctx2) }()
	time.Sleep(10 * time.Millisecond)
	cancel2()
	if err := <-done2; err != nil {
		t.Fatal(err)
	}
	// Cancellation at the first tick (already cancelled).
	ctx3, cancel3 := context.WithCancel(context.Background())
	cancel3()
	if err := NewReverseDNS(ll.lookup, r, ReverseDNSOptions{}).Run(ctx3); err != nil {
		t.Fatal(err)
	}
}
