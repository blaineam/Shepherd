// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"sync"
	"time"
)

// Clock abstracts time so the engine and router are testable without sleeping.
type Clock interface {
	Now() time.Time
	// NewTicker returns a ticker that fires every d.
	NewTicker(d time.Duration) Ticker
}

// Ticker is the subset of time.Ticker the package uses.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// SystemClock is the real clock.
type SystemClock struct{}

// Now returns the current time.
func (SystemClock) Now() time.Time { return time.Now() }

// NewTicker wraps time.NewTicker.
func (SystemClock) NewTicker(d time.Duration) Ticker { return sysTicker{time.NewTicker(d)} }

type sysTicker struct{ t *time.Ticker }

func (s sysTicker) C() <-chan time.Time { return s.t.C }
func (s sysTicker) Stop()               { s.t.Stop() }

// FakeClock is a manually advanced Clock for tests, including tests of code
// that wires the engine into Shepherd.
type FakeClock struct {
	mu      sync.Mutex
	now     time.Time
	tickers map[*fakeTicker]struct{}
}

// NewFakeClock returns a clock fixed at start.
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start, tickers: map[*fakeTicker]struct{}{}}
}

// Now returns the fake time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set moves the clock to t without firing tickers.
func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

// Advance moves the clock forward by d and fires every ticker whose interval
// elapsed (once per interval boundary crossed, never blocking).
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var due []*fakeTicker
	for t := range c.tickers {
		for !t.next.After(now) {
			due = append(due, t)
			t.next = t.next.Add(t.every)
		}
	}
	c.mu.Unlock()
	for _, t := range due {
		select {
		case t.ch <- now:
		default:
		}
	}
}

// NewTicker returns a ticker driven by Advance.
func (c *FakeClock) NewTicker(d time.Duration) Ticker {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTicker{c: c, every: d, next: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.tickers[t] = struct{}{}
	return t
}

type fakeTicker struct {
	c     *FakeClock
	every time.Duration
	next  time.Time
	ch    chan time.Time
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }
func (t *fakeTicker) Stop() {
	t.c.mu.Lock()
	delete(t.c.tickers, t)
	t.c.mu.Unlock()
}
