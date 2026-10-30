// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"sort"
	"sync"
	"time"
)

// Clock abstracts time so the Spoofer's and the Controller's periodic
// work can be driven deterministically in tests, with no real sleeps.
// Production code defaults to realClock; tests use FakeClock.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

var _ Clock = realClock{}

type fakeWaiter struct {
	deadline time.Time
	ch       chan time.Time
}

// FakeClock is a controllable Clock for tests. After registers a waiter
// instead of sleeping; Advance moves virtual time forward and fires every
// waiter whose deadline has now arrived, in deadline order, so a timer
// fires at exactly the virtual instant it is due — never early, and only
// as late as the test chooses to advance.
type FakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []fakeWaiter
}

// NewFakeClock returns a FakeClock starting at start.
func NewFakeClock(start time.Time) *FakeClock { return &FakeClock{now: start} }

// Now returns the current virtual time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After returns a channel that receives the virtual time once the clock
// has advanced to now+d. d <= 0 fires immediately.
func (c *FakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	deadline := c.now.Add(d)
	if !deadline.After(c.now) {
		c.mu.Unlock()
		ch <- deadline
		return ch
	}
	c.waiters = append(c.waiters, fakeWaiter{deadline, ch})
	c.mu.Unlock()
	return ch
}

// Advance moves the virtual clock forward by d and, before returning,
// fires every pending After channel whose deadline is now due, in
// deadline order. Because the sends happen synchronously inside Advance,
// a caller that observes Advance return knows exactly which timers fired
// and which did not — including a timer whose deadline Advance missed by
// design, which is how tests prove "not early" for trial expiry.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var fired []fakeWaiter
	remaining := make([]fakeWaiter, 0, len(c.waiters))
	for _, w := range c.waiters {
		if !w.deadline.After(now) {
			fired = append(fired, w)
		} else {
			remaining = append(remaining, w)
		}
	}
	c.waiters = remaining
	c.mu.Unlock()

	sort.Slice(fired, func(i, j int) bool { return fired[i].deadline.Before(fired[j].deadline) })
	for _, w := range fired {
		w.ch <- now
	}
}

// Pending reports how many After calls are still waiting.
func (c *FakeClock) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

var _ Clock = (*FakeClock)(nil)
