// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"testing"
	"time"
)

func TestFakeClockAdvanceFiresExactlyDueWaiters(t *testing.T) {
	c := NewFakeClock(t0)
	five := c.After(5 * time.Second)
	ten := c.After(10 * time.Second)

	c.Advance(4999 * time.Millisecond)
	select {
	case <-five:
		t.Fatal("fired early")
	default:
	}

	c.Advance(1 * time.Millisecond) // now exactly +5s
	select {
	case got := <-five:
		if !got.Equal(t0.Add(5 * time.Second)) {
			t.Fatalf("fired at %v, want %v", got, t0.Add(5*time.Second))
		}
	default:
		t.Fatal("did not fire at exactly its deadline")
	}
	select {
	case <-ten:
		t.Fatal("the 10s waiter fired early")
	default:
	}

	c.Advance(5 * time.Second) // now +10s
	select {
	case <-ten:
	default:
		t.Fatal("10s waiter never fired")
	}
}

func TestFakeClockAfterNonPositiveFiresImmediately(t *testing.T) {
	c := NewFakeClock(t0)
	select {
	case <-c.After(0):
	default:
		t.Fatal("After(0) should fire without an Advance")
	}
	select {
	case <-c.After(-time.Second):
	default:
		t.Fatal("After(negative) should fire without an Advance")
	}
}

func TestFakeClockPending(t *testing.T) {
	c := NewFakeClock(t0)
	c.After(time.Second)
	c.After(time.Minute)
	if c.Pending() != 2 {
		t.Fatalf("Pending() = %d, want 2", c.Pending())
	}
	c.Advance(time.Second)
	if c.Pending() != 1 {
		t.Fatalf("Pending() after advance = %d, want 1", c.Pending())
	}
}

func TestFakeClockNow(t *testing.T) {
	c := NewFakeClock(t0)
	if !c.Now().Equal(t0) {
		t.Fatal("Now() did not start at t0")
	}
	c.Advance(time.Hour)
	if !c.Now().Equal(t0.Add(time.Hour)) {
		t.Fatal("Advance did not move Now()")
	}
}

func TestRealClock(t *testing.T) {
	var c Clock = realClock{}
	before := time.Now()
	if c.Now().Before(before) {
		t.Fatal("realClock.Now() looked stale")
	}
	select {
	case <-c.After(time.Millisecond):
	case <-time.After(time.Second):
		t.Fatal("realClock.After never fired")
	}
}
