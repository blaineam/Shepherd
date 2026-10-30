// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"testing"
	"time"
)

func TestFakeClockAdvanceFiresDueTickers(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewFakeClock(start)
	tk := c.NewTicker(time.Minute)
	defer tk.Stop()

	c.Advance(30 * time.Second)
	select {
	case <-tk.C():
		t.Fatal("ticker fired before its interval elapsed")
	default:
	}

	c.Advance(30 * time.Second)
	select {
	case got := <-tk.C():
		want := start.Add(time.Minute)
		if !got.Equal(want) {
			t.Errorf("tick time = %v, want %v", got, want)
		}
	default:
		t.Fatal("ticker did not fire when its interval elapsed")
	}

	if got := c.Now(); !got.Equal(start.Add(time.Minute)) {
		t.Errorf("Now() = %v, want %v", got, start.Add(time.Minute))
	}
}

func TestFakeClockAdvanceFiresMultipleBoundaries(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewFakeClock(start)
	tk := c.NewTicker(time.Minute)
	defer tk.Stop()

	c.Advance(3 * time.Minute)
	n := 0
	for {
		select {
		case <-tk.C():
			n++
		default:
			goto done
		}
	}
done:
	if n == 0 {
		t.Fatal("expected at least one buffered tick")
	}
}

func TestFakeClockSetDoesNotFireTickers(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewFakeClock(start)
	tk := c.NewTicker(time.Minute)
	defer tk.Stop()

	c.Set(start.Add(time.Hour))
	select {
	case <-tk.C():
		t.Fatal("Set must not fire tickers")
	default:
	}
	if got := c.Now(); !got.Equal(start.Add(time.Hour)) {
		t.Errorf("Now() = %v, want %v", got, start.Add(time.Hour))
	}
}

func TestFakeTickerStopRemovesIt(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewFakeClock(start)
	tk := c.NewTicker(time.Minute)
	tk.Stop()
	c.Advance(time.Hour) // must not panic or deadlock sending to a stopped ticker
}

func TestSystemClock(t *testing.T) {
	c := SystemClock{}
	before := time.Now()
	got := c.Now()
	if got.Before(before) {
		t.Errorf("Now() = %v, before call time %v", got, before)
	}
	tk := c.NewTicker(10 * time.Millisecond)
	defer tk.Stop()
	select {
	case <-tk.C():
	case <-time.After(time.Second):
		t.Fatal("system ticker never fired")
	}
}
