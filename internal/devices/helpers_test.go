// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newReg builds a registry with a fake clock, sequential IDs and a fake
// vendor table: 00:00:5e is "ExampleCo".
func newReg(t testing.TB) (*Registry, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	n := 0
	r := New(Options{
		NodeID: "node-a",
		Now:    clk.Now,
		NewID:  func() string { n++; return fmt.Sprintf("t-%d", n) },
		Vendor: func(mac string) string {
			if strings.HasPrefix(mac, "00:00:5e") {
				return "ExampleCo"
			}
			return ""
		},
	})
	return r, clk
}

func mustDevice(t testing.TB, r *Registry, id string) Device {
	t.Helper()
	d, ok := r.Get(id)
	if !ok {
		t.Fatalf("device %q not found", id)
	}
	return d
}

func eq(t testing.TB, got, want any) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

type time0 = time.Time

const time0Hour = time.Hour

func time0Date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
