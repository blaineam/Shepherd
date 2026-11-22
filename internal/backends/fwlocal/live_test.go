// SPDX-License-Identifier: AGPL-3.0-or-later

package fwlocal

import (
	"context"
	"os"
	"testing"
	"time"

	"shepherd/internal/backends"
)

// TestLiveBoxReadOnly reads a real box, when FWLOCAL_LIVE_URL points at
// its local API (forward the port over SSH: the API is loopback-only). It
// only reads. It is skipped everywhere else, CI included.
func TestLiveBoxReadOnly(t *testing.T) {
	base := os.Getenv("FWLOCAL_LIVE_URL")
	if base == "" {
		t.Skip("FWLOCAL_LIVE_URL is not set")
	}
	c, err := New(Config{BaseURL: base, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	devs, err := c.Devices(ctx)
	if err != nil || len(devs) == 0 {
		t.Fatalf("devices: %d, %v", len(devs), err)
	}
	typed, online, noMAC := 0, 0, 0
	for _, d := range devs {
		if d.NameFrom == backends.NameTyped {
			typed++
		}
		if d.Online {
			online++
		}
		if d.MAC == "" {
			noMAC++
		}
	}
	t.Logf("devices: %d (%d online, %d with a typed name, %d without a MAC)", len(devs), online, typed, noMAC)

	now := time.Now()
	page, err := c.Flows(ctx, backends.FlowQuery{From: now.Add(-10 * time.Minute), To: now})
	if err != nil || len(page.Flows) == 0 {
		t.Fatalf("flows: %d, %v", len(page.Flows), err)
	}
	named, domains := 0, 0
	for _, f := range page.Flows {
		if f.Device != "" {
			named++
		}
		if f.Domain != "" {
			domains++
		}
	}
	newest, oldest := page.Flows[0].Time, page.Flows[len(page.Flows)-1].Time
	t.Logf("flows: %d on the first page, newest %s old, oldest %s old, %d with a device name, %d with a domain, next %q",
		len(page.Flows), now.Sub(newest).Round(time.Second), now.Sub(oldest).Round(time.Second), named, domains, page.Next)
	if page.Next != "" {
		second, err := c.Flows(ctx, backends.FlowQuery{From: now.Add(-10 * time.Minute), To: now, Cursor: page.Next})
		if err != nil {
			t.Fatalf("second page: %v", err)
		}
		if len(second.Flows) > 0 && second.Flows[0].Time.After(oldest) {
			t.Errorf("the second page starts at %s, after the first page's oldest %s", second.Flows[0].Time, oldest)
		}
		t.Logf("second page: %d flows", len(second.Flows))
	}
	one, err := c.Flows(ctx, backends.FlowQuery{From: now.Add(-time.Hour), To: now, DeviceMAC: page.Flows[0].DeviceMAC})
	if err != nil {
		t.Fatalf("one device's flows: %v", err)
	}
	for _, f := range one.Flows {
		if f.DeviceMAC != page.Flows[0].DeviceMAC {
			t.Fatalf("a flow for another device came back from a one-device query")
		}
	}
	t.Logf("one device: %d flows", len(one.Flows))

	alarms, err := c.Alarms(ctx, backends.AlarmQuery{ActiveOnly: true})
	if err != nil {
		t.Fatalf("alarms: %v", err)
	}
	kinds := map[string]int{}
	for _, a := range alarms.Alarms {
		kinds[a.Type]++
		if a.ID == "" || a.Time.IsZero() {
			t.Errorf("an alarm without an id or a time: %+v", a.Type)
		}
	}
	t.Logf("alarms: %d %v", len(alarms.Alarms), kinds)

	rules, err := c.Rules(ctx)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	shape := map[string]int{}
	for _, r := range rules {
		shape[r.Action+" "+r.TargetType+" scope:"+r.ScopeType]++
		if r.ID == "" {
			t.Error("a rule without an id")
		}
	}
	t.Logf("rules: %d %v", len(rules), shape)

	if err := c.RenameDevice(ctx, devs[0].Ref(), "must not be sent"); err != backends.ErrReadOnly {
		t.Fatalf("a read-only client tried to rename: %v", err)
	}
}
