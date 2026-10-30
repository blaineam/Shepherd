// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"testing"
	"time"
)

func TestPendingDigestAdd(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	p := newPendingDigest("s1", now, now.Add(time.Hour))

	p.add(AccessEvent{Time: now, Item: "gaming", Domain: "a.example.com", ClientID: "dev1", Action: "allowed"})
	p.add(AccessEvent{Time: now.Add(time.Minute), Item: "gaming", Domain: "a.example.com", ClientID: "dev1", Action: "blocked"})
	p.add(AccessEvent{Time: now.Add(2 * time.Minute), Item: "gambling", Domain: "b.example.com", ClientID: "dev2", Action: "blocked"})

	if p.Total != 3 {
		t.Errorf("Total = %d, want 3", p.Total)
	}
	gaming := p.Items["gaming"]
	if gaming == nil || gaming.Count != 2 || gaming.Allowed != 1 || gaming.Blocked != 1 {
		t.Fatalf("gaming agg = %+v", gaming)
	}
	if gaming.Domains["a.example.com"] != 2 {
		t.Errorf("gaming domain count = %d, want 2", gaming.Domains["a.example.com"])
	}
	gambling := p.Items["gambling"]
	if gambling == nil || gambling.Count != 1 || gambling.Blocked != 1 {
		t.Fatalf("gambling agg = %+v", gambling)
	}
	if p.Devices["dev1"] != 2 || p.Devices["dev2"] != 1 {
		t.Errorf("Devices = %v", p.Devices)
	}
}

func TestPendingDigestAddWithoutDomainOrClient(t *testing.T) {
	now := time.Now()
	p := newPendingDigest("s1", now, now)
	p.add(AccessEvent{Time: now, Item: "gaming", Action: "allowed"})
	if p.Items["gaming"].Domains != nil {
		t.Errorf("Domains should stay nil when no domain was given")
	}
	if len(p.Devices) != 0 {
		t.Errorf("Devices should stay empty when no client ID was given")
	}
}

func TestIsBlocked(t *testing.T) {
	cases := map[string]bool{"blocked": true, "Blocked": true, "BLOCKED": true, "allowed": false, "cached": false, "": false}
	for in, want := range cases {
		if got := isBlocked(in); got != want {
			t.Errorf("isBlocked(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestWindowFor(t *testing.T) {
	cases := []struct {
		name string
		sub  Subscription
		want time.Duration
	}{
		{"immediate uses the immediate window", Subscription{Mode: ModeImmediate}, 5 * time.Minute},
		{"digest with explicit interval", Subscription{Mode: ModeDigest, DigestInterval: time.Hour}, time.Hour},
		{"digest with no interval defaults to daily", Subscription{Mode: ModeDigest}, 24 * time.Hour},
		{"digest with weekly interval", Subscription{Mode: ModeDigest, DigestInterval: 7 * 24 * time.Hour}, 7 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowFor(tc.sub, 5*time.Minute); got != tc.want {
				t.Errorf("windowFor() = %v, want %v", got, tc.want)
			}
		})
	}
}
