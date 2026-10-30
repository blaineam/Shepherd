// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

import "testing"

func TestDefaultPortsAreValidAndUnique(t *testing.T) {
	if len(DefaultPorts) < 20 || len(DefaultPorts) > 60 {
		t.Fatalf("DefaultPorts has %d entries, want a short list (roughly 20-60)", len(DefaultPorts))
	}
	seen := map[int]bool{}
	for _, p := range DefaultPorts {
		if p < 1 || p > 65535 {
			t.Fatalf("DefaultPorts contains invalid port %d", p)
		}
		if seen[p] {
			t.Fatalf("DefaultPorts contains duplicate port %d", p)
		}
		seen[p] = true
	}
}

// TestRiskyPortsAreScanned keeps the risky list honest: a port that is never
// in the default scan can never be flagged, so every risky port must also be
// a default one.
func TestRiskyPortsAreScanned(t *testing.T) {
	scanned := map[int]bool{}
	for _, p := range DefaultPorts {
		scanned[p] = true
	}
	for p := range RiskyPorts {
		if !scanned[p] {
			t.Errorf("risky port %d is not in DefaultPorts, so it would never be flagged", p)
		}
	}
}

func TestIsRisky(t *testing.T) {
	if reason, risky := IsRisky(23); !risky || reason == "" {
		t.Fatalf("IsRisky(23) = %q, %v; want a reason and true", reason, risky)
	}
	if _, risky := IsRisky(80); risky {
		t.Fatalf("IsRisky(80) = true, want false")
	}
}
