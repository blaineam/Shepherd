// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"fmt"
	"sync"
	"testing"
)

func TestScopesFor(t *testing.T) {
	r, _ := newReg(t)
	id := r.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	r.Observe(Observation{MAC: macA, IP: "2001:db8::1"})
	r.CreateGroup("Kids", "")
	r.CreateGroup("Guests", "")
	r.BulkAssignGroup([]string{id}, "kids")
	r.BulkAssignGroup([]string{id}, "guests")

	for _, ip := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", "2001:DB8:0:0:0:0:0:1", "2001:db8::1%eth0"} {
		dev, groups := r.ScopesFor(ip)
		if dev != id || fmt.Sprint(groups) != "[guests kids]" {
			t.Errorf("ScopesFor(%q) = %q %v", ip, dev, groups)
		}
	}
	for _, ip := range []string{"", "garbage", "192.0.2.77", "2001:db8::2"} {
		if dev, groups := r.ScopesFor(ip); dev != "" || groups != nil {
			t.Errorf("unknown %q resolved to %q %v", ip, dev, groups)
		}
	}
	// A device without groups yields a nil slice.
	other := r.Observe(Observation{MAC: macB, IP: "192.0.2.2", Source: SourceNeighbor, Hostname: "x"})
	if dev, groups := r.ScopesFor("192.0.2.2"); dev != other || groups != nil {
		t.Fatalf("%q %v", dev, groups)
	}
	// An empty registry answers too.
	e, _ := newReg(t)
	if dev, g := e.ScopesFor("192.0.2.1"); dev != "" || g != nil {
		t.Fatal("empty registry")
	}
}

func TestConcurrentObserveSearchScopes(t *testing.T) {
	r, _ := newReg(t)
	r.CreateGroup("G", "")
	var wg sync.WaitGroup
	const workers, iters = 8, 200
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ip := fmt.Sprintf("192.0.2.%d", (w*31+i)%250+1)
				mac := fmt.Sprintf("02:00:5e:00:%02x:%02x", w, i%64)
				id := r.Observe(Observation{MAC: mac, IP: ip})
				switch i % 5 {
				case 0:
					r.Search("192.0.2", SearchOptions{Limit: 10})
				case 1:
					r.BulkAssignGroup([]string{id}, "g")
				case 2:
					r.BulkSetTags([]string{id}, []string{"t"}, nil)
				case 3:
					r.Rename(id, fmt.Sprintf("n-%d-%d", w, i))
				case 4:
					r.Observe(Observation{Source: SourceDNS, IP: ip})
				}
				r.ScopesFor(ip)
				r.Get(id)
				r.Groups()
			}
		}(w)
	}
	// Readers hammering ScopesFor while writers run.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				r.ScopesFor(fmt.Sprintf("192.0.2.%d", j%250+1))
			}
		}()
	}
	wg.Wait()
	// Index invariant: every current IP resolves to the device that lists it.
	for _, d := range r.List() {
		for _, ip := range d.IPs {
			if got, _ := r.ScopesFor(ip); got != d.ID {
				t.Fatalf("index mismatch for %s: %s vs %s", ip, got, d.ID)
			}
		}
	}
}
