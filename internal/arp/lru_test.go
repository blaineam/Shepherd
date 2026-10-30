// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import "testing"

func TestLRU(t *testing.T) {
	c := newLRU[int, string](2)
	c.put(1, "a")
	c.put(2, "b")
	if v, ok := c.get(1); !ok || v != "a" { // 1 is now most recent
		t.Fatal("get 1")
	}
	c.put(3, "c") // evicts 2
	if _, ok := c.peek(2); ok {
		t.Fatal("2 should be evicted")
	}
	if v, ok := c.peek(1); !ok || v != "a" {
		t.Fatal("1 should remain")
	}
	c.put(1, "z")
	if v, _ := c.get(1); v != "z" || c.len() != 2 {
		t.Fatalf("update: %q len %d", v, c.len())
	}
	if _, ok := c.get(99); ok {
		t.Fatal("phantom")
	}
	if _, ok := c.peek(99); ok {
		t.Fatal("phantom peek")
	}
	if newLRU[int, int](0).cap != 1 {
		t.Fatal("capacity floor")
	}
}
