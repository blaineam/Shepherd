// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"fmt"
	"slices"
	"sync"
	"testing"
)

func TestMemberIndexMembershipAndInterning(t *testing.T) {
	mi := newMemberIndex()
	mi.set("a", set("one.example", "two.example", "both.example"))
	mi.set("b", set("both.example", "three.example"))
	mi.set("c", set("both.example"))

	st := mi.load()
	if got := st.commonNames(st.match("sub.both.example", nil), st.match("sub.both.example", nil)); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("both.example members = %v", got)
	}
	if got := st.match("nothing.example", nil); len(got) != 0 {
		t.Errorf("unlisted name matched %v", got)
	}
	if n := st.size["a"]; n != 3 {
		t.Errorf("size a = %d", n)
	}
	// 5 distinct domains but only the masks {a}, {b}, {a,b,c} (+ intermediates) exist.
	before := len(st.masks)
	for i := 0; i < 1000; i++ {
		mi.set("a", set("one.example", "two.example", "both.example"))
	}
	if after := len(mi.load().masks); after != before {
		t.Errorf("re-setting an identical list grew the mask table %d -> %d", before, after)
	}
}

func TestMemberIndexReplaceAndRemove(t *testing.T) {
	mi := newMemberIndex()
	mi.set("a", set("one.example", "two.example"))
	mi.set("b", set("two.example"))
	mi.set("a", set("two.example", "new.example")) // one.example leaves, new.example joins
	st := mi.load()
	if _, ok := st.dom["one.example"]; ok {
		t.Error("removed domain still indexed")
	}
	if got := st.commonNames(st.match("two.example", nil), st.match("two.example", nil)); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("two.example members = %v", got)
	}

	mi.set("a", nil)
	mi.set("zzz", nil) // removing an unknown item is a no-op
	st = mi.load()
	if _, ok := st.bits["a"]; ok {
		t.Error("removed item keeps its bit")
	}
	if _, ok := st.dom["new.example"]; ok {
		t.Error("exclusive domain survived item removal")
	}
	if got := st.match("two.example", nil); len(got) == 0 {
		t.Error("shared domain lost with the removed item")
	}

	// The freed bit is reused, and a fresh member does not inherit old membership.
	mi.set("d", set("fresh.example"))
	st = mi.load()
	if st.bits["d"] != 0 && st.bits["d"] != 1 {
		t.Errorf("freed bit not reused: %d", st.bits["d"])
	}
	if got := st.commonNames(st.match("two.example", nil), st.match("two.example", nil)); !slices.Equal(got, []string{"b"}) {
		t.Errorf("stale membership after bit reuse: %v", got)
	}
}

func TestMemberIndexManyItemsUseMultipleWords(t *testing.T) {
	mi := newMemberIndex()
	for i := 0; i < 150; i++ {
		mi.set(fmt.Sprintf("item%03d", i), set(fmt.Sprintf("d%d.example", i), "shared.example"))
	}
	st := mi.load()
	hit := st.match("shared.example", nil)
	if len(hit) != 3 {
		t.Fatalf("mask words = %d, want 3", len(hit))
	}
	if n := len(st.commonNames(hit, hit)); n != 150 {
		t.Errorf("shared.example in %d items, want 150", n)
	}
	last := st.match("d149.example", nil)
	if names := st.commonNames(last, last); !slices.Equal(names, []string{"item149"}) {
		t.Errorf("d149.example members = %v", names)
	}
	// Matching ORs parent masks into a reused buffer that must grow.
	small := make([]uint64, 0, 1)
	if got := st.match("x.shared.example", small); len(got) != 3 {
		t.Errorf("grown buffer = %v", got)
	}
}

func TestMemberIndexConcurrentReadersAndWriter(t *testing.T) {
	mi := newMemberIndex()
	mi.set("a", set("x.example"))
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					st := mi.load()
					st.match("x.example", nil)
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		mi.set("a", set("x.example", fmt.Sprintf("n%d.example", i)))
		mi.set("b", set("x.example"))
		mi.set("b", nil)
	}
	close(stop)
	wg.Wait()
}

func TestMaskHelpers(t *testing.T) {
	var m []uint64
	m = setBitIn(m, 70)
	if len(m) != 2 || !hasBit(m, 70) || hasBit(m, 5) || hasBit(m, 500) {
		t.Errorf("setBitIn/hasBit wrong: %v", m)
	}
	if intersects(m, []uint64{1}) || !intersects(m, []uint64{0, 1 << 6}) || intersects(nil, m) {
		t.Error("intersects wrong")
	}
	cleared := clearBitsIn(m, []uint64{0, 1 << 6})
	if hasBit(cleared, 70) || !hasBit(m, 70) {
		t.Error("clearBitsIn must not modify its input and must clear the bit")
	}
	if clearBitsIn(m, nil)[1] != m[1] {
		t.Error("clearing nothing changed the mask")
	}
}
