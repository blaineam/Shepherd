// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"encoding/binary"
	"maps"
	"math/bits"
	"slices"
	"sync"
	"sync/atomic"
)

// memberIndex maps domains to membership bitsets: bit i of a domain's mask is
// set when the domain belongs to item i. Identical masks are interned, so a
// domain costs one uint32 however many items contain it, and 200k to 1M
// domains stay modest in memory.
//
// Readers are lock free: they load an immutable snapshot. A single writer at
// a time builds the next snapshot (copying the domain map) and publishes it
// atomically, so queries never wait for a list refresh.
type memberIndex struct {
	wmu    sync.Mutex // serialises writers; guards intern and trans
	cur    atomic.Pointer[indexState]
	intern map[string]uint32 // mask bytes -> mask id
	trans  map[uint64]uint32 // (mask id, bit, op) -> mask id
}

// indexState is one immutable snapshot of the index.
type indexState struct {
	dom   map[string]uint32 // domain -> mask id; absent means the empty mask
	masks [][]uint64        // mask id -> words with trailing zero words trimmed; id 0 is empty
	bits  map[string]int    // item name -> bit
	names []string          // bit -> item name; "" once the item is removed
	size  map[string]int    // item name -> number of domains
	ver   uint64            // bumps whenever the item-to-bit mapping changes
}

func newMemberIndex() *memberIndex {
	mi := &memberIndex{intern: map[string]uint32{"": 0}, trans: map[uint64]uint32{}}
	mi.cur.Store(&indexState{
		dom:   map[string]uint32{},
		masks: [][]uint64{nil},
		bits:  map[string]int{},
		size:  map[string]int{},
	})
	return mi
}

func hasBit(mask []uint64, bit int) bool {
	w := bit >> 6
	return w < len(mask) && mask[w]&(1<<(uint(bit)&63)) != 0
}

func maskKey(m []uint64) string {
	b := make([]byte, 8*len(m))
	for i, w := range m {
		binary.LittleEndian.PutUint64(b[8*i:], w)
	}
	return string(b)
}

// internLocked returns the id of mask m (trimmed), adding it to st if new.
func (mi *memberIndex) internLocked(st *indexState, m []uint64) uint32 {
	for len(m) > 0 && m[len(m)-1] == 0 {
		m = m[:len(m)-1]
	}
	k := maskKey(m)
	if id, ok := mi.intern[k]; ok {
		return id
	}
	id := uint32(len(st.masks))
	st.masks = append(st.masks, m)
	mi.intern[k] = id
	return id
}

// flip returns the id of mask id with bit set (on) or cleared (off).
func (mi *memberIndex) flip(st *indexState, id uint32, bit int, on bool) uint32 {
	key := uint64(id)<<32 | uint64(bit)<<1
	if on {
		key |= 1
	}
	if r, ok := mi.trans[key]; ok {
		return r
	}
	old := st.masks[id]
	n := len(old)
	if w := bit>>6 + 1; w > n {
		n = w
	}
	m := make([]uint64, n)
	copy(m, old)
	if on {
		m[bit>>6] |= 1 << (uint(bit) & 63)
	} else {
		m[bit>>6] &^= 1 << (uint(bit) & 63)
	}
	r := mi.internLocked(st, m)
	mi.trans[key] = r
	return r
}

// set replaces the domain set of one item. A nil set removes the item.
func (mi *memberIndex) set(name string, set map[string]struct{}) {
	mi.setMany(map[string]map[string]struct{}{name: set})
}

// setMany applies several item replacements as one published snapshot.
func (mi *memberIndex) setMany(sets map[string]map[string]struct{}) {
	mi.wmu.Lock()
	defer mi.wmu.Unlock()
	old := mi.cur.Load()
	st := &indexState{
		dom:   maps.Clone(old.dom),
		masks: old.masks[:len(old.masks):len(old.masks)],
		bits:  maps.Clone(old.bits),
		names: slices.Clone(old.names),
		size:  maps.Clone(old.size),
		ver:   old.ver,
	}
	// Appending to st.masks must not write into storage an older snapshot can
	// see, so the capacity above is clipped and append reallocates.
	for name, set := range sets {
		mi.applyLocked(st, name, set)
	}
	mi.cur.Store(st)
}

func (mi *memberIndex) applyLocked(st *indexState, name string, set map[string]struct{}) {
	bit, known := st.bits[name]
	if set == nil {
		if !known {
			return
		}
		for d, id := range st.dom {
			if hasBit(st.masks[id], bit) {
				if nid := mi.flip(st, id, bit, false); nid == 0 {
					delete(st.dom, d)
				} else {
					st.dom[d] = nid
				}
			}
		}
		delete(st.bits, name)
		delete(st.size, name)
		st.names[bit] = ""
		st.ver++
		return
	}
	if !known {
		bit = slices.Index(st.names, "")
		if bit < 0 {
			bit = len(st.names)
			st.names = append(st.names, "")
		}
		st.names[bit] = name
		st.bits[name] = bit
		st.ver++
	} else {
		for d, id := range st.dom {
			if !hasBit(st.masks[id], bit) {
				continue
			}
			if _, keep := set[d]; keep {
				continue
			}
			if nid := mi.flip(st, id, bit, false); nid == 0 {
				delete(st.dom, d)
			} else {
				st.dom[d] = nid
			}
		}
	}
	for d := range set {
		id := st.dom[d]
		if !hasBit(st.masks[id], bit) {
			st.dom[d] = mi.flip(st, id, bit, true)
		}
	}
	st.size[name] = len(set)
}

func (mi *memberIndex) load() *indexState { return mi.cur.Load() }

// match ORs the masks of name and every parent with two or more labels into
// buf (reusing its storage) and returns the result.
func (st *indexState) match(name string, buf []uint64) []uint64 {
	out := buf[:0]
	walk(name, func(s string) {
		id, ok := st.dom[s]
		if !ok {
			return
		}
		for i, w := range st.masks[id] {
			if i == len(out) {
				out = append(out, w)
			} else {
				out[i] |= w
			}
		}
	})
	return out
}

// maskOf builds a mask with the bits of the named items; unknown names are
// ignored (they may be loaded later, which bumps ver and rebuilds masks).
func (st *indexState) maskOf(names []string) []uint64 {
	var m []uint64
	for _, n := range names {
		if b, ok := st.bits[n]; ok {
			m = setBitIn(m, b)
		}
	}
	return m
}

func setBitIn(m []uint64, bit int) []uint64 {
	for len(m) <= bit>>6 {
		m = append(m, 0)
	}
	m[bit>>6] |= 1 << (uint(bit) & 63)
	return m
}

func clearBitsIn(m, clear []uint64) []uint64 {
	out := slices.Clone(m)
	for i := range out {
		if i < len(clear) {
			out[i] &^= clear[i]
		}
	}
	return out
}

func intersects(a, b []uint64) bool {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i]&b[i] != 0 {
			return true
		}
	}
	return false
}

// commonNames lists the item names whose bits are set in both a and b.
func (st *indexState) commonNames(a, b []uint64) []string {
	var out []string
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		w := a[i] & b[i]
		for w != 0 {
			bit := i<<6 + bits.TrailingZeros64(w)
			w &= w - 1
			out = append(out, st.names[bit])
		}
	}
	return out
}
