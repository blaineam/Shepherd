// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import "container/list"

// lru is a fixed-capacity map that evicts the least recently used entry.
// It is not safe for concurrent use; the Monitor guards it.
type lru[K comparable, V any] struct {
	cap int
	ll  *list.List
	m   map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	k K
	v V
}

func newLRU[K comparable, V any](capacity int) *lru[K, V] {
	if capacity < 1 {
		capacity = 1
	}
	return &lru[K, V]{cap: capacity, ll: list.New(), m: make(map[K]*list.Element)}
}

// get returns the value and marks it recently used.
func (c *lru[K, V]) get(k K) (V, bool) {
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*lruEntry[K, V]).v, true
	}
	var zero V
	return zero, false
}

// peek returns the value without touching recency.
func (c *lru[K, V]) peek(k K) (V, bool) {
	if e, ok := c.m[k]; ok {
		return e.Value.(*lruEntry[K, V]).v, true
	}
	var zero V
	return zero, false
}

// put stores a value, evicting the oldest entry when full.
func (c *lru[K, V]) put(k K, v V) {
	if e, ok := c.m[k]; ok {
		e.Value.(*lruEntry[K, V]).v = v
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(&lruEntry[K, V]{k, v})
	if c.ll.Len() > c.cap {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.m, old.Value.(*lruEntry[K, V]).k)
	}
}

func (c *lru[K, V]) len() int { return c.ll.Len() }
