// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheItem struct {
	msg    *dns.Msg
	stored time.Time
	ttl    time.Duration
}

// Cache is a small TTL cache of upstream answers. A max of zero disables it.
type Cache struct {
	mu  sync.Mutex
	m   map[string]cacheItem
	max int
}

func NewCache(max int) *Cache { return &Cache{m: map[string]cacheItem{}, max: max} }

func cacheKey(r *dns.Msg) string {
	q := r.Question[0]
	do := false
	if o := r.IsEdns0(); o != nil {
		do = o.Do()
	}
	return fmt.Sprintf("%s|%d|%d|%t", strings.ToLower(q.Name), q.Qtype, q.Qclass, do)
}

func (c *Cache) Get(r *dns.Msg) (*dns.Msg, bool) {
	if c.max <= 0 {
		return nil, false
	}
	key := cacheKey(r)
	c.mu.Lock()
	it, ok := c.m[key]
	if ok && time.Since(it.stored) >= it.ttl {
		delete(c.m, key)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	elapsed := uint32(time.Since(it.stored) / time.Second)
	resp := it.msg.Copy()
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 1
			}
		}
	}
	resp.Id = r.Id
	resp.Question = r.Question
	return resp, true
}

// Put stores resp if it is a cacheable answer: NOERROR or NXDOMAIN, not
// truncated, with a nonzero TTL.
func (c *Cache) Put(r, resp *dns.Msg) {
	if c.max <= 0 || resp.Truncated || (resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError) {
		return
	}
	ttl := uint32(30)
	seen := false
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range section {
			if t := rr.Header().Ttl; !seen || t < ttl {
				ttl, seen = t, true
			}
		}
	}
	if ttl == 0 {
		return
	}
	if ttl > 3600 {
		ttl = 3600
	}
	c.mu.Lock()
	if len(c.m) >= c.max {
		for k := range c.m { // evict an arbitrary entry
			delete(c.m, k)
			break
		}
	}
	c.m[cacheKey(r)] = cacheItem{msg: resp.Copy(), stored: time.Now(), ttl: time.Duration(ttl) * time.Second}
	c.mu.Unlock()
}
