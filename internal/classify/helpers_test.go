// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"shepherd/internal/devices"
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

// Documentation ranges stand in for the internet. The synthetic "network
// database" below gives each a made-up owner.
var (
	netStreaming = netip.MustParsePrefix("198.51.100.0/24") // AS2906, a streaming network (a verified hint)
	netCloud     = netip.MustParsePrefix("203.0.113.0/24")  // a big shared cloud (zero weight)
	netGoogle    = netip.MustParsePrefix("2001:db8::/32")   // shared as well
)

func fakeASN(a netip.Addr) (ASNInfo, bool) {
	switch {
	case netStreaming.Contains(a):
		return ASNInfo{2906, "Netflix Streaming Services Inc."}, true
	case netCloud.Contains(a):
		return ASNInfo{16509, "Amazon.com, Inc."}, true
	case netGoogle.Contains(a):
		return ASNInfo{15169, "Google LLC"}, true
	}
	return ASNInfo{}, false
}

func ips(s ...string) []net.IP {
	out := make([]net.IP, len(s))
	for i, x := range s {
		out[i] = net.ParseIP(x)
	}
	return out
}

func newClassifier(t testing.TB, mod ...func(*Options)) (*Classifier, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	o := Options{Now: clk.Now, ASN: fakeASN}
	for _, m := range mod {
		m(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c, clk
}

// look feeds n lookups of name (answered from addr) from a client.
func look(c *Classifier, client, name, addr string, n int) {
	for i := 0; i < n; i++ {
		c.Observe(client, name, ips(addr))
	}
}

// profile is an invented device: what it looks up and what the registry
// knows about it.
type profile struct {
	name       string
	vendor     string
	random     bool
	services   []string
	names      []string
	lookups    []lookup
	want       devices.DeviceType // what a person would say it is
	wantUnsure bool               // "unknown" or a low-confidence answer is also acceptable
	minConf    float64
}

type lookup struct {
	name string
	addr string
	n    int
}

func (p profile) feed(c *Classifier, key, client string) {
	c.SetResolver(func(ip string) string {
		if ip == client {
			return key
		}
		return ""
	})
	c.ObserveDevice(key, p.vendor, p.services, p.random)
	if len(p.names) > 0 {
		c.ObserveNames(key, p.names, nil)
	}
	for _, l := range p.lookups {
		look(c, client, l.name, l.addr, l.n)
	}
}

func mustType(t testing.TB, got devices.DeviceType, want devices.DeviceType, why any) {
	t.Helper()
	if got != want {
		t.Fatalf("type = %q, want %q (%v)", got, want, why)
	}
}

func describe(r Result) string {
	return fmt.Sprintf("%s %.2f %q alts=%v", r.Type, r.Confidence, r.Reasons, r.Alternatives)
}
