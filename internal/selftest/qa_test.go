// SPDX-License-Identifier: AGPL-3.0-or-later

package selftest

import (
	"time"

	"context"
	"github.com/miekg/dns"
	"net"
	"strings"
	"testing"

	"shepherd/internal/dnsengine"
)

// The listener-coverage QA (docs/DNS-QA.md): real sockets on loopback
// aliases, standing in for a NAS with a wired and a Wi-Fi address. Linux
// answers on all of 127.0.0.0/8; where an alias cannot be bound (macOS
// without `ifconfig lo0 alias`) the tests skip.

func bindable(t *testing.T, ip string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("%s is not bindable here: %v", ip, err)
	}
	pc.Close()
}

// qaEngine serves a real engine on every ip at one port and returns the port.
func qaEngine(t *testing.T, ips ...string) (string, *dnsengine.Engine, *Tester) {
	t.Helper()
	pool, err := dnsengine.NewPool([]string{startUpstream(t)})
	if err != nil {
		t.Fatal(err)
	}
	e := &dnsengine.Engine{Filter: dnsengine.NewFilter(), Pool: pool, Cache: dnsengine.NewCache(100), Log: dnsengine.NewQueryLog(50), Stats: dnsengine.NewStats()}
	port := freePort(t)
	var addrs []string
	for _, ip := range ips {
		addrs = append(addrs, net.JoinHostPort(ip, port))
	}
	// Quiet is set before serving starts: the engine reads it on every query.
	tt := New(Options{Addrs: func() []string { return addrs }, Interfaces: hostOf(), Window: pool.Window})
	e.Quiet = tt.IsCanary
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = dnsengine.Serve(ctx, addrs, e); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	if len(addrs) > 0 {
		waitUp(t, addrs[0])
	}
	return port, e, tt
}

func TestQA_EveryServedAddressAnswersOverUDPAndTCP(t *testing.T) {
	bindable(t, "127.0.0.2")
	bindable(t, "127.0.0.3")
	_, e, tt := qaEngine(t, "127.0.0.1", "127.0.0.2", "127.0.0.3")
	r := tt.RunOnce(context.Background())
	if r.Status != StatusOK || len(r.Listeners) != 3 {
		t.Fatalf("report = %+v", r)
	}
	for _, l := range r.Listeners {
		if len(l.Probes) != 6 {
			t.Errorf("%s probes = %+v", l.Addr, l.Probes)
		}
	}
	if n := len(e.Log.All()); n != 0 {
		t.Errorf("%d canary queries leaked into the query log", n)
	}
}

// TestQA_AnAddressDevicesUseWithNoListenerIsCaught is the incident this
// suite exists for: Shepherd listening on the Wi-Fi address while devices
// were configured with the wired one.
func TestQA_AnAddressDevicesUseWithNoListenerIsCaught(t *testing.T) {
	bindable(t, "127.0.0.2")
	port, _, _ := qaEngine(t, "127.0.0.2") // the only address actually served
	wifi, wired := net.JoinHostPort("127.0.0.2", port), net.JoinHostPort("127.0.0.3", port)

	// Shepherd "says" it listens on both; only the Wi-Fi one is real.
	tt := New(Options{Addrs: func() []string { return []string{wifi, wired} }, Interfaces: hostOf()})
	r := tt.RunOnce(context.Background())
	if r.Status != StatusFail {
		t.Fatalf("status = %s", r.Status)
	}
	var down []string
	for _, p := range r.Problems {
		if p.Check == CheckListener {
			down = append(down, p.Subject)
		}
	}
	if len(down) != 2 || !strings.HasPrefix(down[0], wired) {
		t.Fatalf("listener problems = %v, want the wired address over udp and tcp", down)
	}
	if !r.Listeners[0].OK || r.Listeners[1].OK {
		t.Errorf("listeners = %+v", r.Listeners)
	}
}

func TestQA_ABlockedNameOnTheOwnersListIsChecked(t *testing.T) {
	bindable(t, "127.0.0.2")
	port, e, _ := qaEngine(t, "127.0.0.2")
	addr := net.JoinHostPort("127.0.0.2", port)
	opts := func(blocked string) *Tester {
		return New(Options{Addrs: func() []string { return []string{addr} }, Interfaces: hostOf(), BlockedName: blocked})
	}
	// A name on a list is blocked: the check passes.
	e.Filter.SetList("ads", map[string]struct{}{"ads.example": {}})
	if r := opts("tracker.ads.example").RunOnce(context.Background()); r.Status != StatusOK {
		t.Fatalf("listed name: %+v", r.Problems)
	}
	// A name on no list is not blocked: the check fails, naming the block.
	if r := opts("not-listed.example").RunOnce(context.Background()); problemChecks(r)[CheckBlock] != 2 {
		t.Fatalf("unlisted name: %+v", r.Problems)
	}
}

func TestQA_LANAddressWithoutAListenerWarns(t *testing.T) {
	bindable(t, "127.0.0.2")
	port, _, _ := qaEngine(t, "127.0.0.2")
	listen := []string{net.JoinHostPort("127.0.0.2", port)}
	nas := hostOf("eno1=10.0.0.20", "wlan0=10.0.0.102")

	tt := New(Options{Addrs: func() []string { return append(listen, "10.0.0.102:"+port) }, Interfaces: nas, Exchange: func(ctx context.Context, n, a string, m *dns.Msg, d time.Duration) (*dns.Msg, error) {
		// 10.0.0.102 is not really ours: answer from the real loopback listener.
		return exchange(ctx, n, strings.Replace(a, "10.0.0.102", "127.0.0.2", 1), m, d)
	}})
	r := tt.RunOnce(context.Background())
	states := map[string]string{}
	for _, l := range r.LAN {
		states[l.IP] = l.State
	}
	if states["10.0.0.20"] != "unserved" || states["10.0.0.102"] != "served" {
		t.Fatalf("lan = %+v", r.LAN)
	}
	if r.Status != StatusWarn {
		t.Errorf("status = %s, want warn", r.Status)
	}
}
