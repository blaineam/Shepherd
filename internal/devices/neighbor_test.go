// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const procARP = `IP address       HW type     Flags       HW address            Mask     Device
192.0.2.1        0x1         0x2         02:00:5e:00:00:01     *        eth0
192.0.2.2        0x1         0x0         00:00:00:00:00:00     *        eth0
192.0.2.3        0x1         0x6         02:00:5e:00:00:03     *        eth0
198.51.100.9     0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0 # leakcheck:allow broadcast constant
not-an-ip        0x1         0x2         02:00:5e:00:00:04     *        eth0
192.0.2.5        0x1         0x2
`

const arpAn = `? (192.0.2.1) at 2:0:5e:0:0:1 on en0 ifscope [ethernet]
router.example.net (192.0.2.254) at 2:0:5e:0:0:fe on en0 ifscope permanent [ethernet]
? (192.0.2.7) at (incomplete) on en0 ifscope [ethernet]
? (233.252.0.1) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet] # leakcheck:allow multicast test net
? (192.0.2.9) at 2:0:5e:0:0:9
garbage line
? (203.0.113.1) bad
`

const ipNeigh = `2001:db8::1 dev eth0 lladdr 02:00:5e:00:00:01 router REACHABLE
2001:db8::2 dev eth0 FAILED
192.0.2.4 dev eth1 lladdr 02:00:5e:00:00:04 STALE
short line
2001:db8::3 dev eth0 lladdr bogus STALE
`

func TestParseProcNetARP(t *testing.T) {
	got := ParseProcNetARP([]byte(procARP))
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	eq(t, got[0], Neighbor{IP: "192.0.2.1", MAC: "02:00:5e:00:00:01", Iface: "eth0"})
	eq(t, got[1].IP, "192.0.2.3")
	if ParseProcNetARP(nil) != nil {
		t.Fatal("empty input")
	}
}

func TestParseArpAn(t *testing.T) {
	got := ParseArpAn([]byte(arpAn))
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	eq(t, got[0], Neighbor{IP: "192.0.2.1", MAC: "02:00:5e:00:00:01", Iface: "en0"})
	eq(t, got[1].MAC, "02:00:5e:00:00:fe")
	eq(t, got[2], Neighbor{IP: "192.0.2.9", MAC: "02:00:5e:00:00:09"}) // no "on" field
}

func TestParseIPNeigh(t *testing.T) {
	got := ParseIPNeigh([]byte(ipNeigh))
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	eq(t, got[0], Neighbor{IP: "2001:db8::1", MAC: "02:00:5e:00:00:01", Iface: "eth0"})
	eq(t, got[1].Iface, "eth1")
}

func TestNeighborSources(t *testing.T) {
	f := FileNeighbors{Path: "/fake/arp", Parse: ParseProcNetARP,
		ReadFile: func(p string) ([]byte, error) {
			if p != "/fake/arp" {
				t.Fatalf("path %q", p)
			}
			return []byte(procARP), nil
		}}
	ns, err := f.Neighbors(context.Background())
	if err != nil || len(ns) != 2 {
		t.Fatalf("%v %v", ns, err)
	}
	f.ReadFile = func(string) ([]byte, error) { return nil, errors.New("nope") }
	if _, err := f.Neighbors(context.Background()); err == nil {
		t.Fatal("read error swallowed")
	}
	// Default reader hits a path that cannot exist.
	if _, err := (FileNeighbors{Path: "/nonexistent/shepherd-test/arp", Parse: ParseProcNetARP}).Neighbors(context.Background()); err == nil {
		t.Fatal("expected ENOENT")
	}

	c := CommandNeighbors{Name: "arp", Args: []string{"-an"}, Parse: ParseArpAn,
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "arp" || len(args) != 1 || args[0] != "-an" {
				t.Fatalf("command %q %v", name, args)
			}
			return []byte(arpAn), nil
		}}
	ns, err = c.Neighbors(context.Background())
	if err != nil || len(ns) != 3 {
		t.Fatalf("%v %v", ns, err)
	}
	c.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("exec failed") }
	if _, err := c.Neighbors(context.Background()); err == nil {
		t.Fatal("run error swallowed")
	}
	// The default runner executes a real (harmless, local) command that does not exist.
	if _, err := (CommandNeighbors{Name: "shepherd-no-such-command", Parse: ParseArpAn}).Neighbors(context.Background()); err == nil {
		t.Fatal("expected exec error")
	}

	if len(DefaultNeighborSources("linux")) != 2 || len(DefaultNeighborSources("darwin")) != 1 || DefaultNeighborSources("plan9") != nil {
		t.Fatal("DefaultNeighborSources")
	}
}

type fakeSource struct {
	ns  []Neighbor
	err error
}

func (f fakeSource) Neighbors(context.Context) ([]Neighbor, error) { return f.ns, f.err }

func TestPollerFeedsRegistry(t *testing.T) {
	r, clk := newReg(t)
	p := &Poller{
		Sources: []NeighborSource{
			fakeSource{ns: []Neighbor{{IP: "192.0.2.1", MAC: macA}, {IP: "192.0.2.2", MAC: macB}}},
			fakeSource{err: errors.New("ip not installed")},
			fakeSource{ns: []Neighbor{{IP: "2001:db8::1", MAC: macA}}},
		},
		Sink: r, Now: clk.Now,
	}
	n, err := p.PollOnce(context.Background())
	if n != 3 || err == nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if r.Len() != 2 {
		t.Fatalf("devices: %d", r.Len())
	}
	d, _ := r.FindByMAC(macA)
	eq(t, d.IPs, []string{"192.0.2.1", "2001:db8::1"})
}

func TestPollerRun(t *testing.T) {
	r, _ := newReg(t)
	var mu sync.Mutex
	var errs []error
	p := &Poller{
		Sources:  []NeighborSource{fakeSource{ns: []Neighbor{{IP: "192.0.2.1", MAC: macA}}}, fakeSource{err: errors.New("x")}},
		Sink:     r,
		Interval: time.Millisecond,
		OnError:  func(e error) { mu.Lock(); errs = append(errs, e); mu.Unlock() },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- p.Run(ctx) }()
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(errs)
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("poller did not tick")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatal("no device from poller")
	}
	// Defaults: zero interval and nil clock/handler are fine.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	p2 := &Poller{Sources: []NeighborSource{fakeSource{err: errors.New("x")}}, Sink: r}
	if err := p2.Run(ctx2); err != nil {
		t.Fatal(err)
	}
}
