// SPDX-License-Identifier: AGPL-3.0-or-later

package linkwatch

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var lan = netip.MustParseAddr("192.0.2.10")

type script struct {
	ifs  []Iface
	err  error
	now  time.Time
	lost []Episode
	back []Episode
}

func newScript(t *testing.T, addrs ...netip.Addr) (*script, *Watcher) {
	t.Helper()
	s := &script{now: time.Date(2026, 11, 15, 4, 0, 0, 0, time.UTC)}
	s.ifs = []Iface{{Name: "eth0", Up: true, Running: true, Addrs: []netip.Addr{lan}}}
	w := New(Options{
		Addrs:      addrs,
		List:       func() ([]Iface, error) { return s.ifs, s.err },
		Now:        func() time.Time { return s.now },
		OnLost:     func(e Episode) { s.lost = append(s.lost, e) },
		OnRestored: func(e Episode) { s.back = append(s.back, e) },
	})
	return s, w
}

func (s *script) tick(w *Watcher, d time.Duration) { s.now = s.now.Add(d); w.Poll() }

func TestHealthyLinkSaysNothing(t *testing.T) {
	s, w := newScript(t, lan)
	for i := 0; i < 5; i++ {
		s.tick(w, time.Second)
	}
	if len(s.lost)+len(s.back) != 0 {
		t.Fatalf("lost=%v back=%v", s.lost, s.back)
	}
}

func TestCarrierLossIsReportedWithItsDuration(t *testing.T) {
	s, w := newScript(t, lan)
	s.tick(w, time.Second)
	s.ifs[0].Running = false
	s.tick(w, time.Second)
	if len(s.lost) != 1 || !strings.Contains(s.lost[0].Reason, "no carrier") || s.lost[0].Iface != "eth0" {
		t.Fatalf("lost = %+v", s.lost)
	}
	s.tick(w, 11*time.Second) // still down: no second report
	if len(s.lost) != 1 || len(w.Open()) != 1 {
		t.Fatalf("a continuing outage must be reported once: %+v", s.lost)
	}
	s.ifs[0].Running = true
	s.tick(w, time.Second)
	if len(s.back) != 1 {
		t.Fatalf("back = %+v", s.back)
	}
	if d := s.back[0].Duration(s.now); d != 12*time.Second {
		t.Fatalf("duration %v, want 12s", d)
	}
	if len(w.Open()) != 0 {
		t.Fatal("episode should be closed")
	}
}

func TestAdministrativelyDownAndAddressRemoved(t *testing.T) {
	s, w := newScript(t, lan)
	s.ifs[0].Up = false
	s.tick(w, time.Second)
	if !strings.Contains(s.lost[0].Reason, "taken down") {
		t.Fatalf("reason %q", s.lost[0].Reason)
	}
	s.ifs[0].Up = true
	s.tick(w, time.Second)

	s.ifs[0].Addrs = nil // a DHCP renewal that drops the address for a moment
	s.tick(w, time.Second)
	if len(s.lost) != 2 || !strings.Contains(s.lost[1].Reason, "removed") || s.lost[1].Iface != "eth0" {
		t.Fatalf("lost = %+v", s.lost)
	}
	s.ifs[0].Addrs = []netip.Addr{lan}
	s.tick(w, time.Second)
	if len(s.back) != 2 {
		t.Fatalf("back = %+v", s.back)
	}
}

func TestListingFailureIsNotAFinding(t *testing.T) {
	s, w := newScript(t, lan)
	s.err = errors.New("netlink: busy")
	s.tick(w, time.Second)
	if len(s.lost) != 0 {
		t.Fatalf("lost = %+v", s.lost)
	}
}

func TestEachAddressIsTrackedOnItsOwn(t *testing.T) {
	ts := netip.MustParseAddr("198.51.100.7")
	s, w := newScript(t, lan, ts)
	s.ifs = append(s.ifs, Iface{Name: "tailscale0", Up: true, Running: true, Addrs: []netip.Addr{ts}})
	s.tick(w, time.Second)
	s.ifs[1].Running = false
	s.tick(w, time.Second)
	if len(s.lost) != 1 || s.lost[0].Addr != ts {
		t.Fatalf("lost = %+v", s.lost)
	}
}

func TestLoopbackUnspecifiedAndMappedAddressesAreHandled(t *testing.T) {
	w := New(Options{Addrs: []netip.Addr{
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"),
		netip.MustParseAddr("::ffff:192.0.2.10"), {},
	}})
	if w.Watching() != 1 {
		t.Fatalf("watching %d addresses, want 1", w.Watching())
	}
}

func TestRunPollsUntilCancelled(t *testing.T) {
	polls := make(chan struct{}, 8)
	w := New(Options{
		Addrs:    []netip.Addr{lan},
		Interval: 5 * time.Millisecond,
		List: func() ([]Iface, error) {
			select {
			case polls <- struct{}{}:
			default:
			}
			return []Iface{{Name: "eth0", Up: true, Running: true, Addrs: []netip.Addr{lan}}}, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	for i := 0; i < 3; i++ {
		select {
		case <-polls:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not poll")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	// With nothing to watch Run returns at once.
	New(Options{}).Run(context.Background())
}

func TestSystemInterfacesSeesLoopback(t *testing.T) {
	ifs, err := SystemInterfaces()
	if err != nil || len(ifs) == 0 {
		t.Fatalf("ifs=%v err=%v", ifs, err)
	}
	found := false
	for _, i := range ifs {
		for _, a := range i.Addrs {
			if a.IsLoopback() {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no loopback address listed")
	}
}

func TestEpisodeDurationWhileOpen(t *testing.T) {
	st := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := Episode{Start: st}
	if d := e.Duration(st.Add(90 * time.Second)); d != 90*time.Second {
		t.Fatalf("d = %v", d)
	}
}
