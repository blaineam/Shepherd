// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"shepherd/internal/arp"
)

// End to end, against a real kernel: AttachXDP on one end of a veth pair,
// a Controller steering a fake device, frames injected on the peer, and
// the relayed frames read back off the peer (XDP_TX on veth sends the
// frame out, which the peer receives). Needs root (or CAP_NET_ADMIN +
// CAP_BPF + CAP_NET_RAW) and the ip tool; skips otherwise. `make test-xdp`
// runs it in a privileged container.
func TestAttachXDPRelaysOnVeth(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a veth pair and attach XDP")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs the ip tool")
	}
	const a, b = "shepxdp0", "shepxdp1"
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	_ = exec.Command("ip", "link", "del", a).Run()
	// Being root is not enough: an unprivileged container runs as root
	// without CAP_NET_ADMIN, where creating a veth pair is refused. Skip
	// on that rather than failing, so a plain `go test` in a container
	// behaves like one on a developer's machine. `make test-xdp` runs this
	// for real in a privileged container.
	if out, err := exec.Command("ip", "link", "add", a, "type", "veth", "peer", "name", b).CombinedOutput(); err != nil {
		t.Skipf("cannot create a veth pair (needs CAP_NET_ADMIN): %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", a).Run() })
	run("link", "set", a, "up")
	run("link", "set", b, "up")
	run("addr", "add", "192.0.2.2/24", "dev", a)

	ifA, err := net.InterfaceByName(a)
	if err != nil {
		t.Fatal(err)
	}
	var shepMAC arp.MAC
	copy(shepMAC[:], ifA.HardwareAddr)

	// Shepherd's side: the Controller with a sender on a (the Spoofer's
	// ARP claims go out of a too; the peer just sees them).
	sender, err := Open(a)
	if err != nil {
		t.Fatalf("Open(%s): %v", a, err)
	}
	defer sender.(interface{ Close() error }).Close()
	ctrl, err := NewController(ControllerConfig{
		Sender: sender, ShepherdMAC: shepMAC, GatewayIP: gwIP, GatewayMAC: gwMAC,
		IdleGrace: 10 * time.Second, StartupGrace: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attached := make(chan XDPMode, 1)
	xdpErr := make(chan error, 1)
	go func() {
		xdpErr <- ctrl.AttachXDP(ctx, a, XDPOptions{
			Mode:         XDPGeneric, // veth supports native too, but generic is what any NIC gets
			PollInterval: 50 * time.Millisecond,
			OnAttached:   func(m XDPMode) { attached <- m },
		})
	}()
	select {
	case m := <-attached:
		t.Logf("attached in %s mode", m)
	case err := <-xdpErr:
		t.Fatalf("AttachXDP: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("AttachXDP did not attach in time")
	}

	// The device's side: a raw socket on b to inject frames and read what
	// comes back. Everything b receives that is from shepMAC to gwMAC is a
	// relayed frame (the Spoofer's ARP claims are to devMAC).
	peerSender, err := Open(b)
	if err != nil {
		t.Fatal(err)
	}
	defer peerSender.(interface{ Close() error }).Close()
	caps, err := openCaptureGroup(b, gwMAC, 1, false) // filter: IPv4 to gwMAC, i.e. exactly the relayed frames
	if err != nil {
		t.Fatal(err)
	}
	defer caps[0].close()
	got := make(chan []byte, 64)
	capCtx, capCancel := context.WithCancel(context.Background())
	defer capCancel()
	go caps[0].run(capCtx, func(raw []byte) { got <- append([]byte(nil), raw...) })

	remote := netip.AddrFrom4([4]byte{203, 0, 113, 7})
	frame := ipv4Frame(shepMAC, devMAC, devIP, remote, []byte("before steer"))

	// Not steered yet: nothing may come back.
	if err := peerSender.Send(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		t.Fatalf("relayed a frame from an unsteered device: % x", f)
	case <-time.After(300 * time.Millisecond):
	}

	if err := ctrl.Steer(DeviceRef{MAC: devMAC, IP: devIP}, SteerOptions{}); err != nil {
		t.Fatal(err)
	}
	// The observer path should have updated the map synchronously inside
	// Steer; no sleep needed. Send a few frames.
	frame = ipv4Frame(shepMAC, devMAC, devIP, remote, []byte("after steer"))
	const n = 5
	for i := 0; i < n; i++ {
		if err := peerSender.Send(frame); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		select {
		case f := <-got:
			var dst, src arp.MAC
			copy(dst[:], f[0:6])
			copy(src[:], f[6:12])
			if dst != gwMAC || src != shepMAC {
				t.Fatalf("relayed frame MACs dst=%v src=%v, want dst=%v src=%v", dst, src, gwMAC, shepMAC)
			}
			if string(f[14:]) != string(frame[14:]) {
				t.Fatal("relayed frame's IP packet was altered")
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("got only %d of %d relayed frames back", i, n)
		}
	}

	// Counters reach Status() through the poll.
	deadline := time.Now().Add(2 * time.Second)
	for {
		st := ctrl.Status()
		if len(st) == 1 && st[0].PacketsRelayed == n && st[0].BytesRelayed == uint64(n*len(frame)) && st[0].Healthy && !st[0].LastVerified.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Status() never showed %d relayed packets: %+v stats=%+v", n, st, ctrl.Stats())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s := ctrl.Stats(); s.FramesRelayed != n || s.FramesExamined < n {
		t.Fatalf("Stats() = %+v, want %d relayed and at least that many examined", s, n)
	}

	// Unsteer: the map is updated synchronously, so the very next frame
	// must not be relayed.
	if err := ctrl.Unsteer(devMAC); err != nil {
		t.Fatal(err)
	}
	if err := peerSender.Send(ipv4Frame(shepMAC, devMAC, devIP, remote, []byte("after unsteer"))); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		t.Fatalf("relayed a frame after Unsteer: % x", f)
	case <-time.After(300 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-xdpErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("AttachXDP returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AttachXDP did not return after ctx cancel")
	}
}
