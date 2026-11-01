// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"shepherd/internal/arp"
)

// The XDP program can be run without attaching it to anything, through
// the kernel's own BPF_PROG_TEST_RUN, which also means loading it runs it
// through the verifier. This needs CAP_BPF/CAP_SYS_ADMIN, so it skips
// (not fails) where it cannot load; CI with privileges and `make
// test-xdp` (a privileged container) run it for real.
func loadXDPForTest(t *testing.T) *xdpObjects {
	t.Helper()
	_ = rlimit.RemoveMemlock()
	var objs xdpObjects
	if err := loadXdpObjects(&objs, nil); err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) || os.Geteuid() != 0 {
			// CAP_BPF alone is not enough, and saying so matters: the
			// kernel gates the pointer arithmetic this program does on
			// perfmon_capable(), so a loader needs CAP_PERFMON (or
			// CAP_SYS_ADMIN) on top of CAP_BPF or the verifier rejects it
			// with "pointer -= pointer prohibited". That is exactly how
			// Shepherd's own container was configured when this skip was
			// first written, so these tests skipped in the one
			// configuration the product actually ships -- see
			// docs/WATCH.md's capability table.
			t.Skipf("cannot load the XDP program here (needs CAP_BPF plus CAP_PERFMON or CAP_SYS_ADMIN, or root): %v", err)
		}
		t.Fatalf("load XDP objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

func runXDP(t *testing.T, objs *xdpObjects, frame []byte) (verdict uint32, out []byte) {
	t.Helper()
	// XDP test runs need room for the program to grow the frame; give it
	// a full-size buffer and read back only what came out.
	in := make([]byte, 0, 2048)
	in = append(in, frame...)
	// A frame shorter than an Ethernet header is rejected by the test-run
	// machinery itself for XDP (ETH_HLEN minimum), so pad for the call
	// and let the program's own bounds check see the real length... it
	// cannot: the kernel pads. Callers test short frames via the Go Relay.
	ret, outBuf, err := objs.XdpRelay.Test(in)
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret, outBuf
}

const (
	xdpDrop = 1
	xdpPass = 2
	xdpTX   = 3
)

func TestXDPRelayVerdictsAndRewrite(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	shepherdIP := ip(2)
	if err := dp.configure(shepherdMAC, gwMAC, []netip.Addr{shepherdIP}, nil); err != nil {
		t.Fatal(err)
	}
	dp.resync([]steeredEntry{{devMAC, SteerV4}})

	remote := netip.AddrFrom4([4]byte{203, 0, 113, 7})
	other := rndMAC(99)

	t.Run("steered device to the internet is relayed with both MACs rewritten", func(t *testing.T) {
		in := ipv4Frame(shepherdMAC, devMAC, devIP, remote, []byte("hello"))
		verdict, out := runXDP(t, objs, in)
		if verdict != xdpTX {
			t.Fatalf("verdict = %d, want XDP_TX", verdict)
		}
		var gotDst, gotSrc arp.MAC
		copy(gotDst[:], out[0:6])
		copy(gotSrc[:], out[6:12])
		if gotDst != gwMAC || gotSrc != shepherdMAC {
			t.Fatalf("MACs after relay: dst=%v src=%v, want dst=%v src=%v", gotDst, gotSrc, gwMAC, shepherdMAC)
		}
		if string(out[14:]) != string(in[14:]) {
			t.Fatal("the IP packet was altered")
		}
		var v xdpDevCounters
		if err := objs.Steered.Lookup(macKey(devMAC), &v); err != nil {
			t.Fatal(err)
		}
		if v.Packets != 1 || v.Bytes != uint64(len(in)) || v.LastSeenNs == 0 {
			t.Fatalf("counters = %+v, want 1 packet, %d bytes, last_seen set", v, len(in))
		}
	})

	pass := []struct {
		name  string
		frame []byte
	}{
		{"steered device to Shepherd itself (DNS, portal)", ipv4Frame(shepherdMAC, devMAC, devIP, shepherdIP, []byte("dns"))},
		{"unsteered device to the internet", ipv4Frame(shepherdMAC, other, devIP, remote, []byte("x"))},
		{"not addressed to Shepherd", ipv4Frame(gwMAC, devMAC, devIP, remote, []byte("x"))},
		{"ARP", ethFrame(shepherdMAC, devMAC, 0x0806, make([]byte, 28))},
		{"IPv6", ethFrame(shepherdMAC, devMAC, 0x86dd, make([]byte, 40))},
		{"VLAN-tagged", ethFrame(shepherdMAC, devMAC, 0x8100, append([]byte{0, 1, 8, 0}, make([]byte, 20)...))},
		{"IPv4 ethertype but truncated header", ethFrame(shepherdMAC, devMAC, 0x0800, make([]byte, 10))},
	}
	for _, tc := range pass {
		t.Run("passes "+tc.name, func(t *testing.T) {
			before := append([]byte(nil), tc.frame...)
			verdict, out := runXDP(t, objs, tc.frame)
			if verdict != xdpPass {
				t.Fatalf("verdict = %d, want XDP_PASS", verdict)
			}
			if string(out[:len(before)]) != string(before) {
				t.Fatal("a passed frame must be left byte-for-byte untouched")
			}
		})
	}

	t.Run("unsteering removes the device from the map at once", func(t *testing.T) {
		dp.resync(nil)
		verdict, _ := runXDP(t, objs, ipv4Frame(shepherdMAC, devMAC, devIP, remote, []byte("x")))
		if verdict != xdpPass {
			t.Fatalf("verdict after unsteer = %d, want XDP_PASS", verdict)
		}
	})
}

// TestXDPRelayIPv6 exercises the IPv6 branch: a v6-steered device's IPv6
// traffic is relayed (both MACs rewritten, hop limit untouched, counted in
// the v6 counters), its traffic to Shepherd's own IPv6 is passed, and a
// device steered only for IPv4 has its IPv6 passed.
func TestXDPRelayIPv6(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	if err := dp.configure(shepherdMAC, gwMAC, nil, []netip.Addr{shepIP6}); err != nil {
		t.Fatal(err)
	}
	dp.resync([]steeredEntry{{devMAC, SteerV4 | SteerV6}})

	t.Run("v6-steered device to the internet is relayed", func(t *testing.T) {
		in := ipv6Frame(shepherdMAC, devMAC, devIP6, someV6, 42, []byte("hello6"))
		verdict, out := runXDP(t, objs, in)
		if verdict != xdpTX {
			t.Fatalf("verdict = %d, want XDP_TX", verdict)
		}
		if arp.MAC(out[0:6]) != gwMAC || arp.MAC(out[6:12]) != shepherdMAC {
			t.Fatalf("MACs after relay: dst=%v src=%v", arp.MAC(out[0:6]), arp.MAC(out[6:12]))
		}
		if out[ethHeaderLen+7] != 42 {
			t.Fatalf("hop limit = %d, want 42 untouched", out[ethHeaderLen+7])
		}
		var v xdpDevCounters
		if err := objs.Steered.Lookup(macKey(devMAC), &v); err != nil {
			t.Fatal(err)
		}
		if v.Packets6 != 1 || v.Bytes6 != uint64(len(in)) || v.Packets != 0 {
			t.Fatalf("counters = %+v, want 1 v6 packet and 0 v4", v)
		}
	})

	t.Run("v6 to Shepherd itself is passed", func(t *testing.T) {
		in := ipv6Frame(shepherdMAC, devMAC, devIP6, shepIP6, 64, []byte("dns"))
		verdict, _ := runXDP(t, objs, in)
		if verdict != xdpPass {
			t.Fatalf("verdict = %d, want XDP_PASS", verdict)
		}
	})

	t.Run("v4-only device has its IPv6 passed", func(t *testing.T) {
		dp.resync([]steeredEntry{{devMAC, SteerV4}})
		in := ipv6Frame(shepherdMAC, devMAC, devIP6, someV6, 64, []byte("x"))
		verdict, _ := runXDP(t, objs, in)
		if verdict != xdpPass {
			t.Fatalf("v6 frame from a v4-only device: verdict = %d, want XDP_PASS", verdict)
		}
	})
}

// The program and the Go Relay must agree frame for frame on what gets
// relayed, exactly as the classic-BPF capture filter must; the one
// deliberate difference (frames for Shepherd's own IP) is tested above.
func TestXDPRelayAgreesWithHandleFrame(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	if err := dp.configure(shepherdMAC, gwMAC, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Steer the device for both families so the agreement covers IPv6 too;
	// the Go Relay's Lookup reports the same families.
	const fam = SteerV4 | SteerV6
	dp.resync([]steeredEntry{{devMAC, fam}})
	remote := netip.AddrFrom4([4]byte{203, 0, 113, 7})

	for _, dst := range []arp.MAC{shepherdMAC, gwMAC, devMAC, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		for _, src := range []arp.MAC{devMAC, rndMAC(5), shepherdMAC} {
			for _, et := range []uint16{0x0800, 0x0806, 0x86dd, 0x8100} {
				var frame []byte
				switch et {
				case 0x0800:
					frame = ipv4Frame(dst, src, devIP, remote, []byte("p"))
				case 0x86dd:
					frame = ipv6Frame(dst, src, devIP6, someV6, 64, []byte("p"))
				default:
					frame = ethFrame(dst, src, et, make([]byte, 28))
				}
				sender := NewFakeSender()
				r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookupFam(devMAC, devIP, fam)}
				relayed, _ := r.HandleFrame(append([]byte(nil), frame...))
				verdict, _ := runXDP(t, objs, frame)
				if (verdict == xdpTX) != relayed {
					t.Errorf("dst=%v src=%v ethertype=%#04x: XDP verdict %d but HandleFrame relays=%v", dst, src, et, verdict, relayed)
				}
			}
		}
	}
}

// resync must converge the map on the Controller's set from any state.
func TestXDPResyncConverges(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	a, b, c := rndMAC(1), rndMAC(2), rndMAC(3)
	dp.resync([]steeredEntry{{a, SteerV4}, {b, SteerV4}})
	dp.resync([]steeredEntry{{b, SteerV4}, {c, SteerV4}})
	var have []arp.MAC
	var k xdpMacKey
	var v xdpDevCounters
	it := objs.Steered.Iterate()
	for it.Next(&k, &v) {
		var m arp.MAC
		copy(m[:], k.Mac[:])
		have = append(have, m)
	}
	if len(have) != 2 {
		t.Fatalf("map has %v, want exactly {b, c}", have)
	}
	for _, m := range have {
		if m != b && m != c {
			t.Fatalf("map has %v, want exactly {b, c}", have)
		}
	}
}

// A resync must never reset the counters of a device that is already in
// the map: the kernel's counts are the only copy there is until harvest
// reads them.
func TestXDPResyncKeepsExistingCounters(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	dp.resync([]steeredEntry{{devMAC, SteerV4}})
	if err := objs.Steered.Put(macKey(devMAC), xdpDevCounters{Packets: 7, Bytes: 700, LastSeenNs: 1, Families: uint8(SteerV4)}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		dp.resync([]steeredEntry{{devMAC, SteerV4}})
	}
	// And the exact shape of the race the lock guards against: a stale
	// decision to add the device must not overwrite the entry either.
	if err := objs.Steered.Update(macKey(devMAC), xdpDevCounters{}, ebpf.UpdateNoExist); !errors.Is(err, ebpf.ErrKeyExist) {
		t.Fatalf("UpdateNoExist on an existing entry: %v, want ErrKeyExist", err)
	}
	var v xdpDevCounters
	if err := objs.Steered.Lookup(macKey(devMAC), &v); err != nil {
		t.Fatal(err)
	}
	if v.Packets != 7 || v.Bytes != 700 {
		t.Fatalf("resync reset the counters: %+v", v)
	}
}

func TestXDPRelaySamplesRelayedFrames(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	if err := dp.configure(shepherdMAC, gwMAC, []netip.Addr{ip(2)}, nil); err != nil {
		t.Fatal(err)
	}
	dp.resync([]steeredEntry{{devMAC, SteerV4}})
	remote := netip.AddrFrom4([4]byte{203, 0, 113, 7})

	if got := dp.frameSamples(); len(got) != 0 {
		t.Fatalf("samples before any relay = %d, want none", len(got))
	}
	// The first relayed frame on a CPU is sampled (relayed_frames is 0
	// when it is examined); the program sees exactly one here.
	in := ipv4Frame(shepherdMAC, devMAC, devIP, remote, make([]byte, 40))
	if verdict, _ := runXDP(t, objs, in); verdict != xdpTX {
		t.Fatalf("verdict = %d, want XDP_TX", verdict)
	}
	got := dp.frameSamples()
	if len(got) != 1 {
		t.Fatalf("samples after one relayed frame = %d, want 1", len(got))
	}
	s := got[0]
	if s.Seq != 1 || s.Len != uint32(len(in)) || s.Ts == 0 {
		t.Fatalf("sample = seq %d len %d ts %d, want seq 1 len %d", s.Seq, s.Len, s.Ts, len(in))
	}
	if string(s.Bytes) != string(in[:60]) {
		t.Fatal("the sample must be the frame as it arrived, before the MAC rewrite")
	}
	// Drained: the same samples are not handed out twice.
	if again := dp.frameSamples(); len(again) != 0 {
		t.Fatalf("samples handed out twice: %d", len(again))
	}
	// A frame too short to sample is relayed but not sampled. Each one is
	// distinct, since the relay's duplicate brake drops a frame it has
	// already relayed.
	for i := 0; i < 300; i++ {
		short := ipv4Frame(shepherdMAC, devMAC, devIP, netip.AddrFrom4([4]byte{203, 0, 113, byte(i % 251)}), nil)
		if i == 0 && len(short) >= 60 {
			t.Fatalf("test frame is %d bytes, want under 60", len(short))
		}
		if verdict, _ := runXDP(t, objs, short); verdict != xdpTX {
			t.Fatalf("frame %d: verdict = %d, want XDP_TX", i, verdict)
		}
	}
	if got := dp.frameSamples(); len(got) != 0 {
		t.Fatalf("short frames were sampled: %d", len(got))
	}
	lines := SummarizeSamples([]FrameSample{s})
	if len(lines) != 2 || !strings.Contains(lines[1], devIP.String()+"->"+remote.String()) {
		t.Fatalf("summary = %q", lines)
	}
}

func TestXDPRelayCountsItsOwnOutputComingBack(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	if err := dp.configure(shepherdMAC, gwMAC, []netip.Addr{ip(2)}, nil); err != nil {
		t.Fatal(err)
	}
	dp.resync([]steeredEntry{{devMAC, SteerV4}})
	remote := netip.AddrFrom4([4]byte{203, 0, 113, 7})

	// A relayed frame leaves with src = Shepherd's MAC and dst = the
	// gateway's. Either arriving back on this interface is Shepherd's own
	// output returning to it, which is what a relay loop is made of.
	relayed := ipv4Frame(gwMAC, shepherdMAC, devIP, remote, make([]byte, 40))
	if verdict, _ := runXDP(t, objs, relayed); verdict != xdpPass {
		t.Fatalf("Shepherd's own relayed output must be passed, not relayed again")
	}
	var perCPU []xdpRelayStats
	if err := objs.Stats.Lookup(uint32(0), &perCPU); err != nil {
		t.Fatalf("read the program's own stats: %v", err)
	}
	var raw xdpRelayStats
	for _, s := range perCPU {
		raw.OursReturning += s.OursReturning
		raw.ToGateway += s.ToGateway
	}
	if raw.OursReturning != 1 || raw.ToGateway != 1 {
		t.Fatalf("the program's own counters = (%d, %d), want (1, 1)", raw.OursReturning, raw.ToGateway)
	}
	c, _, _ := newTestController(t, nil)
	dp.harvest(c)
	ours, togw := dp.returnPathCounts()
	if ours != 1 || togw != 1 {
		t.Fatalf("return-path counts = (%d, %d), want (1, 1)", ours, togw)
	}
	// An ordinary steered frame counts towards neither.
	if verdict, _ := runXDP(t, objs, ipv4Frame(shepherdMAC, devMAC, devIP, remote, make([]byte, 40))); verdict != xdpTX {
		t.Fatal("an ordinary steered frame must still be relayed")
	}
	dp.harvest(c)
	if ours, togw = dp.returnPathCounts(); ours != 1 || togw != 1 {
		t.Fatalf("return-path counts after an ordinary frame = (%d, %d), want (1, 1)", ours, togw)
	}
}

// The self-test is only meaningful if the probe frame is one the relay
// really relays: it has to pass all four of the program's rules and come
// out with both MACs rewritten, exactly like a steered device's frame.
func TestTheRelaySelfTestProbeIsAFrameTheRelayRelays(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	if err := dp.configure(shepherdMAC, gwMAC, []netip.Addr{ip(2)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := objs.Steered.Update(macKey(probeMAC), xdpDevCounters{Families: uint8(SteerV4)}, 0); err != nil {
		t.Fatal(err)
	}

	// The frame's construction is checked portably in xdp_probe_test.go.
	// What only a real kernel can answer is whether the program relays it.
	frame := probeFrame(shepherdMAC)
	verdict, out := runXDP(t, objs, frame)
	if verdict != xdpTX {
		t.Fatalf("verdict = %d, want XDP_TX: the self-test would never see its own probe relayed", verdict)
	}
	var gotDst, gotSrc arp.MAC
	copy(gotDst[:], out[0:6])
	copy(gotSrc[:], out[6:12])
	if gotDst != gwMAC || gotSrc != shepherdMAC {
		t.Fatalf("probe MACs after relay: dst=%v src=%v, want dst=%v src=%v", gotDst, gotSrc, gwMAC, shepherdMAC)
	}
	var v xdpDevCounters
	if err := objs.Steered.Lookup(macKey(probeMAC), &v); err != nil {
		t.Fatal(err)
	}
	if v.Packets != 1 {
		t.Fatalf("the probe was relayed %d times for one frame, want 1: the loop verdict counts on this", v.Packets)
	}
	// In production the program never sees the probe at all, because a
	// frame this host transmits is not one this interface receives. That
	// is why probeLoopThreshold is 1: a probe the program does see is one
	// that came back. This test injects it deliberately, which is the only
	// way to check the probe is a frame the relay would in fact relay.
	if probeLoopThreshold != 1 {
		t.Fatalf("probeLoopThreshold = %d; this test assumes 1 relayed pass is the loop signal", probeLoopThreshold)
	}
}

// The duplicate brake is what stops a relay loop sustaining itself: the
// same frame arriving again is dropped rather than relayed a second time.
func TestXDPRelayDropsTheSameFrameComingRoundAgain(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	if err := dp.configure(shepherdMAC, gwMAC, []netip.Addr{ip(2)}, nil); err != nil {
		t.Fatal(err)
	}
	dp.resync([]steeredEntry{{devMAC, SteerV4}})
	remote := netip.AddrFrom4([4]byte{203, 0, 113, 7})
	c, _, _ := newTestController(t, nil)

	frame := ipv4Frame(shepherdMAC, devMAC, devIP, remote, make([]byte, 40))
	if verdict, _ := runXDP(t, objs, frame); verdict != xdpTX {
		t.Fatal("the first copy of a frame must be relayed")
	}
	// The same frame again, as a loop would deliver it: same addresses,
	// same identification, same length, same transport header.
	for i := 0; i < 50; i++ {
		if verdict, _ := runXDP(t, objs, frame); verdict != xdpDrop {
			t.Fatalf("copy %d of the same frame: verdict = %d, want XDP_DROP", i+2, verdict)
		}
	}
	dp.harvest(c)
	if got := dp.duplicatesSuppressed(); got != 50 {
		t.Fatalf("duplicates suppressed = %d, want 50", got)
	}
	var v xdpDevCounters
	if err := objs.Steered.Lookup(macKey(devMAC), &v); err != nil {
		t.Fatal(err)
	}
	if v.Packets != 1 {
		t.Fatalf("the device was credited %d relayed frames, want 1: a loop must not inflate it", v.Packets)
	}

	// A different frame of the same flow is still relayed: the brake must
	// not mistake a busy device for a loop. Only the identification field
	// and the transport header differ, which is the least a real packet
	// differs by.
	for i, next := range [][]byte{
		ipv4Frame(shepherdMAC, devMAC, devIP, remote, []byte("a different transport header entirely")),
		ipv4Frame(shepherdMAC, devMAC, devIP, netip.AddrFrom4([4]byte{203, 0, 113, 8}), make([]byte, 40)),
	} {
		if verdict, _ := runXDP(t, objs, next); verdict != xdpTX {
			t.Fatalf("a different frame (%d) must still be relayed, got verdict %d", i, verdict)
		}
	}
}

// The duplicate brake covers IPv6 too. The loop that made it necessary was
// IPv4 and IPv6 steering is off by default, but a loop here would be just
// as severe, so this holds the brake to both families.
func TestXDPRelayDropsARepeatedIPv6Frame(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	if err := dp.configure(shepherdMAC, gwMAC, []netip.Addr{ip(2)}, []netip.Addr{shepIP6}); err != nil {
		t.Fatal(err)
	}
	dp.resync([]steeredEntry{{devMAC, SteerV4 | SteerV6}})
	c, _, _ := newTestController(t, nil)

	frame := ipv6Frame(shepherdMAC, devMAC, devIP6, someV6, 64, []byte("a payload long enough to fingerprint"))
	if verdict, _ := runXDP(t, objs, frame); verdict != xdpTX {
		t.Fatal("the first copy of an IPv6 frame must be relayed")
	}
	for i := 0; i < 20; i++ {
		if verdict, _ := runXDP(t, objs, frame); verdict != xdpDrop {
			t.Fatalf("copy %d of the same IPv6 frame: verdict = %d, want XDP_DROP", i+2, verdict)
		}
	}
	dp.harvest(c)
	if got := dp.duplicatesSuppressed(); got != 20 {
		t.Fatalf("IPv6 duplicates suppressed = %d, want 20", got)
	}
	// A different IPv6 frame of the same flow is still relayed.
	next := ipv6Frame(shepherdMAC, devMAC, devIP6, someV6, 64, []byte("different payload, same flow entirely"))
	if verdict, _ := runXDP(t, objs, next); verdict != xdpTX {
		t.Fatal("a different IPv6 frame must still be relayed")
	}
	var v xdpDevCounters
	if err := objs.Steered.Lookup(macKey(devMAC), &v); err != nil {
		t.Fatal(err)
	}
	if v.Packets6 != 2 {
		t.Fatalf("the device was credited %d relayed IPv6 frames, want 2", v.Packets6)
	}
}

// The per-device duplicate count is what tells a loop belonging to one
// device from one belonging to all of them, which the global figure cannot.
func TestXDPRelayCountsDuplicatesPerDevice(t *testing.T) {
	objs := loadXDPForTest(t)
	dp := &xdpDataPlane{objs: objs}
	if err := dp.configure(shepherdMAC, gwMAC, []netip.Addr{ip(2)}, nil); err != nil {
		t.Fatal(err)
	}
	other := rndMAC(77)
	dp.resync([]steeredEntry{{devMAC, SteerV4}, {other, SteerV4}})
	remote := netip.AddrFrom4([4]byte{203, 0, 113, 7})

	// One device's frame comes back three times; the other's never does.
	loopy := ipv4Frame(shepherdMAC, devMAC, devIP, remote, []byte("the frame that keeps coming back"))
	if v, _ := runXDP(t, objs, loopy); v != xdpTX {
		t.Fatal("the first copy must be relayed")
	}
	for i := 0; i < 3; i++ {
		if v, _ := runXDP(t, objs, loopy); v != xdpDrop {
			t.Fatalf("copy %d must be dropped", i+2)
		}
	}
	for i := 0; i < 3; i++ {
		clean := ipv4Frame(shepherdMAC, other, ip(9), remote, []byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8})
		if v, _ := runXDP(t, objs, clean); v != xdpTX {
			t.Fatalf("the other device's distinct frame %d must be relayed", i)
		}
	}

	byDev := dp.duplicatesByDevice()
	if got := byDev[devMAC]; got != 3 {
		t.Fatalf("duplicates for the looping device = %d, want 3", got)
	}
	if _, ok := byDev[other]; ok {
		t.Fatalf("a device with no duplicates must be absent, got %v", byDev)
	}
	c, _, _ := newTestController(t, nil)
	dp.harvest(c)
	if got := dp.duplicatesSuppressed(); got != 3 {
		t.Fatalf("global duplicates = %d, want 3", got)
	}
}
