// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

import (
	"errors"
	"net/netip"
	"os"
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
