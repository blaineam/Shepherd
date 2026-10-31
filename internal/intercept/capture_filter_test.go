// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"testing"

	"golang.org/x/net/bpf"

	"shepherd/internal/arp"
)

// The capture filter is the one piece of the Linux capture path that can
// be tested without CAP_NET_RAW: run the exact program the socket gets
// through x/net/bpf's interpreter and check it admits precisely the frames
// HandleFrame can relay, and nothing else.
func TestCaptureFilterAdmitsOnlyIPv4ForShepherd(t *testing.T) {
	raw, err := captureFilter(shepherdMAC, false)
	if err != nil {
		t.Fatal(err)
	}
	insns, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("assembled filter does not disassemble cleanly")
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	bcast := arp.MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	// A MAC that shares Shepherd's low 4 bytes but not the high 2, and one
	// that shares the high 2 but not the low 4: each half of the compare
	// has to be able to reject on its own.
	lowMatch := shepherdMAC
	lowMatch[0] ^= 0x02
	highMatch := shepherdMAC
	highMatch[5] ^= 0x01

	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"ipv4 to shepherd", ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x")), true},
		{"ipv4 to shepherd, empty payload", ethFrame(shepherdMAC, devMAC, 0x0800, nil), true},
		{"ipv4 to gateway (loopback of our own relay)", ethFrame(gwMAC, shepherdMAC, 0x0800, []byte("x")), false},
		{"ipv4 to the device (misdelivered inbound)", ethFrame(devMAC, gwMAC, 0x0800, []byte("x")), false},
		{"ipv4 broadcast", ethFrame(bcast, devMAC, 0x0800, []byte("x")), false},
		{"ipv4, low 4 bytes match only", ethFrame(lowMatch, devMAC, 0x0800, []byte("x")), false},
		{"ipv4, high 2 bytes match only", ethFrame(highMatch, devMAC, 0x0800, []byte("x")), false},
		{"arp to shepherd", ethFrame(shepherdMAC, devMAC, 0x0806, []byte("x")), false},
		{"ipv6 to shepherd", ethFrame(shepherdMAC, devMAC, 0x86dd, []byte("x")), false},
		{"vlan-tagged to shepherd", ethFrame(shepherdMAC, devMAC, 0x8100, []byte{0, 1, 8, 0}), false},
		{"too short", []byte{1, 2, 3}, false},
	}
	for _, tc := range cases {
		n, err := vm.Run(tc.frame)
		if err != nil {
			t.Fatalf("%s: vm.Run: %v", tc.name, err)
		}
		if got := n > 0; got != tc.want {
			t.Errorf("%s: filter accepted=%v (ret %d), want %v", tc.name, got, n, tc.want)
		}
		if tc.want && n < len(tc.frame) {
			t.Errorf("%s: filter truncated the frame to %d of %d bytes", tc.name, n, len(tc.frame))
		}
	}
}

// TestCaptureFilterAdmitsIPv4AndIPv6WhenV6 checks the admitV6 shape: both
// IPv4 and IPv6 to Shepherd pass, everything else still drops.
func TestCaptureFilterAdmitsIPv4AndIPv6WhenV6(t *testing.T) {
	raw, err := captureFilter(shepherdMAC, true)
	if err != nil {
		t.Fatal(err)
	}
	insns, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("assembled filter does not disassemble cleanly")
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	bcast := arp.MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"ipv4 to shepherd", ethFrame(shepherdMAC, devMAC, 0x0800, []byte("x")), true},
		{"ipv6 to shepherd", ethFrame(shepherdMAC, devMAC, 0x86dd, []byte("x")), true},
		{"ipv6 to gateway (loopback)", ethFrame(gwMAC, shepherdMAC, 0x86dd, []byte("x")), false},
		{"ipv6 broadcast/multicast dst", ethFrame(bcast, devMAC, 0x86dd, []byte("x")), false},
		{"arp to shepherd", ethFrame(shepherdMAC, devMAC, 0x0806, []byte("x")), false},
		{"vlan-tagged to shepherd", ethFrame(shepherdMAC, devMAC, 0x8100, []byte{0, 1, 0x86, 0xdd}), false},
		{"other ethertype to shepherd", ethFrame(shepherdMAC, devMAC, 0x88cc, []byte("x")), false},
		{"too short", []byte{1, 2, 3}, false},
	}
	for _, tc := range cases {
		n, err := vm.Run(tc.frame)
		if err != nil {
			t.Fatalf("%s: vm.Run: %v", tc.name, err)
		}
		if got := n > 0; got != tc.want {
			t.Errorf("%s: filter accepted=%v (ret %d), want %v", tc.name, got, n, tc.want)
		}
	}
}

// Whatever the filter admits, HandleFrame would have relayed (given a
// source steered for that family); whatever HandleFrame relays, the filter
// admits. The two must agree, or the kernel-side filter would silently
// change what Watch mode does rather than just what it costs. Checked for
// both filter shapes against a device steered for the matching families.
func TestCaptureFilterAgreesWithHandleFrame(t *testing.T) {
	for _, tc := range []struct {
		name    string
		admitV6 bool
		fam     Family
	}{
		{"v4 only", false, SteerV4},
		{"v4 and v6", true, SteerV4 | SteerV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := captureFilter(shepherdMAC, tc.admitV6)
			if err != nil {
				t.Fatal(err)
			}
			insns, _ := bpf.Disassemble(raw)
			vm, err := bpf.NewVM(insns)
			if err != nil {
				t.Fatal(err)
			}
			for _, dst := range []arp.MAC{shepherdMAC, gwMAC, devMAC, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
				for _, et := range []uint16{0x0800, 0x0806, 0x86dd, 0x8100, 0x88cc} {
					frame := ethFrame(dst, devMAC, et, []byte("payload"))
					sender := NewFakeSender()
					r := &Relay{Sender: sender, ShepherdMAC: shepherdMAC, GatewayMAC: gwMAC, Lookup: steeredLookupFam(devMAC, devIP, tc.fam)}
					relayed, _ := r.HandleFrame(frame)
					n, err := vm.Run(frame)
					if err != nil {
						t.Fatal(err)
					}
					if admitted := n > 0; admitted != relayed {
						t.Errorf("dst=%v ethertype=%#04x: filter admits=%v but HandleFrame relays=%v", dst, et, admitted, relayed)
					}
				}
			}
		})
	}
}
