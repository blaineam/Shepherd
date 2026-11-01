// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/net/bpf"

	"shepherd/internal/arp"
)

// captureFilter builds the classic BPF program ParallelRelay attaches to
// each capture socket (SO_ATTACH_FILTER, capture_linux.go), so the kernel
// drops, before copying anything to userspace, every frame the Relay
// would discard anyway. It accepts exactly the frames HandleFrame can
// ever relay: destination MAC == shepherdMAC and ethertype == IPv4 (and,
// when admitV6 is true, IPv6 as well). Everything else — broadcast,
// multicast, frames for other hosts that a promiscuous NIC (a Docker
// macvlan, a VM bridge, a running tcpdump) would otherwise deliver here,
// ARP, and IPv6 when it is not admitted — is dropped in the kernel at a
// fraction of the cost of a recvfrom, a parse and a discard.
//
// This is a cost removal only, never a correctness change: HandleFrame
// still applies every one of its own checks to whatever gets through
// (including the per-device family check that actually enforces the
// IPv6-only-when-steered rule), so a filter that failed to attach, was
// built with the wrong admitV6, or was ignored by the kernel leaves
// behaviour identical, only slower. Admitting IPv6 here is therefore
// safe even when no device is IPv6-steered yet: the cost is a userspace
// discard HandleFrame already makes, and the IPv6 steering rule
// (docs/IPV6.md) is proven by the Relay fuzz tests, not by this filter.
// A caller that wants the extra saving can rebuild with admitV6=false
// whenever nothing is IPv6-steered; the Controller keeps it simple by
// admitting IPv6 whenever IPv6 steering is enabled at all.
//
// It lives in a file with no build tag, and is built with x/net/bpf's
// assembler rather than hand-written opcodes, so its logic is unit-tested
// on every platform with x/net/bpf's own interpreter (capture_filter_test.go):
// the raw-socket code around it cannot run without CAP_NET_RAW, but the
// program itself can.
func captureFilter(shepherdMAC arp.MAC, admitV6 bool) ([]bpf.RawInstruction, error) {
	// A MAC is 6 bytes; classic BPF loads at most 4 at a time, so the
	// address is compared as a 32-bit load at offset 2 (bytes 2..5) and a
	// 16-bit load at offset 0 (bytes 0..1). Same shape tcpdump compiles
	// "ether dst X and ip" to.
	dstLow := binary.BigEndian.Uint32(shepherdMAC[2:6])
	dstHigh := uint32(binary.BigEndian.Uint16(shepherdMAC[0:2]))

	// The ethertype gate. Without admitV6 it is a single "!= IPv4 -> drop".
	// With admitV6 it is "== IPv4 -> fall through to the MAC check; else
	// != IPv6 -> drop", i.e. accept exactly IPv4 or IPv6. The MAC-check and
	// accept/drop instructions that follow are identical either way; only
	// the SkipTrue offsets differ because the v6 form is one instruction
	// longer. Keeping the two shapes side by side (rather than computing
	// offsets) keeps the program auditable against tcpdump's output.
	var prog []bpf.Instruction
	if admitV6 {
		prog = []bpf.Instruction{
			// 0: A = ethertype
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// 1: A == IPv4 -> 3 (skip the IPv6 test, go to the MAC check)
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(etherTypeIPv4), SkipTrue: 1},
			// 2: A != IPv6 -> 8 (drop)
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(etherTypeIPv6), SkipTrue: 5},
			// 3: A = dst MAC bytes 2..5
			bpf.LoadAbsolute{Off: 2, Size: 4},
			// 4: A != low -> 8 (drop)
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstLow, SkipTrue: 3},
			// 5: A = dst MAC bytes 0..1
			bpf.LoadAbsolute{Off: 0, Size: 2},
			// 6: A != high -> 8 (drop)
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstHigh, SkipTrue: 1},
			// 7: accept
			bpf.RetConstant{Val: 0xffffffff},
			// 8: drop
			bpf.RetConstant{Val: 0},
		}
	} else {
		prog = []bpf.Instruction{
			// 0: A = ethertype
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// 1: A != IPv4 -> 7 (drop)
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(etherTypeIPv4), SkipTrue: 5},
			// 2: A = dst MAC bytes 2..5
			bpf.LoadAbsolute{Off: 2, Size: 4},
			// 3: A != low -> 7 (drop)
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstLow, SkipTrue: 3},
			// 4: A = dst MAC bytes 0..1
			bpf.LoadAbsolute{Off: 0, Size: 2},
			// 5: A != high -> 7 (drop)
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstHigh, SkipTrue: 1},
			// 6: accept: pass the whole frame to userspace
			bpf.RetConstant{Val: 0xffffffff},
			// 7: drop
			bpf.RetConstant{Val: 0},
		}
	}
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("intercept: assemble capture filter: %w", err)
	}
	return raw, nil
}
