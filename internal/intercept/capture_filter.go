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
// ever relay: destination MAC == shepherdMAC and ethertype == IPv4.
// Everything else — broadcast, multicast, frames for other hosts that a
// promiscuous NIC (a Docker macvlan, a VM bridge, a running tcpdump)
// would otherwise deliver here, ARP, and IPv6 — is dropped in the kernel
// at a fraction of the cost of a recvfrom, a parse and a discard.
//
// This is a cost removal only, never a correctness change: HandleFrame
// still applies every one of its own checks to whatever gets through, so
// a filter that failed to attach (or a kernel that ignored it) leaves
// behaviour identical, only slower. The ethertype check also means the
// IPv4-only rule (docs/IPV6.md) is now enforced twice, once in the kernel
// and once in HandleFrame; the fuzz test still proves the second.
//
// It lives in a file with no build tag, and is built with x/net/bpf's
// assembler rather than hand-written opcodes, so its logic is unit-tested
// on every platform with x/net/bpf's own interpreter (capture_filter_test.go):
// the raw-socket code around it cannot run without CAP_NET_RAW, but the
// program itself can.
func captureFilter(shepherdMAC arp.MAC) ([]bpf.RawInstruction, error) {
	// A MAC is 6 bytes; classic BPF loads at most 4 at a time, so the
	// address is compared as a 32-bit load at offset 2 (bytes 2..5) and a
	// 16-bit load at offset 0 (bytes 0..1). Same shape tcpdump compiles
	// "ether dst X and ip" to.
	dstLow := binary.BigEndian.Uint32(shepherdMAC[2:6])
	dstHigh := uint32(binary.BigEndian.Uint16(shepherdMAC[0:2]))

	prog := []bpf.Instruction{
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
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("intercept: assemble capture filter: %w", err)
	}
	return raw, nil
}
