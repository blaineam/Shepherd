// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"encoding/binary"
	"time"

	"shepherd/internal/arp"
)

// The relay self-test. Before a single real device is steered, Shepherd
// relays one frame of its own and checks what happens to it. This file
// holds the probe frame and the thresholds; xdp_probe_linux.go runs it,
// since that needs a loaded program and a live interface.
//
// It exists because of a failure that cost weeks to find and could not be
// found by reasoning: on one host the relay carried its own output back to
// itself at line rate, 10 Gbit/s and over a million packets a second,
// within seconds of steering an ordinary device. The frames going round
// were the same handful of frames -- one IP identification field each, a
// TTL never decremented -- arriving over and over with the device's source
// MAC and Shepherd's destination MAC, which is how they arrived the first
// time. Interface receive, interface transmit and the relay's own count
// were all within a percent of each other, so each pass produced exactly
// one more.
//
// A relay that rewrites both MAC addresses and puts the frame back on the
// wire cannot do that, because the rewritten frame is addressed to the
// gateway and the gateway does not send it back. One whose rewrite does
// not reach the wire does exactly that: the frame leaves still addressed
// to Shepherd, the switch returns it, and the relay relays it again.
//
// So rather than reason about which it is on a given kernel, driver and
// attach mode, Shepherd measures it: one probe frame, from a MAC of its
// own that nothing else can be using.
//
// The program only ever sees frames the interface *receives*, and a frame
// this host transmits is not one of them, so a healthy run relays the
// probe zero times: it goes out, the switch declines to send it back out
// the port it arrived on, and that is the end of it. Measured on real
// hardware, and worth stating because it is also the first thing this test
// established: a frame leaving an interface addressed to that interface's
// own MAC does not come back.
//
//	the probe is never seen again     the relay works
//	the probe is relayed at all       a frame this relay transmits returns
//	                                  to the interface it left and is
//	                                  relayed again, which is a loop
//	frames return with Shepherd's
//	source MAC                        the segment reflects the relay's own
//	                                  output back to it
//
// Either failure means the relay must not be used here, and Shepherd says
// which one it saw.
//
// The probe is harmless by construction: a 60-byte UDP datagram inside
// 198.51.100.0/24 (TEST-NET-2, which is not routable and which no real
// host answers) addressed to port 9, discard. If the relay works, one such
// frame reaches the gateway and is dropped there. If it loops, it loops for
// probeSettle and is then gone, which is thousands of frames rather than
// the hundreds of millions a real device's traffic produces.
//
// The destination matters more than it looks: the program passes, rather
// than relays, a frame addressed to one of Shepherd's own IP addresses
// (rule 4), so a probe sent to an address Shepherd happens to hold would be
// passed and the test would report that it never saw its own probe.
// TEST-NET-2 is used rather than TEST-NET-1 because documentation
// addresses do turn up as placeholders in real configurations, and this
// package's own tests put Shepherd on 192.0.2.2.

// probeMAC is the source MAC of the probe frame: locally administered
// (bit 1 of the first octet), unicast, and not an address any vendor
// assigns, so no real device on the segment can own it.
var probeMAC = arp.MAC{0x02, 0x00, 0x5e, 0x53, 0x48, 0x50}

const (
	// probeSettle is how long to wait after sending the probe before
	// reading the counters. A loop at this scale makes thousands of passes
	// in that time, so one pass is unambiguous; and a working relay has
	// nothing to report however long you wait.
	probeSettle = 250 * time.Millisecond
	// probeLoopThreshold is how many relayed probe frames count as a loop.
	// The program sees only received frames and the probe is transmitted,
	// so a healthy relay reports zero: one is already a frame that came
	// back.
	probeLoopThreshold = 1
	// probeIPHeaderLen and probeFrameLen are the probe's IPv4 header length
	// and its total length on the wire: the 60-byte minimum, so no switch
	// or NIC pads it and changes what comes back.
	probeIPHeaderLen = 20
	probeFrameLen    = 60
)

// probeFrame builds the probe: 60 bytes, Ethernet to shepherd from
// probeMAC, IPv4 UDP from 198.51.100.1 to 198.51.100.2 port 9 (discard).
func probeFrame(shepherd arp.MAC) Frame {
	f := make([]byte, probeFrameLen)
	copy(f[0:6], shepherd[:])
	copy(f[6:12], probeMAC[:])
	binary.BigEndian.PutUint16(f[12:14], 0x0800)

	ip := f[14 : 14+probeIPHeaderLen]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(probeFrameLen-14))
	binary.BigEndian.PutUint16(ip[4:6], 0x5348) // a recognizable IP ID
	ip[8] = 64                                  // TTL
	ip[9] = 17                                  // UDP
	copy(ip[12:16], []byte{198, 51, 100, 1})
	copy(ip[16:20], []byte{198, 51, 100, 2})
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	udp := f[14+probeIPHeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], 9)
	binary.BigEndian.PutUint16(udp[2:4], 9)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	// The UDP checksum is optional over IPv4 and zero means "not computed".
	return Frame(f)
}

// ipChecksum is the standard one's-complement header checksum. Run over a
// header whose own checksum field is already filled in, it returns 0.
func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
