// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

import (
	"encoding/binary"
	"fmt"
	"time"

	"shepherd/internal/arp"
)

// The relay self-test. Before a single real device is steered, Shepherd
// relays one frame of its own and checks what happens to it.
//
// This exists because of a failure that cost weeks to find and could not
// be found by reasoning: on one host the relay carried its own output back
// to itself at line rate, 10 Gbit/s and over a million packets a second,
// within seconds of steering an ordinary device. The frames going round
// were the same handful of frames -- one IP ID each, TTL never
// decremented -- arriving over and over with the device's source MAC and
// Shepherd's destination MAC, which is how they arrived the first time.
// Interface receive, interface transmit and the relay's own count were all
// within a percent of each other, so each pass produced exactly one more.
//
// A relay that rewrites both MAC addresses and puts the frame back on the
// wire cannot do that, because the rewritten frame is addressed to the
// gateway and the gateway does not send it back. One whose rewrite does
// not reach the wire does exactly that: the frame leaves still addressed
// to Shepherd, the switch returns it, and the relay relays it again.
//
// So rather than reason about which it is on a given kernel, driver and
// attach mode, Shepherd measures it: one probe frame, from a MAC of its
// own that nothing else can be using, and then two readings.
//
// The program only ever sees frames the interface *receives*, and a frame
// this host transmits is not one of them, so a healthy run relays the probe
// zero times: it goes out, the switch declines to send it back out the port
// it arrived on, and that is the end of it. Measured on real hardware, and
// worth stating because it is also the first thing this test established:
// a frame leaving eth0 addressed to eth0's own MAC does not come back.
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
// (rule 4), so a probe sent to an address Shepherd happens to hold would
// be passed and the test would report that it never saw its own probe.
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
)

// probeRelay sends one probe frame through the attached program and
// reports whether the relay loops. It must run after the program is
// attached and before anything else touches the steered map.
func (dp *xdpDataPlane) probeRelay(c *Controller) error {
	shepherd := c.cfg.ShepherdMAC
	if c.cfg.Sender == nil {
		return nil // nothing to send with; the caller's own checks cover this
	}
	// The probe is steered for IPv4 only, exactly like a real device.
	if err := dp.objs.Steered.Update(macKey(probeMAC), xdpDevCounters{Families: uint8(SteerV4)}, 0); err != nil {
		return fmt.Errorf("%w: adding the probe failed: %v", ErrRelayUnverified, err)
	}
	defer func() { _ = dp.objs.Steered.Delete(macKey(probeMAC)) }()

	beforeOurs, beforeGW := dp.returnPathCounts()
	if err := sendWithTimeout(c.cfg.Sender, probeFrame(shepherd), DefaultSendTimeout); err != nil {
		return fmt.Errorf("%w: sending the probe failed: %v", ErrRelayUnverified, err)
	}
	time.Sleep(probeSettle)

	var v xdpDevCounters
	if err := dp.objs.Steered.Lookup(macKey(probeMAC), &v); err != nil {
		return fmt.Errorf("%w: reading the probe's counters failed: %v", ErrRelayUnverified, err)
	}
	dp.harvest(c)
	afterOurs, afterGW := dp.returnPathCounts()
	ours, gw := afterOurs-beforeOurs, afterGW-beforeGW

	switch {
	case v.Packets >= probeLoopThreshold:
		return fmt.Errorf("%w: a single probe frame was relayed %d times within %s, so a frame this relay transmits comes back to the interface it left, still addressed to Shepherd, and is relayed again -- steering any device here would loop at line rate",
			ErrRelayLoops, v.Packets, probeSettle)
	case ours > 0 || gw > 0:
		return fmt.Errorf("%w: after one probe frame, %d frames arrived with Shepherd's own source MAC and %d addressed to the gateway's, so this segment reflects the relay's own output back to it",
			ErrRelayLoops, ours, gw)
	}
	return nil
}

// probeFrame builds the probe: 60 bytes, Ethernet to shepherd from
// probeMAC, IPv4 UDP from 192.0.2.1 to 192.0.2.2 port 9 (discard).
func probeFrame(shepherd arp.MAC) Frame {
	const (
		ipHdr  = 20
		udpHdr = 8
		total  = 60
	)
	f := make([]byte, total)
	copy(f[0:6], shepherd[:])
	copy(f[6:12], probeMAC[:])
	binary.BigEndian.PutUint16(f[12:14], 0x0800)

	ip := f[14 : 14+ipHdr]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(total-14))
	binary.BigEndian.PutUint16(ip[4:6], 0x5348) // a recognizable IP ID
	ip[8] = 64                                  // TTL
	ip[9] = 17                                  // UDP
	copy(ip[12:16], []byte{198, 51, 100, 1})
	copy(ip[16:20], []byte{198, 51, 100, 2})
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	udp := f[14+ipHdr:]
	binary.BigEndian.PutUint16(udp[0:2], 9)
	binary.BigEndian.PutUint16(udp[2:4], 9)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	// The UDP checksum is optional over IPv4 and zero means "not computed".
	return Frame(f)
}

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
