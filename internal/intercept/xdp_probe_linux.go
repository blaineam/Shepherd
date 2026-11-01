// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

import (
	"fmt"
	"time"
)

// probeRelay sends one probe frame through the attached program and
// reports whether the relay loops. It must run after the program is
// attached and before anything else touches the steered map. See
// xdp_probe.go for what is measured and why.
func (dp *xdpDataPlane) probeRelay(c *Controller) error {
	if c.cfg.Sender == nil {
		return nil // nothing to send with; the caller's own checks cover this
	}
	// The probe is steered for IPv4 only, exactly like a real device.
	if err := dp.objs.Steered.Update(macKey(probeMAC), xdpDevCounters{Families: uint8(SteerV4)}, 0); err != nil {
		return fmt.Errorf("%w: adding the probe failed: %v", ErrRelayUnverified, err)
	}
	defer func() { _ = dp.objs.Steered.Delete(macKey(probeMAC)) }()

	beforeOurs, beforeGW := dp.returnPathCounts()
	if err := sendWithTimeout(c.cfg.Sender, probeFrame(c.cfg.ShepherdMAC), DefaultSendTimeout); err != nil {
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
