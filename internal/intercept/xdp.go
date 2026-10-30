// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// XDPMode selects how AttachXDP attaches the relay program to the NIC.
type XDPMode int

const (
	// XDPAuto tries native (driver) mode first and falls back to generic.
	XDPAuto XDPMode = iota
	// XDPNative attaches in the NIC driver's receive path, before an skb is
	// ever allocated: the fast path, but the driver must support XDP.
	XDPNative
	// XDPGeneric attaches in the kernel's generic receive path, after the
	// skb exists. Works with any driver; slower than native but still
	// never involves userspace.
	XDPGeneric
)

// ParseXDPMode parses "auto", "native" or "generic".
func ParseXDPMode(s string) (XDPMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto":
		return XDPAuto, nil
	case "native", "driver":
		return XDPNative, nil
	case "generic", "skb":
		return XDPGeneric, nil
	}
	return 0, fmt.Errorf("intercept: unknown XDP mode %q (want auto, native or generic)", s)
}

func (m XDPMode) String() string {
	switch m {
	case XDPAuto:
		return "auto"
	case XDPNative:
		return "native"
	case XDPGeneric:
		return "generic"
	}
	return fmt.Sprintf("XDPMode(%d)", int(m))
}

// DefaultXDPPollInterval is how often AttachXDP reads the kernel's
// per-device counters back into the Controller when the caller does not
// choose: well inside the health loop's IdleGrace, so a device that is
// relaying is never mistaken for idle between polls.
const DefaultXDPPollInterval = time.Second

// XDPOptions configures AttachXDP. The zero value is usable.
type XDPOptions struct {
	Mode XDPMode
	// PollInterval is how often the kernel's counters are read back into
	// the Controller (default DefaultXDPPollInterval).
	PollInterval time.Duration
	// LocalIPs are Shepherd's own IPv4 addresses on the interface: a
	// steered device's frame to one of these is for Shepherd itself (its
	// DNS resolver, its portal) and is passed to the kernel, never relayed.
	// Empty means "every IPv4 address configured on the interface", read
	// at attach time.
	LocalIPs []netip.Addr
	// OnAttached, if set, is called once the program is attached, with the
	// mode actually in effect (meaningful when Mode is XDPAuto). Optional.
	OnAttached func(mode XDPMode)
}

// ErrXDPMACMismatch is returned by AttachXDP when the Controller's
// ShepherdMAC is not the interface's own MAC: the program only ever
// matches frames addressed to ShepherdMAC, and a NIC only receives
// frames addressed to its own (or in promiscuous mode, anyone's), so a
// mismatch means either nothing would ever be relayed or the Controller
// was configured for a different interface.
var ErrXDPMACMismatch = errors.New("intercept: Controller's ShepherdMAC is not the interface's MAC")
