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

// ErrRelayLoops means the relay self-test found that a frame this relay
// transmits comes back to the interface it left, so steering any device
// would loop at line rate. See xdp_probe_linux.go for what is measured.
// ErrRelayUnverified means the self-test could not reach a verdict; the
// relay is used anyway, with the loop brake as the backstop.
var (
	ErrRelayLoops      = errors.New("intercept: the relay loops on this interface")
	ErrRelayUnverified = errors.New("intercept: the relay could not be verified")
)

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
	// LocalIPs6 are Shepherd's own IPv6 addresses on the interface, the
	// IPv6 counterpart of LocalIPs. Used only when IPv6 steering is
	// enabled; empty means "every IPv6 address configured on the
	// interface", read at attach time.
	LocalIPs6 []netip.Addr
	// SelfTest relays one probe frame of Shepherd's own, before any device
	// is steered, and refuses the relay with ErrRelayLoops when that frame
	// comes back to the interface it left. Strongly recommended: it is the
	// only check that catches a relay whose MAC rewrite does not reach the
	// wire, which is a loop at line rate the moment a real device is
	// steered. See xdp_probe_linux.go.
	SelfTest bool
	// OnSelfTestInconclusive, if set, is called when the self-test ran but
	// could not reach a verdict. The relay is used anyway. Optional.
	OnSelfTestInconclusive func(error)
	// OnAttached, if set, is called once the program is attached, with the
	// mode actually in effect (meaningful when Mode is XDPAuto). Optional.
	// It is called after the self-test has passed.
	OnAttached func(mode XDPMode)
}

// ErrXDPMACMismatch is returned by AttachXDP when the Controller's
// ShepherdMAC is not the interface's own MAC: the program only ever
// matches frames addressed to ShepherdMAC, and a NIC only receives
// frames addressed to its own (or in promiscuous mode, anyone's), so a
// mismatch means either nothing would ever be relayed or the Controller
// was configured for a different interface.
var ErrXDPMACMismatch = errors.New("intercept: Controller's ShepherdMAC is not the interface's MAC")
