// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package intercept

import "errors"

// ErrUnsupported is returned by Open on platforms without a raw-frame
// sender implementation.
var ErrUnsupported = errors.New("intercept: raw frame injection is not supported on this platform")

// Open is only implemented on Linux (see docs/DESIGN.md's platform
// matrix: Watch mode's ARP interception is Linux-first). Elsewhere it
// reports that a real Sender is unavailable; the rest of this package
// (Spoofer, Relay, Controller) works everywhere against FakeSender.
func Open(iface string) (Sender, error) { return nil, ErrUnsupported }
