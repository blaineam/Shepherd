// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package dhcp

import (
	"context"
	"errors"
)

// ErrUnsupported is what the real socket opener reports on an operating
// system with no Unix sockets. DHCP mode is a Linux feature; elsewhere
// Shepherd reports it unavailable in the portal and starts normally, the same
// way Watch mode does.
var ErrUnsupported = errors.New("dhcp: DHCP mode needs a Unix-like operating system")

func listenUDP(context.Context, string, int, bool) (Conn, error) { return nil, ErrUnsupported }
