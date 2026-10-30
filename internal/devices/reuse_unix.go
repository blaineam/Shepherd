// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package devices

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseControl lets several processes bind the mDNS port together.
func reuseControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return serr
}
