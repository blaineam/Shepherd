// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package dhcp

import "golang.org/x/sys/unix"

// bindToDevice pins the socket to one interface. Linux only; elsewhere the
// socket is left unbound, which on a single-interface host is the same thing.
func bindToDevice(fd int, iface string) error {
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
}
