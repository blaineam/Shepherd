// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package dhcp

import (
	"context"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenUDP binds one UDP port for DHCP.
//
// This file is deliberately thin, and it is the one part of the package an
// unprivileged test cannot reach: binding port 67 needs CAP_NET_BIND_SERVICE
// and setting SO_BROADCAST or SO_BINDTODEVICE needs the socket. Everything
// that decides anything is behind the Conn and Opener interfaces, which the
// tests drive with fakes instead — the same arrangement watch.Platform has
// for the same reason.
//
// The options, each for a reason:
//
//   - SO_REUSEADDR, so a restart does not have to wait out a socket, and so
//     binding port 68 alongside another DHCP client has a chance of working.
//   - SO_BROADCAST, without which sending to 255.255.255.255 fails with
//     EACCES. A DHCP server that cannot broadcast cannot answer a client that
//     has no address yet, which is every client the first time.
//   - SO_BINDTODEVICE, so a host with several interfaces on the LAN — a NAS
//     with wired and wireless both up is the ordinary case — serves on the
//     one that was configured rather than on whichever the kernel picks.
func listenUDP(ctx context.Context, iface string, port int, broadcast bool) (Conn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					ctrlErr = err
					return
				}
				if broadcast {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
						ctrlErr = err
						return
					}
				}
				if iface != "" {
					if err := bindToDevice(int(fd), iface); err != nil {
						ctrlErr = err
					}
				}
			})
			if err != nil {
				return err
			}
			return ctrlErr
		},
	}
	c, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		return nil, errNotUDP
	}
	return udpConn{c: uc}, nil
}
