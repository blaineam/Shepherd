// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

import (
	"fmt"
	"net"
	"sync"
	"syscall"
)

// This file is the only code in this package that touches a socket. It
// opens an AF_PACKET SOCK_RAW socket bound to one interface and only ever
// calls sendto on it: no promiscuous mode, no setsockopt that changes
// kernel behaviour, no receive. It needs CAP_NET_RAW, so it cannot run in
// an unprivileged test; everything that decides what to send (Spoofer,
// Relay, Controller) is tested against FakeSender instead, same pattern
// as internal/arp/open_linux.go on the read side.
//
// Sending a complete, already-addressed Ethernet frame through an
// AF_PACKET SOCK_RAW socket bypasses the kernel's IP stack entirely: it
// never reaches a routing decision, netfilter, or conntrack, so this path
// needs no net.ipv4.ip_forward and sets none. See docs/INTERCEPT.md.

// Open binds a send-only raw Ethernet Sender to the named interface.
func Open(iface string) (Sender, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("intercept: interface %q: %w", iface, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("intercept: raw socket (needs CAP_NET_RAW): %w", err)
	}
	addr := &syscall.SockaddrLinklayer{Ifindex: ifc.Index}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("intercept: bind %q: %w", iface, err)
	}
	return &rawSender{fd: fd, addr: addr}, nil
}

type rawSender struct {
	mu   sync.Mutex
	fd   int
	addr *syscall.SockaddrLinklayer
}

// Send implements Sender. f must already be a complete Ethernet frame;
// Spoofer and Relay both build exactly that.
func (s *rawSender) Send(f Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return syscall.Sendto(s.fd, f, 0, s.addr)
}

// Close releases the socket. It is not part of the Sender interface
// (which this package deliberately keeps to one method); whoever opens a
// rawSender owns closing it.
func (s *rawSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return syscall.Close(s.fd)
}

var _ Sender = (*rawSender)(nil)
