// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// This file is the only code in this package that touches a socket. It
// opens an AF_PACKET SOCK_RAW socket bound to one interface and only ever
// calls sendto on it: no promiscuous mode, no receive, and no setsockopt
// that changes what the NIC does or what anything else on the system
// sees — the one exception is SO_SNDTIMEO (below), which only bounds how
// long a blocking Sendto on this one process's own socket can take and
// touches nothing else's behaviour. It needs CAP_NET_RAW, so it cannot
// run in an unprivileged test; everything that decides what to send
// (Spoofer, Relay, Controller) is tested against FakeSender instead, same
// pattern as internal/arp/open_linux.go on the read side.
//
// Sending a complete, already-addressed Ethernet frame through an
// AF_PACKET SOCK_RAW socket bypasses the kernel's IP stack entirely: it
// never reaches a routing decision, netfilter, or conntrack, so this path
// needs no net.ipv4.ip_forward and sets none. See docs/INTERCEPT.md.

// Open binds a send-only raw Ethernet Sender to the named interface.
func Open(iface string) (Sender, error) {
	s, err := openOne(iface)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// OpenMany opens n independent send-only raw Ethernet Senders on the same
// interface, each its own socket with no shared state (no mutex, no fd) so
// n callers can send concurrently without ever contending on each other.
// It exists for ParallelRelay: one Sender per capture worker, so a packet
// relayed by worker 2 never waits on worker 1's send. If any socket fails
// to open, every socket already opened in this call is closed first.
func OpenMany(iface string, n int) ([]Sender, error) {
	if n < 1 {
		n = 1
	}
	out := make([]Sender, 0, n)
	for i := 0; i < n; i++ {
		s, err := openOne(iface)
		if err != nil {
			for _, prior := range out {
				_ = prior.(*rawSender).Close()
			}
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func openOne(iface string) (*rawSender, error) {
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
	// A kernel-enforced send timeout, set once here, is what lets
	// sendWithTimeout skip its own goroutine-and-timer wrapper for every
	// single frame this socket ever sends (see selfBounded in sender.go):
	// Sendto itself cannot block past this, so wrapping it again would
	// only add overhead with no further protection.
	secs := int64(DefaultSendTimeout / time.Second)
	tv := syscall.Timeval{Sec: secs, Usec: int64((DefaultSendTimeout % time.Second) / time.Microsecond)}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("intercept: set send timeout on %q: %w", iface, err)
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

// selfBounded marks rawSender for sendWithTimeout's fast path: see
// SO_SNDTIMEO in openOne and the selfBounded doc comment in sender.go.
func (s *rawSender) selfBounded() {}

var (
	_ Sender      = (*rawSender)(nil)
	_ selfBounded = (*rawSender)(nil)
)
