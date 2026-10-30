// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// This file is the other half of what a real capture-and-relay needs: a
// read-only AF_PACKET capture, split across several sockets by Linux's
// own PACKET_FANOUT so several goroutines (and cores) can read, decide,
// and send in parallel. No socket here ever sends; the Senders ParallelRelay
// opens through OpenMany do that, each on its own fd, so there is nothing
// shared between workers to contend on. Nothing here changes kernel
// behaviour beyond the fanout group membership itself, which is scoped to
// these sockets and torn down when they close.

// DefaultParallelism is how many PACKET_FANOUT workers ParallelRelay uses
// when a caller does not pick a number: enough to get real multi-core
// throughput on a typical home NAS without opening more sockets than it
// has cores to use them on.
const DefaultParallelism = 4

const ethPAll = 0x0003

func htons(v uint16) uint16 { return v<<8 | v>>8 }

type captureSocket struct{ fd int }

// openCaptureGroup opens n read-only AF_PACKET sockets bound to iface and
// joined to one PACKET_FANOUT group, hashed by flow so one TCP (or UDP)
// flow always lands on the same socket — a device's traffic is split
// across workers, but never reordered within one connection.
func openCaptureGroup(iface string, n int) ([]*captureSocket, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("intercept: interface %q: %w", iface, err)
	}
	groupID := os.Getpid() & 0xffff

	out := make([]*captureSocket, 0, n)
	closeAll := func() {
		for _, s := range out {
			_ = unix.Close(s.fd)
		}
	}
	for i := 0; i < n; i++ {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(ethPAll)))
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("intercept: raw capture socket (needs CAP_NET_RAW): %w", err)
		}
		addr := &unix.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifc.Index}
		if err := unix.Bind(fd, addr); err != nil {
			_ = unix.Close(fd)
			closeAll()
			return nil, fmt.Errorf("intercept: bind capture socket %q: %w", iface, err)
		}
		// Without this, an AF_PACKET socket bound to iface also receives a
		// loopback copy of every frame this same host transmits on iface —
		// including every frame the Relay and Spoofer send out through
		// their own separate (send-only) sockets on the same interface.
		// HandleFrame's destination-MAC check already discards those
		// correctly (Shepherd never sends anything addressed to its own
		// MAC), so this is not a correctness fix; it is cutting, at the
		// kernel's own packet-rate cost, the biggest single avoidable part
		// of it: one wasted capture-and-discard for every frame relayed.
		// PACKET_IGNORE_OUTGOING is Linux 4.20+; an older kernel returns
		// ENOPROTOOPT here and capture keeps working exactly as before,
		// just without this saving.
		_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)
		fanoutArg := groupID | (unix.PACKET_FANOUT_HASH << 16)
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
			_ = unix.Close(fd)
			closeAll()
			return nil, fmt.Errorf("intercept: join fanout group on %q: %w", iface, err)
		}
		out = append(out, &captureSocket{fd: fd})
	}
	return out, nil
}

// run reads frames until ctx is done, calling handle for each one. The
// receive timeout is set once, not per read, so a slow interface does not
// pay an extra syscall per packet on top of the unavoidable recv itself.
func (s *captureSocket) run(ctx context.Context, handle func([]byte)) {
	tv := unix.Timeval{Sec: 0, Usec: 250000}
	_ = unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return
		}
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		handle(buf[:n])
	}
}

func (s *captureSocket) close() error { return unix.Close(s.fd) }

// ParallelRelay captures iface's traffic across n PACKET_FANOUT workers
// (DefaultParallelism if n <= 0) and relays every steered device's frames
// through n independent Senders (OpenMany), each on its own goroutine: a
// capture-and-relay pipeline that runs truly in parallel across cores
// instead of one goroutine serializing every packet, which is what made an
// earlier single-socket version the throughput bottleneck under a real,
// sustained transfer (see docs/INTERCEPT.md). Every worker's Relay is
// built with NewRelay, so Steer, Unsteer, PanicStop, the health loop and
// Status all still see one unified Controller; nothing about what gets
// steered changes, only how many goroutines carry its traffic.
//
// Blocks until ctx is done, then closes every socket (capture and send)
// and returns. Needs CAP_NET_RAW on the process; nothing here needs
// CAP_NET_ADMIN (that is only for the caller's own GRO handling, if any).
func (c *Controller) ParallelRelay(ctx context.Context, iface string, n int) error {
	if n <= 0 {
		n = DefaultParallelism
	}
	senders, err := OpenMany(iface, n)
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range senders {
			if closer, ok := s.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
	}()

	captures, err := openCaptureGroup(iface, n)
	if err != nil {
		return err
	}
	defer func() {
		for _, cs := range captures {
			_ = cs.close()
		}
	}()

	var wg sync.WaitGroup
	for i := range captures {
		relay := c.NewRelay(senders[i])
		sock := captures[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sock.run(ctx, func(raw []byte) { _, _ = relay.HandleFrame(raw) })
		}()
	}
	wg.Wait()
	return nil
}
