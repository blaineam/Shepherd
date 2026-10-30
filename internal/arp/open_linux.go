// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package arp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// This file is the only code that touches a socket. It opens an AF_PACKET
// socket for EtherType 0x0806 bound to one interface and only ever calls
// read on it: no sendto, no write, no promiscuous mode, no setsockopt that
// changes kernel behaviour. It needs CAP_NET_RAW, so it cannot run in an
// unprivileged test; everything around it (decoding, the Monitor) is tested
// through packetReader fakes.

// Open binds a read-only ARP source to the named interface. An empty name
// selects the interface of the default route. It returns the source and
// the interface name actually used.
func Open(iface string) (Source, string, error) {
	if iface == "" {
		r, err := DefaultRoute(os.ReadFile)
		if err != nil {
			return nil, "", fmt.Errorf("arp: pick interface: %w", err)
		}
		iface = r.Iface
	}
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, "", fmt.Errorf("arp: interface %q: %w", iface, err)
	}
	proto := htons(etherTypeARP)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return nil, "", fmt.Errorf("arp: raw socket (needs CAP_NET_RAW): %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: proto, Ifindex: ifc.Index}); err != nil {
		syscall.Close(fd)
		return nil, "", fmt.Errorf("arp: bind %q: %w", iface, err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, "", err
	}
	return newByteSource(&rawReader{f: os.NewFile(uintptr(fd), "arp-"+iface)}), iface, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

type rawReader struct{ f *os.File }

func (r *rawReader) ReadPacket(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 2048)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		_ = r.f.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := r.f.Read(buf)
		switch {
		case err == nil:
			return buf[:n], nil
		case errors.Is(err, os.ErrDeadlineExceeded):
			continue
		case errors.Is(err, os.ErrClosed):
			return nil, ErrClosed
		default:
			return nil, err
		}
	}
}

func (r *rawReader) Close() error { return r.f.Close() }
