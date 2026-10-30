// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package intercept

//go:generate go tool bpf2go -target bpfel,bpfeb -go-package intercept -tags linux xdp bpf/xdp_relay.c -- -I bpf/include -Wall -Werror

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"shepherd/internal/arp"
)

// This file is the Go half of the XDP relay: it loads the program
// bpf2go compiled from bpf/xdp_relay.c (the generated xdp_bpfel.go /
// xdp_bpfeb.go embed the object code, so an ordinary `go build` needs no
// clang; `go generate` in this package rebuilds them and needs a clang
// with the BPF backend on PATH or in BPF2GO_CC), attaches it to the
// interface, keeps its steered-device map in step with the Controller,
// and reads its counters back so Status(), Stats() and the health loop
// see exactly what they would with ParallelRelay.
//
// Nothing here changes what gets steered. The Controller remains the
// only authority: this file only mirrors its steered set into a map the
// program consults, and takes the Controller's word for it the moment the
// set changes (steeredSetObserver), with a periodic full resync as a
// safety net. Detaching the program (ctx done, or any error) restores the
// interface to exactly what it was.
//
// Needs CAP_NET_ADMIN and CAP_BPF (CAP_SYS_ADMIN before Linux 5.8) to
// load and attach. Nothing here needs CAP_NET_RAW; the Spoofer's sends
// still do.

// AttachXDP attaches the in-kernel relay program to iface and runs it
// until ctx is done, then detaches it. It is the in-kernel alternative to
// ParallelRelay; do not run both on the same interface (the program
// bounces a relayed frame back out before any socket, AF_PACKET included,
// would see it, so ParallelRelay would simply see nothing to do — but
// there is no reason to pay for both).
//
// Blocks until ctx is done. Returns ErrXDPMACMismatch if the Controller's
// ShepherdMAC is not iface's MAC.
func (c *Controller) AttachXDP(ctx context.Context, iface string, opts XDPOptions) error {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("intercept: interface %q: %w", iface, err)
	}
	var ifMAC arp.MAC
	copy(ifMAC[:], ifc.HardwareAddr)
	if ifMAC != c.cfg.ShepherdMAC {
		return fmt.Errorf("%w: interface %s has %s, Controller has %s", ErrXDPMACMismatch, iface, ifMAC, c.cfg.ShepherdMAC)
	}

	localIPs := opts.LocalIPs
	if len(localIPs) == 0 {
		localIPs, err = interfaceIPv4s(ifc)
		if err != nil {
			return err
		}
	}

	// Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK, which is
	// tiny by default; on 5.11+ this is a no-op.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("intercept: raise memlock rlimit for BPF: %w", err)
	}

	var objs xdpObjects
	if err := loadXdpObjects(&objs, nil); err != nil {
		return fmt.Errorf("intercept: load XDP relay program: %w", err)
	}
	defer objs.Close()

	dp := &xdpDataPlane{objs: &objs}
	if err := dp.configure(c.cfg.ShepherdMAC, c.cfg.GatewayMAC, localIPs); err != nil {
		return err
	}

	l, mode, err := attachXDP(objs.XdpRelay, ifc.Index, opts.Mode)
	if err != nil {
		return err
	}
	defer l.Close()
	if opts.OnAttached != nil {
		opts.OnAttached(mode)
	}

	// From here the program is live. Mirror the steered set now and on
	// every change; stop mirroring (and empty the map, via the deferred
	// detach) when we leave.
	c.setObserver(dp)
	defer c.setObserver(nil)

	poll := opts.PollInterval
	if poll <= 0 {
		poll = DefaultXDPPollInterval
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			dp.resync(c.steeredMACs())
			dp.harvest(c)
		}
	}
}

// attachXDP attaches prog to ifindex in the requested mode. XDPAuto tries
// native first and, if the driver refuses, generic.
func attachXDP(prog *ebpf.Program, ifindex int, mode XDPMode) (link.Link, XDPMode, error) {
	try := func(flags link.XDPAttachFlags) (link.Link, error) {
		return link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifindex, Flags: flags})
	}
	switch mode {
	case XDPNative:
		l, err := try(link.XDPDriverMode)
		if err != nil {
			return nil, mode, fmt.Errorf("intercept: attach XDP in native mode: %w", err)
		}
		return l, XDPNative, nil
	case XDPGeneric:
		l, err := try(link.XDPGenericMode)
		if err != nil {
			return nil, mode, fmt.Errorf("intercept: attach XDP in generic mode: %w", err)
		}
		return l, XDPGeneric, nil
	default:
		l, nativeErr := try(link.XDPDriverMode)
		if nativeErr == nil {
			return l, XDPNative, nil
		}
		l, err := try(link.XDPGenericMode)
		if err != nil {
			return nil, mode, fmt.Errorf("intercept: attach XDP: native mode: %v; generic mode: %w", nativeErr, err)
		}
		return l, XDPGeneric, nil
	}
}

// interfaceIPv4s returns the IPv4 addresses configured on ifc.
func interfaceIPv4s(ifc *net.Interface) ([]netip.Addr, error) {
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, fmt.Errorf("intercept: addresses of %s: %w", ifc.Name, err)
	}
	var out []netip.Addr
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() {
			out = append(out, ip.Unmap())
		}
	}
	return out, nil
}

// xdpDataPlane owns the loaded maps and mirrors the Controller's steered
// set into the program's `steered` map. It implements steeredSetObserver.
type xdpDataPlane struct {
	objs *xdpObjects

	mu   sync.Mutex
	last map[arp.MAC]xdpDevCounters // counters as of the previous harvest
	// stats as of the previous harvest, summed across CPUs
	lastStats xdpRelayStats
}

func macKey(mac arp.MAC) xdpMacKey {
	var k xdpMacKey
	copy(k.Mac[:], mac[:])
	return k
}

// ipKey is the map key for an IPv4 address: the program compares the
// packet's destination address bytes in place, so the key's in-memory
// bytes must be the address's bytes in network order, whatever the
// host's endianness.
func ipKey(ip netip.Addr) uint32 {
	b := ip.Unmap().As4()
	return binary.NativeEndian.Uint32(b[:])
}

func (dp *xdpDataPlane) configure(shepherdMAC, gatewayMAC arp.MAC, localIPs []netip.Addr) error {
	cfg := xdpRelayConfig{ShepherdMac: shepherdMAC, GatewayMac: gatewayMAC}
	if err := dp.objs.Config.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("intercept: set XDP relay config: %w", err)
	}
	for _, ip := range localIPs {
		if !ip.Unmap().Is4() {
			continue
		}
		if err := dp.objs.LocalIps.Put(ipKey(ip), uint8(1)); err != nil {
			return fmt.Errorf("intercept: add local IP %s to XDP relay: %w", ip, err)
		}
	}
	return nil
}

// steeredSetChanged implements steeredSetObserver: called by the
// Controller, outside its lock, with the complete new steered set.
func (dp *xdpDataPlane) steeredSetChanged(macs []arp.MAC) { dp.resync(macs) }

// resync makes the program's steered map hold exactly macs: new ones are
// added with zeroed counters, missing ones removed. Entries already
// present keep their counters, guaranteed two ways: the whole resync runs
// under dp.mu (the Controller's observer call and the poll loop's safety
// resync can otherwise interleave, and an add decided on a stale
// iteration would reset counters the kernel had since bumped), and adds
// use UpdateNoExist, so even then the kernel refuses to overwrite an
// entry that exists. Errors are deliberately swallowed here (there is no
// one to return them to from the observer path, and the next poll
// retries); the health loop is what fails a device open if it is steered
// but nothing is ever relayed for it.
func (dp *xdpDataPlane) resync(macs []arp.MAC) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	want := make(map[arp.MAC]struct{}, len(macs))
	for _, m := range macs {
		want[m] = struct{}{}
	}

	// Remove what should no longer be there.
	var have []xdpMacKey
	var k xdpMacKey
	var v xdpDevCounters
	it := dp.objs.Steered.Iterate()
	for it.Next(&k, &v) {
		have = append(have, k)
	}
	for _, k := range have {
		var mac arp.MAC
		copy(mac[:], k.Mac[:])
		if _, ok := want[mac]; !ok {
			_ = dp.objs.Steered.Delete(k)
			delete(dp.last, mac)
		} else {
			delete(want, mac) // already present
		}
	}
	// Add what is missing, with zeroed counters, never touching an
	// entry that exists.
	for mac := range want {
		_ = dp.objs.Steered.Update(macKey(mac), xdpDevCounters{}, ebpf.UpdateNoExist)
	}
}

// harvest reads the kernel's counters and credits the deltas since the
// previous harvest to the Controller, per device and globally.
func (dp *xdpDataPlane) harvest(c *Controller) {
	now := c.cfg.Clock.Now()

	dp.mu.Lock()
	defer dp.mu.Unlock()
	if dp.last == nil {
		dp.last = map[arp.MAC]xdpDevCounters{}
	}
	var k xdpMacKey
	var v xdpDevCounters
	it := dp.objs.Steered.Iterate()
	for it.Next(&k, &v) {
		var mac arp.MAC
		copy(mac[:], k.Mac[:])
		prev := dp.last[mac]
		dp.last[mac] = v
		if v.Packets > prev.Packets {
			c.recordRelayedBatch(mac, v.Packets-prev.Packets, v.Bytes-prev.Bytes, now)
		}
	}

	var perCPU []xdpRelayStats
	if err := dp.objs.Stats.Lookup(uint32(0), &perCPU); err == nil {
		var sum xdpRelayStats
		for _, s := range perCPU {
			sum.Examined += s.Examined
			sum.PassedLocal += s.PassedLocal
			sum.RelayedFrames += s.RelayedFrames
			sum.RelayedBytes += s.RelayedBytes
		}
		if sum.Examined > dp.lastStats.Examined {
			c.recordExaminedBatch(sum.Examined-dp.lastStats.Examined, 0)
		}
		dp.lastStats = sum
	}
}

// XDPStats is a snapshot of the program's own global counters, summed
// across CPUs. Exposed for diagnostics (cmd/intercept-trial); the
// Controller's Stats() and Status() already include the relayed numbers.
type XDPStats struct {
	Examined      uint64 // every frame the program saw on the interface
	PassedLocal   uint64 // from a steered device, but for Shepherd itself: passed, not relayed
	RelayedFrames uint64
	RelayedBytes  uint64
}

var _ steeredSetObserver = (*xdpDataPlane)(nil)
