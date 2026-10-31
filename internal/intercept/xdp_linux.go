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

	// Shepherd's own addresses, in order of preference: the caller's,
	// the Controller's (ControllerConfig.ShepherdIPs, shared with the
	// userspace Relay), else read from the interface.
	localIPs := opts.LocalIPs
	if len(localIPs) == 0 {
		localIPs = c.cfg.ShepherdIPs
	}
	if len(localIPs) == 0 {
		localIPs, err = interfaceIPv4s(ifc)
		if err != nil {
			return err
		}
	}

	// Shepherd's own IPv6 addresses, used only when IPv6 steering is on:
	// the caller's, the Controller's (ShepherdIPs6), else the interface's.
	// An XDP_TX frame never reaches the stack, so a steered device's IPv6
	// traffic to Shepherd itself must be recognized here and passed.
	var localIPs6 []netip.Addr
	if c.cfg.IPv6SteeringEnabled {
		localIPs6 = opts.LocalIPs6
		if len(localIPs6) == 0 {
			localIPs6 = c.cfg.ShepherdIPs6
		}
		if len(localIPs6) == 0 {
			localIPs6, err = interfaceIPv6s(ifc)
			if err != nil {
				return err
			}
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
	if err := dp.configure(c.cfg.ShepherdMAC, c.cfg.GatewayMAC, localIPs, localIPs6); err != nil {
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
			dp.resync(c.steeredEntries())
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

// interfaceIPv6s returns the IPv6 addresses configured on ifc (link-local,
// ULA and global), so a steered device's IPv6 traffic to any of Shepherd's
// own addresses is passed through rather than relayed.
func interfaceIPv6s(ifc *net.Interface) ([]netip.Addr, error) {
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
		if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Is6() && !ip.Is4In6() {
			out = append(out, ip)
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

// ip6Key is the map key for an IPv6 address: the program compares the
// packet's 16 destination bytes in place, so the key holds the address's
// bytes in network order.
func ip6Key(ip netip.Addr) xdpIn6Key {
	return xdpIn6Key{Addr: ip.As16()}
}

func (dp *xdpDataPlane) configure(shepherdMAC, gatewayMAC arp.MAC, localIPs, localIPs6 []netip.Addr) error {
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
	for _, ip := range localIPs6 {
		if !ip.Is6() || ip.Is4In6() {
			continue
		}
		if err := dp.objs.LocalIps6.Put(ip6Key(ip), uint8(1)); err != nil {
			return fmt.Errorf("intercept: add local IPv6 %s to XDP relay: %w", ip, err)
		}
	}
	return nil
}

// steeredSetChanged implements steeredSetObserver: called by the
// Controller, outside its lock, with the complete new steered set.
func (dp *xdpDataPlane) steeredSetChanged(entries []steeredEntry) { dp.resync(entries) }

// resync makes the program's steered map hold exactly entries: new devices
// are added with zeroed counters and their steered families, devices no
// longer present are removed, and a device whose families changed (e.g. a
// single-family unsteer that kept the other) has just its families field
// updated in place. Counters already present are never reset, guaranteed
// three ways: the whole resync runs under dp.mu (the Controller's observer
// call and the poll loop's safety resync can otherwise interleave, and an
// add decided on a stale iteration would reset counters the kernel had
// since bumped); adds use UpdateNoExist, so even then the kernel refuses to
// overwrite an entry that exists; and a families-only change reads the live
// counters first and writes them straight back. Errors are deliberately
// swallowed here (there is no one to return them to from the observer path,
// and the next poll retries); the health loop is what fails a device open
// if it is steered but nothing is ever relayed for it.
func (dp *xdpDataPlane) resync(entries []steeredEntry) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	want := make(map[arp.MAC]Family, len(entries))
	for _, e := range entries {
		want[e.MAC] = e.Fam
	}

	// Pass over what is there: remove the unwanted, fix a changed family.
	var k xdpMacKey
	var v xdpDevCounters
	type present struct {
		key xdpMacKey
		val xdpDevCounters
	}
	var have []present
	it := dp.objs.Steered.Iterate()
	for it.Next(&k, &v) {
		have = append(have, present{k, v})
	}
	for _, p := range have {
		var mac arp.MAC
		copy(mac[:], p.key.Mac[:])
		fam, ok := want[mac]
		if !ok {
			_ = dp.objs.Steered.Delete(p.key)
			delete(dp.last, mac)
			continue
		}
		if p.val.Families != uint8(fam) {
			nv := p.val
			nv.Families = uint8(fam)
			_ = dp.objs.Steered.Update(p.key, nv, ebpf.UpdateExist)
		}
		delete(want, mac) // already present
	}
	// Add what is missing, with zeroed counters and its families, never
	// touching an entry that exists.
	for mac, fam := range want {
		_ = dp.objs.Steered.Update(macKey(mac), xdpDevCounters{Families: uint8(fam)}, ebpf.UpdateNoExist)
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
			c.recordRelayedBatch(mac, SteerV4, v.Packets-prev.Packets, v.Bytes-prev.Bytes, now)
		}
		if v.Packets6 > prev.Packets6 {
			c.recordRelayedBatch(mac, SteerV6, v.Packets6-prev.Packets6, v.Bytes6-prev.Bytes6, now)
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
			c.recordExaminedBatch(sum.Examined-dp.lastStats.Examined, 0, sum.PassedLocal-dp.lastStats.PassedLocal)
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
