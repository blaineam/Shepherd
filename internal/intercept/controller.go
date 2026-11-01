// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"shepherd/internal/arp"
)

// Defaults for ControllerConfig. docs/INTERCEPT.md explains each one.
const (
	DefaultHealthInterval = 3 * time.Second
	DefaultIdleGrace      = 15 * time.Second
	DefaultStartupGrace   = 30 * time.Second
	DefaultSendTimeout    = 2 * time.Second
)

// Sentinel errors returned by Controller.
var (
	ErrSenderRequired      = errors.New("intercept: Sender is required")
	ErrShepherdMACRequired = errors.New("intercept: ShepherdMAC is required")
	ErrGatewayRequired     = errors.New("intercept: GatewayIP and GatewayMAC are required")
	ErrInvalidDevice       = errors.New("intercept: device MAC or IP is not a usable IPv4 address")
	ErrGatewayExcluded     = errors.New("intercept: cannot steer the gateway or Shepherd's own interface")
	ErrExcluded            = errors.New("intercept: device is excluded from steering")
	ErrAlreadySteered      = errors.New("intercept: device is already steered")
	ErrNotSteered          = errors.New("intercept: device is not steered")
	ErrPanicked            = errors.New("intercept: panic stop is active; call Rearm to resume")
	ErrTrialDuration       = errors.New("intercept: Trial requires a positive Duration")
	ErrClosed              = errors.New("intercept: controller is closed")

	// ErrIPv6Disabled is returned by Steer for an IPv6 steer when the
	// Controller was not built with IPv6SteeringEnabled. IPv6 steering is
	// off by default and this is the master switch (docs/IPV6-WATCH.md).
	ErrIPv6Disabled = errors.New("intercept: IPv6 steering is disabled (IPv6SteeringEnabled is false)")
	// ErrNoGatewayLinkLocal is returned by Steer for an IPv6 steer when
	// the Controller has no gateway link-local address to advertise.
	ErrNoGatewayLinkLocal = errors.New("intercept: IPv6 steering needs the gateway's link-local address (GatewayLinkLocal)")
	// ErrInvalidV6Device is returned by Steer for an IPv6 steer whose
	// device has no usable unicast IPv6 address to send advertisements to.
	ErrInvalidV6Device = errors.New("intercept: device has no usable unicast IPv6 address (DeviceRef.IP6)")
)

// Excluder reports whether a device must never be steered. The caller
// wires this to the device registry's Excluded flag (or anything else)
// so Steer cannot be made to steer a device the operator opted out of,
// no matter what is asked of it.
type Excluder interface {
	Excluded(mac arp.MAC) bool
}

// DeviceRef identifies a device to steer. IP is the device's IPv4 address
// (required for IPv4 steering). IP6 is a unicast IPv6 address the device
// holds — its link-local is the natural choice — to which Neighbor
// Advertisements are sent; it is required only when SteerOptions.Family
// includes SteerV6, and ignored otherwise.
type DeviceRef struct {
	MAC arp.MAC
	IP  netip.Addr
	IP6 netip.Addr
}

// SteerOptions configures one Steer call.
type SteerOptions struct {
	// Trial, when true, auto-unsteers the device after Duration even if
	// nothing else calls Unsteer first. Duration must be positive.
	Trial    bool
	Duration time.Duration

	// Family is the set of address families to steer. The zero value is
	// treated as SteerV4, so existing callers are unchanged. SteerV6 (on
	// its own or with SteerV4) additionally requires IPv6SteeringEnabled,
	// a GatewayLinkLocal, and a usable DeviceRef.IP6; see docs/IPV6-WATCH.md.
	Family Family
}

// SteeredDevice is a snapshot of one currently steered device.
// BytesRelayed/PacketsRelayed/LastVerified are summed across the device's
// active families; Family says which families those are, and Healthy is
// true only when every active family is healthy.
type SteeredDevice struct {
	MAC            arp.MAC
	IP             netip.Addr
	Family         Family
	Since          time.Time
	Healthy        bool
	BytesRelayed   uint64
	PacketsRelayed uint64
	LastVerified   time.Time // zero if no traffic has been relayed yet
}

// ControllerStats is a cumulative, global packet-rate snapshot: every
// frame any Relay sharing this Controller's state (the Controller's own,
// and every one returned by NewRelay — ParallelRelay's workers included)
// has ever been given, regardless of which device it belonged to or
// whether that device is still steered. Status() answers "how is this
// device doing"; Stats() answers "how much traffic is actually moving
// through Shepherd" — sample it periodically (e.g. every few seconds, as
// cmd/intercept-trial does) and diff consecutive snapshots to get
// frames/bytes per second. See docs/INTERCEPT.md's "Throughput" section.
type ControllerStats struct {
	FramesExamined       uint64 // every frame HandleFrame was ever given, matched or not
	BytesExamined        uint64 // their total wire length
	FramesNotForShepherd uint64 // subset discarded because dst != ShepherdMAC (see OnFrameNotForShepherd)
	// FramesForShepherdItself is the subset left alone because they were for
	// Shepherd's own IP (see Relay.ShepherdIPs). The XDP relay reports the
	// same thing from its own counters.
	FramesForShepherdItself uint64
	FramesRelayed           uint64 // subset actually relayed
	BytesRelayed            uint64 // their total wire length
}

// UnsteerRecord is one entry in the Controller's unsteer history: what
// was unsteered, when, and why. The health loop, trial expiry and
// PanicStop all fill this in automatically; Unsteer records the caller's
// own request.
type UnsteerRecord struct {
	MAC    arp.MAC
	Reason string
	Time   time.Time
}

// ControllerConfig configures a Controller. Sender, ShepherdMAC,
// GatewayIP and GatewayMAC are required; everything else has a safe
// default.
type ControllerConfig struct {
	Sender Sender
	Clock  Clock // default: the real wall clock

	ShepherdMAC arp.MAC
	GatewayIP   netip.Addr
	GatewayMAC  arp.MAC
	// GatewayLinkLocal is the gateway's IPv6 link-local address — the next
	// hop a device's IPv6 default route points at, and the address IPv6
	// steering claims for Shepherd's MAC. Required only for IPv6 steering;
	// the gateway's real MAC is GatewayMAC, reused for the IPv6 corrective.
	GatewayLinkLocal netip.Addr
	// ShepherdIPs are this host's own IPv4 addresses on the interface
	// being relayed on, passed straight through to every Relay (see
	// Relay.ShepherdIPs for why this matters: without it, traffic a
	// steered device sends to Shepherd itself — a DNS query, a portal
	// connection — gets needlessly relayed to the real gateway too,
	// which just drops it, wasting a relay worker's capacity on every
	// single locally-destined packet for nothing). AttachXDP uses them
	// the same way, and there it is not optional in effect: an XDP_TX
	// frame never reaches the kernel, so AttachXDP reads the interface's
	// own addresses itself when this is empty. Optional for the userspace
	// relay but strongly recommended; empty keeps relaying everything.
	ShepherdIPs []netip.Addr
	// ShepherdIPs6 are this host's own IPv6 addresses on the interface:
	// the IPv6 counterpart of ShepherdIPs, so a steered device's IPv6
	// traffic to Shepherd itself is passed through, not relayed. Optional.
	ShepherdIPs6 []netip.Addr

	// IPv6SteeringEnabled is the master switch for IPv6 steering, off by
	// default. While it is false, any Steer with SteerV6 is rejected with
	// ErrIPv6Disabled no matter what else is configured — the single flag
	// docs/IPV6-WATCH.md's safety story turns on. It gates nothing for IPv4.
	IPv6SteeringEnabled bool

	// Excluder is consulted on every Steer call. Optional.
	Excluder Excluder
	// V6Excluder is consulted, in addition to Excluder, only on an IPv6
	// steer. The caller wires it to a stricter rule than the IPv4 one —
	// refusing every smart-home / Thread / Matter / router device (the
	// TypeSmartHome and TypeRouter devices the registry already classifies
	// from their mDNS services, plus anything seen sourcing a Router
	// Advertisement) — so IPv6 steering can never be pointed at the gear
	// docs/IPV6.md exists to protect. Optional, but strongly recommended
	// whenever IPv6SteeringEnabled is true.
	V6Excluder Excluder
	// ExcludedMACs is a static exclusion list (infrastructure devices,
	// Shepherd host's own other interfaces) checked alongside Excluder.
	ExcludedMACs []arp.MAC

	SpoofInterval  time.Duration // default DefaultSpoofInterval
	HealthInterval time.Duration // default DefaultHealthInterval
	IdleGrace      time.Duration // default DefaultIdleGrace: silence grace for an established device
	StartupGrace   time.Duration // default DefaultStartupGrace: grace for a device that has never once relayed
	SendTimeout    time.Duration // default DefaultSendTimeout

	// OnUnsteer is called whenever a device stops being steered, for any
	// reason (the caller's own Unsteer, a health failure, trial expiry,
	// or PanicStop). Optional.
	OnUnsteer func(UnsteerRecord)
}

func (c ControllerConfig) withDefaults() ControllerConfig {
	if c.Clock == nil {
		c.Clock = realClock{}
	}
	if c.SpoofInterval <= 0 {
		c.SpoofInterval = DefaultSpoofInterval
	}
	if c.HealthInterval <= 0 {
		c.HealthInterval = DefaultHealthInterval
	}
	if c.IdleGrace <= 0 {
		c.IdleGrace = DefaultIdleGrace
	}
	if c.StartupGrace <= 0 {
		c.StartupGrace = DefaultStartupGrace
	}
	if c.SendTimeout <= 0 {
		c.SendTimeout = DefaultSendTimeout
	}
	return c
}

// usableDeviceIP reports whether ip is a concrete, usable IPv4 address: no
// IPv6 (the hard rule in docs/IPV6.md — Watch mode never touches it), no
// unspecified/multicast/loopback/broadcast address.
func usableDeviceIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return false
	}
	b := ip.As4()
	return b[0] != 0 && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// usableGatewayV6 reports whether a is a concrete IPv6 address usable as
// the gateway's link-local target of an advertisement: IPv6, not a 4-in-6
// mapping, not unspecified, not multicast.
func usableGatewayV6(a netip.Addr) bool {
	return a.Is6() && !a.Is4In6() && !a.IsUnspecified() && !a.IsMulticast()
}

// usableDeviceV6 reports whether a is a unicast IPv6 address an
// advertisement can be sent to (a device's link-local is the usual one).
func usableDeviceV6(a netip.Addr) bool {
	return usableGatewayV6(a)
}

// famState is one address family's bookkeeping for one steered device.
// The fields the Relay's hot path writes (bytes, packets, last-verified,
// healthy) are atomics, updated by every ParallelRelay worker on every
// relayed frame without taking Controller.mu: at a real transfer's packet
// rate (tens to hundreds of thousands of frames per second, split across
// workers) a shared mutex on that path is contention the relay cannot
// afford, and the health loop and Status read these only occasionally.
// cancel/done are the family's own spoofer handle, written once under mu
// when the family is steered, so one family can be unsteered (its spoofer
// stopped, its corrective sent) without touching the other.
type famState struct {
	bytesRelayed   atomic.Uint64
	packetsRelayed atomic.Uint64
	// lastVerifiedNanos is the wall-clock UnixNano of the last relayed
	// frame; everVerified says whether there has been one at all, so a
	// clock that happens to sit at the Unix epoch is not mistaken for
	// "never" (and the zero time's UnixNano, which is undefined, is never
	// stored). lastVerified() turns the pair back into a time.Time.
	lastVerifiedNanos atomic.Int64
	everVerified      atomic.Bool
	healthy           atomic.Bool

	cancel context.CancelFunc
	done   chan struct{}
}

func (fs *famState) lastVerified() time.Time {
	if !fs.everVerified.Load() {
		return time.Time{}
	}
	return time.Unix(0, fs.lastVerifiedNanos.Load())
}

func (fs *famState) record(n int, now time.Time) {
	fs.bytesRelayed.Add(uint64(n))
	fs.packetsRelayed.Add(1)
	fs.lastVerifiedNanos.Store(now.UnixNano())
	fs.everVerified.Store(true)
	fs.healthy.Store(true)
}

// deviceState is one steered device's bookkeeping, one famState per
// address family. ip (IPv4) and ip6 (the address IPv6 advertisements are
// sent to) and since are written once under mu in Steer. fam is the set
// of currently-active families, read lock-free on the hot path
// (lookupSteered) and written only under mu, so it is an atomic.
type deviceState struct {
	ip    netip.Addr
	ip6   netip.Addr
	since time.Time
	fam   atomic.Uint32 // Family bits currently active

	// cancel is the device-level context cancel, parent of every family's
	// own. Cancelling it stops all families at once (full unsteer,
	// PanicStop, Close); a family's own famState.cancel stops just that one.
	cancel context.CancelFunc

	v4 famState
	v6 famState
}

func (ds *deviceState) family() Family { return Family(ds.fam.Load()) }

// fs returns the famState for a single family (SteerV4 or SteerV6).
func (ds *deviceState) fs(f Family) *famState {
	if f == SteerV6 {
		return &ds.v6
	}
	return &ds.v4
}

// Controller is the safety-governed steering authority: the only thing in
// this package allowed to start or stop one-sided ARP steering of a real
// device, and the best-tested part of it. Nothing calls it automatically;
// a caller outside this package wires it up and decides when Steer runs.
// See docs/INTERCEPT.md for the full safety model.
type Controller struct {
	cfg ControllerConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	relay *Relay

	mu       sync.Mutex
	closed   bool
	panicked bool
	devices  map[arp.MAC]*deviceState
	history  []UnsteerRecord

	// steered is the lock-free snapshot of c.devices that every Relay's
	// hot path reads: Lookup (is this source MAC steered, and to which
	// IP) and recordRelayed (bump this device's counters) both go through
	// it and never take mu. It is rebuilt, under mu, on every Steer,
	// Unsteer and PanicStop (publishSnapshotLocked). A worker that loaded
	// the snapshot just before an unsteer may bump a deviceState that is
	// no longer in c.devices; that is harmless, since nothing reads a
	// removed deviceState's counters again.
	steered atomic.Pointer[map[arp.MAC]*deviceState]

	// observer, when set, is told (outside mu, after the snapshot above
	// has been republished) every time the steered set changes, so an
	// in-kernel data plane (AttachXDP) can mirror it at once instead of
	// finding out on its next poll. One at a time; nil means none.
	observer atomic.Pointer[steeredSetObserver]

	// Packet-rate diagnostics (ControllerStats), updated from every Relay's
	// hot path without taking mu, like the per-device counters in
	// deviceState: nothing on the relay's per-frame path takes a lock.
	framesExamined          atomic.Uint64
	bytesExamined           atomic.Uint64
	framesNotForShepherd    atomic.Uint64
	framesForShepherdItself atomic.Uint64
	framesRelayed           atomic.Uint64
	bytesRelayedTotal       atomic.Uint64

	// afterHealthCheck is a test-only hook, called at the end of every
	// health-check tick the background loop runs, after the next tick has
	// been armed. It lets tests synchronize with the autonomous loop
	// without sleeping. Nothing in this package's public API sets it.
	afterHealthCheck func(now time.Time)
}

// NewController builds a Controller and starts its health-verification
// loop. Call Close to stop the loop and un-steer every device.
func NewController(cfg ControllerConfig) (*Controller, error) {
	cfg = cfg.withDefaults()
	if cfg.Sender == nil {
		return nil, ErrSenderRequired
	}
	if cfg.ShepherdMAC.IsZero() {
		return nil, ErrShepherdMACRequired
	}
	gw := cfg.GatewayIP.Unmap()
	if !usableDeviceIP(gw) || cfg.GatewayMAC.IsZero() {
		return nil, ErrGatewayRequired
	}
	cfg.GatewayIP = gw

	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{
		cfg:     cfg,
		ctx:     ctx,
		cancel:  cancel,
		devices: map[arp.MAC]*deviceState{},
	}
	empty := map[arp.MAC]*deviceState{}
	c.steered.Store(&empty)

	c.relay = &Relay{
		Sender:                   cfg.Sender,
		ShepherdMAC:              cfg.ShepherdMAC,
		ShepherdIPs:              cfg.ShepherdIPs,
		ShepherdIPs6:             cfg.ShepherdIPs6,
		GatewayMAC:               cfg.GatewayMAC,
		SendTimeout:              cfg.SendTimeout,
		Lookup:                   c.lookupSteered,
		OnRelayed:                c.recordRelayed,
		OnRelayError:             c.recordRelayError,
		OnFrameExamined:          c.recordFrameExamined,
		OnFrameNotForShepherd:    c.recordFrameNotForShepherd,
		OnFrameForShepherdItself: c.recordFrameForShepherdItself,
		Now:                      cfg.Clock.Now,
	}

	first := cfg.Clock.After(cfg.HealthInterval)
	c.wg.Add(1)
	go c.healthLoop(ctx, first)

	return c, nil
}

// HandleFrame is the Relay's public entry point, wired to whatever feeds
// Shepherd raw frames. See Relay.HandleFrame for exactly what it does and
// ignores.
func (c *Controller) HandleFrame(raw []byte) (bool, error) {
	return c.relay.HandleFrame(raw)
}

// NewRelay returns an additional Relay wired to this Controller's own
// internal state (the same Lookup, OnRelayed, OnRelayError and Now as the
// Controller's own relay) but sending through sender instead of the
// Controller's own Sender. Every Relay returned this way, and the
// Controller's own, publish into and read from the same steered set,
// byte counters and health state; Steer, Unsteer, PanicStop and Status
// see them as one thing.
//
// This exists so a caller that wants to spread one steered device's
// traffic across several concurrent readers and senders (several raw
// sockets, each on its own goroutine, for real multi-core throughput
// instead of one serialized path) can build one Relay per sender and run
// them in parallel, without the Controller's safety-critical state ever
// being duplicated or raced. ParallelRelay (Linux only) is the ready-made
// version of exactly this.
func (c *Controller) NewRelay(sender Sender) *Relay {
	return &Relay{
		Sender:                   sender,
		ShepherdMAC:              c.cfg.ShepherdMAC,
		ShepherdIPs:              c.cfg.ShepherdIPs,
		ShepherdIPs6:             c.cfg.ShepherdIPs6,
		GatewayMAC:               c.cfg.GatewayMAC,
		SendTimeout:              c.cfg.SendTimeout,
		Lookup:                   c.lookupSteered,
		OnRelayed:                c.recordRelayed,
		OnRelayError:             c.recordRelayError,
		OnFrameExamined:          c.recordFrameExamined,
		OnFrameNotForShepherd:    c.recordFrameNotForShepherd,
		OnFrameForShepherdItself: c.recordFrameForShepherdItself,
		Now:                      c.cfg.Clock.Now,
	}
}

func (c *Controller) lookupSteered(mac arp.MAC) (netip.Addr, Family, bool) {
	m := c.steered.Load()
	if m == nil {
		return netip.Addr{}, 0, false
	}
	ds, ok := (*m)[mac]
	if !ok {
		return netip.Addr{}, 0, false
	}
	return ds.ip, ds.family(), true
}

// steeredSetObserver mirrors the Controller's steered set somewhere else
// (the XDP program's map). steeredSetChanged is called outside mu after
// every Steer, Unsteer, trial expiry, health unsteer, PanicStop and Close,
// with the complete current set; it must be quick and must not call back
// into the Controller.
type steeredSetObserver interface {
	steeredSetChanged(entries []steeredEntry)
}

// steeredEntry is one steered device and the families it is steered for,
// as published to an observer (the XDP data plane).
type steeredEntry struct {
	MAC arp.MAC
	Fam Family
}

// setObserver installs (or, with nil, removes) the steered-set observer
// and immediately tells a new one the current set.
func (c *Controller) setObserver(o steeredSetObserver) {
	if o == nil {
		c.observer.Store(nil)
		return
	}
	c.observer.Store(&o)
	c.notifySteeredChanged()
}

// steeredEntries returns the currently steered devices and their families
// from the lock-free snapshot, in no particular order.
func (c *Controller) steeredEntries() []steeredEntry {
	m := c.steered.Load()
	if m == nil {
		return nil
	}
	out := make([]steeredEntry, 0, len(*m))
	for mac, ds := range *m {
		out = append(out, steeredEntry{MAC: mac, Fam: ds.family()})
	}
	return out
}

func (c *Controller) notifySteeredChanged() {
	if o := c.observer.Load(); o != nil {
		(*o).steeredSetChanged(c.steeredEntries())
	}
}

// recordRelayedBatch is recordRelayed for a data plane that counts in bulk
// (AttachXDP reads the kernel's per-device counters once a second): it
// credits packets and bytes to mac and marks it verified as of now, which
// is what the health loop needs. A zero packets is a no-op.
func (c *Controller) recordRelayedBatch(mac arp.MAC, fam Family, packets, bytes uint64, now time.Time) {
	if packets == 0 {
		return
	}
	c.framesRelayed.Add(packets)
	c.bytesRelayedTotal.Add(bytes)
	m := c.steered.Load()
	if m == nil {
		return
	}
	if ds, ok := (*m)[mac]; ok {
		fs := ds.fs(fam)
		fs.bytesRelayed.Add(bytes)
		fs.packetsRelayed.Add(packets)
		fs.lastVerifiedNanos.Store(now.UnixNano())
		fs.everVerified.Store(true)
		fs.healthy.Store(true)
	}
}

// recordExaminedBatch adds to the examined-frame counters in bulk, for a
// data plane that counts in the kernel. bytes may be zero when the data
// plane does not track it; forShepherdItself is how many of the examined
// frames were a steered device's traffic for Shepherd's own IP.
func (c *Controller) recordExaminedBatch(frames, bytes, forShepherdItself uint64) {
	c.framesExamined.Add(frames)
	c.bytesExamined.Add(bytes)
	c.framesForShepherdItself.Add(forShepherdItself)
}

// recordRelayed is the Relay's per-frame hook, and with lookupSteered the
// whole of what the hot path does on the Controller. Neither takes mu:
// the global counters are atomics, and the device's own counters live in
// the deviceState reached through the lock-free snapshot. See deviceState.
func (c *Controller) recordRelayed(mac arp.MAC, fam Family, n int, now time.Time) {
	c.framesRelayed.Add(1)
	c.bytesRelayedTotal.Add(uint64(n))

	m := c.steered.Load()
	if m == nil {
		return
	}
	if ds, ok := (*m)[mac]; ok {
		ds.fs(fam).record(n, now)
	}
}

// recordFrameExamined and recordFrameNotForShepherd are Relay's
// OnFrameExamined/OnFrameNotForShepherd hooks: diagnostics only, so they
// run lock-free and never touch c.devices. See ControllerStats.
func (c *Controller) recordFrameExamined(n int) {
	c.framesExamined.Add(1)
	c.bytesExamined.Add(uint64(n))
}

func (c *Controller) recordFrameNotForShepherd(int) {
	c.framesNotForShepherd.Add(1)
}

func (c *Controller) recordFrameForShepherdItself(int) {
	c.framesForShepherdItself.Add(1)
}

// recordRelayError is the Relay's error hook: a send failure while
// relaying is an immediate fail-open signal, so that family of the device
// is unsteered right away rather than waiting for the next health-check
// tick to notice. Only the failing family is reverted — a broken IPv6
// send never disturbs a healthy IPv4 steer, and vice versa. It runs
// synchronously (bounded by SendTimeout), so a Sender that keeps failing
// cannot be retried against the same device forever.
func (c *Controller) recordRelayError(mac arp.MAC, fam Family, err error) {
	c.unsteerFamilies(mac, fam, fmt.Sprintf("%s relay send failed: %v", famName(fam), err))
}

// famName is a short human label for a family, for history/log messages.
func famName(f Family) string {
	switch {
	case f == SteerV4:
		return "IPv4"
	case f == SteerV6:
		return "IPv6"
	case f.Has(SteerV4) && f.Has(SteerV6):
		return "IPv4+IPv6"
	}
	return "none"
}

// publishSnapshotLocked rebuilds the lock-free snapshot the Relay's hot
// path reads. Callers must hold c.mu.
func (c *Controller) publishSnapshotLocked() {
	m := make(map[arp.MAC]*deviceState, len(c.devices))
	for mac, ds := range c.devices {
		m[mac] = ds
	}
	c.steered.Store(&m)
}

// Steer begins one-sided ARP steering of dev. See docs/INTERCEPT.md for
// exactly what this does and does not see, and for the health and
// trial-mode safety behaviour.
func (c *Controller) Steer(dev DeviceRef, opts SteerOptions) error {
	ip := dev.IP.Unmap()
	fam := opts.Family
	if fam == 0 {
		fam = SteerV4 // the zero value steers IPv4, so existing callers are unchanged
	}
	if dev.MAC.IsZero() || dev.MAC.IsMulticast() {
		return ErrInvalidDevice
	}
	if fam.Has(SteerV4) && !usableDeviceIP(ip) {
		return ErrInvalidDevice
	}
	if opts.Trial && opts.Duration <= 0 {
		return ErrTrialDuration
	}
	// IPv6 prerequisites, all independent of the lock (cfg is immutable
	// after NewController). The master switch comes first: while it is
	// off, nothing else about an IPv6 steer even gets considered.
	var ip6 netip.Addr
	if fam.Has(SteerV6) {
		if !c.cfg.IPv6SteeringEnabled {
			return ErrIPv6Disabled
		}
		if !usableGatewayV6(c.cfg.GatewayLinkLocal) {
			return ErrNoGatewayLinkLocal
		}
		ip6 = dev.IP6
		if !usableDeviceV6(ip6) {
			return ErrInvalidV6Device
		}
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	if c.panicked {
		c.mu.Unlock()
		return ErrPanicked
	}
	if dev.MAC == c.cfg.GatewayMAC || dev.MAC == c.cfg.ShepherdMAC {
		c.mu.Unlock()
		return ErrGatewayExcluded
	}
	if fam.Has(SteerV4) && ip == c.cfg.GatewayIP {
		c.mu.Unlock()
		return ErrGatewayExcluded
	}
	if fam.Has(SteerV6) && ip6 == c.cfg.GatewayLinkLocal {
		c.mu.Unlock()
		return ErrGatewayExcluded
	}
	for _, m := range c.cfg.ExcludedMACs {
		if m == dev.MAC {
			c.mu.Unlock()
			return ErrExcluded
		}
	}
	if c.cfg.Excluder != nil && c.cfg.Excluder.Excluded(dev.MAC) {
		c.mu.Unlock()
		return ErrExcluded
	}
	// The stricter IPv6 exclusion: smart-home / Thread / Matter / router
	// devices must never be IPv6-steered (docs/IPV6.md, docs/IPV6-WATCH.md
	// §3), enforced at the call, not just documented.
	if fam.Has(SteerV6) && c.cfg.V6Excluder != nil && c.cfg.V6Excluder.Excluded(dev.MAC) {
		c.mu.Unlock()
		return ErrExcluded
	}
	if _, ok := c.devices[dev.MAC]; ok {
		c.mu.Unlock()
		return ErrAlreadySteered
	}

	now := c.cfg.Clock.Now()
	// Armed synchronously, in the caller's own goroutine, before Steer
	// returns: by the time the caller observes Steer's return, this timer
	// already exists, so advancing a FakeClock by exactly Duration can
	// never race the goroutine that is about to watch it.
	var trialTimer <-chan time.Time
	if opts.Trial {
		trialTimer = c.cfg.Clock.After(opts.Duration)
	}

	// A device-level context, parent of each family's own. Cancelling it
	// stops every family at once (full unsteer, PanicStop, Close);
	// cancelling one family's child context stops only that family.
	devCtx, devCancel := context.WithCancel(c.ctx)
	ds := &deviceState{ip: ip, ip6: ip6, since: now, cancel: devCancel}
	ds.fam.Store(uint32(fam))

	type launch struct {
		fam Family
		ctx context.Context
	}
	var launches []launch
	for _, f := range []Family{SteerV4, SteerV6} {
		if !fam.Has(f) {
			continue
		}
		fctx, fcancel := context.WithCancel(devCtx)
		fs := ds.fs(f)
		fs.cancel = fcancel
		fs.done = make(chan struct{})
		launches = append(launches, launch{f, fctx})
	}

	c.devices[dev.MAC] = ds
	c.publishSnapshotLocked()
	c.mu.Unlock()
	c.notifySteeredChanged()

	for _, l := range launches {
		c.runSpoofer(ds, dev, l.fam, l.ctx)
	}

	if opts.Trial {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer func() { recover() }()
			select {
			case <-devCtx.Done():
				// Unsteered some other way first; nothing to do.
			case <-trialTimer:
				// devCtx can be cancelled (by a manual Unsteer, PanicStop,
				// or Close) at essentially the same moment trialTimer also
				// becomes ready -- e.g. a test's FakeClock.Advance landing
				// right after Unsteer. Go's select does not prefer one ready
				// case over another when more than one is ready at once, so
				// this branch can still be chosen even though cancellation
				// "won" in real time. Re-check explicitly, with a
				// non-blocking select, before acting: if dev.MAC was
				// re-Steer'd in the meantime (same MAC, a new deviceState),
				// c.unsteer's own presence check can't tell that apart from
				// the original device and would wrongly unsteer it.
				select {
				case <-devCtx.Done():
					return
				default:
				}
				c.unsteer(dev.MAC, "trial duration elapsed")
			}
		}()
	}
	return nil
}

// runSpoofer launches dev's spoofer for one family on its own goroutine,
// using the family's own context (fctx) so it can be stopped
// independently. The family's done channel (set in Steer under mu) is
// closed when the spoofer's Run returns, which is after its corrective
// revert has been attempted.
func (c *Controller) runSpoofer(ds *deviceState, dev DeviceRef, fam Family, fctx context.Context) {
	done := ds.fs(fam).done
	var run func(context.Context)
	switch fam {
	case SteerV6:
		sp := newNDPSpoofer(ndpSpooferConfig{
			Sender:           c.cfg.Sender,
			Clock:            c.cfg.Clock,
			Interval:         c.cfg.SpoofInterval,
			SendTimeout:      c.cfg.SendTimeout,
			ShepherdMAC:      c.cfg.ShepherdMAC,
			GatewayMAC:       c.cfg.GatewayMAC,
			GatewayLinkLocal: c.cfg.GatewayLinkLocal,
			DeviceMAC:        dev.MAC,
			DeviceIP6:        ds.ip6,
		})
		run = sp.Run
	default:
		sp := NewSpoofer(SpooferConfig{
			Sender:      c.cfg.Sender,
			Clock:       c.cfg.Clock,
			Interval:    c.cfg.SpoofInterval,
			SendTimeout: c.cfg.SendTimeout,
			ShepherdMAC: c.cfg.ShepherdMAC,
			GatewayIP:   c.cfg.GatewayIP,
			GatewayMAC:  c.cfg.GatewayMAC,
			TargetMAC:   dev.MAC,
			TargetIP:    ds.ip,
		})
		run = sp.Run
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer close(done)
		defer func() { recover() }()
		run(fctx)
	}()
}

// unsteer stops every family of mac. See unsteerFamilies.
func (c *Controller) unsteer(mac arp.MAC, reason string) bool {
	return c.unsteerFamilies(mac, SteerV4|SteerV6, reason)
}

// unsteerFamilies stops the given families of mac (intersected with the
// families actually active), cancelling each one's spoofer to trigger its
// corrective revert, waiting a bounded time for that revert to be
// attempted, and recording why. If no family remains active the device is
// removed from the steered set entirely. It is a safe no-op when mac is
// not steered for any of fams, so a late-firing trial timer or an
// overlapping caller never races into an error.
func (c *Controller) unsteerFamilies(mac arp.MAC, fams Family, reason string) bool {
	c.mu.Lock()
	ds, ok := c.devices[mac]
	if !ok {
		c.mu.Unlock()
		return false
	}
	stop := ds.family() & fams
	if stop == 0 {
		c.mu.Unlock()
		return false
	}
	remaining := ds.family() &^ stop
	ds.fam.Store(uint32(remaining))
	removed := remaining == 0
	if removed {
		delete(c.devices, mac)
	}
	c.publishSnapshotLocked()
	now := c.cfg.Clock.Now()
	c.recordHistoryLocked(UnsteerRecord{MAC: mac, Reason: reason, Time: now})
	c.mu.Unlock()
	c.notifySteeredChanged()

	for _, f := range []Family{SteerV4, SteerV6} {
		if !stop.Has(f) {
			continue
		}
		fs := ds.fs(f)
		if fs.cancel != nil {
			fs.cancel()
		}
		if fs.done != nil {
			select {
			case <-fs.done:
			case <-time.After(c.cfg.SendTimeout + time.Second):
				// Belt and suspenders: the spoofer's own bounded send should
				// have finished well within this, but unsteer must never
				// block forever even if that guarantee is somehow broken.
			}
		}
	}
	if removed && ds.cancel != nil {
		ds.cancel() // release the device-level context once nothing uses it
	}

	if c.cfg.OnUnsteer != nil {
		c.cfg.OnUnsteer(UnsteerRecord{MAC: mac, Reason: reason, Time: now})
	}
	return true
}

// recordHistoryLocked appends to the bounded unsteer history. Callers
// must hold c.mu.
func (c *Controller) recordHistoryLocked(r UnsteerRecord) {
	c.history = append(c.history, r)
	if len(c.history) > 256 {
		c.history = c.history[len(c.history)-256:]
	}
}

// Unsteer stops steering mac immediately: a corrective ARP reply is sent
// (best effort) and the device's outbound traffic goes straight back to
// the real gateway.
func (c *Controller) Unsteer(mac arp.MAC) error {
	if !c.unsteer(mac, "unsteered by caller") {
		return ErrNotSteered
	}
	return nil
}

type famTask struct {
	mac    arp.MAC
	fam    Family
	reason string
}

// checkHealth is the periodic health-verification step, run per family.
//
// IPv4 (the original rule): healthy only while real relayed traffic has
// been observed recently (IdleGrace), or, before it has ever relayed,
// within StartupGrace of being added. Anything else is fail-open.
//
// IPv6 is deliberately more lenient (docs/IPV6-WATCH.md §5): legitimate
// IPv6 idle is normal, and on a ULA-only LAN there is nothing off-link to
// relay at all, so idle silence must NOT flap a working IPv6 steer. The
// only IPv6 health check is the startup one — did the neighbor-cache flip
// take? If no IPv6 frame has ever been relayed within StartupGrace, the
// steer did not take and that family is reverted; once it has relayed even
// once, idle silence never fails it again (a stuck send fails it through
// recordRelayError instead). Either way only the unhealthy family is
// reverted, never the whole device.
func (c *Controller) checkHealth(now time.Time) {
	c.mu.Lock()
	var tasks []famTask
	for mac, ds := range c.devices {
		fam := ds.family()
		if fam.Has(SteerV4) {
			fs := &ds.v4
			baseline, grace := fs.lastVerified(), c.cfg.IdleGrace
			if baseline.IsZero() {
				baseline, grace = ds.since, c.cfg.StartupGrace
			}
			age := now.Sub(baseline)
			healthy := age < grace
			fs.healthy.Store(healthy)
			if !healthy {
				tasks = append(tasks, famTask{mac, SteerV4,
					fmt.Sprintf("IPv4: no relayed traffic observed for %s (grace %s)", age, grace)})
			}
		}
		if fam.Has(SteerV6) {
			fs := &ds.v6
			if fs.lastVerified().IsZero() {
				age := now.Sub(ds.since)
				healthy := age < c.cfg.StartupGrace
				fs.healthy.Store(healthy)
				if !healthy {
					tasks = append(tasks, famTask{mac, SteerV6,
						fmt.Sprintf("IPv6: no relayed traffic since steering began %s ago (startup grace %s); neighbor-cache flip did not take", age, c.cfg.StartupGrace)})
				}
			} else {
				// Relayed at least once; idle silence is not a failure.
				fs.healthy.Store(true)
			}
		}
	}
	c.mu.Unlock()

	for _, t := range tasks {
		c.unsteerFamilies(t.mac, t.fam, t.reason)
	}
}

func (c *Controller) healthLoop(ctx context.Context, first <-chan time.Time) {
	defer c.wg.Done()
	defer func() { recover() }()
	tick := first
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick:
			c.checkHealth(now)
			tick = c.cfg.Clock.After(c.cfg.HealthInterval)
			if c.afterHealthCheck != nil {
				c.afterHealthCheck(now)
			}
		}
	}
}

// PanicStop immediately un-steers every device and refuses new Steer
// calls until Rearm is called. It never waits on a Sender: PanicStop
// itself returns at once even if the Sender is completely wedged.
// Corrective reverts are still attempted by each device's own spoofer in
// the background, best effort, exactly as on any other Unsteer — PanicStop
// just does not wait around for them.
func (c *Controller) PanicStop() {
	c.mu.Lock()
	c.panicked = true
	now := c.cfg.Clock.Now()
	devs := c.devices
	c.devices = map[arp.MAC]*deviceState{}
	c.publishSnapshotLocked()
	for mac := range devs {
		c.recordHistoryLocked(UnsteerRecord{MAC: mac, Reason: "panic stop", Time: now})
	}
	c.mu.Unlock()
	// Before anything else, PanicStop included: an in-kernel data plane
	// must stop relaying the moment the steered set is emptied, not on its
	// next poll.
	c.notifySteeredChanged()

	for mac, ds := range devs {
		ds.cancel()
		if c.cfg.OnUnsteer != nil {
			c.cfg.OnUnsteer(UnsteerRecord{MAC: mac, Reason: "panic stop", Time: now})
		}
	}
}

// Rearm re-enables Steer after PanicStop.
func (c *Controller) Rearm() {
	c.mu.Lock()
	c.panicked = false
	c.mu.Unlock()
}

// Status returns a snapshot of every currently steered device, sorted by
// MAC for a stable order.
func (c *Controller) Status() []SteeredDevice {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SteeredDevice, 0, len(c.devices))
	for mac, ds := range c.devices {
		fam := ds.family()
		var bytes, packets uint64
		var last time.Time
		healthy := true
		for _, f := range []Family{SteerV4, SteerV6} {
			if !fam.Has(f) {
				continue
			}
			fs := ds.fs(f)
			bytes += fs.bytesRelayed.Load()
			packets += fs.packetsRelayed.Load()
			if lv := fs.lastVerified(); lv.After(last) {
				last = lv
			}
			if !fs.healthy.Load() {
				healthy = false
			}
		}
		out = append(out, SteeredDevice{
			MAC: mac, IP: ds.ip, Family: fam, Since: ds.since, Healthy: healthy,
			BytesRelayed: bytes, PacketsRelayed: packets, LastVerified: last,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC.String() < out[j].MAC.String() })
	return out
}

// Stats returns a snapshot of this Controller's cumulative packet-rate
// counters. See ControllerStats.
func (c *Controller) Stats() ControllerStats {
	return ControllerStats{
		FramesExamined:          c.framesExamined.Load(),
		BytesExamined:           c.bytesExamined.Load(),
		FramesNotForShepherd:    c.framesNotForShepherd.Load(),
		FramesForShepherdItself: c.framesForShepherdItself.Load(),
		FramesRelayed:           c.framesRelayed.Load(),
		BytesRelayed:            c.bytesRelayedTotal.Load(),
	}
}

// History returns a snapshot of the most recent unsteer events (bounded
// to the last 256), oldest first.
func (c *Controller) History() []UnsteerRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]UnsteerRecord(nil), c.history...)
}

// Close stops the health loop and un-steers every device (each with its
// own best-effort corrective revert), then waits for every background
// goroutine to exit. Safe to call more than once.
func (c *Controller) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	macs := make([]arp.MAC, 0, len(c.devices))
	for mac := range c.devices {
		macs = append(macs, mac)
	}
	c.mu.Unlock()

	for _, mac := range macs {
		c.unsteer(mac, "controller closed")
	}
	c.cancel()
	c.wg.Wait()
	return nil
}
