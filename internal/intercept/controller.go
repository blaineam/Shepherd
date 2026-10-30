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
)

// Excluder reports whether a device must never be steered. The caller
// wires this to the device registry's Excluded flag (or anything else)
// so Steer cannot be made to steer a device the operator opted out of,
// no matter what is asked of it.
type Excluder interface {
	Excluded(mac arp.MAC) bool
}

// DeviceRef identifies a device to steer.
type DeviceRef struct {
	MAC arp.MAC
	IP  netip.Addr
}

// SteerOptions configures one Steer call.
type SteerOptions struct {
	// Trial, when true, auto-unsteers the device after Duration even if
	// nothing else calls Unsteer first. Duration must be positive.
	Trial    bool
	Duration time.Duration
}

// SteeredDevice is a snapshot of one currently steered device.
type SteeredDevice struct {
	MAC            arp.MAC
	IP             netip.Addr
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
	FramesRelayed        uint64 // subset actually relayed
	BytesRelayed         uint64 // their total wire length
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

	// Excluder is consulted on every Steer call. Optional.
	Excluder Excluder
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

// deviceState is one steered device's bookkeeping. The fields the
// Relay's hot path writes (bytes, packets, last-verified, healthy) are
// atomics, updated by every ParallelRelay worker on every relayed frame
// without taking Controller.mu: at a real transfer's packet rate (tens to
// hundreds of thousands of frames per second, split across workers) a
// shared mutex on that path is contention the relay cannot afford, and
// the health loop and Status read these fields only occasionally. The
// rest (ip, since, cancel, done) is written once, under mu, in Steer.
type deviceState struct {
	ip    netip.Addr
	since time.Time

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

func (ds *deviceState) lastVerified() time.Time {
	if !ds.everVerified.Load() {
		return time.Time{}
	}
	return time.Unix(0, ds.lastVerifiedNanos.Load())
}

func (ds *deviceState) recordRelayed(n int, now time.Time) {
	ds.bytesRelayed.Add(uint64(n))
	ds.packetsRelayed.Add(1)
	ds.lastVerifiedNanos.Store(now.UnixNano())
	ds.everVerified.Store(true)
	ds.healthy.Store(true)
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
	framesExamined       atomic.Uint64
	bytesExamined        atomic.Uint64
	framesNotForShepherd atomic.Uint64
	framesRelayed        atomic.Uint64
	bytesRelayedTotal    atomic.Uint64

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
		Sender:                cfg.Sender,
		ShepherdMAC:           cfg.ShepherdMAC,
		GatewayMAC:            cfg.GatewayMAC,
		SendTimeout:           cfg.SendTimeout,
		Lookup:                c.lookupSteered,
		OnRelayed:             c.recordRelayed,
		OnRelayError:          c.recordRelayError,
		OnFrameExamined:       c.recordFrameExamined,
		OnFrameNotForShepherd: c.recordFrameNotForShepherd,
		Now:                   cfg.Clock.Now,
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
		Sender:                sender,
		ShepherdMAC:           c.cfg.ShepherdMAC,
		GatewayMAC:            c.cfg.GatewayMAC,
		SendTimeout:           c.cfg.SendTimeout,
		Lookup:                c.lookupSteered,
		OnRelayed:             c.recordRelayed,
		OnRelayError:          c.recordRelayError,
		OnFrameExamined:       c.recordFrameExamined,
		OnFrameNotForShepherd: c.recordFrameNotForShepherd,
		Now:                   c.cfg.Clock.Now,
	}
}

func (c *Controller) lookupSteered(mac arp.MAC) (netip.Addr, bool) {
	m := c.steered.Load()
	if m == nil {
		return netip.Addr{}, false
	}
	ds, ok := (*m)[mac]
	if !ok {
		return netip.Addr{}, false
	}
	return ds.ip, true
}

// steeredSetObserver mirrors the Controller's steered set somewhere else
// (the XDP program's map). steeredSetChanged is called outside mu after
// every Steer, Unsteer, trial expiry, health unsteer, PanicStop and Close,
// with the complete current set; it must be quick and must not call back
// into the Controller.
type steeredSetObserver interface {
	steeredSetChanged(macs []arp.MAC)
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

// steeredMACs returns the currently steered MACs from the lock-free
// snapshot, in no particular order.
func (c *Controller) steeredMACs() []arp.MAC {
	m := c.steered.Load()
	if m == nil {
		return nil
	}
	out := make([]arp.MAC, 0, len(*m))
	for mac := range *m {
		out = append(out, mac)
	}
	return out
}

func (c *Controller) notifySteeredChanged() {
	if o := c.observer.Load(); o != nil {
		(*o).steeredSetChanged(c.steeredMACs())
	}
}

// recordRelayedBatch is recordRelayed for a data plane that counts in bulk
// (AttachXDP reads the kernel's per-device counters once a second): it
// credits packets and bytes to mac and marks it verified as of now, which
// is what the health loop needs. A zero packets is a no-op.
func (c *Controller) recordRelayedBatch(mac arp.MAC, packets, bytes uint64, now time.Time) {
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
		ds.bytesRelayed.Add(bytes)
		ds.packetsRelayed.Add(packets)
		ds.lastVerifiedNanos.Store(now.UnixNano())
		ds.everVerified.Store(true)
		ds.healthy.Store(true)
	}
}

// recordExaminedBatch adds to the examined-frame counters in bulk, for a
// data plane that counts in the kernel. bytes may be zero when the data
// plane does not track it.
func (c *Controller) recordExaminedBatch(frames, bytes uint64) {
	c.framesExamined.Add(frames)
	c.bytesExamined.Add(bytes)
}

// recordRelayed is the Relay's per-frame hook, and with lookupSteered the
// whole of what the hot path does on the Controller. Neither takes mu:
// the global counters are atomics, and the device's own counters live in
// the deviceState reached through the lock-free snapshot. See deviceState.
func (c *Controller) recordRelayed(mac arp.MAC, n int, now time.Time) {
	c.framesRelayed.Add(1)
	c.bytesRelayedTotal.Add(uint64(n))

	m := c.steered.Load()
	if m == nil {
		return
	}
	if ds, ok := (*m)[mac]; ok {
		ds.recordRelayed(n, now)
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

// recordRelayError is the Relay's error hook: a send failure while
// relaying is an immediate fail-open signal, so the device is unsteered
// right away rather than waiting for the next health-check tick to
// notice. It runs synchronously (bounded by SendTimeout), so a Sender
// that keeps failing cannot be retried against the same device forever.
func (c *Controller) recordRelayError(mac arp.MAC, err error) {
	c.unsteer(mac, fmt.Sprintf("relay send failed: %v", err))
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
	if dev.MAC.IsZero() || dev.MAC.IsMulticast() || !usableDeviceIP(ip) {
		return ErrInvalidDevice
	}
	if opts.Trial && opts.Duration <= 0 {
		return ErrTrialDuration
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
	if dev.MAC == c.cfg.GatewayMAC || ip == c.cfg.GatewayIP || dev.MAC == c.cfg.ShepherdMAC {
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

	spoofCtx, cancel := context.WithCancel(c.ctx)
	ds := &deviceState{ip: ip, since: now, cancel: cancel, done: make(chan struct{})}
	c.devices[dev.MAC] = ds
	c.publishSnapshotLocked()
	c.mu.Unlock()
	c.notifySteeredChanged()

	sp := NewSpoofer(SpooferConfig{
		Sender:      c.cfg.Sender,
		Clock:       c.cfg.Clock,
		Interval:    c.cfg.SpoofInterval,
		SendTimeout: c.cfg.SendTimeout,
		ShepherdMAC: c.cfg.ShepherdMAC,
		GatewayIP:   c.cfg.GatewayIP,
		GatewayMAC:  c.cfg.GatewayMAC,
		TargetMAC:   dev.MAC,
		TargetIP:    ip,
	})

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer close(ds.done)
		defer func() { recover() }()
		sp.Run(spoofCtx)
	}()

	if opts.Trial {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer func() { recover() }()
			select {
			case <-spoofCtx.Done():
				// Unsteered some other way first; nothing to do.
			case <-trialTimer:
				// spoofCtx can be cancelled (by a manual Unsteer, PanicStop,
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
				case <-spoofCtx.Done():
					return
				default:
				}
				c.unsteer(dev.MAC, "trial duration elapsed")
			}
		}()
	}
	return nil
}

type unsteerTask struct {
	mac    arp.MAC
	reason string
}

// unsteer removes mac from the steered set, if present, cancels its
// spoofer (triggering the corrective revert), waits a bounded time for
// that revert to be attempted, and records why. It is a safe no-op when
// mac is not steered, so a late-firing trial timer or an overlapping
// caller never races into an error.
func (c *Controller) unsteer(mac arp.MAC, reason string) bool {
	c.mu.Lock()
	ds, ok := c.devices[mac]
	if !ok {
		c.mu.Unlock()
		return false
	}
	delete(c.devices, mac)
	c.publishSnapshotLocked()
	now := c.cfg.Clock.Now()
	c.recordHistoryLocked(UnsteerRecord{MAC: mac, Reason: reason, Time: now})
	c.mu.Unlock()
	c.notifySteeredChanged()

	ds.cancel()
	select {
	case <-ds.done:
	case <-time.After(c.cfg.SendTimeout + time.Second):
		// Belt and suspenders: Spoofer.Run's own bounded send should have
		// already finished well within this, but Unsteer must still never
		// block forever even if that guarantee is somehow broken.
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

// checkHealth is the periodic health-verification step: a steered device
// is healthy only while real relayed traffic has been observed recently
// (IdleGrace) or, for a device that has never once relayed, since it was
// added (StartupGrace). Anything else is fail-open — unsteered at once,
// never left in a stuck, half-steered state.
func (c *Controller) checkHealth(now time.Time) {
	c.mu.Lock()
	var tasks []unsteerTask
	for mac, ds := range c.devices {
		baseline, grace := ds.lastVerified(), c.cfg.IdleGrace
		if baseline.IsZero() {
			baseline, grace = ds.since, c.cfg.StartupGrace
		}
		age := now.Sub(baseline)
		healthy := age < grace
		ds.healthy.Store(healthy)
		if !healthy {
			tasks = append(tasks, unsteerTask{mac, fmt.Sprintf("no relayed traffic observed for %s (grace %s)", age, grace)})
		}
	}
	c.mu.Unlock()

	for _, t := range tasks {
		c.unsteer(t.mac, t.reason)
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
		out = append(out, SteeredDevice{
			MAC: mac, IP: ds.ip, Since: ds.since, Healthy: ds.healthy.Load(),
			BytesRelayed: ds.bytesRelayed.Load(), PacketsRelayed: ds.packetsRelayed.Load(),
			LastVerified: ds.lastVerified(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC.String() < out[j].MAC.String() })
	return out
}

// Stats returns a snapshot of this Controller's cumulative packet-rate
// counters. See ControllerStats.
func (c *Controller) Stats() ControllerStats {
	return ControllerStats{
		FramesExamined:       c.framesExamined.Load(),
		BytesExamined:        c.bytesExamined.Load(),
		FramesNotForShepherd: c.framesNotForShepherd.Load(),
		FramesRelayed:        c.framesRelayed.Load(),
		BytesRelayed:         c.bytesRelayedTotal.Load(),
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
