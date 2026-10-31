// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/devices"
	"shepherd/internal/intercept"
)

// Mode is the relay the configuration asks for.
type Mode int

// Relay modes. docs/WATCH.md explains the choice.
const (
	// ModeAuto tries XDP in the NIC driver, then XDP in the kernel's
	// generic path, then the userspace ParallelRelay.
	ModeAuto Mode = iota
	// ModeXDP uses XDP only and reports Watch mode unavailable when the
	// program cannot load or attach.
	ModeXDP
	// ModeUserspace never tries XDP.
	ModeUserspace
	// ModeOff disables the engine, like Config.Enabled = false.
	ModeOff
)

// ParseMode reads "auto", "xdp", "userspace" or "off".
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return ModeAuto, nil
	case "xdp":
		return ModeXDP, nil
	case "userspace":
		return ModeUserspace, nil
	case "off":
		return ModeOff, nil
	}
	return 0, fmt.Errorf("watch: unknown mode %q (want auto, xdp, userspace or off)", s)
}

func (m Mode) String() string {
	switch m {
	case ModeAuto:
		return "auto"
	case ModeXDP:
		return "xdp"
	case ModeUserspace:
		return "userspace"
	case ModeOff:
		return "off"
	}
	return fmt.Sprintf("Mode(%d)", int(m))
}

// Relay names, as reported in Snapshot.Relay.
const (
	RelayXDPNative  = "xdp-native"
	RelayXDPGeneric = "xdp-generic"
	RelayUserspace  = "userspace"
)

// Engine phases, as reported in Snapshot.Phase.
const (
	PhaseDisabled    = "disabled"    // enabled = false or mode = off
	PhaseStarting    = "starting"    // discovering addresses, attaching the relay
	PhaseRunning     = "running"     // relay attached; the steered set tracks the policy
	PhaseUnavailable = "unavailable" // could not start; Reason says why; retried on a backoff
)

// Config configures an Engine. Registry is required; everything else has a
// default.
type Config struct {
	Enabled bool
	// Interface to steer on; empty means the default route's interface.
	Interface string
	Mode      Mode
	// Workers for the userspace relay; 0 means intercept.DefaultParallelism.
	Workers int
	// IPv6 additionally steers each eligible device's IPv6 traffic, by
	// unicast Neighbor Advertisements (docs/IPV6-WATCH.md). Off by
	// default, and even when on it engages only where the network has a
	// global IPv6 route to steer anything to and the gateway's link-local
	// address can be found; infrastructure and smart-home devices are
	// never IPv6-steered whatever their own switch says (DecideV6).
	IPv6   bool
	Policy PolicyConfig
	// Health knobs passed to intercept.ControllerConfig; zero keeps that
	// package's defaults.
	HealthInterval, IdleGrace, StartupGrace time.Duration

	// Registry is the device registry the policy reads and the steered set
	// follows. Required.
	Registry *devices.Registry
	// StatePath persists the kill switch (0600). Empty keeps it in memory.
	StatePath string

	Platform Platform        // default RealPlatform{}
	Clock    intercept.Clock // default the wall clock
	// Logf receives the engine's log lines; default log.Printf.
	Logf func(format string, args ...any)
}

// Sentinel errors.
var (
	ErrNoRegistry     = errors.New("watch: Registry is required")
	errGatewayChanged = errors.New("watch: the gateway's MAC address changed")
	errRelayStopped   = errors.New("watch: the relay stopped")
)

// Retry backoff for a device the health loop keeps failing open: first
// retry after retryBase, doubling per consecutive failure up to retryMax.
// A device that then relays healthily for retryReset has its count
// forgiven.
const (
	retryBase  = 30 * time.Second
	retryMax   = 10 * time.Minute
	retryReset = 2 * time.Minute
	// observeEvery bounds how often a steered device's relayed traffic is
	// reported to the registry as a sighting.
	observeEvery = time.Minute
	// gatewayRecheck is how often the gateway's MAC is re-read from the
	// neighbour table while running, besides on an ARP monitor prompt.
	gatewayRecheck = time.Minute
	// restartBackoffMin/Max bound how long the engine waits before trying to
	// start again after it could not.
	restartBackoffMin = 15 * time.Second
	restartBackoffMax = 5 * time.Minute
	historyCap        = 256
)

// HistoryRecord is one unsteer, with the device's registry identity
// attached to the Controller's own record.
type HistoryRecord struct {
	Time     time.Time `json:"time"`
	MAC      string    `json:"mac"`
	DeviceID string    `json:"device_id,omitempty"`
	Name     string    `json:"name,omitempty"`
	Reason   string    `json:"reason"`
}

// DeviceStatus is one registry device's Watch state.
type DeviceStatus struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	// State is one of the State* constants; Reason explains a state other
	// than steered.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Steered lists the (MAC, IP) pairs currently steered for this device
	// (a device the registry merged from several MACs can have several).
	Steered []SteeredEntry `json:"steered,omitempty"`
	// Families are the address families actually being steered, "ipv4"
	// and/or "ipv6". Empty when nothing is steered.
	Families []string `json:"families,omitempty"`
	// IPv6Reason explains why a device steered for IPv4 is not also
	// steered for IPv6, when IPv6 steering is otherwise in effect.
	IPv6Reason string `json:"ipv6_reason,omitempty"`
	// Healthy is true when every steered entry has relayed within grace.
	Healthy bool `json:"healthy"`
	// Totals across the device's steered entries since they were steered.
	BytesRelayed   uint64 `json:"bytes_relayed"`
	PacketsRelayed uint64 `json:"packets_relayed"`
	// Live rates over the last sampling interval.
	BytesPerSecond   float64 `json:"bytes_per_second"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	// NextRetry is when a device on a health-failure backoff is tried
	// again; zero otherwise.
	NextRetry time.Time `json:"next_retry,omitempty"`
	// Failures is how many times in a row the health loop failed it open.
	Failures int `json:"failures,omitempty"`
}

// SteeredEntry is one steered (MAC, IP) pair.
type SteeredEntry struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
	// Families is which of "ipv4"/"ipv6" this entry is steered for.
	Families     []string  `json:"families"`
	Since        time.Time `json:"since"`
	Healthy      bool      `json:"healthy"`
	LastVerified time.Time `json:"last_verified,omitempty"`
}

// Snapshot is the engine's whole state for the portal and the API.
type Snapshot struct {
	Enabled bool   `json:"enabled"`
	Phase   string `json:"phase"`
	Reason  string `json:"reason,omitempty"`
	// Relay is the relay in effect while running: RelayXDPNative,
	// RelayXDPGeneric or RelayUserspace.
	Relay string `json:"relay,omitempty"`
	// Armed is false after the kill switch, until Rearm.
	Armed     bool   `json:"armed"`
	Interface string `json:"interface,omitempty"`
	// IPv6 is true while IPv6 steering is actually in effect. IPv6Wanted
	// says whether the configuration asked for it, and IPv6Reason says why
	// it is not in effect when it was asked for (no IPv6 router, no global
	// route to steer to, no link-local next hop).
	IPv6             bool            `json:"ipv6"`
	IPv6Wanted       bool            `json:"ipv6_wanted"`
	IPv6Reason       string          `json:"ipv6_reason,omitempty"`
	GatewayLinkLocal string          `json:"gateway_link_local,omitempty"`
	GatewayIP        string          `json:"gateway_ip,omitempty"`
	GatewayMAC       string          `json:"gateway_mac,omitempty"`
	ShepherdMAC      string          `json:"shepherd_mac,omitempty"`
	ShepherdIPs      []string        `json:"shepherd_ips,omitempty"`
	Since            time.Time       `json:"since,omitempty"`
	Stats            RelayStats      `json:"stats"`
	Steered          int             `json:"steered"`
	Devices          []DeviceStatus  `json:"devices"`
	History          []HistoryRecord `json:"history"`
}

// RelayStats is intercept.ControllerStats plus the live rates derived from
// consecutive samples of it.
type RelayStats struct {
	FramesExamined          uint64  `json:"frames_examined"`
	FramesRelayed           uint64  `json:"frames_relayed"`
	BytesRelayed            uint64  `json:"bytes_relayed"`
	FramesForShepherdItself uint64  `json:"frames_for_shepherd_itself"`
	FramesNotForShepherd    uint64  `json:"frames_not_for_shepherd"`
	PacketsPerSecond        float64 `json:"packets_per_second"`
	BytesPerSecond          float64 `json:"bytes_per_second"`
}

type retryState struct {
	failures int
	until    time.Time
	// healthySince is when the device was last seen steered and verified,
	// for forgiving failures after retryReset of good behaviour.
	healthySince time.Time
}

type rateSample struct {
	packets, bytes uint64
	at             time.Time
	pps, bps       float64
}

// Engine runs Watch mode. Build one with New, run it with Run, and read it
// with Snapshot; Kill and Rearm are the kill switch.
type Engine struct {
	cfg   Config
	plat  Platform
	clock intercept.Clock
	logf  func(string, ...any)
	reg   *devices.Registry

	mu sync.Mutex
	// Lifecycle, written by the session.
	phase   string
	reason  string
	relay   string
	link    Link
	gateway netip.Addr
	gwMAC   arp.MAC
	gwLL    netip.Addr // the gateway's link-local address, for IPv6 steering
	// pinnedIface is the interface a session last ran on, kept so a moving
	// default route does not drag a working relay onto another interface.
	pinnedIface string
	v6          bool   // IPv6 steering is in effect this session
	v6Why       string // why it is not, when it was asked for
	since       time.Time
	ctrl        *intercept.Controller
	killed      bool
	// Per-MAC bookkeeping.
	retry       map[arp.MAC]*retryState
	refused     map[arp.MAC]string // last Steer refusal, for the pending state's reason
	v6Refused   map[arp.MAC]string // why a steered device is IPv4-only
	selfUnsteer map[arp.MAC]bool   // Unsteer calls the engine itself made
	// believed is what the engine last asked the Controller to steer. The
	// Controller drops a device from Status() and records its history
	// entry atomically, but calls OnUnsteer a moment later (after the
	// spoofer's corrective reply has been attempted). In that window a
	// reconcile would see "not steered, no backoff armed" and steer the
	// device straight back, which is exactly what the fail-open backoff
	// exists to prevent. A MAC that is believed steered but is not in
	// Status() has an unsteer in flight, so reconcile leaves it alone for
	// that pass and picks it up once onUnsteer has said why.
	believed map[arp.MAC]bool
	rates    map[arp.MAC]*rateSample
	observed map[arp.MAC]time.Time
	global   rateSample
	history  []HistoryRecord
	lastLog  string

	kick    chan struct{} // reconcile now
	gwCheck chan struct{} // re-read the gateway MAC now

	// Test seams: how long to wait for a relay to come up.
	attachTimeout time.Duration
	relayGrace    time.Duration
}

// New builds an Engine. It loads the persisted kill switch but starts
// nothing; call Run.
func New(cfg Config) (*Engine, error) {
	if cfg.Registry == nil {
		return nil, ErrNoRegistry
	}
	if cfg.Platform == nil {
		cfg.Platform = RealPlatform{}
	}
	if cfg.Clock == nil {
		cfg.Clock = wallClock{}
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	st, err := loadState(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg: cfg, plat: cfg.Platform, clock: cfg.Clock, logf: cfg.Logf, reg: cfg.Registry,
		phase:  PhaseDisabled,
		killed: st.Killed,
		retry:  map[arp.MAC]*retryState{}, refused: map[arp.MAC]string{}, v6Refused: map[arp.MAC]string{},
		selfUnsteer: map[arp.MAC]bool{},
		believed:    map[arp.MAC]bool{},
		rates:       map[arp.MAC]*rateSample{}, observed: map[arp.MAC]time.Time{},
		kick: make(chan struct{}, 1), gwCheck: make(chan struct{}, 1),
		attachTimeout: 30 * time.Second, relayGrace: time.Second,
	}
	if cfg.Enabled && cfg.Mode != ModeOff {
		e.phase, e.reason = PhaseStarting, "starting"
	}
	return e, nil
}

type wallClock struct{}

func (wallClock) Now() time.Time                         { return time.Now() }
func (wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func (e *Engine) enabled() bool { return e.cfg.Enabled && e.cfg.Mode != ModeOff }

// Run runs the engine until ctx ends. A disabled engine returns at once.
// Anything that stops a session short of ctx ending (no capability, the
// relay dying, the gateway's MAC changing) is logged, reported in the
// Snapshot and retried on a backoff; Run itself never returns an error
// for it, so Watch mode can never take the rest of Shepherd down.
func (e *Engine) Run(ctx context.Context) error {
	if !e.enabled() {
		e.setPhase(PhaseDisabled, "Watch mode is turned off in the configuration")
		return nil
	}
	backoff := restartBackoffMin
	for {
		err := e.session(ctx)
		if ctx.Err() != nil {
			e.setPhase(PhaseUnavailable, "Shepherd is shutting down")
			return nil
		}
		wait := backoff
		if errors.Is(err, errGatewayChanged) {
			wait = 2 * time.Second // nothing is wrong: start again with the new MAC
		} else {
			backoff = min(backoff*2, restartBackoffMax)
		}
		e.setPhase(PhaseUnavailable, err.Error())
		e.logOnce("watch: not running: %v (retrying in %s)", err, wait)
		select {
		case <-ctx.Done():
			e.setPhase(PhaseUnavailable, "Shepherd is shutting down")
			return nil
		case <-e.clock.After(wait):
		}
	}
}

// logOnce logs a line unless it is the same as the previous one, so an
// install that can never run Watch mode says so once per distinct reason,
// not every retry.
func (e *Engine) logOnce(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	e.mu.Lock()
	same := msg == e.lastLog
	e.lastLog = msg
	e.mu.Unlock()
	if !same {
		e.logf("%s", msg)
	}
}

func (e *Engine) setPhase(phase, reason string) {
	e.mu.Lock()
	e.phase, e.reason = phase, reason
	if phase != PhaseRunning {
		e.relay, e.ctrl, e.since = "", nil, time.Time{}
		e.v6, e.gwLL = false, netip.Addr{}
	}
	e.mu.Unlock()
}

// session is one attempt to run Watch mode: discover, build, attach, then
// track the policy until ctx ends or something forces a restart. It always
// leaves the network as it found it: every steered device gets its
// corrective ARP reply through Controller.Close, the relay detaches and GRO
// is restored.
func (e *Engine) session(ctx context.Context) error {
	e.setPhase(PhaseStarting, "finding the interface and the gateway")
	iface, gw, err := e.plat.DefaultRoute()
	if err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	switch {
	case e.cfg.Interface != "":
		iface = e.cfg.Interface
	default:
		// Stay on the interface an earlier session settled on, even if the
		// default route has since moved. A host with both a wired and a
		// wireless interface on one subnet can briefly publish a default
		// route through the wrong one (a Wi-Fi DHCP renew is enough), and
		// chasing it means tearing down a working relay to re-attach on an
		// interface whose gateway may not even resolve -- which is exactly
		// what happened on the live host, where the engine jumped from eth0
		// to wlan0 for five seconds and refused to steer there at all.
		// Picking once and keeping it is what an operator would do, and
		// watch.interface overrides it outright.
		e.mu.Lock()
		pinned := e.pinnedIface
		e.mu.Unlock()
		if pinned != "" && pinned != iface {
			if _, err := e.plat.Link(pinned); err == nil {
				e.logOnce("watch: the default route moved to %s; staying on %s (set watch.interface to choose)", iface, pinned)
				iface = pinned
			}
		}
	}
	link, err := e.plat.Link(iface)
	if err != nil {
		return err
	}
	gwMAC, err := e.plat.GatewayMAC(ctx, iface, gw)
	if err != nil {
		return fmt.Errorf("gateway %s: %w", gw, err)
	}
	if gwMAC == link.MAC {
		return fmt.Errorf("the gateway %s has %s's own MAC %s; is Shepherd the gateway?", gw, iface, link.MAC)
	}

	// IPv6 steering, when it was asked for. Nothing here can fail the
	// session: a network with no IPv6 router, or a ULA-only one like the
	// maintainer's, simply runs IPv4-only and says so.
	gwLL, v6, v6Why := e.discoverV6(iface, link)

	sender, closeSender, err := e.plat.OpenSender(iface)
	if err != nil {
		return fmt.Errorf("open raw socket on %s: %w", iface, err)
	}
	defer closeSender()

	ctrl, err := intercept.NewController(intercept.ControllerConfig{
		Sender: sender, Clock: e.clock,
		ShepherdMAC: link.MAC, ShepherdIPs: link.IPv4s, ShepherdIPs6: link.IPv6s,
		GatewayIP: gw, GatewayMAC: gwMAC,
		GatewayLinkLocal:    gwLL,
		IPv6SteeringEnabled: v6,
		Excluder:            e,
		// The stricter IPv6 exclusion, enforced at the call: no Steer with
		// SteerV6 can reach a device DecideV6 refuses, whatever asked for
		// it (docs/IPV6-WATCH.md, docs/IPV6.md).
		V6Excluder:     v6Excluder{e},
		HealthInterval: e.cfg.HealthInterval, IdleGrace: e.cfg.IdleGrace, StartupGrace: e.cfg.StartupGrace,
		OnUnsteer: e.onUnsteer,
	})
	if err != nil {
		return err
	}
	defer ctrl.Close()

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.setPhase(PhaseStarting, "attaching the relay to "+iface)
	relay, relayDone, stopRelay, err := e.startRelay(sctx, ctrl, link)
	if err != nil {
		return err
	}
	defer stopRelay()

	now := e.clock.Now()
	e.mu.Lock()
	e.phase, e.reason, e.relay = PhaseRunning, "", relay
	e.link, e.gateway, e.gwMAC, e.ctrl, e.since = link, gw, gwMAC, ctrl, now
	e.pinnedIface = iface
	e.gwLL, e.v6, e.v6Why = gwLL, v6, v6Why
	e.global = rateSample{at: now}
	e.rates = map[arp.MAC]*rateSample{}
	e.believed = map[arp.MAC]bool{}
	killed := e.killed
	e.mu.Unlock()
	if killed {
		ctrl.PanicStop() // the kill switch is still down: refuse Steer until Rearm
	}
	if e.cfg.IPv6 {
		if v6 {
			e.logf("watch: IPv6 steering is on; the gateway's link-local address is %s", gwLL)
		} else {
			e.logf("watch: IPv6 steering was asked for but is not in effect: %s", v6Why)
		}
	}
	e.logf("watch: running on %s (%s %v), gateway %s (%s), relay %s%s", iface, link.MAC, link.IPv4s, gw, gwMAC, relay,
		map[bool]string{true: "; kill switch is down, nothing is steered until it is re-armed", false: ""}[killed])

	unsub := e.reg.Subscribe(func(devices.Event) { e.poke(e.kick) })
	defer unsub()

	e.reconcile(now)
	tick := e.clock.After(time.Second)
	nextGW := now.Add(gatewayRecheck)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-relayDone:
			// A relay that stopped because our own context ended is an
			// ordinary shutdown, not a failure: Close below unsteers every
			// device with its corrective reply and the history says so.
			// Panic-stopping here instead would record every device as
			// "panic stop" on a clean stop, which is not what happened.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			ctrl.PanicStop()
			if err == nil {
				err = errRelayStopped
			}
			return fmt.Errorf("%s relay: %w", relay, err)
		case <-e.kick:
			e.reconcile(e.clock.Now())
		case <-e.gwCheck:
			if changed := e.gatewayChanged(ctx, iface, gw, gwMAC); changed {
				return errGatewayChanged
			}
		case now := <-tick:
			tick = e.clock.After(time.Second)
			e.sample(now)
			e.reconcile(now)
			if !now.Before(nextGW) {
				nextGW = now.Add(gatewayRecheck)
				if e.gatewayChanged(ctx, iface, gw, gwMAC) {
					return errGatewayChanged
				}
			}
		}
	}
}

// gatewayChanged re-reads the gateway's MAC from the neighbour table and
// reports whether it differs from the one this session was built with.
func (e *Engine) gatewayChanged(ctx context.Context, iface string, gw netip.Addr, have arp.MAC) bool {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	mac, err := e.plat.GatewayMAC(cctx, iface, gw)
	if err != nil || mac.IsZero() || mac == have {
		return false
	}
	e.logf("watch: gateway %s moved from %s to %s; unsteering everything and starting again", gw, have, mac)
	return true
}

// startRelay attaches the data plane the configuration asks for and
// reports which one is in effect. done receives the relay's exit (an error,
// or nil when its context ended); stop detaches it and undoes any interface
// change (GRO) it made.
func (e *Engine) startRelay(ctx context.Context, ctrl *intercept.Controller, link Link) (relay string, done <-chan error, stop func(), err error) {
	if e.cfg.Mode == ModeAuto || e.cfg.Mode == ModeXDP {
		relay, done, stop, err = e.startXDP(ctx, ctrl, link)
		if err == nil {
			return relay, done, stop, nil
		}
		if e.cfg.Mode == ModeXDP {
			return "", nil, nil, fmt.Errorf("XDP relay (mode = xdp, no fallback): %w", err)
		}
		e.logf("watch: XDP relay unavailable (%v); using the userspace relay", err)
	}
	return e.startUserspace(ctx, ctrl, link)
}

func (e *Engine) startXDP(ctx context.Context, ctrl *intercept.Controller, link Link) (string, <-chan error, func(), error) {
	rctx, cancel := context.WithCancel(ctx)
	attached := make(chan intercept.XDPMode, 1)
	done := make(chan error, 1)
	go func() {
		done <- e.plat.AttachXDP(rctx, ctrl, link.Name, intercept.XDPOptions{
			Mode:       intercept.XDPAuto,
			LocalIPs:   link.IPv4s,
			OnAttached: func(m intercept.XDPMode) { attached <- m },
		})
	}()
	select {
	case m := <-attached:
		name := RelayXDPGeneric
		if m == intercept.XDPNative {
			name = RelayXDPNative
		}
		return name, done, cancel, nil
	case err := <-done:
		cancel()
		if err == nil {
			err = errRelayStopped
		}
		return "", nil, nil, err
	case <-time.After(e.attachTimeout):
		cancel()
		return "", nil, nil, errors.New("XDP attach timed out")
	}
}

func (e *Engine) startUserspace(ctx context.Context, ctrl *intercept.Controller, link Link) (string, <-chan error, func(), error) {
	restore := func() {}
	on, err := e.plat.GRO(link.Name)
	if err != nil {
		return "", nil, nil, fmt.Errorf("userspace relay needs GRO off on %s: %w", link.Name, err)
	}
	if on {
		if err := e.plat.SetGRO(link.Name, false); err != nil {
			return "", nil, nil, fmt.Errorf("userspace relay needs GRO off on %s: %w", link.Name, err)
		}
		e.logf("watch: turned GRO off on %s for the userspace relay; it is restored on exit", link.Name)
		restore = func() {
			if err := e.plat.SetGRO(link.Name, true); err != nil {
				e.logf("watch: WARNING: could not restore GRO on %s: %v (run `ethtool -K %s gro on`)", link.Name, err, link.Name)
				return
			}
			e.logf("watch: restored GRO on %s", link.Name)
		}
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- e.plat.ParallelRelay(rctx, ctrl, link.Name, e.cfg.Workers) }()
	// ParallelRelay has no "attached" callback: it opens its sockets and
	// blocks. A capability problem surfaces as an immediate error, so a
	// short grace with no error means it is capturing.
	select {
	case err := <-done:
		cancel()
		restore()
		if err == nil {
			err = errRelayStopped
		}
		return "", nil, nil, fmt.Errorf("userspace relay: %w", err)
	case <-time.After(e.relayGrace):
	}
	stop := func() { cancel(); restore() }
	return RelayUserspace, done, stop, nil
}

func (e *Engine) poke(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// GatewayChanged tells the engine the passive ARP monitor saw the gateway
// IP claimed by another MAC. The engine re-reads the kernel's neighbour
// table and, only if that too has moved, unsteers everything and starts
// again with the new MAC. The event's own MAC is never taken on trust.
func (e *Engine) GatewayChanged() { e.poke(e.gwCheck) }

// Excluded implements intercept.Excluder for the Controller: the policy's
// standing refusals, enforced at Steer time as well as by reconcile, plus
// "never steer a MAC the registry does not know".
func (e *Engine) Excluded(mac arp.MAC) bool {
	d, ok := e.reg.FindByMAC(mac.String())
	if !ok {
		return true
	}
	dec := Decide(&d, e.cfg.Policy, e.ownMACs(), e.clock.Now())
	return dec.Policy
}

func (e *Engine) ownMACs() []arp.MAC {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []arp.MAC
	if !e.link.MAC.IsZero() {
		out = append(out, e.link.MAC)
	}
	if !e.gwMAC.IsZero() {
		out = append(out, e.gwMAC)
	}
	return out
}

// onUnsteer is the Controller's OnUnsteer hook. It records history with the
// device's name attached and, for a health failure, arms the retry backoff
// so the device is not re-steered at once only to fail open again.
func (e *Engine) onUnsteer(r intercept.UnsteerRecord) {
	rec := HistoryRecord{Time: r.Time, MAC: r.MAC.String(), Reason: r.Reason}
	if d, ok := e.reg.FindByMAC(r.MAC.String()); ok {
		rec.DeviceID, rec.Name = d.ID, d.DisplayName()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.history = append(e.history, rec)
	if len(e.history) > historyCap {
		e.history = e.history[len(e.history)-historyCap:]
	}
	delete(e.rates, r.MAC)
	delete(e.believed, r.MAC)
	if e.selfUnsteer[r.MAC] {
		delete(e.selfUnsteer, r.MAC)
		return
	}
	if r.Reason == "panic stop" || r.Reason == "controller closed" {
		return
	}
	rs := e.retry[r.MAC]
	if rs == nil {
		rs = &retryState{}
		e.retry[r.MAC] = rs
	}
	rs.failures++
	rs.healthySince = time.Time{}
	rs.until = r.Time.Add(backoffFor(rs.failures))
}

func backoffFor(failures int) time.Duration {
	d := retryBase
	for i := 1; i < failures && d < retryMax; i++ {
		d *= 2
	}
	return min(d, retryMax)
}

// sample reads the Controller's counters once a second: live rates for the
// Snapshot, forgiveness of old failures for devices relaying healthily, and
// a registry sighting for each device whose traffic moved.
func (e *Engine) sample(now time.Time) {
	e.mu.Lock()
	ctrl := e.ctrl
	e.mu.Unlock()
	if ctrl == nil {
		return
	}
	st := ctrl.Stats()
	status := ctrl.Status()
	var observe []intercept.SteeredDevice

	e.mu.Lock()
	elapsed := now.Sub(e.global.at).Seconds()
	if elapsed > 0 {
		e.global.pps = float64(st.FramesRelayed-e.global.packets) / elapsed
		e.global.bps = float64(st.BytesRelayed-e.global.bytes) / elapsed
	}
	e.global.packets, e.global.bytes, e.global.at = st.FramesRelayed, st.BytesRelayed, now
	live := map[arp.MAC]bool{}
	for _, d := range status {
		live[d.MAC] = true
		rs := e.rates[d.MAC]
		if rs == nil {
			rs = &rateSample{at: d.Since}
			e.rates[d.MAC] = rs
		}
		if el := now.Sub(rs.at).Seconds(); el > 0 {
			rs.pps = float64(d.PacketsRelayed-rs.packets) / el
			rs.bps = float64(d.BytesRelayed-rs.bytes) / el
		}
		moved := d.PacketsRelayed > rs.packets
		rs.packets, rs.bytes, rs.at = d.PacketsRelayed, d.BytesRelayed, now
		if moved && now.Sub(e.observed[d.MAC]) >= observeEvery {
			e.observed[d.MAC] = now
			observe = append(observe, d)
		}
		if r := e.retry[d.MAC]; r != nil && d.Healthy && !d.LastVerified.IsZero() {
			if r.healthySince.IsZero() {
				r.healthySince = now
			} else if now.Sub(r.healthySince) >= retryReset {
				delete(e.retry, d.MAC)
			}
		}
	}
	for mac := range e.rates {
		if !live[mac] {
			delete(e.rates, mac)
		}
	}
	e.mu.Unlock()

	for _, d := range observe {
		e.reg.Observe(devices.Observation{Source: devices.SourceARP, MAC: d.MAC.String(), IP: d.IP.String(), Time: now})
	}
}

// reconcile makes the Controller's steered set match the policy: steer
// every eligible (MAC, IP) pair that is not on a backoff, re-steer one
// whose address changed, unsteer anything no longer eligible or no longer
// in the registry.
func (e *Engine) reconcile(now time.Time) {
	e.mu.Lock()
	ctrl, killed := e.ctrl, e.killed
	e.mu.Unlock()
	if ctrl == nil || killed {
		return
	}
	steered := map[arp.MAC]intercept.SteeredDevice{}
	for _, d := range ctrl.Status() {
		steered[d.MAC] = d
	}
	own := e.ownMACs()
	e.mu.Lock()
	v6 := e.v6
	e.mu.Unlock()
	var neighbors map[netip.Addr]arp.MAC
	loadNeighbors := func() map[netip.Addr]arp.MAC {
		if neighbors != nil {
			return neighbors
		}
		neighbors = map[netip.Addr]arp.MAC{}
		e.mu.Lock()
		iface := e.link.Name
		e.mu.Unlock()
		if ns, err := e.plat.Neighbors(iface); err == nil {
			for _, n := range ns {
				neighbors[n.IP] = n.MAC
			}
		}
		return neighbors
	}

	want := map[arp.MAC]target{}
	wantFam := map[arp.MAC]intercept.Family{}
	refused := map[arp.MAC]string{}
	v6Why := map[arp.MAC]string{}
	for _, d := range e.reg.List() {
		d := d
		dec := Decide(&d, e.cfg.Policy, own, now)
		if !dec.Eligible {
			for _, mac := range deviceMACs(&d) {
				if _, on := steered[mac]; on {
					e.unsteer(ctrl, mac, dec.Reason)
					delete(steered, mac)
				}
			}
			continue
		}
		var nb map[netip.Addr]arp.MAC
		if len(d.MACs) > 1 {
			nb = loadNeighbors()
		}
		ts, skipped := targets(&d, nb)
		if skipped != "" {
			for _, mac := range deviceMACs(&d) {
				refused[mac] = skipped
			}
		}
		// IPv6, only where the session has it and only for a device the
		// stricter IPv6 policy allows. A device the registry merged from
		// several MACs is left IPv4-only: the host's neighbour table that
		// pairs its addresses with its MACs is IPv4, so which MAC owns its
		// IPv6 address is a guess, and an advertisement sent to the wrong
		// one is not something to guess at.
		fam := intercept.SteerV4
		ip6 := netip.Addr{}
		if v6 {
			switch dec6 := DecideV6(&d, e.cfg.Policy, now); {
			case !dec6.Eligible:
				for _, mac := range deviceMACs(&d) {
					v6Why[mac] = dec6.Reason
				}
			case len(deviceMACs(&d)) > 1:
				for _, mac := range deviceMACs(&d) {
					v6Why[mac] = "this device has several MACs, so which one holds its IPv6 address is not known"
				}
			default:
				fam |= intercept.SteerV6
				ip6 = deviceIPv6(&d)
			}
		}
		for _, t := range ts {
			t.IP6 = ip6
			want[t.MAC] = t
			wantFam[t.MAC] = fam
		}
	}
	for mac, sd := range steered {
		t, ok := want[mac]
		switch {
		case !ok:
			e.unsteer(ctrl, mac, "no longer eligible or no longer in the registry")
			delete(steered, mac)
		case sd.IP != t.IP:
			e.unsteer(ctrl, mac, "address changed to "+t.IP.String())
			delete(steered, mac)
		case sd.Family != wantFam[mac]:
			e.unsteer(ctrl, mac, "steering "+wantFam[mac].String()+" instead of "+sd.Family.String())
			delete(steered, mac)
		}
	}
	e.mu.Lock()
	retry := make(map[arp.MAC]time.Time, len(e.retry))
	for mac, rs := range e.retry {
		retry[mac] = rs.until
	}
	inFlight := map[arp.MAC]bool{}
	for mac := range e.believed {
		if _, on := steered[mac]; !on {
			inFlight[mac] = true
		}
	}
	e.mu.Unlock()
	for mac, t := range want {
		if _, on := steered[mac]; on {
			continue
		}
		if inFlight[mac] {
			continue // an unsteer is in flight; wait for its reason
		}
		if until, ok := retry[mac]; ok && now.Before(until) {
			continue
		}
		ref := intercept.DeviceRef{MAC: mac, IP: t.IP, IP6: t.IP6}
		fam := wantFam[mac]
		err := ctrl.Steer(ref, intercept.SteerOptions{Family: fam})
		// An IPv6 refusal must never cost the device its IPv4 steering:
		// fall back to IPv4 alone and record why IPv6 did not happen.
		if err != nil && fam.Has(intercept.SteerV6) && !errors.Is(err, intercept.ErrPanicked) && !errors.Is(err, intercept.ErrClosed) {
			v6Why[mac] = "IPv6 steering was refused: " + err.Error()
			err = ctrl.Steer(intercept.DeviceRef{MAC: mac, IP: t.IP}, intercept.SteerOptions{Family: intercept.SteerV4})
		}
		switch {
		case err == nil, errors.Is(err, intercept.ErrAlreadySteered):
			e.mu.Lock()
			e.believed[mac] = true
			e.mu.Unlock()
		case errors.Is(err, intercept.ErrPanicked), errors.Is(err, intercept.ErrClosed):
			return
		default:
			refused[mac] = err.Error()
		}
	}
	e.mu.Lock()
	e.refused = refused
	e.v6Refused = v6Why
	e.mu.Unlock()
}

func (e *Engine) unsteer(ctrl *intercept.Controller, mac arp.MAC, reason string) {
	e.mu.Lock()
	e.selfUnsteer[mac] = true
	e.mu.Unlock()
	if err := ctrl.Unsteer(mac); err != nil {
		e.mu.Lock()
		delete(e.selfUnsteer, mac)
		e.mu.Unlock()
		return
	}
	e.logf("watch: unsteered %s: %s", mac, reason)
}

// Kill is the kill switch: every steered device is unsteered at once with
// its corrective ARP reply, nothing is steered again until Rearm, and the
// state is persisted so a restart does not quietly undo it.
func (e *Engine) Kill() error {
	e.mu.Lock()
	e.killed = true
	ctrl := e.ctrl
	err := saveState(e.cfg.StatePath, persisted{Killed: true})
	e.mu.Unlock()
	if ctrl != nil {
		ctrl.PanicStop()
	}
	e.logf("watch: KILL SWITCH: all steering stopped; nothing is steered until it is re-armed")
	return err
}

// Rearm lifts the kill switch; eligible devices are steered again on the
// next reconcile.
func (e *Engine) Rearm() error {
	e.mu.Lock()
	e.killed = false
	ctrl := e.ctrl
	err := saveState(e.cfg.StatePath, persisted{Killed: false})
	e.mu.Unlock()
	if ctrl != nil {
		ctrl.Rearm()
	}
	e.logf("watch: re-armed")
	e.poke(e.kick)
	return err
}

// Armed reports whether the kill switch is up (steering allowed).
func (e *Engine) Armed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.killed
}

// Snapshot reports the engine's state and every registry device's Watch
// state as of now.
func (e *Engine) Snapshot() Snapshot {
	now := e.clock.Now()
	e.mu.Lock()
	ctrl := e.ctrl
	snap := Snapshot{
		Enabled: e.enabled(), Phase: e.phase, Reason: e.reason, Relay: e.relay, Armed: !e.killed,
		Interface: e.link.Name, Since: e.since,
		Stats:   RelayStats{PacketsPerSecond: e.global.pps, BytesPerSecond: e.global.bps},
		History: append([]HistoryRecord(nil), e.history...),
	}
	snap.IPv6, snap.IPv6Wanted, snap.IPv6Reason = e.v6, e.cfg.IPv6, e.v6Why
	if e.gwLL.IsValid() {
		snap.GatewayLinkLocal = e.gwLL.String()
	}
	if e.gateway.IsValid() {
		snap.GatewayIP = e.gateway.String()
	}
	if !e.gwMAC.IsZero() {
		snap.GatewayMAC = e.gwMAC.String()
	}
	if !e.link.MAC.IsZero() {
		snap.ShepherdMAC = e.link.MAC.String()
	}
	for _, ip := range e.link.IPv4s {
		snap.ShepherdIPs = append(snap.ShepherdIPs, ip.String())
	}
	e.mu.Unlock()
	if snap.History == nil {
		snap.History = []HistoryRecord{}
	}

	steered := map[arp.MAC]intercept.SteeredDevice{}
	if ctrl != nil {
		st := ctrl.Stats()
		snap.Stats.FramesExamined, snap.Stats.FramesRelayed, snap.Stats.BytesRelayed = st.FramesExamined, st.FramesRelayed, st.BytesRelayed
		snap.Stats.FramesForShepherdItself, snap.Stats.FramesNotForShepherd = st.FramesForShepherdItself, st.FramesNotForShepherd
		for _, d := range ctrl.Status() {
			steered[d.MAC] = d
		}
	}
	snap.Steered = len(steered)
	snap.Devices = e.deviceStatuses(now, steered, snap.Phase == PhaseRunning && snap.Armed)
	return snap
}

// DeviceStatuses is Snapshot().Devices alone, keyed by device ID.
func (e *Engine) DeviceStatuses() map[string]DeviceStatus {
	snap := e.Snapshot()
	out := make(map[string]DeviceStatus, len(snap.Devices))
	for _, d := range snap.Devices {
		out[d.DeviceID] = d
	}
	return out
}

func (e *Engine) deviceStatuses(now time.Time, steered map[arp.MAC]intercept.SteeredDevice, running bool) []DeviceStatus {
	own := e.ownMACs()
	e.mu.Lock()
	retry := make(map[arp.MAC]retryState, len(e.retry))
	for mac, rs := range e.retry {
		retry[mac] = *rs
	}
	refused := make(map[arp.MAC]string, len(e.refused))
	for mac, r := range e.refused {
		refused[mac] = r
	}
	v6Why := make(map[arp.MAC]string, len(e.v6Refused))
	for mac, r := range e.v6Refused {
		v6Why[mac] = r
	}
	v6On := e.v6
	rates := make(map[arp.MAC]rateSample, len(e.rates))
	for mac, rs := range e.rates {
		rates[mac] = *rs
	}
	e.mu.Unlock()

	list := e.reg.List()
	out := make([]DeviceStatus, 0, len(list))
	for _, d := range list {
		d := d
		ds := DeviceStatus{DeviceID: d.ID, Name: d.DisplayName(), Healthy: true}
		var fams intercept.Family
		dec := Decide(&d, e.cfg.Policy, own, now)
		for _, mac := range deviceMACs(&d) {
			sd, on := steered[mac]
			if !on {
				continue
			}
			ds.Steered = append(ds.Steered, SteeredEntry{MAC: mac.String(), IP: sd.IP.String(), Families: familyNames(sd.Family),
				Since: sd.Since, Healthy: sd.Healthy, LastVerified: sd.LastVerified})
			fams = fams | sd.Family
			if v6On && !sd.Family.Has(intercept.SteerV6) && ds.IPv6Reason == "" {
				ds.IPv6Reason = v6Why[mac]
			}
			ds.Healthy = ds.Healthy && sd.Healthy
			ds.BytesRelayed += sd.BytesRelayed
			ds.PacketsRelayed += sd.PacketsRelayed
			if rs, ok := rates[mac]; ok {
				ds.BytesPerSecond += rs.bps
				ds.PacketsPerSecond += rs.pps
			}
		}
		ds.Families = familyNames(fams)
		switch {
		case len(ds.Steered) > 0:
			ds.State = StateSteered
		case !dec.Eligible:
			ds.State, ds.Reason = dec.State, dec.Reason
		case !running:
			ds.State, ds.Reason = StateUnavailable, "Watch mode is not running"
		default:
			ds.State, ds.Reason = StatePending, "waiting to be steered"
			for _, mac := range deviceMACs(&d) {
				if rs, ok := retry[mac]; ok && now.Before(rs.until) {
					ds.NextRetry, ds.Failures = rs.until, rs.failures
					ds.Reason = "failed open " + plural(rs.failures, "time") + "; retrying in " + roundAge(rs.until.Sub(now), now)
				} else if why, ok := refused[mac]; ok {
					ds.Reason = why
				}
			}
		}
		if ds.State != StateSteered {
			ds.Healthy = false
		}
		out = append(out, ds)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].State != out[j].State {
			return stateRank(out[i].State) < stateRank(out[j].State)
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func stateRank(s string) int {
	switch s {
	case StateSteered:
		return 0
	case StatePending:
		return 1
	case StateUnavailable:
		return 2
	case StateIdle:
		return 3
	}
	return 4
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

var _ intercept.Excluder = (*Engine)(nil)

// discoverV6 works out whether IPv6 steering can run on this network, and
// says plainly why not when it cannot. Three things have to hold, and all
// three are properties of the network rather than of Shepherd:
//
//  1. an IPv6 default route exists — otherwise there is no IPv6 router and
//     nothing for a device to send off-link;
//  2. its next hop is a link-local address — that is the address a device's
//     own default route resolves, and the only one an advertisement may
//     claim (docs/IPV6-WATCH.md);
//  3. the interface holds a global (2000::/3) address — a ULA-only network
//     has no off-link IPv6 traffic to steer at all, so steering it would
//     take the risk and relay nothing. This is the maintainer's own LAN,
//     and the reason IPv6 steering idles there rather than engaging.
func (e *Engine) discoverV6(iface string, link Link) (netip.Addr, bool, string) {
	if !e.cfg.IPv6 {
		return netip.Addr{}, false, "IPv6 steering is turned off in the configuration"
	}
	r, err := e.plat.DefaultRoute6()
	if err != nil {
		return netip.Addr{}, false, "this network has no IPv6 default route, so there is no IPv6 traffic to steer"
	}
	if r.Iface != "" && r.Iface != iface {
		return netip.Addr{}, false, fmt.Sprintf("the IPv6 default route leaves through %s, not %s", r.Iface, iface)
	}
	if !r.NextHop.IsLinkLocalUnicast() {
		return netip.Addr{}, false, fmt.Sprintf("the IPv6 default route's next hop (%s) is not a link-local address", r.NextHop)
	}
	global := false
	for _, a := range link.IPv6s {
		if isGlobalV6(a) {
			global = true
			break
		}
	}
	if !global {
		return netip.Addr{}, false, "this network has no global IPv6 route (unique-local addresses only), so there is no off-link IPv6 traffic to steer"
	}
	return r.NextHop, true, ""
}

// v6Excluder is the Controller's V6Excluder: the stricter IPv6 refusal,
// enforced at the Steer call itself so an IPv6 steer can never reach a
// device DecideV6 refuses, even if something asks for it.
type v6Excluder struct{ e *Engine }

func (x v6Excluder) Excluded(mac arp.MAC) bool {
	d, ok := x.e.reg.FindByMAC(mac.String())
	if !ok {
		return true
	}
	now := x.e.clock.Now()
	if dec := Decide(&d, x.e.cfg.Policy, x.e.ownMACs(), now); dec.Policy {
		return true
	}
	return DecideV6(&d, x.e.cfg.Policy, now).Policy
}

// familyNames renders an intercept.Family as the JSON-facing names the
// portal shows.
func familyNames(f intercept.Family) []string {
	var out []string
	if f.Has(intercept.SteerV4) {
		out = append(out, "ipv4")
	}
	if f.Has(intercept.SteerV6) {
		out = append(out, "ipv6")
	}
	return out
}

var _ intercept.Excluder = v6Excluder{}
