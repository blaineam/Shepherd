// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"shepherd/internal/devices"
)

// ServerPort and ClientPort are the BOOTP ports.
const (
	ServerPort = 67
	ClientPort = 68
)

// Conn is the socket Server reads from and, in serve mode only, writes to.
// Observe mode is handed a Conn whose WriteTo always fails, and is never
// asked to write anyway: the guarantee is enforced in two places because it
// is the one that makes observe mode safe to run on a live network.
type Conn interface {
	ReadFrom(p []byte) (n int, from netip.AddrPort, err error)
	WriteTo(p []byte, to netip.AddrPort) (int, error)
	Close() error
}

// Opener opens the DHCP socket on iface. write is false in observe mode, and
// an Opener must then return a connection with no send path.
type Opener func(ctx context.Context, iface string, write bool) (Conn, error)

// Server runs DHCP mode: one socket, one handler, and a timer that keeps the
// kernel's NAT rules in step with the leases.
type Server struct {
	// Mode, Settings and Route are read afresh each time, so the portal
	// changes things without a restart.
	Mode     func() Mode
	Settings func() Settings
	// Route is the one routing switch. It is separate from Settings
	// because turning routing off must be able to happen without touching
	// anything about addressing.
	Route func() bool
	// RouteConsoles routes game consoles too (off by default).
	RouteConsoles func() bool
	// Own is this host's and the gateway's identity, recomputed on demand
	// because an interface can gain an address while Shepherd runs.
	Own func() Own
	// Lookup resolves a MAC to a device record, for the routing policy.
	Lookup func(mac string) (devices.Device, bool)
	// Observe reports the network as it is now -- this host's addresses,
	// the gateway and every address the registry knows is in use -- so a
	// chosen range can be checked against it before anything is served.
	Observe func() Observed

	// Store is the lease store.
	Store *Leases
	State *State
	Peers *Peers
	Sink  devices.Sink
	NAT   *Reconciler

	Open      Opener
	Iface     string
	LeasePath string
	// Settle is how long the segment must be free of other DHCP servers
	// before Shepherd answers. Zero means DefaultSettle.
	Settle time.Duration
	// Interval is how often the housekeeping tick runs: the serve gate is
	// re-evaluated, NAT is reconciled, expired leases are purged and the
	// store is saved. Zero means DefaultInterval.
	Interval time.Duration
	Now      func() time.Time
	Log      *log.Logger
	// Alarm reports a condition the operator must know about: another DHCP
	// server answering, or the kernel refusing the NAT rules. Optional.
	Alarm func(severity, title, detail string)

	mu      sync.RWMutex
	status  Status
	handler *Handler
}

// DefaultInterval is the housekeeping period. Five seconds is frequent enough
// that a lease change becomes a NAT change before the device has finished
// configuring its interface, and cheap enough to ignore.
const DefaultInterval = 5 * time.Second

// leaseGrace is how long an expired lease is remembered, so a device that
// comes back after a weekend away gets the address it had.
const leaseGrace = 7 * 24 * time.Hour

// Alarm severities, matching the words internal/alarms uses.
const (
	severityCritical = "critical"
	severityWarning  = "warning"
)

// NATStatus is what the portal says about the kernel side.
type NATStatus struct {
	// Available is whether nft could be run at all.
	Available bool `json:"available"`
	// Error is why not, or why the last apply failed.
	Error string `json:"error,omitempty"`
	// Applied is the addresses the kernel is currently translating.
	Applied []string `json:"applied,omitempty"`
}

// Status is DHCP mode's whole state, for the portal. Every field is something
// an operator would otherwise have to guess.
type Status struct {
	Mode string `json:"mode"`
	// Listening is whether the socket is open.
	Listening bool `json:"listening"`
	// Serving is whether Shepherd is answering requests right now.
	Serving bool `json:"serving"`
	// Blocked says why it is not, when the mode asks it to be. This is the
	// field that turns "it is not working" into "the router's DHCP is still
	// on".
	Blocked string `json:"blocked,omitempty"`
	// Routing is whether routed devices are getting Shepherd's own address
	// in option 3.
	Routing bool `json:"routing"`
	// RoutingBlocked says why routing is off while the switch is on.
	RoutingBlocked string `json:"routing_blocked,omitempty"`

	Confirmed      bool      `json:"confirmed"`
	Disarmed       bool      `json:"disarmed"`
	DisarmedReason string    `json:"disarmed_reason,omitempty"`
	DisarmedAt     time.Time `json:"disarmed_at,omitempty"`

	Peers []Peer `json:"peers"`

	Leases      int `json:"leases"`
	RoutedCount int `json:"routed_count"`

	NAT NATStatus `json:"nat"`

	// Error is a configuration problem that stops the mode working at all.
	Error string `json:"error,omitempty"`
	// Since is when the current state was last recomputed.
	Since time.Time `json:"since"`
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log.Printf(format, args...)
	}
}

func (s *Server) alarm(severity, title, detail string) {
	if s.Alarm != nil {
		s.Alarm(severity, title, detail)
	}
}

func (s *Server) mode() Mode {
	if s.Mode == nil {
		return ModeOff
	}
	m := s.Mode()
	if m == "" {
		return ModeOff
	}
	return m
}

// settings is the addressing in force: what the configuration file and the
// interface give, with the operator's chosen range (if any) on top.
func (s *Server) settings() Settings {
	var base Settings
	if s.Settings != nil {
		base = s.Settings()
	}
	if s.State == nil {
		return base
	}
	return s.State.Range().Apply(base)
}

// observed is the network as Shepherd can see it now, for the collision
// check. A server with no Observe function sees nothing, which makes Check
// report only what is wrong with the range on its own terms.
func (s *Server) observed() Observed {
	if s.Observe == nil {
		return Observed{}
	}
	return s.Observe()
}

// Conflicts is why the chosen range does not fit the network as it is. It is
// empty when no range has been chosen, because then there is nothing to
// compare: the settings already came from the interface.
func (s *Server) Conflicts() []Conflict {
	if s.State == nil {
		return nil
	}
	r := s.State.Range()
	if !r.Set() {
		return nil
	}
	o := s.observed()
	// Mark the addresses Shepherd itself handed out. They are the ones
	// that move on their own at the next renewal, so they are not the
	// collision a static address is -- and the caller supplying Observed
	// has no way to know which is which.
	if s.Store != nil {
		leased := map[netip.Addr]bool{}
		for _, l := range s.Store.All() {
			if l.Origin == OriginShepherd && l.IP.IsValid() {
				leased[l.IP] = true
			}
		}
		for i := range o.Holders {
			if leased[o.Holders[i].IP] {
				o.Holders[i].Leased = true
			}
		}
	}
	return Check(r, o, s.State.Reservations())
}

func (s *Server) own() Own {
	if s.Own == nil {
		return Own{}
	}
	return s.Own()
}

func (s *Server) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return DefaultInterval
}

// Status returns the latest computed state.
func (s *Server) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// serveGate decides whether Shepherd may answer requests, and says why not.
// Every condition here is one that, if ignored, would either split the
// household between two DHCP servers or hand out an address twice.
func (s *Server) serveGate(now time.Time) (ok bool, why string) {
	if s.mode() != ModeServe {
		return false, "the mode is " + s.mode().String()
	}
	if s.State == nil || !s.State.Confirmed() {
		return false, "serving has not been confirmed in the portal"
	}
	if err := s.settings().Valid(); err != nil {
		return false, err.Error()
	}
	if s.Store == nil || !s.Store.Loaded() {
		return false, "the lease store has not loaded, so an address could be handed out twice"
	}
	if s.Peers != nil {
		if active := s.Peers.Active(now, s.Settle); len(active) > 0 {
			return false, "another DHCP server is answering from " + active[0].Server.String() +
				"; turn the router's DHCP off, then clear this in the portal"
		}
	}
	// A chosen range that does not fit the network is the one refusal an
	// operator asked for themselves. Serving it anyway would hand out
	// addresses nothing can route, or hand one address to two devices.
	if c, blocked := Blocked(s.Conflicts()); blocked {
		return false, c.Detail
	}
	return true, ""
}

// routeGate decides whether routed devices get Shepherd's address. It is a
// separate decision from serving, which is the heart of the fail-open
// behaviour: Shepherd keeps handing out addresses — with the gateway in
// option 3 — through every failure that stops it being a safe path.
func (s *Server) routeGate() (ok bool, why string) {
	if s.Route == nil || !s.Route() {
		return false, ""
	}
	if s.State != nil {
		if off, reason, _ := s.State.Disarmed(); off {
			if reason != "" {
				return false, "the kill switch is pulled: " + reason
			}
			return false, "the kill switch is pulled"
		}
	}
	s.mu.RLock()
	nat := s.status.NAT
	s.mu.RUnlock()
	if !nat.Available {
		detail := nat.Error
		if detail == "" {
			detail = "the kernel's NAT configuration is not available"
		}
		return false, detail
	}
	return true, ""
}

func (s *Server) policy() RoutePolicy {
	route, _ := s.routeGate()
	consoles := false
	if s.RouteConsoles != nil {
		consoles = s.RouteConsoles()
	}
	return RoutePolicy{Route: route, RouteConsoles: consoles, Own: s.own(), Lookup: s.Lookup}
}

// Prepare builds the handler and allocator and loads the lease store. Run
// calls it; the portal calls it too, so a mode that never starts can still
// show reservations and the reason it is not running.
func (s *Server) Prepare() error {
	if s.Store == nil {
		s.Store = NewLeases()
	}
	if s.Peers == nil {
		s.Peers = NewPeers()
	}
	if !s.Store.Loaded() && s.LeasePath != "" {
		reset, err := s.Store.LoadOrReset(s.LeasePath)
		if err != nil {
			return err
		}
		if reset {
			// Loud on purpose. Losing the lease file is recoverable in
			// one renewal interval, but it is not nothing: for that
			// interval two devices could be offered the same address.
			s.logf("dhcp: %s could not be parsed and was moved to %s.bad; starting with no leases", s.LeasePath, s.LeasePath)
			s.alarm(severityWarning, "DHCP lease file reset",
				"Shepherd could not read its DHCP lease file and started with none. Addresses are re-learned as devices renew.")
		}
	} else if !s.Store.Loaded() {
		// No path means an in-memory store, which is a legitimate
		// configuration for a test and for observe mode.
		s.Store.MarkLoaded()
	}
	set := s.settings()
	alloc := &Allocator{
		Pool: set.Pool, Subnet: set.Subnet, Leases: s.Store, State: s.State, Now: s.now,
		Taken: func(ip netip.Addr) bool { return s.own().HasIP(ip) },
	}
	s.handler = &Handler{
		Settings: s.settings, Policy: s.policy, Leases: s.Store,
		Alloc: alloc, Peers: s.Peers, Sink: s.Sink, Now: s.now,
	}
	s.updateStatus()
	return nil
}

// Run opens the socket and serves until ctx ends. In ModeOff it refreshes the
// status once and returns nil: there is nothing to run, and that is not an
// error.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Prepare(); err != nil {
		s.setError(err.Error())
		return err
	}
	// Clear any table a previous run left behind before anything else, so
	// a crash cannot leave the kernel translating for a set of addresses
	// nobody is tracking any more.
	if s.NAT != nil {
		if err := s.NAT.Available(ctx); err != nil {
			s.setNAT(NATStatus{Error: err.Error()})
			s.logf("dhcp: %v", err)
		} else {
			s.setNAT(NATStatus{Available: true})
			if err := s.NAT.Clear(ctx); err != nil {
				s.logf("dhcp: clearing a leftover rule set: %v", err)
			}
		}
	}

	mode := s.mode()
	if !mode.Listens() {
		s.refresh(ctx)
		return nil
	}
	if s.Open == nil {
		err := errors.New("dhcp: no socket opener configured")
		s.setError(err.Error())
		return err
	}
	conn, err := s.Open(ctx, s.Iface, mode == ModeServe)
	if err != nil {
		s.setError(err.Error())
		return err
	}
	defer conn.Close()
	s.mu.Lock()
	s.status.Listening = true
	s.mu.Unlock()

	packets := make(chan packet, 64)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(packets)
		s.read(ctx, conn, packets)
	}()

	tick := time.NewTicker(s.interval())
	defer tick.Stop()
	s.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			s.shutdown(conn)
			wg.Wait()
			return nil
		case <-tick.C:
			s.refresh(ctx)
		case p, ok := <-packets:
			if !ok {
				s.shutdown(conn)
				return nil
			}
			s.serve(ctx, conn, p)
		}
	}
}

type packet struct {
	pkt  *dhcpv4.DHCPv4
	from netip.Addr
}

// read decodes packets off the socket until ctx ends. A decode failure is
// logged at most as a counter, not as an error: a DHCP socket on a household
// LAN sees malformed and unrelated traffic, and treating that as a fault
// would mean the log is noise exactly when it needs to be read.
func (s *Server) read(ctx context.Context, conn Conn, out chan<- packet) {
	buf := make([]byte, 1500)
	fails := 0
	for ctx.Err() == nil {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fails++
			if fails > 5 {
				s.logf("dhcp: giving up reading the socket after %d failures: %v", fails, err)
				return
			}
			continue
		}
		fails = 0
		pkt, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		select {
		case out <- packet{pkt: pkt, from: from.Addr()}:
		case <-ctx.Done():
			return
		}
	}
}

// serve handles one packet and sends the reply, if the gate allows one.
func (s *Server) serve(ctx context.Context, conn Conn, p packet) {
	mode := s.mode()
	if mode == ModeServe {
		if ok, _ := s.serveGate(s.now()); !ok {
			// Fall back to observing. The packet is still identity
			// evidence and another server's reply is still the thing
			// the interlock needs to see.
			mode = ModeObserve
		}
	}
	// The handler records another server's reply in Peers as it decodes it;
	// the serve gate picks that up on the next tick, which is where the
	// alarm is raised and the serving stops.
	res := s.handler.Handle(p.pkt, mode, p.from)
	if res.Reply == nil {
		return
	}
	if mode != ModeServe {
		// Belt and braces. A reply in a non-serving mode is a bug, and
		// it must not reach the wire while it is being found.
		s.logf("dhcp: refusing to send a %s in %s mode", res.Action, mode)
		return
	}
	to := netip.AddrPortFrom(res.To, ClientPort)
	if _, err := conn.WriteTo(res.Reply.ToBytes(), to); err != nil {
		s.logf("dhcp: sending %s to %s: %v", res.Action, to, err)
		return
	}
	if res.Action == ActionAck {
		s.logf("dhcp: %s %s to %s%s", res.Action, res.Lease.IP, res.Lease.MAC, routedNote(res.Routing))
		// Reconcile at once rather than waiting for the tick: a device
		// that has just been told Shepherd is its gateway needs the NAT
		// rule before its first packet, not five seconds later.
		s.reconcile(ctx)
	}
}

func routedNote(d Decision) string {
	if d.Routed {
		return " (routed through Shepherd)"
	}
	if d.Reason == "" {
		return ""
	}
	return " (not routed: " + d.Reason + ")"
}

// shutdown stops routing on the way out, as a courtesy rather than as the
// safety mechanism. The safety mechanism is that leases are short and an
// absent Shepherd stops renewing them with its own address in option 3; a
// shutdown hook cannot be relied on for SIGKILL, the OOM killer or a panic,
// which is exactly the argument docs/GATEWAY.md makes about fail-closed.
//
// Clearing the rule set here is still worth doing: it means a deliberate stop
// leaves the kernel clean, so the next start is not inheriting state.
func (s *Server) shutdown(conn Conn) {
	_ = conn.Close()
	if s.Store != nil && s.LeasePath != "" && s.Store.Dirty() {
		if err := s.Store.Save(s.LeasePath); err != nil {
			s.logf("dhcp: saving leases on the way out: %v", err)
		}
	}
	if s.NAT != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.NAT.Clear(ctx); err != nil {
			s.logf("dhcp: clearing the rule set on the way out: %v", err)
		}
	}
}

// reconcile pushes the current routed set into the kernel.
func (s *Server) reconcile(ctx context.Context) {
	if s.NAT == nil || s.Store == nil {
		return
	}
	routing, _ := s.routeGate()
	var want []netip.Addr
	if routing {
		want = s.Store.Routed(s.now(), s.own().IPs)
	}
	// Check that what was installed is still installed before deciding
	// nothing needs doing: an idempotent Apply cannot notice a kernel that
	// stopped cooperating, and noticing is how this mode fails open.
	err := s.NAT.Verify(ctx)
	var changed bool
	if err == nil {
		changed, err = s.NAT.Apply(ctx, want)
	}
	if err != nil {
		s.setNAT(NATStatus{Available: false, Error: err.Error()})
		// A kernel that will not take the rules means routed devices have
		// no path. The right response is to stop claiming to be their
		// gateway, which happens by itself: routeGate now returns false,
		// so the next renewal hands out the router's address instead.
		s.alarm(severityCritical, "DHCP mode could not configure NAT",
			"Shepherd could not install its forwarding rules, so it has stopped routing devices through itself. "+
				"They move back to the router at their next DHCP renewal. The error was: "+err.Error())
		return
	}
	st := NATStatus{Available: true}
	for _, a := range s.NAT.Applied() {
		st.Applied = append(st.Applied, a.String())
	}
	s.setNAT(st)
	if changed {
		s.logf("dhcp: NAT now covers %d device(s)", len(want))
	}
}

// refresh is the housekeeping tick: reconcile the kernel, then recompute the
// status, expire old leases and save.
func (s *Server) refresh(ctx context.Context) {
	s.reconcile(ctx)
	s.updateStatus()
}

// updateStatus recomputes the gates and the counters without touching the
// kernel. Prepare calls it so the portal has an honest status for a mode that
// never starts, which is the ordinary case: the whole arrangement is meant to
// be reviewable before it is switched on.
func (s *Server) updateStatus() {
	now := s.now()
	serving, why := s.serveGate(now)
	routing, routeWhy := s.routeGate()

	if s.Peers != nil {
		if active := s.Peers.Active(now, s.Settle); len(active) > 0 && s.mode() == ModeServe {
			s.mu.RLock()
			announced := s.status.Serving || s.status.Blocked == ""
			s.mu.RUnlock()
			if announced {
				s.alarm(severityCritical, "Another DHCP server is answering",
					"Shepherd has stopped serving DHCP because a reply came from "+active[0].Server.String()+
						". Two DHCP servers on one segment hand out addresses unpredictably. Turn the router's DHCP off, "+
						"then clear the sighting in the portal.")
			}
		}
	}

	if s.Store != nil {
		if n := s.Store.Purge(now, leaseGrace); n > 0 {
			s.logf("dhcp: forgot %d lease(s) that expired more than %s ago", n, leaseGrace)
		}
		if s.LeasePath != "" && s.Store.Dirty() {
			if err := s.Store.Save(s.LeasePath); err != nil {
				s.logf("dhcp: saving leases: %v", err)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Mode = s.mode().String()
	s.status.Serving = serving
	s.status.Blocked = ""
	if !serving && s.mode() == ModeServe {
		s.status.Blocked = why
	}
	s.status.Routing = routing
	s.status.RoutingBlocked = ""
	if !routing && s.Route != nil && s.Route() {
		s.status.RoutingBlocked = routeWhy
	}
	if s.State != nil {
		s.status.Confirmed = s.State.Confirmed()
		s.status.Disarmed, s.status.DisarmedReason, s.status.DisarmedAt = s.State.Disarmed()
	}
	if s.Peers != nil {
		s.status.Peers = s.Peers.All()
	}
	if s.Store != nil {
		s.status.Leases = s.Store.Len()
		s.status.RoutedCount = len(s.Store.Routed(now, s.own().IPs))
	}
	if err := s.settings().Valid(); err != nil && s.mode().Listens() {
		s.status.Error = err.Error()
	} else {
		s.status.Error = ""
	}
	s.status.Since = now
}

func (s *Server) setNAT(st NATStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.NAT = st
}

func (s *Server) setError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Error = msg
	s.status.Since = s.now()
}

// Unroute pulls the kill switch: routing stops now, the kernel's rules go,
// and the state survives a restart. Leasing carries on, with the router's own
// address in option 3, so no device loses its address.
func (s *Server) Unroute(ctx context.Context, reason string) error {
	if s.State == nil {
		return errors.New("dhcp: no state store")
	}
	if err := s.State.SetDisarmed(true, reason); err != nil {
		return err
	}
	if s.NAT != nil {
		if err := s.NAT.Clear(ctx); err != nil {
			return fmt.Errorf("dhcp: the kill switch was recorded but the rules could not be cleared: %w", err)
		}
	}
	s.logf("dhcp: kill switch pulled (%s); routing stopped, leases continue", reason)
	s.refresh(ctx)
	return nil
}

// Rearm undoes Unroute.
func (s *Server) Rearm(ctx context.Context) error {
	if s.State == nil {
		return errors.New("dhcp: no state store")
	}
	if err := s.State.SetDisarmed(false, ""); err != nil {
		return err
	}
	s.refresh(ctx)
	return nil
}

// ---- The portal's handle on DHCP mode -------------------------------------
//
// These wrap the stores so the portal depends on one interface rather than on
// the lease store, the state file and the peer record separately. Every one
// of them works with the mode off, which is what lets the whole thing be set
// up and reviewed before it is ever switched on.

// LeaseView is one lease as the portal shows it: the record, plus the two
// things the record cannot answer on its own.
type LeaseView struct {
	Lease
	// Routed is whether this lease sends the device through Shepherd.
	Routed bool `json:"routed"`
	// Reason is why it does not, when it does not. It is recomputed rather
	// than stored, so it explains the decision as it stands now — which is
	// what the device will get at its next renewal.
	Reason string `json:"reason,omitempty"`
	// Expired is whether the lease has run out, which the portal shows
	// rather than hiding: an expired lease is how a device that has gone
	// away is told from one that never had an address.
	Expired bool `json:"expired"`
}

// Leases returns every lease, newest first, with the routing decision
// attached.
func (s *Server) Leases() []LeaseView {
	if s.Store == nil {
		return nil
	}
	now := s.now()
	own := s.own()
	pol := s.policy()
	all := s.Store.All()
	out := make([]LeaseView, 0, len(all))
	for _, l := range all {
		v := LeaseView{Lease: l, Routed: l.Routed(own.IPs), Expired: !l.Active(now)}
		if !v.Routed {
			v.Reason = pol.Decide(l.MAC, l.IP).Reason
		}
		out = append(out, v)
	}
	return out
}

// RangeView is the chosen range as the portal shows it, with what it would
// replace, so the screen can say "this is what you are changing from".
type RangeView struct {
	// Chosen is true when the operator has picked a range; false means the
	// configuration file and the interface are in charge.
	Chosen    bool   `json:"chosen"`
	Subnet    string `json:"subnet,omitempty"`
	ServerIP  string `json:"server_ip,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	PoolStart string `json:"pool_start,omitempty"`
	PoolEnd   string `json:"pool_end,omitempty"`
	// Current is what the interface and the configuration file say today,
	// which is what a cleared range falls back to.
	Current SettingsView `json:"current"`
}

// RangeView returns the chosen range and what it would replace.
func (s *Server) RangeView() RangeView {
	v := RangeView{}
	if s.Settings != nil {
		v.Current = settingsView(s.Settings())
	}
	if s.State == nil {
		return v
	}
	r := s.State.Range()
	if !r.Set() {
		return v
	}
	v.Chosen = true
	v.Subnet = r.Subnet.String()
	if r.ServerIP.IsValid() {
		v.ServerIP = r.ServerIP.String()
	}
	if r.Gateway.IsValid() {
		v.Gateway = r.Gateway.String()
	}
	if r.Pool.Valid() {
		v.PoolStart, v.PoolEnd = r.Pool.Start.String(), r.Pool.End.String()
	}
	return v
}

// SetRange stores the operator's chosen addressing, or clears it when r is
// not set. It takes effect on the next renewal; serving stops while the
// range does not fit the network (see Check).
func (s *Server) SetRange(ctx context.Context, r Range) error {
	if s.State == nil {
		return errors.New("dhcp: no state store")
	}
	if err := s.State.SetRange(r); err != nil {
		return err
	}
	s.refresh(ctx)
	return nil
}

// Reservation returns the reservation for one MAC, which is what the device
// list needs to show a per-device reserved switch.
func (s *Server) Reservation(mac string) (Reservation, bool) {
	if s.State == nil {
		return Reservation{}, false
	}
	return s.State.Reservation(mac)
}

// Reservations returns every reservation.
func (s *Server) Reservations() []Reservation {
	if s.State == nil {
		return nil
	}
	return s.State.Reservations()
}

// SetReservation adds or replaces one, validated against the current
// settings so the portal cannot store an address inside the dynamic pool.
func (s *Server) SetReservation(r Reservation) error {
	if s.State == nil {
		return errors.New("dhcp: no state store")
	}
	set := s.settings()
	return s.State.SetReservation(r, set.Subnet, set.Pool)
}

// DeleteReservation removes one.
func (s *Server) DeleteReservation(mac string) (bool, error) {
	if s.State == nil {
		return false, errors.New("dhcp: no state store")
	}
	return s.State.DeleteReservation(mac)
}

// Confirm records or withdraws the confirmation that Shepherd may serve DHCP
// for this network. Withdrawing it stops serving at the next tick.
func (s *Server) Confirm(ctx context.Context, on bool) error {
	if s.State == nil {
		return errors.New("dhcp: no state store")
	}
	if err := s.State.SetConfirmed(on); err != nil {
		return err
	}
	s.refresh(ctx)
	return nil
}

// ForgetPeers clears the record of other DHCP servers seen. The operator
// does this after turning the router's DHCP off, rather than waiting out the
// settle window for a server that is already gone.
func (s *Server) ForgetPeers(ctx context.Context) {
	if s.Peers != nil {
		s.Peers.Forget()
	}
	s.refresh(ctx)
}

// SettingsView is what the portal shows about the addressing, as strings,
// because every one of these is something a person reads and compares with
// their router's own screen.
type SettingsView struct {
	Subnet       string   `json:"subnet,omitempty"`
	ServerIP     string   `json:"server_ip,omitempty"`
	Gateway      string   `json:"gateway,omitempty"`
	PoolStart    string   `json:"pool_start,omitempty"`
	PoolEnd      string   `json:"pool_end,omitempty"`
	DNS          []string `json:"dns,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	LeaseSeconds int      `json:"lease_seconds"`
	PoolSize     int      `json:"pool_size"`
}

// SettingsView returns the addressing in force, for the portal.
func (s *Server) SettingsView() SettingsView { return settingsView(s.settings()) }

func settingsView(set Settings) SettingsView {
	v := SettingsView{Domain: set.Domain, LeaseSeconds: int(set.leaseTime() / time.Second), PoolSize: set.Pool.Size()}
	if set.Subnet.IsValid() {
		v.Subnet = set.Subnet.String()
	}
	if set.ServerIP.IsValid() {
		v.ServerIP = set.ServerIP.String()
	}
	if set.Gateway.IsValid() {
		v.Gateway = set.Gateway.String()
	}
	if set.Pool.Valid() {
		v.PoolStart, v.PoolEnd = set.Pool.Start.String(), set.Pool.End.String()
	}
	for _, a := range set.DNS {
		v.DNS = append(v.DNS, a.String())
	}
	return v
}
