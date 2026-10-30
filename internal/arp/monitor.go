// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"shepherd/internal/devices"
)

// maxIPsPerMAC bounds the per-MAC address set used by mac-claims-many-ips.
const maxIPsPerMAC = 64

// Stats are the Monitor's counters, for the portal.
type Stats struct {
	Frames             uint64               `json:"frames"`              // frames read from the source
	Malformed          uint64               `json:"malformed"`           // undecodable ARP frames
	NotARP             uint64               `json:"not_arp"`             // frames that were not IPv4 ARP
	Ignored            uint64               `json:"ignored"`             // unusable sender MAC or IP
	Probes             uint64               `json:"probes"`              // RFC 5227 probes seen
	Gratuitous         uint64               `json:"gratuitous"`          // gratuitous frames seen
	UnsolicitedReplies uint64               `json:"unsolicited_replies"` // replies with no request seen
	SenderMismatch     uint64               `json:"sender_mismatch"`     // Ethernet source differs from ARP sender MAC
	Observations       uint64               `json:"observations"`        // observations sent to the Sink
	EventsSuppressed   uint64               `json:"events_suppressed"`   // repeats swallowed by the cooldown
	Events             map[EventType]uint64 `json:"events"`              // delivered events by type
	TrackedMACs        int                  `json:"tracked_macs"`
	TrackedIPs         int                  `json:"tracked_ips"`
}

type counter struct {
	start time.Time
	n     int
}

// add counts one hit in a fixed window and returns the window's total.
func (c *counter) add(now time.Time, window time.Duration) int {
	if now.Before(c.start) || now.Sub(c.start) >= window {
		c.start, c.n = now, 0
	}
	c.n++
	return c.n
}

type macState struct {
	first, last time.Time
	ips         map[netip.Addr]time.Time
	grat, unsol counter
}

type ipState struct {
	owner     MAC
	lastClaim time.Time
	flips     []time.Time
}

type pairKey struct {
	mac MAC
	ip  netip.Addr
}

type sigState struct{ at map[EventType]time.Time }

// Monitor is the passive ARP monitor. Create one with NewMonitor and call
// Run. It implements devices.Discoverer.
type Monitor struct {
	src Source
	cfg Config

	mu      sync.Mutex
	started bool
	start   time.Time

	macs  *lru[MAC, *macState]
	ips   *lru[netip.Addr, *ipState]
	pairs *lru[pairKey, time.Time]
	reqs  *lru[netip.Addr, time.Time]
	cool  *lru[string, time.Time]
	sigs  *lru[MAC, *sigState]

	trusted map[MAC]bool

	gw        netip.Addr
	gwMAC     MAC
	gwKnown   bool
	gwChecked time.Time

	stats Stats

	// outgoing work collected under mu and delivered after unlocking
	obsOut []devices.Observation
	evOut  []Event
}

var _ devices.Discoverer = (*Monitor)(nil)

// NewMonitor builds a Monitor over src. src is closed when Run returns.
func NewMonitor(src Source, cfg Config) *Monitor {
	cfg = cfg.withDefaults()
	m := &Monitor{
		src:     src,
		cfg:     cfg,
		macs:    newLRU[MAC, *macState](cfg.MaxTracked),
		ips:     newLRU[netip.Addr, *ipState](cfg.MaxTracked),
		pairs:   newLRU[pairKey, time.Time](cfg.MaxTracked),
		reqs:    newLRU[netip.Addr, time.Time](cfg.MaxTracked),
		cool:    newLRU[string, time.Time](cfg.MaxTracked),
		sigs:    newLRU[MAC, *sigState](cfg.MaxTracked),
		trusted: map[MAC]bool{},
		stats:   Stats{Events: map[EventType]uint64{}},
	}
	for _, t := range cfg.TrustedMACs {
		m.trusted[t] = true
	}
	if cfg.Gateway.IsValid() {
		m.gw = cfg.Gateway.Unmap()
	}
	if !cfg.GatewayMAC.IsZero() {
		m.gwMAC, m.gwKnown = cfg.GatewayMAC, true
	}
	return m
}

// Stats returns a snapshot of the counters.
func (m *Monitor) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.stats
	s.Events = make(map[EventType]uint64, len(m.stats.Events))
	for k, v := range m.stats.Events {
		s.Events[k] = v
	}
	s.TrackedMACs, s.TrackedIPs = m.macs.len(), m.ips.len()
	return s
}

// Run reads frames until ctx ends, the source closes, or the capture fails.
// A cancelled context or a closed source is a clean stop (nil). The source
// is always closed on return.
func (m *Monitor) Run(ctx context.Context) error {
	defer m.src.Close()
	for {
		f, err := m.src.Next(ctx)
		switch {
		case err == nil:
			m.Handle(f)
		case ctx.Err() != nil, errors.Is(err, ErrClosed):
			return nil
		case isRecoverable(err):
			m.mu.Lock()
			m.stats.Frames++
			if errors.Is(err, ErrNotARP) {
				m.stats.NotARP++
			} else {
				m.stats.Malformed++
			}
			m.mu.Unlock()
		default:
			return fmt.Errorf("arp: capture failed: %w", err)
		}
	}
}

// Handle processes one frame. Run calls it; tests and replays may too. It
// is safe for concurrent use but intended for a single reader.
func (m *Monitor) Handle(f Frame) {
	m.mu.Lock()
	now := f.Time
	if now.IsZero() {
		now = m.cfg.Now()
	}
	m.stats.Frames++
	m.process(f, now)
	obs, evs := m.obsOut, m.evOut
	m.obsOut, m.evOut = nil, nil
	m.mu.Unlock()

	// Deliver outside the lock so a slow Sink cannot block Stats().
	if len(obs) > 0 && m.cfg.Sink != nil {
		for _, o := range obs {
			m.cfg.Sink.Observe(o)
		}
	}
	if len(obs) > 0 {
		m.mu.Lock()
		if m.cfg.Sink != nil {
			m.stats.Observations += uint64(len(obs))
		}
		m.mu.Unlock()
	}
	if m.cfg.OnEvent != nil {
		for _, e := range evs {
			m.cfg.OnEvent(e)
		}
	}
}

func usableIP(a netip.Addr) bool {
	if !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
		return false
	}
	b := a.As4()
	return b[0] != 0 && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func (m *Monitor) process(f Frame, now time.Time) {
	if !m.started {
		m.started, m.start = true, now
	}
	m.refreshGateway(now)
	if f.Op != OpRequest && f.Op != OpReply || !f.SenderIP.Is4() || !f.TargetIP.Is4() {
		m.stats.Ignored++
		return
	}
	if f.SrcMAC != f.SenderMAC {
		m.stats.SenderMismatch++
	}
	kind := f.Kind()
	if kind == KindRequest || kind == KindProbe {
		m.reqs.put(f.TargetIP, now)
	}
	if !f.SenderMAC.usable() {
		m.stats.Ignored++
		return
	}
	if kind == KindProbe {
		m.stats.Probes++
		m.probe(f, now)
		return
	}
	if !usableIP(f.SenderIP) {
		m.stats.Ignored++
		return
	}
	ms, isNew := m.macState(f.SenderMAC, now)
	if f.IsGratuitous() {
		m.stats.Gratuitous++
		if ms.grat.add(now, m.cfg.RateWindow) == m.cfg.GratuitousLimit {
			sev := SeverityLow
			if f.SenderIP == m.gw {
				sev = SeverityMedium
			}
			m.signal(f.SenderMAC, EventGratuitousFlood, now)
			m.emit(Event{Type: EventGratuitousFlood, Severity: sev,
				Key: key(EventGratuitousFlood, f.SenderMAC.String()), Time: now,
				MAC: f.SenderMAC.String(), IP: f.SenderIP.String(),
				Summary: fmt.Sprintf("%s sent %d gratuitous ARP frames within %s", f.SenderMAC, m.cfg.GratuitousLimit, m.cfg.RateWindow),
				Evidence: map[string]string{"count": strconv.Itoa(m.cfg.GratuitousLimit), "window": m.cfg.RateWindow.String(),
					"last_ip": f.SenderIP.String()}})
		}
	}
	if kind == KindReply {
		if t, ok := m.reqs.peek(f.SenderIP); !ok || now.Before(t) || now.Sub(t) > m.cfg.RequestWindow {
			m.stats.UnsolicitedReplies++
			if ms.unsol.add(now, m.cfg.RateWindow) == m.cfg.UnsolicitedLimit {
				m.signal(f.SenderMAC, EventUnsolicitedStorm, now)
				m.emit(Event{Type: EventUnsolicitedStorm, Severity: SeverityMedium,
					Key: key(EventUnsolicitedStorm, f.SenderMAC.String()), Time: now,
					MAC: f.SenderMAC.String(), IP: f.SenderIP.String(),
					Summary: fmt.Sprintf("%s sent %d ARP replies nobody asked for within %s", f.SenderMAC, m.cfg.UnsolicitedLimit, m.cfg.RateWindow),
					Evidence: map[string]string{"count": strconv.Itoa(m.cfg.UnsolicitedLimit), "window": m.cfg.RateWindow.String(),
						"last_ip": f.SenderIP.String()}})
			}
		}
	}
	if isNew {
		m.emit(Event{Type: EventNewMAC, Severity: SeverityInfo, Key: key(EventNewMAC, f.SenderMAC.String()), Time: now,
			MAC: f.SenderMAC.String(), IP: f.SenderIP.String(),
			Summary: fmt.Sprintf("new hardware address %s seen at %s", f.SenderMAC, f.SenderIP),
			Evidence: map[string]string{"randomized": strconv.FormatBool(f.SenderMAC.IsLocallyAdministered()),
				"kind": kind.String()}})
	}
	m.claim(f.SenderMAC, f.SenderIP, ms, now)
}

// macState finds or creates the record for mac and reports whether it is new.
func (m *Monitor) macState(mac MAC, now time.Time) (*macState, bool) {
	if ms, ok := m.macs.get(mac); ok {
		ms.last = now
		return ms, false
	}
	ms := &macState{first: now, last: now, ips: map[netip.Addr]time.Time{}}
	m.macs.put(mac, ms)
	return ms, true
}

func (m *Monitor) claim(mac MAC, ip netip.Addr, ms *macState, now time.Time) {
	m.trackIPs(mac, ip, ms, now)
	isGW := m.gw.IsValid() && ip == m.gw
	if isGW {
		m.checkGateway(mac, ip, now)
	}
	st, ok := m.ips.get(ip)
	switch {
	case !ok:
		m.ips.put(ip, &ipState{owner: mac, lastClaim: now})
	case st.owner == mac:
		st.lastClaim = now
	default:
		prev := st.owner
		st.owner, st.lastClaim = mac, now
		st.flips = append(st.flips, now)
		kept := st.flips[:0]
		for _, t := range st.flips {
			if now.Sub(t) < m.cfg.DuplicateWindow && !t.After(now) {
				kept = append(kept, t)
			}
		}
		st.flips = kept
		if len(st.flips) > 16 {
			st.flips = st.flips[len(st.flips)-16:]
		}
		if !isGW {
			m.ipMoved(prev, mac, ip, now)
		}
		if len(st.flips) >= m.cfg.DuplicateFlips {
			m.signal(mac, EventDuplicateIP, now)
			m.emit(Event{Type: EventDuplicateIP, Severity: SeverityMedium, Key: key(EventDuplicateIP, ip.String()), Time: now,
				MAC: mac.String(), OtherMAC: prev.String(), IP: ip.String(),
				Summary:  fmt.Sprintf("%s keeps changing hands between %s and %s: two devices claim it", ip, prev, mac),
				Evidence: map[string]string{"owner_changes": strconv.Itoa(len(st.flips)), "window": m.cfg.DuplicateWindow.String()}})
			st.flips = st.flips[:0]
		}
	}
	m.observe(mac, ip, now)
}

func (m *Monitor) ipMoved(prev, mac MAC, ip netip.Addr, now time.Time) {
	quiet := true
	if ps, ok := m.macs.peek(prev); ok {
		quiet = now.Sub(ps.last) >= m.cfg.QuietPeriod
	}
	sev, why := SeverityMedium, "previous owner is still active"
	switch {
	case quiet && prev.IsLocallyAdministered() && mac.IsLocallyAdministered():
		sev, why = SeverityInfo, "randomized address rotation"
	case quiet:
		sev, why = SeverityLow, "previous owner has gone quiet"
	default:
		m.signal(mac, EventIPMoved, now)
	}
	m.emit(Event{Type: EventIPMoved, Severity: sev, Key: key(EventIPMoved, ip.String(), mac.String()), Time: now,
		MAC: mac.String(), OtherMAC: prev.String(), IP: ip.String(),
		Summary: fmt.Sprintf("%s moved from %s to %s (%s)", ip, prev, mac, why),
		Evidence: map[string]string{"reason": why, "previous_mac": prev.String(),
			"previous_randomized": strconv.FormatBool(prev.IsLocallyAdministered()),
			"new_randomized":      strconv.FormatBool(mac.IsLocallyAdministered())}})
}

// trackIPs records mac claiming ip and raises mac-claims-many-ips.
func (m *Monitor) trackIPs(mac MAC, ip netip.Addr, ms *macState, now time.Time) {
	if _, has := ms.ips[ip]; !has && len(ms.ips) >= maxIPsPerMAC {
		oldest, ot := netip.Addr{}, now.Add(time.Hour)
		for a, t := range ms.ips {
			if t.Before(ot) || !oldest.IsValid() {
				oldest, ot = a, t
			}
		}
		delete(ms.ips, oldest)
	}
	ms.ips[ip] = now
	if m.trusted[mac] || (m.gwKnown && mac == m.gwMAC) {
		return
	}
	if len(ms.ips) < m.cfg.ManyIPsThreshold {
		return
	}
	live := make([]string, 0, len(ms.ips))
	for a, t := range ms.ips {
		if now.Sub(t) >= m.cfg.ManyIPsWindow {
			delete(ms.ips, a)
			continue
		}
		live = append(live, a.String())
	}
	if len(live) < m.cfg.ManyIPsThreshold {
		return
	}
	sort.Strings(live)
	m.signal(mac, EventManyIPs, now)
	m.emit(Event{Type: EventManyIPs, Severity: SeverityMedium, Key: key(EventManyIPs, mac.String()), Time: now,
		MAC: mac.String(), IP: ip.String(),
		Summary: fmt.Sprintf("%s claimed %d different addresses within %s", mac, len(live), m.cfg.ManyIPsWindow),
		Evidence: map[string]string{"count": strconv.Itoa(len(live)), "window": m.cfg.ManyIPsWindow.String(),
			"ips": strings.Join(firstN(live, 10), ",")}})
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (m *Monitor) checkGateway(mac MAC, ip netip.Addr, now time.Time) {
	if !m.gwKnown {
		m.gwMAC, m.gwKnown = mac, true
		return
	}
	if mac == m.gwMAC {
		return
	}
	old := m.gwMAC
	if m.cfg.GatewayMAC.IsZero() { // unpinned: the new owner becomes the baseline
		m.gwMAC = mac
	}
	m.signal(mac, EventGatewayMACChanged, now)
	m.emit(Event{Type: EventGatewayMACChanged, Severity: SeverityHigh,
		Key: key(EventGatewayMACChanged, ip.String(), old.String(), mac.String()), Time: now,
		MAC: mac.String(), OtherMAC: old.String(), IP: ip.String(),
		Summary: fmt.Sprintf("the gateway %s now answers from %s instead of %s", ip, mac, old),
		Evidence: map[string]string{"gateway_ip": ip.String(), "expected_mac": old.String(), "claimed_mac": mac.String(),
			"pinned":     strconv.FormatBool(!m.cfg.GatewayMAC.IsZero()),
			"randomized": strconv.FormatBool(mac.IsLocallyAdministered())}})
}

// probe handles an RFC 5227 probe. The sender IP is 0.0.0.0 and says
// nothing about the sender, but probing an address someone else holds is a
// conflict.
func (m *Monitor) probe(f Frame, now time.Time) {
	if !usableIP(f.TargetIP) {
		return
	}
	st, ok := m.ips.peek(f.TargetIP)
	if !ok || st.owner == f.SenderMAC || now.Before(st.lastClaim) || now.Sub(st.lastClaim) >= m.cfg.OwnerLive {
		return
	}
	sev := SeverityLow
	if f.TargetIP == m.gw {
		sev = SeverityMedium
	}
	m.emit(Event{Type: EventDuplicateIP, Severity: sev, Key: key(EventDuplicateIP, f.TargetIP.String()), Time: now,
		MAC: f.SenderMAC.String(), OtherMAC: st.owner.String(), IP: f.TargetIP.String(),
		Summary:  fmt.Sprintf("%s probed %s, which %s is using", f.SenderMAC, f.TargetIP, st.owner),
		Evidence: map[string]string{"via": "probe", "owner_last_seen": st.lastClaim.UTC().Format(time.RFC3339)}})
}

func (m *Monitor) observe(mac MAC, ip netip.Addr, now time.Time) {
	k := pairKey{mac, ip}
	if last, ok := m.pairs.get(k); ok && (now.Before(last) || now.Sub(last) < m.cfg.ObserveInterval) {
		return
	}
	m.pairs.put(k, now)
	m.obsOut = append(m.obsOut, devices.Observation{Source: devices.SourceARP, MAC: mac.String(), IP: ip.String(), Time: now})
}

func (m *Monitor) refreshGateway(now time.Time) {
	if m.cfg.Gateway.IsValid() || m.cfg.GatewayFunc == nil {
		return
	}
	if !m.gwChecked.IsZero() && !now.Before(m.gwChecked) && now.Sub(m.gwChecked) < m.cfg.GatewayRefresh {
		return
	}
	m.gwChecked = now
	ip, err := m.cfg.GatewayFunc()
	if err != nil {
		if m.cfg.OnError != nil {
			m.cfg.OnError(fmt.Errorf("arp: gateway lookup: %w", err))
		}
		return
	}
	ip = ip.Unmap()
	if usableIP(ip) && ip != m.gw {
		m.gw = ip
		if m.cfg.GatewayMAC.IsZero() {
			m.gwKnown = false
		}
	}
}

func key(t EventType, parts ...string) string {
	return "arp:" + string(t) + ":" + strings.Join(parts, ":")
}

// emit queues an event unless its Key is cooling down.
func (m *Monitor) emit(e Event) {
	if last, ok := m.cool.peek(e.Key); ok && !e.Time.Before(last) && e.Time.Sub(last) < m.cfg.EventCooldown {
		m.stats.EventsSuppressed++
		return
	}
	m.cool.put(e.Key, e.Time)
	e.Baseline = e.Time.Sub(m.start) < m.cfg.LearnPeriod
	m.stats.Events[e.Type]++
	m.evOut = append(m.evOut, e)
}

// signal records that mac showed a spoofing-related behaviour and raises
// the conservative summary when several distinct signals combine.
func (m *Monitor) signal(mac MAC, t EventType, now time.Time) {
	ss, ok := m.sigs.get(mac)
	if !ok {
		ss = &sigState{at: map[EventType]time.Time{}}
		m.sigs.put(mac, ss)
	}
	ss.at[t] = now
	var types []string
	for k, at := range ss.at {
		if now.Sub(at) >= m.cfg.SpoofWindow {
			delete(ss.at, k)
			continue
		}
		types = append(types, string(k))
	}
	_, hasGW := ss.at[EventGatewayMACChanged]
	if len(types) < m.cfg.SpoofMinSignals && !(hasGW && len(types) >= 2) {
		return
	}
	sort.Strings(types)
	m.emit(Event{Type: EventSpoofingSuspected, Severity: SeverityHigh, Key: key(EventSpoofingSuspected, mac.String()), Time: now,
		MAC:     mac.String(),
		Summary: fmt.Sprintf("%s shows %d ARP spoofing signals: %s", mac, len(types), strings.Join(types, ", ")),
		Evidence: map[string]string{"signals": strings.Join(types, ","), "window": m.cfg.SpoofWindow.String(),
			"gateway_involved": strconv.FormatBool(hasGW)}})
}
