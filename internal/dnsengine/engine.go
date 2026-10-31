// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// Engine answers DNS queries: filter, cache, then forward upstream.
type Engine struct {
	Filter        *Filter
	Pool          *Pool
	Cache         *Cache
	Log           *QueryLog
	Stats         *Stats
	BlockNXDOMAIN bool
	// Geo places answer addresses on the globe. Nil disables geolocation.
	Geo Geo
	// Clients maps a client address to its device and groups for scoped
	// policy; nil means every client gets network scope only.
	Clients ClientScopes
	// Names labels each query with its device (Entry.Device, Entry.DeviceID)
	// and reports devices excluded from protection. Nil leaves entries unlabeled.
	Names DeviceNamer
	// ClientSeen is called with every query's client address, before the
	// filter runs, so the device registry can learn who is asking. It must be
	// cheap and rate-limit itself.
	ClientSeen func(clientIP string)
	// Observe is called with every allowed or cached query's real answer
	// addresses (never a blocked query's sinkhole address), so the automatic
	// classifier can learn what a device talks to. Must be cheap; the
	// classifier's own Observe is non-blocking.
	Observe func(clientIP, qname string, answers []net.IP)
	// OnAccess is called for every completed query (blocked, allowed or
	// cached — never one that errored, since nothing was actually accessed)
	// whose name matches at least one catalog or custom list item, whatever
	// the policy engine decided to do about it. This is the opposite filter
	// from Observe, which exists for the automatic classifier and
	// deliberately skips blocked queries; accountability-partner alerts
	// (docs/ACCOUNTABILITY.md) want to know about a watched access whether
	// or not it was blocked. Must be cheap; nil disables it.
	OnAccess func(AccessInfo)
	// CountryBlock, when set, runs after a query would otherwise be answered
	// (allowed or cached) and may turn it into a blocked one. It receives the
	// client's address and the already-geolocated answer destinations (nil
	// when Geo is nil or placed none of them) and reports the ISO country
	// code that matched and whether to block. This is an additive check,
	// layered outside the Filter's own decision, never one of its rules
	// (see internal/geo and docs/GEOBLOCK.md); nil disables it. It must be
	// fast and must not block.
	CountryBlock func(clientIP string, dests []Dest) (country string, blocked bool)
}

// AccessInfo is what OnAccess receives for one query matching a watched
// catalog or custom list item.
type AccessInfo struct {
	Time     time.Time
	ClientIP string
	// Items are every catalog or custom list ID that name (or a parent
	// domain) belongs to, regardless of whether any of them is enabled for
	// this client's scope (see Filter.ItemsFor). Never empty: OnAccess is
	// not called otherwise.
	Items []string
	// Domain is the exact name queried.
	Domain string
	// Action is what ServeDNS decided: "blocked", "allowed" or "cached".
	Action string
}

// DeviceInfo is what the device registry knows about a client address.
type DeviceInfo struct {
	ID   string
	Name string
	// Excluded devices opted out of protection: their queries are answered
	// without any blocking (and are still logged and named).
	Excluded bool
	// Wandering devices are not filtered at all and every request is watched:
	// the engine records what filtering WOULD have blocked in Entry.Shadow.
	// WanderingUntil ends it; the zero time means until turned off.
	Wandering      bool
	WanderingUntil time.Time
}

// wandering reports whether the device is in wandering mode right now.
func (i DeviceInfo) wandering(now time.Time) bool {
	return i.Wandering && (i.WanderingUntil.IsZero() || now.Before(i.WanderingUntil))
}

// DeviceNamer maps a client address to its device. It runs on every query, so
// implementations must be lock-free or nearly so. An unknown client returns
// the zero DeviceInfo.
type DeviceNamer interface {
	DeviceFor(clientIP string) DeviceInfo
}

func clientIP(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.TCPAddr:
		return v.IP.String()
	}
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}

func maxSize(w dns.ResponseWriter, r *dns.Msg) int {
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		return dns.MaxMsgSize
	}
	if o := r.IsEdns0(); o != nil {
		if s := int(o.UDPSize()); s > dns.MinMsgSize {
			return s
		}
	}
	return dns.MinMsgSize
}

func (e *Engine) write(w dns.ResponseWriter, r, resp *dns.Msg) {
	resp.Id = r.Id
	resp.Truncate(maxSize(w, r))
	_ = w.WriteMsg(resp)
}

func (e *Engine) sinkhole(r *dns.Msg, q dns.Question, nxdomain bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	if nxdomain || e.BlockNXDOMAIN {
		m.Rcode = dns.RcodeNameError
		return m
	}
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60}
	switch q.Qtype {
	case dns.TypeA:
		hdr.Rrtype = dns.TypeA
		m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4zero.To4()})
	case dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero})
	}
	return m // other types: NOERROR with no answer
}

// publicIP reports whether ip is a routable address worth placing on a map.
func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64 { // 100.64.0.0/10
		return false
	}
	return true
}

// PublicIP reports whether ip is a routable address (not private, loopback,
// link-local, multicast or carrier-grade NAT).
func PublicIP(ip net.IP) bool { return publicIP(ip) }

// answerIPs returns every distinct A/AAAA address in resp, in answer order.
func answerIPs(resp *dns.Msg) []net.IP {
	if resp == nil {
		return nil
	}
	var out []net.IP
	seen := map[string]bool{}
	for _, rr := range resp.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		}
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out
}

// destsOf geolocates up to three distinct public addresses in ips.
func (e *Engine) destsOf(ips []net.IP) []Dest {
	if e.Geo == nil {
		return nil
	}
	var out []Dest
	for _, ip := range ips {
		if !publicIP(ip) {
			continue
		}
		if d, ok := e.Geo.Locate(ip); ok {
			d.IP = ip.String()
			out = append(out, d)
		}
		if len(out) == 3 {
			break
		}
	}
	return out
}

// done records entry in Log and Stats. Every caller runs this before writing
// the response to the client (not after): a client that already has its
// answer can immediately act on it (a test, or the portal's live query feed)
// and check the log, and nothing then guarantees this goroutine has reached
// its next line before that happens — the response left over the wire the
// moment the write syscall returns, regardless of what Go code follows it.
// Recording first closes that race entirely rather than narrowing it.
func (e *Engine) done(entry Entry, start time.Time) {
	entry.Ms = float64(time.Since(start).Microseconds()) / 1000
	e.Log.Add(entry)
	e.Stats.Record(entry)
}

// reportAccess calls OnAccess when entry's name matches a watched item.
// Filter.ItemsFor ignores scope on purpose (unlike the Decision that chose
// entry.Action): accountability's whole point is that a category can be
// watched whether or not it is actually blocked for this client.
func (e *Engine) reportAccess(entry Entry) {
	if e.OnAccess == nil {
		return
	}
	items := e.Filter.ItemsFor(entry.Name)
	if len(items) == 0 {
		return
	}
	e.OnAccess(AccessInfo{Time: entry.Time, ClientIP: entry.Client, Items: items, Domain: entry.Name, Action: entry.Action})
}

// finishAllowed geolocates resp's answer and gives CountryBlock a chance to
// turn this otherwise-allowed or cached query into a blocked one (an
// additive check that runs after the Filter's own decision, never inside
// it). entry.Action and entry.Rcode must already reflect "allowed" or
// "cached"; a country block overrides both. Observe only ever sees the real
// answer, never when the query ends up blocked.
func (e *Engine) finishAllowed(w dns.ResponseWriter, r *dns.Msg, q dns.Question, entry Entry, resp *dns.Msg, start time.Time) {
	ips := answerIPs(resp)
	entry.Dests = e.destsOf(ips)
	if e.CountryBlock != nil {
		if country, blocked := e.CountryBlock(entry.Client, entry.Dests); blocked {
			resp = e.sinkhole(r, q, false)
			entry.Action, entry.Reason, entry.GeoCountry = "blocked", "geo", country
			entry.Rcode = dns.RcodeToString[resp.Rcode]
			e.reportAccess(entry)
			e.done(entry, start)
			e.write(w, r, resp)
			return
		}
	}
	if e.Observe != nil {
		e.Observe(entry.Client, entry.Name, ips)
	}
	e.reportAccess(entry)
	e.done(entry, start)
	e.write(w, r, resp)
}

// ServeDNS implements dns.Handler.
func (e *Engine) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	if r.Response {
		return
	}
	if len(r.Question) != 1 || r.Opcode != dns.OpcodeQuery {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	entry := Entry{Time: start, Client: clientIP(w.RemoteAddr()), Name: normalize(q.Name), Type: dns.TypeToString[q.Qtype]}
	if entry.Type == "" {
		entry.Type = fmt.Sprintf("TYPE%d", q.Qtype)
	}

	if e.ClientSeen != nil {
		e.ClientSeen(entry.Client)
	}
	var d Decision
	wander := false
	if e.Names != nil {
		info := e.Names.DeviceFor(entry.Client)
		entry.DeviceID, entry.Device = info.ID, info.Name
		wander = info.wandering(start)
		if info.Excluded && !wander {
			d.Reason = "excluded"
		}
	}
	if d.Reason == "" {
		d = e.Filter.CheckFor(entry.Client, entry.Name, e.Clients)
	}
	if wander { // answer everything, but remember what filtering would have done
		if d.Blocked {
			entry.Shadow = d.Reason
			if d.Scope != "" {
				entry.Shadow += " (" + d.Scope + ")"
			}
		}
		d = Decision{Reason: "wandering"}
		entry.Wandering = true
	}
	if d.Blocked {
		resp := e.sinkhole(r, q, d.NXDOMAIN)
		entry.Action, entry.Reason, entry.Rcode = "blocked", d.Reason, dns.RcodeToString[resp.Rcode]
		e.reportAccess(entry)
		e.done(entry, start)
		e.write(w, r, resp)
		return
	}
	entry.Reason = d.Reason // "allowlist" or empty

	if resp, ok := e.Cache.Get(r); ok {
		entry.Action, entry.Rcode = "cached", dns.RcodeToString[resp.Rcode]
		e.finishAllowed(w, r, q, entry, resp, start)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	resp, up, _, err := e.Pool.Exchange(ctx, r)
	if err != nil {
		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)
		entry.Action, entry.Reason, entry.Rcode = "error", err.Error(), "SERVFAIL"
		e.done(entry, start)
		e.write(w, r, fail)
		return
	}
	e.Cache.Put(r, resp)
	entry.Action, entry.Upstream, entry.Rcode = "allowed", up.Addr, dns.RcodeToString[resp.Rcode]
	e.finishAllowed(w, r, q, entry, resp, start)
}

// ServeOption configures Serve.
type ServeOption func(*serveConfig)

type serveConfig struct {
	onBindError func(addr string, err error)
}

// TolerateMissingAddresses makes Serve carry on when an address does not
// exist on this host, reporting each one through onMissing and failing only
// if that leaves nothing bound at all.
//
// It exists because the strict behaviour turned a missing address into a
// total outage. Shepherd was listening on three addresses, one of them on a
// wired interface; that interface lost carrier, the address went with it,
// and Shepherd then refused to start — so a network whose resolver was fine
// on two other addresses had none at all, in a restart loop. An address that
// was correct yesterday can be gone today, and on a home network that is
// ordinary rather than a misconfiguration.
//
// It is deliberately narrow. Only "cannot assign requested address" is
// tolerated — the address is not on this host, so nothing is answering for
// it and serving the rest is strictly better. An address another process
// already holds stays fatal: then something *is* answering on it, and
// starting anyway would leave the operator believing Shepherd was handling
// their DNS while a different resolver did. That distinction is the whole
// point, and TestRunFailsFastOnBusyPorts holds the line on it.
//
// Each address is a unit: if its UDP or TCP half cannot be bound the other
// half is closed too, so an address is never half-served.
func TolerateMissingAddresses(onMissing func(addr string, err error)) ServeOption {
	return func(c *serveConfig) { c.onBindError = onMissing }
}

// addressMissing reports whether err means "this host does not have that
// address" rather than "something else is using it" or anything else.
func addressMissing(err error) bool { return errors.Is(err, syscall.EADDRNOTAVAIL) }

// Serve listens on every address over UDP and TCP until ctx ends. By
// default all binds must succeed, so a misconfigured address fails at
// startup rather than silently; TolerateUnbindable relaxes that.
func Serve(ctx context.Context, addrs []string, h dns.Handler, opts ...ServeOption) error {
	var cfg serveConfig
	for _, o := range opts {
		o(&cfg)
	}
	var servers []*dns.Server
	shutdown := func() {
		for _, s := range servers {
			_ = s.Shutdown()
		}
	}
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}
	for _, a := range addrs {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			if cfg.onBindError == nil || !addressMissing(err) {
				closeAll()
				return fmt.Errorf("listening udp %s: %w", a, err)
			}
			cfg.onBindError(a, fmt.Errorf("udp: %w", err))
			continue
		}
		ln, err := net.Listen("tcp", a)
		if err != nil {
			pc.Close() // never leave an address served over UDP only
			if cfg.onBindError == nil || !addressMissing(err) {
				closeAll()
				return fmt.Errorf("listening tcp %s: %w", a, err)
			}
			cfg.onBindError(a, fmt.Errorf("tcp: %w", err))
			continue
		}
		closers = append(closers, func() { pc.Close() }, func() { ln.Close() })
		servers = append(servers, &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: ln, Handler: h})
	}
	if len(servers) == 0 {
		closeAll()
		return fmt.Errorf("dnsengine: not listening on any of %d configured addresses", len(addrs))
	}
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() { errc <- s.ActivateAndServe() }()
	}
	select {
	case <-ctx.Done():
		shutdown()
		return nil
	case err := <-errc:
		shutdown()
		return err
	}
}
