// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"fmt"
	"net"
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

func (e *Engine) done(entry Entry, start time.Time) {
	entry.Ms = float64(time.Since(start).Microseconds()) / 1000
	e.Log.Add(entry)
	e.Stats.Record(entry)
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
			e.write(w, r, resp)
			e.done(entry, start)
			return
		}
	}
	if e.Observe != nil {
		e.Observe(entry.Client, entry.Name, ips)
	}
	e.write(w, r, resp)
	e.done(entry, start)
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
		e.write(w, r, resp)
		e.done(entry, start)
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
		e.write(w, r, fail)
		e.done(entry, start)
		return
	}
	e.Cache.Put(r, resp)
	entry.Action, entry.Upstream, entry.Rcode = "allowed", up.Addr, dns.RcodeToString[resp.Rcode]
	e.finishAllowed(w, r, q, entry, resp, start)
}

// Serve listens on every address over UDP and TCP until ctx ends. All binds
// must succeed, so a misconfigured address fails at startup, not silently.
func Serve(ctx context.Context, addrs []string, h dns.Handler) error {
	var servers []*dns.Server
	shutdown := func() {
		for _, s := range servers {
			_ = s.Shutdown()
		}
	}
	var closers []func()
	for _, a := range addrs {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			for _, c := range closers {
				c()
			}
			return fmt.Errorf("listening udp %s: %w", a, err)
		}
		closers = append(closers, func() { pc.Close() })
		ln, err := net.Listen("tcp", a)
		if err != nil {
			for _, c := range closers {
				c()
			}
			return fmt.Errorf("listening tcp %s: %w", a, err)
		}
		closers = append(closers, func() { ln.Close() })
		servers = append(servers, &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: ln, Handler: h})
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
