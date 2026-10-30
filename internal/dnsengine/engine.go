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

func (e *Engine) done(entry Entry, start time.Time) {
	entry.Ms = float64(time.Since(start).Microseconds()) / 1000
	e.Log.Add(entry)
	e.Stats.Record(entry)
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

	d := e.Filter.Check(entry.Name)
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
		e.write(w, r, resp)
		e.done(entry, start)
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
	e.write(w, r, resp)
	e.done(entry, start)
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
