// SPDX-License-Identifier: AGPL-3.0-or-later

package reverseproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// loopHeader carries this process's marker on every forwarded request. A
// host pointed back at the proxy's own listener would otherwise forward to
// itself forever, opening a connection per hop until something gives out.
const loopHeader = "X-Shepherd-Proxy"

// HostLookup is the one thing Proxy needs from a Store, so routing tests can
// hand it any table they like.
type HostLookup interface {
	Lookup(hostHeader string) (Host, bool)
}

// Options configures a Proxy. Only Hosts is required.
type Options struct {
	Hosts HostLookup
	// Transport and InsecureTransport carry requests to backends that
	// verify and skip certificate verification respectively. Nil builds
	// real ones (see newTransport); routing tests substitute fakes so no
	// socket is needed.
	Transport         http.RoundTripper
	InsecureTransport http.RoundTripper
	// RootCAs, when set, replaces the system roots for verifying https
	// backends. Tests use it to trust an httptest backend.
	RootCAs *x509.CertPool
	// OnError, when set, hears about every request a backend failed, for
	// the server log. A client that hung up first is not reported.
	OnError func(r *http.Request, err error)
	// LocalPrefixes supplies what Host.Allow's "local" stands for: every
	// network this machine has an address on, plus Tailscale's range.
	// Called per refused-or-checked request, so it should be cheap or
	// cached. Nil means "local" matches nothing.
	LocalPrefixes func() []netip.Prefix
	// OnRefused, when set, hears about a request a host's allow list
	// turned away, at most once per client address per minute so a scan
	// cannot flood the log.
	OnRefused func(r *http.Request, client netip.Addr)
}

// Proxy forwards each request to the backend its Host header names. A name
// with no enabled host gets a plain 404 from the proxy itself; it never
// falls through to anything else, so a typo or a removed host cannot
// expose Shepherd's own portal under someone else's name.
type Proxy struct {
	hosts     HostLookup
	verify    *httputil.ReverseProxy
	insecure  *httputil.ReverseProxy
	onError   func(*http.Request, error)
	onRefused func(*http.Request, netip.Addr)
	local     func() []netip.Prefix
	marker    string

	refusedMu sync.Mutex
	refusedAt map[netip.Addr]time.Time
	now       func() time.Time
}

// refusalLogEvery bounds OnRefused to one call per client per this long.
const refusalLogEvery = time.Minute

// refusedTableMax bounds the per-client timestamp table; past it the
// table is reset, which costs at worst one extra log line per client.
const refusedTableMax = 4096

type hostKey struct{}

// New builds a Proxy. httputil.ReverseProxy does the forwarding: it already
// handles hop-by-hop headers, streaming, trailers and, since Go 1.12,
// WebSocket and other Upgrade requests by hijacking both connections and
// copying bytes in each direction. websocket_test.go proves that end to end
// rather than taking it on faith.
func New(opts Options) *Proxy {
	marker := make([]byte, 8)
	rand.Read(marker) // crypto/rand.Read never fails on supported platforms
	p := &Proxy{hosts: opts.Hosts, onError: opts.OnError, onRefused: opts.OnRefused, local: opts.LocalPrefixes,
		marker: hex.EncodeToString(marker), refusedAt: map[netip.Addr]time.Time{}, now: time.Now}
	verify, insecure := opts.Transport, opts.InsecureTransport
	if verify == nil {
		verify = newTransport(&tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12})
	}
	if insecure == nil {
		insecure = newTransport(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // per-host opt-in, see Host.SkipTLSVerify
	}
	p.verify = &httputil.ReverseProxy{Rewrite: p.rewrite, Transport: verify, ErrorHandler: p.backendFailed}
	p.insecure = &httputil.ReverseProxy{Rewrite: p.rewrite, Transport: insecure, ErrorHandler: p.backendFailed}
	return p
}

// newTransport dials backends directly (never through an HTTP_PROXY from
// the environment, which would send LAN traffic somewhere unexpected) and
// speaks only HTTP/1.1 to them: an HTTP/2 connection cannot carry a classic
// WebSocket upgrade, and a reverse-proxy manager's nginx talks HTTP/1.1
// upstream too. No overall timeout: video streams, uploads and sockets
// legitimately run for hours.
func newTransport(tc *tls.Config) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext:           d.DialContext,
		TLSClientConfig:       tc,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
}

// ServeHTTP routes r by its Host header.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(loopHeader) == p.marker {
		http.Error(w, "shepherd: this proxy host points back at the proxy itself", http.StatusLoopDetected)
		return
	}
	h, ok := p.hosts.Lookup(r.Host)
	if !ok || !h.Enabled {
		http.Error(w, "shepherd: no proxy host is configured for this name", http.StatusNotFound)
		return
	}
	if len(h.Allow) > 0 {
		client := clientAddr(r.RemoteAddr)
		if !client.IsValid() || !h.Allowed(client, p.local) {
			p.refused(r, client)
			http.Error(w, "shepherd: this name is not open to your address", http.StatusForbidden)
			return
		}
	}
	if h.HSTS && r.TLS != nil {
		// Set before the backend's headers are copied in; ReverseProxy
		// adds to the writer's header rather than replacing it.
		w.Header().Set("Strict-Transport-Security", "max-age="+strconv.Itoa(HSTSMaxAge))
	}
	rp := p.verify
	if h.TargetScheme == "https" && h.SkipTLSVerify {
		rp = p.insecure
	}
	rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), hostKey{}, h)))
}

// clientAddr is the address a request came from, or an invalid Addr when
// RemoteAddr is not an address (a test without one, say).
func clientAddr(remote string) netip.Addr {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// refused reports one turned-away request to OnRefused, once per client
// per refusalLogEvery.
func (p *Proxy) refused(r *http.Request, client netip.Addr) {
	if p.onRefused == nil {
		return
	}
	now := p.now()
	p.refusedMu.Lock()
	if len(p.refusedAt) >= refusedTableMax {
		p.refusedAt = map[netip.Addr]time.Time{}
	}
	last, seen := p.refusedAt[client]
	if seen && now.Sub(last) < refusalLogEvery {
		p.refusedMu.Unlock()
		return
	}
	p.refusedAt[client] = now
	p.refusedMu.Unlock()
	p.onRefused(r, client)
}

// rewrite points the outbound request at the backend while keeping what
// the client asked for: the path, query and Host header are untouched (the
// last is what a reverse-proxy manager passes too, and what apps use to
// build their own links), and the X-Forwarded-* headers say who really
// asked and over what. ReverseProxy has already stripped any X-Forwarded-*
// the client sent; X-Forwarded-For is set to the client's own address,
// not appended to a client-supplied chain, because this proxy is the edge
// and nothing before it is trusted.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	h := pr.In.Context().Value(hostKey{}).(Host)
	pr.SetURL(h.Target())
	pr.Out.Host = pr.In.Host
	client := pr.In.RemoteAddr
	if ip, _, err := net.SplitHostPort(client); err == nil {
		client = ip
	}
	proto := "http"
	if pr.In.TLS != nil {
		proto = "https"
	}
	pr.Out.Header.Set("X-Forwarded-For", client)
	pr.Out.Header.Set("X-Real-IP", client)
	pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
	pr.Out.Header.Set(loopHeader, p.marker)
}

func (p *Proxy) backendFailed(w http.ResponseWriter, r *http.Request, err error) {
	if p.onError != nil && !errors.Is(err, context.Canceled) && r.Context().Err() == nil {
		p.onError(r, err)
	}
	http.Error(w, "shepherd: the backend for this name did not answer", http.StatusBadGateway)
}
