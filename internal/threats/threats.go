// SPDX-License-Identifier: AGPL-3.0-or-later

// Package threats matches what devices look up and connect to against
// curated threat-intelligence feeds: malware distribution hosts, botnet
// command-and-control addresses, hijacked network ranges. It is the cheap
// kind of threat detection, deliberately: a few hash-set lookups per DNS
// query on data that is a few hundred kilobytes and refreshed every few
// hours. Nothing inspects packets, nothing runs a model, and a match
// raises an alarm rather than blocking anything, because the blocklists
// already block and this exists to say *which device* reached for a known
// bad name or address, blocked or not. See docs/THREATS.md.
package threats

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"shepherd/internal/dnsengine"
)

// Kind is what a feed lists.
type Kind string

const (
	KindDomain Kind = "domain" // host names, one per line or in hosts-file form
	KindIP     Kind = "ip"     // addresses and CIDR prefixes
)

// Feed is one source. Built-in feeds are in Builtin; a feed from the
// configuration has the same shape.
type Feed struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	URL  string `json:"url"`
	// What is on it, in the owner's words: this is what the alarm says.
	Describes string `json:"describes"`
}

// Builtin is the curated set: plain-text, permissively licensed, fetched
// without a key, and maintained by people whose job it is. The address
// feeds are a few hundred kilobytes at most; the name feed (HaGeZi's
// Threat Intelligence Feeds, mini edition) is a few megabytes, the one
// place a broad list earns its size. abuse.ch's URLhaus and ThreatFox
// downloads were built in until 2026-11-01, when they went behind an
// Auth-Key (HTTP 410); its SSL Blacklist was deprecated in January 2025.
func Builtin() []Feed {
	return []Feed{
		{ID: "hagezi-tif", Name: "HaGeZi Threat Intelligence (mini)", Kind: KindDomain, URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", Describes: "a name tied to malware, phishing, scams or botnets"},
		{ID: "ipsum", Name: "IPsum (level 3)", Kind: KindIP, URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", Describes: "an address on at least three public blacklists for attacks, scanning or malware"},
		{ID: "feodo", Name: "Feodo Tracker (abuse.ch)", Kind: KindIP, URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", Describes: "a botnet command-and-control server"},
		{ID: "spamhaus-drop", Name: "Spamhaus DROP", Kind: KindIP, URL: "https://www.spamhaus.org/drop/drop.txt", Describes: "a hijacked or criminal-controlled network"},
	}
}

// FeedStatus is one feed's state for the portal.
type FeedStatus struct {
	Feed
	Count   int       `json:"count"`
	Bytes   int64     `json:"bytes"`
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"`
}

// Match is one device reaching for something on a feed.
type Match struct {
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	DeviceID string    `json:"device_id,omitempty"`
	Device   string    `json:"device,omitempty"`
	// Name is what the device asked for; Indicator is the feed entry that
	// matched (a parent domain, an address, or the prefix an address fell
	// in), and FeedID which feed.
	Name      string `json:"name"`
	Indicator string `json:"indicator"`
	FeedID    string `json:"feed_id"`
	Kind      Kind   `json:"kind"`
	// Action is what the DNS engine did with the query: a blocked lookup is
	// still a device that tried.
	Action string `json:"action"`
}

// Options configures an Engine.
type Options struct {
	// Dir caches each feed as <Dir>/<id>.txt so a restart has data before
	// the first refresh. Empty keeps everything in memory.
	Dir string
	// Feeds defaults to Builtin.
	Feeds []Feed
	// Client fetches feeds; nil uses a two-minute-timeout client.
	Client *http.Client
	// MaxBytes caps one feed download (default DefaultMaxBytes).
	MaxBytes int64
	// OnMatch hears every match, after it is recorded. Called on the DNS
	// path, so it must not block: hand it to the alarm engine's Raise.
	OnMatch func(Match)
	// Now is the clock.
	Now func() time.Time
	// Quiet is how long the same device and indicator are not reported
	// again (default DefaultQuiet). The alarm engine dedupes too; this
	// keeps a chatty beacon from even reaching it.
	Quiet time.Duration
}

const (
	DefaultMaxBytes = 16 << 20
	DefaultQuiet    = time.Hour
	recentMax       = 200
)

// Engine holds the loaded feeds and matches queries against them.
type Engine struct {
	opt Options

	mu       sync.RWMutex
	domains  map[string]string // name -> feed ID
	ips      map[netip.Addr]string
	prefixes []prefixEntry
	status   map[string]*FeedStatus
	recent   []Match
	lastSeen map[string]time.Time // client|indicator -> when last reported
	loadedAt time.Time
}

type prefixEntry struct {
	p    netip.Prefix
	feed string
}

// New builds an Engine with nothing loaded.
func New(o Options) *Engine {
	if o.Feeds == nil {
		o.Feeds = Builtin()
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 2 * time.Minute}
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Quiet <= 0 {
		o.Quiet = DefaultQuiet
	}
	e := &Engine{opt: o, domains: map[string]string{}, ips: map[netip.Addr]string{}, status: map[string]*FeedStatus{}, lastSeen: map[string]time.Time{}}
	for _, f := range o.Feeds {
		e.status[f.ID] = &FeedStatus{Feed: f}
	}
	return e
}

// Feeds lists the configured feeds.
func (e *Engine) Feeds() []Feed { return append([]Feed(nil), e.opt.Feeds...) }

// Status reports every feed's state, in configuration order.
func (e *Engine) Status() []FeedStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]FeedStatus, 0, len(e.opt.Feeds))
	for _, f := range e.opt.Feeds {
		out = append(out, *e.status[f.ID])
	}
	return out
}

// Recent returns the latest matches, newest first, at most 200.
func (e *Engine) Recent() []Match {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Match, len(e.recent))
	for i, m := range e.recent {
		out[len(e.recent)-1-i] = m
	}
	return out
}

// Loaded reports how many indicators are loaded in all.
func (e *Engine) Loaded() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.domains) + len(e.ips) + len(e.prefixes)
}

// parsed is one feed's parsed content.
type parsed struct {
	domains  []string
	ips      []netip.Addr
	prefixes []netip.Prefix
}

// Parse reads a feed in the formats these sources use: one entry per
// line, '#' or ';' comments, hosts-file lines ("127.0.0.1 name" or
// "0.0.0.0 name"), addresses, and CIDR prefixes with trailing comments.
// Lines it cannot read are skipped, not fatal: one bad line in a feed of
// thousands must not empty it.
func Parse(kind Kind, r io.Reader) (parsed, int, error) {
	var out parsed
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	skipped := 0
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch kind {
		case KindDomain:
			name := fields[0]
			if len(fields) >= 2 && (fields[0] == "127.0.0.1" || fields[0] == "0.0.0.0" || fields[0] == "::1" || fields[0] == "::") {
				name = fields[1]
			}
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			if name == "localhost" || name == "localhost.localdomain" || name == "broadcasthost" || !dnsengine.ValidDomain(name) || !strings.Contains(name, ".") {
				skipped++
				continue
			}
			out.domains = append(out.domains, name)
		case KindIP:
			// A CSV feed (first seen, address, port, as abuse.ch's lists
			// are laid out) carries the address in a later column, and
			// its first column may have a space in it.
			candidates := fields[:1]
			if strings.Contains(line, ",") {
				candidates = strings.Split(line, ",")
			}
			found := false
			for _, col := range candidates {
				col = strings.TrimSpace(col)
				if p, err := netip.ParsePrefix(col); err == nil {
					if p.Bits() == p.Addr().BitLen() {
						out.ips = append(out.ips, p.Addr().Unmap())
					} else {
						out.prefixes = append(out.prefixes, p.Masked())
					}
					found = true
					break
				}
				if a, err := netip.ParseAddr(col); err == nil {
					out.ips = append(out.ips, a.Unmap())
					found = true
					break
				}
			}
			if found {
				continue
			}
			skipped++
		default:
			return parsed{}, 0, fmt.Errorf("threats: unknown feed kind %q", kind)
		}
	}
	return out, skipped, sc.Err()
}

// cachePath is where feed id is cached, or "" without a Dir.
func (e *Engine) cachePath(id string) string {
	if e.opt.Dir == "" {
		return ""
	}
	return filepath.Join(e.opt.Dir, id+".txt")
}

// LoadCached loads every feed's cached file, so a restart matches at once.
func (e *Engine) LoadCached() {
	for _, f := range e.opt.Feeds {
		path := e.cachePath(f.ID)
		if path == "" {
			continue
		}
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		r, err := os.Open(path)
		if err != nil {
			continue
		}
		p, _, err := Parse(f.Kind, r)
		r.Close()
		if err != nil {
			continue
		}
		e.install(f, p, fi.Size(), fi.ModTime(), nil)
	}
}

// install replaces feed f's indicators with p and records its status.
func (e *Engine) install(f Feed, p parsed, size int64, at time.Time, fetchErr error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.status[f.ID]
	if fetchErr != nil {
		st.Error = fetchErr.Error()
		return
	}
	for name, id := range e.domains {
		if id == f.ID {
			delete(e.domains, name)
		}
	}
	for ip, id := range e.ips {
		if id == f.ID {
			delete(e.ips, ip)
		}
	}
	kept := e.prefixes[:0:0]
	for _, pe := range e.prefixes {
		if pe.feed != f.ID {
			kept = append(kept, pe)
		}
	}
	e.prefixes = kept
	for _, d := range p.domains {
		e.domains[d] = f.ID
	}
	for _, ip := range p.ips {
		e.ips[ip] = f.ID
	}
	for _, pre := range p.prefixes {
		e.prefixes = append(e.prefixes, prefixEntry{pre, f.ID})
	}
	sort.Slice(e.prefixes, func(i, j int) bool { return e.prefixes[i].p.Bits() > e.prefixes[j].p.Bits() })
	st.Count = len(p.domains) + len(p.ips) + len(p.prefixes)
	st.Bytes = size
	st.Updated = at
	st.Error = ""
	e.loadedAt = at
}

// Refresh downloads every feed, one after another. A feed that fails keeps
// its previous indicators and records the error; one that comes back
// empty is treated as a failure too, since no source here is ever empty.
func (e *Engine) Refresh(ctx context.Context) {
	for _, f := range e.opt.Feeds {
		if ctx.Err() != nil {
			return
		}
		p, size, err := e.fetch(ctx, f)
		if err == nil && len(p.domains)+len(p.ips)+len(p.prefixes) == 0 {
			err = errors.New("the feed came back empty, keeping the previous copy")
		}
		e.install(f, p, size, e.opt.Now(), err)
	}
}

func (e *Engine) fetch(ctx context.Context, f Feed) (parsed, int64, error) {
	var src io.ReadCloser
	if path, ok := strings.CutPrefix(f.URL, "file://"); ok {
		r, err := os.Open(path)
		if err != nil {
			return parsed{}, 0, err
		}
		src = r
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
		if err != nil {
			return parsed{}, 0, err
		}
		req.Header.Set("User-Agent", "shepherd")
		resp, err := e.opt.Client.Do(req)
		if err != nil {
			return parsed{}, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return parsed{}, 0, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
		}
		src = resp.Body
	}
	defer src.Close()

	lr := &io.LimitedReader{R: src, N: e.opt.MaxBytes + 1}
	var body io.Reader = lr
	var tmp *os.File
	if path := e.cachePath(f.ID); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return parsed{}, 0, err
		}
		t, err := os.CreateTemp(filepath.Dir(path), f.ID+".*.tmp")
		if err != nil {
			return parsed{}, 0, err
		}
		tmp = t
		defer os.Remove(t.Name())
		body = io.TeeReader(lr, t)
	}
	p, _, err := Parse(f.Kind, body)
	n := e.opt.MaxBytes + 1 - lr.N
	if n > e.opt.MaxBytes {
		return parsed{}, 0, fmt.Errorf("the feed is larger than the %d MiB cap", e.opt.MaxBytes>>20)
	}
	if err != nil {
		return parsed{}, 0, err
	}
	if tmp != nil {
		if err := tmp.Sync(); err != nil {
			return parsed{}, 0, err
		}
		tmp.Close()
		if err := os.Rename(tmp.Name(), e.cachePath(f.ID)); err != nil {
			return parsed{}, 0, err
		}
	}
	return p, n, nil
}

// Run loads the cache, refreshes now, then every `every`.
func (e *Engine) Run(ctx context.Context, every time.Duration) {
	e.LoadCached()
	e.Refresh(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Refresh(ctx)
		}
	}
}

// Hit is one indicator a query touched.
type Hit struct {
	Indicator string
	FeedID    string
	Kind      Kind
}

// Check matches a name and the addresses it resolved to. The name matches
// itself or any parent on a domain feed (a feed lists "bad.example.com";
// "x.bad.example.com" counts); an address matches exactly or by prefix.
// Pure, so tests can drive it directly.
func (e *Engine) Check(name string, ips []netip.Addr) []Hit {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var hits []Hit
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for n != "" {
		if id, ok := e.domains[n]; ok {
			hits = append(hits, Hit{Indicator: n, FeedID: id, Kind: KindDomain})
			break
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if id, ok := e.ips[ip]; ok {
			hits = append(hits, Hit{Indicator: ip.String(), FeedID: id, Kind: KindIP})
			continue
		}
		for _, pe := range e.prefixes {
			if pe.p.Contains(ip) {
				hits = append(hits, Hit{Indicator: pe.p.String(), FeedID: pe.feed, Kind: KindIP})
				break
			}
		}
	}
	return hits
}

// Observe is the DNS engine's OnEntry hook: every recorded query, allowed
// or blocked, is checked. A match is remembered and handed to OnMatch,
// unless the same client reached the same indicator within Quiet.
func (e *Engine) Observe(entry dnsengine.Entry) {
	ips := make([]netip.Addr, 0, len(entry.Dests))
	for _, d := range entry.Dests {
		if a, err := netip.ParseAddr(d.IP); err == nil {
			ips = append(ips, a)
		}
	}
	hits := e.Check(entry.Name, ips)
	if len(hits) == 0 {
		return
	}
	now := e.opt.Now()
	var report []Match
	e.mu.Lock()
	for _, h := range hits {
		key := entry.Client + "|" + h.Indicator
		if last, ok := e.lastSeen[key]; ok && now.Sub(last) < e.opt.Quiet {
			continue
		}
		e.lastSeen[key] = now
		if len(e.lastSeen) > 4096 {
			for k, t := range e.lastSeen {
				if now.Sub(t) >= e.opt.Quiet {
					delete(e.lastSeen, k)
				}
			}
		}
		m := Match{Time: now, Client: entry.Client, DeviceID: entry.DeviceID, Device: entry.Device,
			Name: entry.Name, Indicator: h.Indicator, FeedID: h.FeedID, Kind: h.Kind, Action: entry.Action}
		e.recent = append(e.recent, m)
		if len(e.recent) > recentMax {
			e.recent = e.recent[len(e.recent)-recentMax:]
		}
		report = append(report, m)
	}
	e.mu.Unlock()
	if e.opt.OnMatch != nil {
		for _, m := range report {
			e.opt.OnMatch(m)
		}
	}
}

// Describe is what a feed says its entries are, for an alarm.
func (e *Engine) Describe(feedID string) string {
	for _, f := range e.opt.Feeds {
		if f.ID == feedID {
			return f.Describes
		}
	}
	return "a known threat"
}
