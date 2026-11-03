// SPDX-License-Identifier: AGPL-3.0-or-later

// Package setup is Shepherd's first-run setup: a small web server that runs
// before there is any configuration, walks the owner through the handful of
// decisions only they can make, and writes shepherd.toml (docs/SETUP.md).
//
// It is a browser flow because that is how installing something should feel:
// start Shepherd, it tells you the address to open, and you finish the setup
// on a page. Shepherd then carries straight on with the configuration it
// just wrote, so nothing has to be restarted by hand.
//
// It is NOT the portal. The portal needs a data directory, a policy store,
// a DNS engine and a token; none of that exists yet on a first run, and the
// portal's own defaults put it on loopback, which is unreachable from the
// laptop of whoever is installing Shepherd on a NAS or a Pi. So setup brings
// up its own listener, on every address this host has, protected by a
// one-time token that is printed on the console — the one place that proves
// you are the person who started the process. It shuts down the moment setup
// finishes.
//
// It does not repeat scripts/shepherd-doctor either: that is a read-only
// preflight of the host (ports held, IPv6, link speeds, container runtime)
// and changes nothing. Setup asks the questions and writes the file, and
// points at the doctor where a host check is what is actually wanted.
package setup

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The setup page and its assets. Every file served has to be listed here:
// an asset missing from this directive is a 404 at runtime that no test
// catches, which has bitten this repository before.
//
//go:embed web/index.html web/setup.css web/setup.js
var webFS embed.FS

// Server is the first-run setup flow. The function fields are its only
// contact with the world, which is what lets the tests drive the whole thing
// with no network and no host dependency; cmd/shepherd fills them in.
type Server struct {
	// ConfigPath is the file to write, "shepherd.toml" by convention.
	ConfigPath string

	// HostAddrs lists the addresses this host could serve DNS on. Setup
	// offers all of them, because the most common way a new install
	// fails is Shepherd listening on one address (the Wi-Fi one) while a
	// device or the router is pointed at another (the wired one).
	HostAddrs func() ([]Addr, error)
	// PortFree reports whether host:port can be bound right now over both
	// UDP and TCP. A false answer is a warning, never a refusal: setup
	// cannot know whether the holder is a resolver about to be stopped.
	PortFree func(host string, port int) bool
	// TestUpstream probes one resolver exactly as the portal's own test
	// button does, so an unreachable one is caught here rather than after
	// the first restart.
	TestUpstream func(ctx context.Context, addr string) error
	// ConnectRouter verifies and stores a UniFi controller for the
	// optional bandwidth step. Nil in a build that cannot read a router,
	// and the page then says so instead of offering it.
	ConnectRouter func(ctx context.Context, dataDir string, c RouterConn) error
	// SaveDNSToken checks a Cloudflare API token against the zone the
	// chosen hostname is in -- read-only lookups, nothing published --
	// and, if it works, keeps it as the portal-managed DNS provider
	// credential. It is how setup can offer HTTPS (and so passkeys) at
	// all: a token that cannot edit that zone is a certificate that will
	// never be issued, and finding that out now beats finding it out in
	// a log an hour later. Nil leaves the step unoffered.
	SaveDNSToken func(ctx context.Context, dataDir, hostname, token string) error

	// DataDir is where Shepherd will keep its state. It is worked out
	// from the configuration file's own directory rather than asked
	// about: "data" beside shepherd.toml is right for every install this
	// page is for, and a path typed into a web page is both a question
	// nobody can answer better than Shepherd and a path this process
	// would then create and write to on a stranger's say-so. The page
	// shows it, with whether it is writable, and nothing it sends can
	// change it.
	DataDir string

	// Categories are the network-wide blocking choices the page offers.
	// They come from the shipped catalog, which is known before anything
	// starts; switching them on needs the running policy, which arrives
	// later in Running.SetCategories.
	Categories []Category

	// Token gates every request. Empty means NewServer generates one.
	Token string

	// done is closed once the configuration has been written, which is
	// what Run waits for.
	done chan struct{}
	// written is the path actually written, for the log line.
	written string

	mu      sync.Mutex
	port    string // the port Run is actually listening on
	running *Running
	closed  chan struct{}
	srv     *http.Server
}

// Started hands setup the Shepherd that is now running on the file it
// wrote. Everything the second half of the page does needs it.
func (s *Server) Started(r Running) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = &r
}

func (s *Server) runningNow() *Running {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Close stops serving. Safe to call more than once, and from any
// goroutine: cmd/shepherd defers it, and the page's "I am done" calls it.
func (s *Server) Close() {
	s.mu.Lock()
	srv, closed := s.srv, s.closed
	s.srv = nil
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	if closed != nil {
		select {
		case <-closed:
		default:
			close(closed)
		}
	}
}

// Port is the port setup is serving on, empty before Run has started. It is
// read while Run is serving, hence the lock.
func (s *Server) Port() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// Running is what cmd/shepherd hands setup once Shepherd itself is up on
// the configuration just written. It is what turns the second half of the
// page from instructions into something that can be checked: DNS is proved
// by asking Shepherd's own listeners, the portal token is shown where the
// owner already is, and a category switched on here is switched on in the
// running policy.
//
// It is nil for "shepherd setup" run on its own, where nothing starts
// afterwards; the page then says so instead of pretending.
type Running struct {
	// PortalURL is where the portal is listening, for the link.
	PortalURL string
	// Token is the portal's access token. It is shown on the page behind
	// a reveal, and the page makes the owner say they have kept it before
	// it moves on: it is the only way back in, and a fresh install's
	// owner has no other copy of it yet.
	Token string
	// Verify asks Shepherd's own listeners a known-good and a
	// known-blocked name, over UDP and TCP (internal/selftest). It is how
	// the page proves filtering works rather than telling the owner to go
	// and run dig.
	Verify func(ctx context.Context) []ListenerCheck
	// SetCategories switches the chosen categories on at network scope.
	// Nil when there is no policy store to put them in.
	SetCategories func(ids []string) error
	// TLSURL is the portal's own HTTPS address, empty when [tls] is off.
	// It is where a passkey can be registered, and nowhere else: WebAuthn
	// binds a passkey to exactly that name (docs/PASSKEYS.md).
	TLSURL string
	// CertReady reports whether a certificate has actually been obtained
	// yet, and what to say while it has not. The first one takes a minute
	// or two over DNS-01, which is long enough that a page saying nothing
	// looks broken.
	CertReady func() (bool, string)
}

// ListenerCheck is one address's verification: whether it answered at all,
// resolved a name that must resolve, and blocked a name that must be
// blocked.
type ListenerCheck struct {
	Addr    string `json:"addr"`
	Proto   string `json:"proto"`
	Answers bool   `json:"answers"`
	Resolve bool   `json:"resolve"`
	Blocks  bool   `json:"blocks"`
	Detail  string `json:"detail,omitempty"`
}

// Category is one network-wide blocking choice offered during setup.
type Category struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Suggested marks the ones a new install usually wants, which the
	// page ticks for them.
	Suggested bool `json:"suggested"`
}

// RouterConn is the UniFi controller the optional bandwidth step collects.
// Only UniFi is offered: an eero account signs in with a code emailed at the
// time, which belongs in the portal's own flow rather than in a setup page
// that runs before Shepherd has ever started.
type RouterConn struct {
	BaseURL         string `json:"base_url"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	Site            string `json:"site"`
	AllowSelfSigned bool   `json:"allow_self_signed"`
}

// NewServer prepares s: it fills in the defaults, generates the one-time
// token when none was given, and must be called before Handler or Run.
func NewServer(s *Server) (*Server, error) {
	if s.ConfigPath == "" {
		s.ConfigPath = "shepherd.toml"
	}
	if s.HostAddrs == nil {
		s.HostAddrs = HostAddrs
	}
	if s.PortFree == nil {
		s.PortFree = PortFree
	}
	if s.DataDir == "" {
		s.DataDir = filepath.Join(filepath.Dir(s.ConfigPath), "data")
	}
	if s.Token == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		s.Token = hex.EncodeToString(raw)
	}
	s.done = make(chan struct{})
	s.closed = make(chan struct{})
	return s, nil
}

// Run serves setup and returns the path it wrote as soon as the owner
// presses Finish. It keeps serving afterwards, because the second half of
// the page -- proving DNS works, handing over the portal token, switching
// categories on, pointing the router here -- can only happen once Shepherd
// is running on that file. The caller starts Shepherd, calls Started, and
// defers Close.
//
// It listens on addr: every address of this host, by convention, since the
// whole point is being reachable from the machine the owner is sitting at.
//
// An empty return with no error means ctx ended first: the caller should
// carry on with whatever configuration it already had.
func (s *Server) Run(ctx context.Context, addr string, logf func(string, ...any)) (string, error) {
	if logf == nil {
		logf = log.Printf
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("setup: cannot listen on %s: %w", addr, err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	s.mu.Lock()
	s.port, s.srv = port, srv
	s.mu.Unlock()
	errc := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	go func() {
		// Whatever ends first -- the owner finishing the whole flow, or
		// the process being asked to stop -- the listener goes.
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.closed:
		}
	}()

	logf("setup: no configuration yet, so Shepherd is waiting for you to finish setting it up.")
	logf("setup: open one of these in a browser (the token is what proves it is you):")
	for _, u := range s.URLs(port) {
		logf("setup:   %s", u)
	}
	logf("setup: nothing is written until you finish, and this page stays up until you are done with it.")

	select {
	case <-s.done:
		return s.written, nil
	case err := <-errc:
		return "", err
	case <-ctx.Done():
		return "", nil
	}
}

// URLs are the addresses to open, loopback first (always true) and then each
// LAN address, which is what someone on another machine needs.
func (s *Server) URLs(port string) []string {
	out := []string{"http://" + net.JoinHostPort("127.0.0.1", port) + "/?token=" + s.Token}
	addrs, err := s.HostAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		out = append(out, "http://"+net.JoinHostPort(a.IP, port)+"/?token="+s.Token)
	}
	return out
}

// Handler is the setup page and its small API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(webFS, "web")
	// The stylesheet and the script hold nothing about this host, and the
	// page has to load them before any JavaScript of ours has run, so
	// they are the one thing here that is not behind the token.
	mux.Handle("GET /setup.css", http.FileServerFS(assets))
	mux.Handle("GET /setup.js", http.FileServerFS(assets))
	mux.Handle("GET /", s.gate(http.HandlerFunc(s.page)))
	mux.Handle("GET /api/setup/state", s.gate(http.HandlerFunc(s.state)))
	mux.Handle("POST /api/setup/upstream-test", s.gate(http.HandlerFunc(s.upstreamTest)))
	mux.Handle("POST /api/setup/upstream-rank", s.gate(http.HandlerFunc(s.upstreamRank)))
	mux.Handle("POST /api/setup/port-check", s.gate(http.HandlerFunc(s.portCheck)))
	mux.Handle("POST /api/setup/router", s.gate(http.HandlerFunc(s.router)))
	mux.Handle("POST /api/setup/dns-token", s.gate(http.HandlerFunc(s.dnsToken)))
	mux.Handle("POST /api/setup/finish", s.gate(http.HandlerFunc(s.finish)))
	mux.Handle("GET /api/setup/running", s.gate(http.HandlerFunc(s.runningState)))
	mux.Handle("POST /api/setup/verify", s.gate(http.HandlerFunc(s.verify)))
	mux.Handle("GET /api/setup/token", s.gate(http.HandlerFunc(s.portalToken)))
	mux.Handle("POST /api/setup/categories", s.gate(http.HandlerFunc(s.categories)))
	mux.Handle("GET /api/setup/certificate", s.gate(http.HandlerFunc(s.certificate)))
	mux.Handle("POST /api/setup/done", s.gate(http.HandlerFunc(s.finished)))
	return mux
}

// gate requires the one-time token, from the ?token= in the printed URL or
// from the X-Shepherd-Setup header the page sends afterwards, so the rest of
// the network cannot configure this Shepherd while setup is up. It is
// compared in constant time, and a wrong one is a flat 403 with no hint.
//
// The token is deliberately not put in a cookie: setup is plain HTTP (there
// is no certificate yet and cannot be), and a cookie would be stored by the
// browser and sent on every later request to this host and port -- which,
// once setup finishes, is the portal. Keeping it in the page's memory and
// sending it as a header leaves nothing behind.
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get(tokenHeader)
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) != 1 {
			http.Error(w, "Open the address Shepherd printed on the console: it carries the setup token.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenHeader is how the page proves itself after the first load.
const tokenHeader = "X-Shepherd-Setup"

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil { // only possible if the embed directive lost the file
		http.Error(w, "the setup page is missing from this build", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

// stateJSON is everything the page needs to draw itself: what this host
// looks like, and the defaults every field starts on.
type stateJSON struct {
	ConfigPath   string      `json:"config_path"`
	ConfigExists bool        `json:"config_exists"`
	Addrs        []Addr      `json:"addrs"`
	AddrsError   string      `json:"addrs_error,omitempty"`
	Candidates   []Candidate `json:"candidates"`
	DataDir      string      `json:"data_dir"`
	DataDirError string      `json:"data_dir_error,omitempty"`
	DNSPort      int         `json:"dns_port"`
	PortalPort   int         `json:"portal_port"`
	PortalHost   string      `json:"portal_host"`
	DNSPortFree  bool        `json:"dns_port_free"`
	CanRouter    bool        `json:"can_router"`
	CanTLS       bool        `json:"can_tls"`
	TLSPort      int         `json:"tls_port"`
	Categories   []Category  `json:"categories"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	out := stateJSON{ConfigPath: s.ConfigPath, Candidates: Candidates,
		DataDir: s.DataDir, DNSPort: 53, PortalPort: 8787, PortalHost: "127.0.0.1",
		CanRouter: s.ConnectRouter != nil, Categories: s.Categories,
		CanTLS: s.SaveDNSToken != nil, TLSPort: 8443}
	// Checked here rather than left for the owner to discover at the end:
	// a directory Shepherd cannot write is the one thing about this step
	// that can go wrong, and it is better said on the page than in a
	// startup error after they have walked away.
	if err := os.MkdirAll(s.DataDir, 0o750); err != nil {
		out.DataDirError = err.Error()
	}
	if _, err := os.Stat(s.ConfigPath); err == nil {
		out.ConfigExists = true
	}
	addrs, err := s.HostAddrs()
	if err != nil {
		out.AddrsError = err.Error()
	}
	out.Addrs = addrs
	out.DNSPortFree = s.portFreeEverywhere(addrs, 53)
	writeJSON(w, out)
}

// portFreeEverywhere reports whether port is free on every offered address.
// One address already answering is enough to warn about: that is where the
// resolver being replaced is listening.
func (s *Server) portFreeEverywhere(addrs []Addr, port int) bool {
	for _, a := range addrs {
		if !s.PortFree(a.IP, port) {
			return false
		}
	}
	return true
}

func (s *Server) upstreamTest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Addr string `json:"addr"`
	}
	if !decodeBody(w, r, &b) {
		return
	}
	if s.TestUpstream == nil {
		writeJSON(w, map[string]any{"ok": false, "error": "this build cannot test a resolver"})
		return
	}
	// Twice before giving up: public resolvers drop the odd uncached
	// query, and one lost packet is not a reason to send someone off to
	// debug a resolver that works.
	start := time.Now()
	err := s.TestUpstream(r.Context(), b.Addr)
	if err != nil {
		start = time.Now()
		err = s.TestUpstream(r.Context(), b.Addr)
	}
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "ms": time.Since(start).Milliseconds()})
}

// upstreamRank measures every candidate from this host and returns them
// ranked, with the numbers the ranking was made from. The page shows those
// numbers: a recommendation nobody can check is just another opinion.
func (s *Server) upstreamRank(w http.ResponseWriter, r *http.Request) {
	// Bounded, because the page is waiting on it: a candidate that is
	// simply unreachable must not hold the whole measurement open.
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	writeJSON(w, map[string]any{"results": Measure(ctx, Candidates, s.TestUpstream)})
}

// portCheck is what the page calls when the port is changed, so "something
// already answers there" is said while it can still be acted on.
func (s *Server) portCheck(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Port  int      `json:"port"`
		Addrs []string `json:"addrs"`
	}
	if !decodeBody(w, r, &b) {
		return
	}
	if b.Port < 1 || b.Port > 65535 {
		http.Error(w, "that is not a port number", http.StatusBadRequest)
		return
	}
	var held []string
	for _, a := range b.Addrs {
		if !s.PortFree(a, b.Port) {
			held = append(held, a)
		}
	}
	writeJSON(w, map[string]any{"free": len(held) == 0, "held": held})
}

// router verifies a UniFi controller and keeps it, which needs the data
// directory the owner has chosen (the credentials go into its secrets.json,
// never into shepherd.toml).
func (s *Server) router(w http.ResponseWriter, r *http.Request) {
	var b RouterConn
	if !decodeBody(w, r, &b) {
		return
	}
	if s.ConnectRouter == nil {
		notFound(w, "this build cannot read bandwidth from a router")
		return
	}
	// The directory is Shepherd's own, never one the request names.
	if err := s.ConnectRouter(r.Context(), s.DataDir, b); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// dnsToken checks the owner's Cloudflare token against the zone their
// chosen hostname is in and, if it works, keeps it. The token never goes
// into shepherd.toml: it lands in the data directory's secrets.json, which
// is where the portal manages it from then on, so the file setup writes
// can be read, copied and kept in version control like any other.
func (s *Server) dnsToken(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Hostname string `json:"hostname"`
		Token    string `json:"token"`
	}
	if !decodeBody(w, r, &b) {
		return
	}
	if s.SaveDNSToken == nil {
		notFound(w, "this build cannot set up HTTPS")
		return
	}
	host := strings.TrimSpace(b.Hostname)
	if err := checkHostname(host); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if strings.TrimSpace(b.Token) == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "the API token is empty"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.SaveDNSToken(ctx, s.DataDir, host, b.Token); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// certificate is what the second half of the page polls while Let's
// Encrypt is being asked: the first certificate takes a minute or two over
// DNS-01, and a page that said nothing for that long would look broken.
func (s *Server) certificate(w http.ResponseWriter, r *http.Request) {
	run := s.runningNow()
	if run == nil || run.TLSURL == "" {
		writeJSON(w, map[string]any{"configured": false})
		return
	}
	out := map[string]any{"configured": true, "url": run.TLSURL, "ready": false}
	if run.CertReady != nil {
		ready, detail := run.CertReady()
		out["ready"], out["detail"] = ready, detail
	}
	writeJSON(w, out)
}

// finish writes the file. It is the only thing here that changes anything
// outside the data directory, and it is the last step on purpose: an
// abandoned setup leaves nothing behind.
func (s *Server) finish(w http.ResponseWriter, r *http.Request) {
	var a Answers
	if !decodeBody(w, r, &a) {
		return
	}
	// Whatever the page sent, the state goes where this process decided
	// it goes: nothing a request carries becomes a path Shepherd creates.
	a.DataDir = s.DataDir
	// Setup keeps serving while Shepherd starts, so the two listeners
	// exist at once and the portal cannot have this port.
	if p := s.Port(); p != "" && p == strconv.Itoa(a.PortalPort) {
		http.Error(w, "the setup page is using port "+p+" while it walks you through the rest; give the portal another port", http.StatusBadRequest)
		return
	}
	if err := a.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(s.DataDir, 0o750); err != nil {
		http.Error(w, "Shepherd's data directory cannot be used: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := os.Stat(s.ConfigPath); err == nil {
		// Replacing is the owner's call (the page asks), but the old
		// file is always kept: it may hold settings this page never
		// asked about.
		old, err := os.ReadFile(s.ConfigPath)
		if err != nil {
			http.Error(w, "the existing configuration could not be read: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(s.ConfigPath+".bak", old, 0o600); err != nil {
			http.Error(w, "the existing configuration could not be backed up: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := os.WriteFile(s.ConfigPath, []byte(Render(a)), 0o600); err != nil {
		http.Error(w, "the configuration could not be written: "+err.Error(), http.StatusInternalServerError)
		return
	}
	abs, _ := filepath.Abs(s.ConfigPath)
	writeJSON(w, map[string]any{
		"written":    s.ConfigPath,
		"portal":     "http://" + joinHostPort(a.PortalHost, a.PortalPort),
		"dig":        a.digHint(),
		"token_file": filepath.Join(a.DataDir, "portal-token"),
		"absolute":   abs,
	})
	s.written = s.ConfigPath
	// Closing this hands control back to cmd/shepherd, which starts
	// everything on the configuration just written. Guarded because a
	// second finish would otherwise panic on a closed channel.
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// runningState is what the second half of the page polls after Finish: it
// is how it knows Shepherd came up, and what it can offer.
func (s *Server) runningState(w http.ResponseWriter, r *http.Request) {
	run := s.runningNow()
	if run == nil {
		writeJSON(w, map[string]any{"running": false})
		return
	}
	writeJSON(w, map[string]any{
		"running":     true,
		"portal":      run.PortalURL,
		"can_verify":  run.Verify != nil,
		"can_block":   run.SetCategories != nil,
		"token_ready": run.Token != "",
	})
}

// verify asks Shepherd's own listeners a name that must resolve and one
// that must be blocked, over UDP and TCP. Proving it here is the point: a
// listener that works for this host and not for the network is the failure
// everything else in this page is arranged to prevent, and "run dig from
// another machine" is advice most people will not take.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	run := s.runningNow()
	if run == nil || run.Verify == nil {
		writeJSON(w, map[string]any{"ready": false})
		return
	}
	checks := run.Verify(r.Context())
	ok := len(checks) > 0
	for _, c := range checks {
		if !c.Answers || !c.Resolve || !c.Blocks {
			ok = false
		}
	}
	writeJSON(w, map[string]any{"ready": true, "ok": ok, "checks": checks})
}

// portalToken hands over the portal's access token. It is behind the setup
// token like everything else here, and the page says plainly that it is
// coming over plain HTTP on the LAN, so an owner who would rather read it
// out of the data directory can.
func (s *Server) portalToken(w http.ResponseWriter, r *http.Request) {
	run := s.runningNow()
	if run == nil || run.Token == "" {
		notFound(w, "Shepherd is not running yet, so it has no token to show")
		return
	}
	writeJSON(w, map[string]any{"token": run.Token, "portal": run.PortalURL})
}

// categories switches the chosen network-wide blocking on, in the policy
// the portal owns from now on, so the choice made here is the same object
// the Blocking screen edits later rather than a copy in the config file.
func (s *Server) categories(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []string `json:"ids"`
	}
	if !decodeBody(w, r, &b) {
		return
	}
	run := s.runningNow()
	if run == nil || run.SetCategories == nil {
		notFound(w, "Shepherd is not running yet, so there is no policy to change")
		return
	}
	if err := run.SetCategories(b.IDs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"blocked": b.IDs})
}

// finished is the owner saying they are done with this page, which is the
// only thing that takes the setup listener down once Shepherd is up.
func (s *Server) finished(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"closed": true})
	go s.Close() // after the answer has been written
}

func notFound(w http.ResponseWriter, msg string) { http.Error(w, msg, http.StatusNotFound) }

// Done reports the channel Run waits on, for a caller that wants to know
// setup finished without owning the listener.
func (s *Server) Done() <-chan struct{} { return s.done }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// decodeBody reads a small JSON body, answering 400 itself when it cannot.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "the request was too large or could not be read", http.StatusBadRequest)
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		http.Error(w, "that was not valid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
