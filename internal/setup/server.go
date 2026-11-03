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

	// DataDir is where Shepherd will keep its state. It is worked out
	// from the configuration file's own directory rather than asked
	// about: "data" beside shepherd.toml is right for every install this
	// page is for, and a path typed into a web page is both a question
	// nobody can answer better than Shepherd and a path this process
	// would then create and write to on a stranger's say-so. The page
	// shows it, with whether it is writable, and nothing it sends can
	// change it.
	DataDir string

	// Token gates every request. Empty means NewServer generates one.
	Token string

	// done is closed once the configuration has been written, which is
	// what Run waits for.
	done chan struct{}
	// written is the path actually written, for the log line.
	written string

	mu   sync.Mutex
	port string // the port Run is actually listening on
}

// Port is the port setup is serving on, empty before Run has started. It is
// read while Run is serving, hence the lock.
func (s *Server) Port() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
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
	return s, nil
}

// Run serves setup until the configuration has been written (or ctx ends)
// and returns the path it wrote. It listens on addr — every address of this
// host, by convention, since the whole point is being reachable from the
// machine the owner is sitting at — and prints the URLs to open.
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
	s.mu.Lock()
	s.port = port
	s.mu.Unlock()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	defer srv.Close()

	logf("setup: no configuration yet, so Shepherd is waiting for you to finish setting it up.")
	logf("setup: open one of these in a browser (the token is what proves it is you):")
	for _, u := range s.URLs(port) {
		logf("setup:   %s", u)
	}
	logf("setup: nothing is written until you finish, and this listener stops as soon as you do.")

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
	mux.Handle("POST /api/setup/port-check", s.gate(http.HandlerFunc(s.portCheck)))
	mux.Handle("POST /api/setup/router", s.gate(http.HandlerFunc(s.router)))
	mux.Handle("POST /api/setup/finish", s.gate(http.HandlerFunc(s.finish)))
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
	ConfigPath   string   `json:"config_path"`
	ConfigExists bool     `json:"config_exists"`
	Addrs        []Addr   `json:"addrs"`
	AddrsError   string   `json:"addrs_error,omitempty"`
	Presets      []Preset `json:"presets"`
	DataDir      string   `json:"data_dir"`
	DataDirError string   `json:"data_dir_error,omitempty"`
	DNSPort      int      `json:"dns_port"`
	PortalPort   int      `json:"portal_port"`
	PortalHost   string   `json:"portal_host"`
	DNSPortFree  bool     `json:"dns_port_free"`
	CanRouter    bool     `json:"can_router"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	out := stateJSON{ConfigPath: s.ConfigPath, Presets: Presets,
		DataDir: s.DataDir, DNSPort: 53, PortalPort: 8787, PortalHost: "127.0.0.1",
		CanRouter: s.ConnectRouter != nil}
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
		http.Error(w, "this build cannot read bandwidth from a router", http.StatusNotFound)
		return
	}
	// The directory is Shepherd's own, never one the request names.
	if err := s.ConnectRouter(r.Context(), s.DataDir, b); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
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
