// SPDX-License-Identifier: AGPL-3.0-or-later

// Package portal serves Shepherd's web interface and JSON API. Everything the
// underlying engines can do is controlled from here.
package portal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"shepherd/internal/accountability"
	"shepherd/internal/alarms"
	"shepherd/internal/arp"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/geo"
	"shepherd/internal/importers"
	"shepherd/internal/nethealth"
	"shepherd/internal/portscan"
	"shepherd/internal/reverseproxy"
	"shepherd/internal/settings"
	"shepherd/internal/vulnscan"
)

// Only what the browser needs is embedded: the page, its modules and vendored
// libraries. The unit tests under web/test stay out of the binary.
//
//go:embed web/index.html web/app.js web/style.css web/icon.png web/js web/vendor
var webFS embed.FS

const cookieName = "shepherd_session"

// GeoStatus reports the state of the map data.
type GeoStatus interface{ Status() geo.Status }

// ARPStatus reports the passive ARP monitor's counters.
type ARPStatus interface{ Stats() arp.Stats }

type Deps struct {
	Engine *dnsengine.Engine
	Lists  *dnsengine.ListManager
	// Policy owns the blocking policy: the catalog, custom lists, and the
	// switches, allow and block rules at network, group and device scope.
	Policy  *dnsengine.PolicyStore
	Token   string
	Version string
	// GeoBlock owns the per-scope blocked-country lists, an additive check
	// layered outside Policy (see dnsengine.Engine.CountryBlock). Nil gets a
	// memory-only store, so the API still works but nothing persists.
	GeoBlock *dnsengine.GeoBlockStore

	// Devices is the device registry. Nil gives an empty registry that no
	// source feeds (the API still works).
	Devices *devices.Registry
	// Upstreams edits the upstream list and persists the edits. Nil edits
	// Engine.Pool in memory only.
	Upstreams *dnsengine.UpstreamStore

	// History serves past entries. Nil means the in-memory ring.
	History dnsengine.HistorySource
	// Settings stores the home location. Nil keeps it in memory only.
	Settings *settings.Store
	// Geo reports map data status. Nil means the map is disabled.
	Geo GeoStatus
	// ARP reports the passive ARP monitor's counters. Nil means ARP
	// monitoring is disabled, unsupported on this platform, or lacks the
	// capability it needs.
	ARP ARPStatus
	// DetectHome re-detects the automatic home now (nil when automatic home is off).
	DetectHome func(ctx context.Context) error
	// Heartbeat is how often the live stream sends a keep-alive (default 15s).
	Heartbeat time.Duration

	// NewEeroClient builds the eero API client for one import flow (see
	// api_import.go). Nil talks to production eero over https; tests point it
	// at a fake server with importers.NewTestClient.
	NewEeroClient func() (*importers.Client, error)

	// Alarms is the alarm engine (docs/ALARMS.md). Nil gives an unwired,
	// in-memory engine that nothing raises alarms through, so the API still
	// works (and returns no alarms).
	Alarms *alarms.Engine

	// Accountability manages accountability-partner contacts and
	// subscriptions (docs/ACCOUNTABILITY.md). Nil means the feature is not
	// wired up (see cmd/shepherd's startAccountability): the API answers 404
	// for every /api/accountability/... route instead of panicking.
	Accountability *accountability.Engine

	// Portscan runs and remembers the gentle TCP port scans of known devices
	// (docs/PORTSCAN.md). Nil gives a scanner that works (a manual scan is
	// still possible) but is never run on a schedule and persists nothing.
	Portscan *portscan.Scanner
	// PortscanEnabled reports whether cmd/shepherd started Portscan's
	// scheduled scan, for the status endpoint; it carries no behavior of its
	// own here.
	PortscanEnabled bool

	// DataDir is where locking.json (the idle-lock override, the PIN and the
	// trusted-browser registry) is persisted. Empty keeps it in memory only.
	DataDir string
	// IdleLockMinutes is the configured default idle-lock timeout (0 = never).
	// A value saved from the portal's own settings screen wins over it.
	IdleLockMinutes int

	// Vulnscan runs and remembers the gentle vulnerability-signature probes
	// of ports Portscan found open (docs/VULNSCAN.md). Nil gives a scanner
	// that works (a manual scan is still possible, though it will have
	// nothing to probe without Portscan feeding it) but is never run on a
	// schedule and persists nothing.
	Vulnscan *vulnscan.Scanner
	// VulnscanEnabled reports whether cmd/shepherd started Vulnscan's
	// scheduled scan, for the status endpoint.
	VulnscanEnabled bool

	// Nethealth probes and remembers latency/jitter/loss/reachability and
	// bufferbloat history (docs/NETHEALTH.md). Nil gives a prober that
	// works (a manual probe is still possible) but is never run on a
	// schedule and persists nothing.
	Nethealth *nethealth.Prober
	// NethealthTargets is the target list cmd/shepherd computed for
	// Nethealth at startup (the configured DNS upstreams plus the public
	// resolvers and, when available, the default gateway — see
	// cmd/shepherd/nethealth.go). It is what a manual "probe now"/"run
	// bufferbloat test now" uses when Nethealth has not completed a
	// scheduled probe yet (including when the schedule is disabled
	// entirely, the default — see docs/NETHEALTH.md). Empty when cmd/
	// shepherd did not wire this feature in at all.
	NethealthTargets []string
	// NethealthEnabled reports whether cmd/shepherd started Nethealth's
	// scheduled probe, for the status endpoint.
	NethealthEnabled bool
	// NethealthBufferbloatEnabled reports whether cmd/shepherd also started
	// the separate, less frequent bufferbloat check.
	NethealthBufferbloatEnabled bool

	// ReverseProxy holds the hosts the [reverseproxy] listener forwards
	// (docs/REVERSEPROXY.md). Nil gets a memory-only store, so the API
	// still works but nothing persists.
	ReverseProxy *reverseproxy.Store
	// ReverseProxyStatus describes that listener; the zero value is "off".
	ReverseProxyStatus ReverseProxyStatus
}

type Server struct {
	Deps
	started time.Time
	mux     *http.ServeMux

	mu      sync.Mutex
	memHome *settings.Home // used when no settings store is configured

	importSessions *eeroSessions

	clock     func() time.Time
	sleep     func(time.Duration)
	sessions  *sessionStore
	lockStore *lockStore
	// pinArgonTime/pinArgonMem override the PIN's Argon2id cost; zero (the
	// production default) uses pinParams' strong default. Tests lower this.
	pinArgonTime, pinArgonMem uint32
}

// LoadOrCreateToken returns the portal access token stored in dir, creating a
// random one on first run.
func LoadOrCreateToken(dir string) (string, error) {
	path := filepath.Join(dir, "portal-token")
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); len(t) >= 32 {
			return t, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	return tok, os.WriteFile(path, []byte(tok+"\n"), 0o600)
}

func New(d Deps) *Server {
	if d.History == nil {
		d.History = dnsengine.MemoryHistory{Log: d.Engine.Log}
	}
	if d.Devices == nil {
		d.Devices = devices.New(devices.Options{})
	}
	if d.Upstreams == nil {
		d.Upstreams = dnsengine.OpenUpstreamStore("", d.Engine.Pool)
	}
	if d.Portscan == nil {
		d.Portscan = portscan.New(portscan.Options{})
	}
	if d.GeoBlock == nil {
		d.GeoBlock, _ = dnsengine.OpenGeoBlockStore("") // empty path never errors
	}
	if d.Vulnscan == nil {
		d.Vulnscan = vulnscan.New(vulnscan.Options{})
	}
	if d.Nethealth == nil {
		d.Nethealth = nethealth.New(nethealth.Options{})
	}
	if d.ReverseProxy == nil {
		d.ReverseProxy, _ = reverseproxy.Open("") // empty path never errors
	}
	if d.Heartbeat <= 0 {
		d.Heartbeat = 15 * time.Second
	}
	if d.Alarms == nil {
		d.Alarms, _ = alarms.New(alarms.Options{}) // in-memory; zero Options never errors
	}
	s := &Server{Deps: d, started: time.Now(), mux: http.NewServeMux(), importSessions: newEeroSessions()}
	s.clock = time.Now
	s.sleep = time.Sleep
	s.sessions = newSessionStore()
	lockPath := ""
	if d.DataDir != "" {
		lockPath = filepath.Join(d.DataDir, "locking.json")
	}
	s.lockStore = openLockStore(lockPath, tokenHash(d.Token))
	sub, _ := fs.Sub(webFS, "web")
	s.mux.Handle("GET /", http.FileServerFS(sub))
	s.mux.HandleFunc("POST /api/login", s.login)
	s.mux.HandleFunc("POST /api/login/pin", s.loginPIN)
	s.mux.Handle("POST /api/lock", s.auth(s.lockSession))
	s.mux.Handle("POST /api/pin", s.auth(s.setPIN))
	s.mux.Handle("DELETE /api/pin", s.auth(s.clearPIN))
	s.mux.Handle("POST /api/pin/trust", s.auth(s.trustPIN))
	s.mux.Handle("GET /api/trusted-devices", s.auth(s.listTrustedDevices))
	s.mux.Handle("DELETE /api/trusted-devices/{id}", s.auth(s.revokeTrustedDevice))
	// status, queries and stream are polled automatically; they must not
	// themselves count as activity or idle locking would never trigger while
	// a tab merely sits open (see sessionStore.valid).
	s.mux.Handle("GET /api/status", s.authPassive(s.status))
	s.mux.Handle("GET /api/queries", s.authPassive(s.queries))
	s.mux.Handle("GET /api/rules", s.auth(s.getRules))
	s.mux.Handle("POST /api/rules", s.auth(s.addRule))
	s.mux.Handle("DELETE /api/rules", s.auth(s.delRule))
	s.mux.Handle("POST /api/policies", s.auth(s.setPolicy))
	s.mux.Handle("POST /api/lists/refresh", s.auth(s.refreshLists))
	s.routes()
	s.mux.Handle("GET /api/stream", s.authPassive(s.stream))
	s.mux.Handle("GET /api/history", s.auth(s.historyQuery))
	s.mux.Handle("POST /api/history/unlock", s.auth(s.historyUnlock))
	s.mux.Handle("GET /api/settings", s.auth(s.getSettings))
	s.mux.Handle("POST /api/settings/home", s.auth(s.setHome))
	s.mux.Handle("DELETE /api/settings/home", s.auth(s.resetHome))
	s.mux.Handle("POST /api/settings/home/detect", s.auth(s.detectHome))
	s.mux.Handle("POST /api/settings/locking", s.auth(s.setLockingSettings))
	return s
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Handler returns the portal with security headers applied.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		s.mux.ServeHTTP(w, r)
	})
}

// authorized checks the Authorization header (a stateless comparison against
// the token, used by scripts and the command line, never affected by idle
// locking) or the session cookie (a server-side session, subject to idle
// locking). active is false for routes that are polled automatically: they
// may ride an existing session, but must not themselves extend it, or a tab
// merely left open would never go idle. See sessionStore.valid vs touch.
func (s *Server) authorized(r *http.Request, active bool) bool {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return subtle.ConstantTimeCompare([]byte(h[len("Bearer "):]), []byte(s.Token)) == 1
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	now := s.clock()
	if !s.sessions.valid(c.Value, s.idleLockMinutes(), now) {
		return false
	}
	if active {
		s.sessions.touch(c.Value, now)
	}
	return true
}

// auth requires a valid token or session, sliding the session's idle window
// forward. Anything that changes state must also carry the X-Shepherd
// header, which a cross-site request cannot add without a CORS preflight
// (the portal answers none).
func (s *Server) auth(next http.HandlerFunc) http.Handler { return s.authMiddleware(next, true) }

// authPassive is like auth but never extends a session's idle window; use it
// for endpoints the frontend polls automatically (see the comment in New).
func (s *Server) authPassive(next http.HandlerFunc) http.Handler {
	return s.authMiddleware(next, false)
}

func (s *Server) authMiddleware(next http.HandlerFunc, active bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r, active) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Shepherd") == "" {
			http.Error(w, "missing X-Shepherd header", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.Token)), []byte(s.Token)) != 1 {
		s.sleep(400 * time.Millisecond)
		http.Error(w, "wrong token", http.StatusUnauthorized)
		return
	}
	sess := s.sessions.create("", s.clock())
	s.setSessionCookie(w, sess.id)
	_, pinSet := s.lockStore.pin()
	writeJSON(w, map[string]any{"ok": true, "pin_set": pinSet})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	listed, allow, block := s.Engine.Filter.Counts()
	snap := s.Policy.Snapshot()
	policies := snap.Network.Policies
	enabled := 0
	for _, on := range snap.Network.Items {
		if on {
			enabled++
		}
	}
	writeJSON(w, map[string]any{
		"version":        s.Version,
		"uptime_seconds": int64(time.Since(s.started).Seconds()),
		"stats":          s.Engine.Stats.Snapshot(),
		"upstreams":      s.Engine.Pool.Status(),
		"lists":          s.Lists.Status(),
		"listed_domains": listed,
		"allow_rules":    allow,
		"block_rules":    block,
		"policies":       policies,
		// Device and catalog counts for the overview.
		"device_count":       s.Devices.Len(),
		"group_count":        len(s.Devices.Groups()),
		"catalog_count":      len(snap.Catalog),
		"custom_list_count":  len(snap.Custom),
		"network_item_count": enabled,
	})
}

func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 1 {
		limit = 200
	}
	limit = min(limit, 1000)
	entries, last := s.Engine.Log.After(after, limit)
	if entries == nil {
		entries = []dnsengine.Entry{}
	}
	writeJSON(w, map[string]any{"entries": entries, "last": last})
}

// The rule, policy and list endpoints below predate scopes; they act on the
// network scope, which is what every device falls back to.

func (s *Server) getRules(w http.ResponseWriter, r *http.Request) {
	n := s.Policy.Snapshot().Network
	policies := n.Policies
	if policies == nil {
		policies = map[string]bool{}
	}
	writeJSON(w, map[string]any{"allow": orEmpty(n.Allow), "block": orEmpty(n.Block), "policies": policies})
}

type ruleBody struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
}

func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Policy.AddRule(dnsengine.NetworkScope(), b.Kind, b.Domain); err != nil {
		policyError(w, err)
		return
	}
	s.getRules(w, r)
}

func (s *Server) delRule(w http.ResponseWriter, r *http.Request) {
	if err := s.Policy.RemoveRule(dnsengine.NetworkScope(), r.URL.Query().Get("kind"), r.URL.Query().Get("domain")); err != nil {
		policyError(w, err)
		return
	}
	s.getRules(w, r)
}

func (s *Server) setPolicy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Policy.SetPolicy(dnsengine.NetworkScope(), b.Name, b.Enabled); err != nil {
		policyError(w, err)
		return
	}
	s.getRules(w, r)
}

func (s *Server) refreshLists(w http.ResponseWriter, r *http.Request) {
	s.refreshAsync("")
	w.WriteHeader(http.StatusAccepted)
}

// routes registers the management API (devices, groups, policy, upstreams).
func (s *Server) routes() {
	h := func(pattern string, fn http.HandlerFunc) { s.mux.Handle(pattern, s.auth(fn)) }
	h("GET /api/devices", s.listDevices)
	h("POST /api/devices/bulk", s.bulkDevices)
	h("POST /api/devices/merge", s.mergeDevices)
	h("GET /api/devices/{id}", s.getDevice)
	h("PATCH /api/devices/{id}", s.patchDevice)
	h("DELETE /api/devices/{id}", s.deleteDevice)
	h("GET /api/arp/stats", s.arpStats)
	h("GET /api/groups", s.listGroups)
	h("POST /api/groups", s.createGroup)
	h("PATCH /api/groups/{id}", s.patchGroup)
	h("DELETE /api/groups/{id}", s.deleteGroup)

	h("POST /api/import/eero/start", s.importEeroStart)
	h("POST /api/import/eero/verify", s.importEeroVerify)
	h("POST /api/import/eero/preview", s.importEeroPreview)
	h("POST /api/import/eero/apply", s.importEeroApply)
	h("POST /api/import/eero/cancel", s.importEeroCancel)
	h("POST /api/import/csv/preview", s.importCSVPreview)
	h("POST /api/import/csv/apply", s.importCSVApply)

	h("GET /api/catalog", s.getCatalog)
	h("GET /api/policy", s.getPolicy)
	h("POST /api/policy/items", s.setPolicyItem)
	h("POST /api/policy/rules", s.addPolicyRule)
	h("DELETE /api/policy/rules", s.deletePolicyRule)
	h("POST /api/policy/switches", s.setPolicySwitch)
	h("POST /api/policy/mode", s.setPolicyMode)
	h("POST /api/policy/custom-lists", s.addCustomList)
	h("DELETE /api/policy/custom-lists/{id}", s.deleteCustomList)
	h("POST /api/policy/refresh", s.refreshPolicy)

	h("GET /api/accountability/contacts", s.listContacts)
	h("POST /api/accountability/contacts", s.addContact)
	h("DELETE /api/accountability/contacts/{id}", s.deleteContact)
	h("GET /api/accountability/subscriptions", s.listSubscriptions)
	h("POST /api/accountability/subscriptions", s.addSubscription)
	h("DELETE /api/accountability/subscriptions/{id}", s.deleteSubscription)

	h("GET /api/geoblock", s.getGeoBlock)
	h("POST /api/geoblock", s.setGeoBlock)

	h("GET /api/upstreams", s.getUpstreams)
	h("POST /api/upstreams/test", s.testUpstream)
	h("POST /api/upstreams", s.addUpstream)
	h("DELETE /api/upstreams", s.deleteUpstream)
	h("PUT /api/upstreams", s.putUpstreams)
	h("PUT /api/upstreams/bootstrap", s.putBootstrap)

	h("GET /api/alarms", s.listAlarms)
	h("GET /api/alarms/summary", s.alarmsSummary)
	h("GET /api/alarms/types", s.alarmTypes)
	h("GET /api/alarms/rules", s.listAlarmRules)
	h("POST /api/alarms/rules", s.createAlarmRule)
	h("DELETE /api/alarms/rules/{id}", s.deleteAlarmRule)
	h("POST /api/alarms/bulk", s.alarmsBulk)
	h("POST /api/alarms/undo", s.undoAlarms)
	h("GET /api/alarms/{id}", s.getAlarm)
	h("PATCH /api/alarms/{id}", s.patchAlarm)
	h("DELETE /api/alarms/{id}", s.deleteAlarm)
	h("POST /api/alarms/{id}/mute", s.muteAlarm)

	h("GET /api/portscan", s.getPortscan)
	h("GET /api/portscan/devices", s.listPortscanDevices)
	h("GET /api/portscan/devices/{id}", s.getPortscanDevice)
	h("POST /api/portscan/scan", s.scanNow)

	h("GET /api/vulnscan", s.getVulnscan)
	h("GET /api/vulnscan/devices", s.listVulnscanDevices)
	h("GET /api/vulnscan/devices/{id}", s.getVulnscanDevice)
	h("POST /api/vulnscan/scan", s.vulnscanNow)

	h("GET /api/nethealth", s.getNethealth)
	h("GET /api/nethealth/series", s.nethealthSeries)
	h("GET /api/nethealth/bufferbloat", s.nethealthBufferbloat)
	h("POST /api/nethealth/probe", s.nethealthProbeNow)
	h("POST /api/nethealth/bufferbloat/run", s.nethealthBufferbloatNow)

	h("GET /api/reverseproxy", s.getReverseProxy)
	h("GET /api/reverseproxy/hosts", s.listProxyHosts)
	h("POST /api/reverseproxy/hosts", s.addProxyHost)
	h("PUT /api/reverseproxy/hosts/{id}", s.putProxyHost)
	h("DELETE /api/reverseproxy/hosts/{id}", s.deleteProxyHost)
}
