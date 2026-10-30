// SPDX-License-Identifier: AGPL-3.0-or-later

// Package portal serves Shepherd's web interface and JSON API. Everything the
// underlying engines can do is controlled from here.
package portal

import (
	"context"
	"crypto/rand"
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
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/geo"
	"shepherd/internal/settings"
)

// Only what the browser needs is embedded: the page, its modules and vendored
// libraries. The unit tests under web/test stay out of the binary.
//
//go:embed web/index.html web/app.js web/style.css web/icon.png web/js web/vendor
var webFS embed.FS

const cookieName = "shepherd_session"

// GeoStatus reports the state of the map data.
type GeoStatus interface{ Status() geo.Status }

type Deps struct {
	Engine *dnsengine.Engine
	Lists  *dnsengine.ListManager
	// Policy owns the blocking policy: the catalog, custom lists, and the
	// switches, allow and block rules at network, group and device scope.
	Policy  *dnsengine.PolicyStore
	Token   string
	Version string

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
	// DetectHome re-detects the automatic home now (nil when automatic home is off).
	DetectHome func(ctx context.Context) error
	// Heartbeat is how often the live stream sends a keep-alive (default 15s).
	Heartbeat time.Duration
	// Accountability manages accountability-partner contacts and
	// subscriptions (docs/ACCOUNTABILITY.md). Nil means the feature is not
	// wired up (see cmd/shepherd's startAccountability): the API answers 404
	// for every /api/accountability/... route instead of panicking.
	Accountability *accountability.Engine
}

type Server struct {
	Deps
	started time.Time
	mux     *http.ServeMux

	mu      sync.Mutex
	memHome *settings.Home // used when no settings store is configured
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
	if d.Heartbeat <= 0 {
		d.Heartbeat = 15 * time.Second
	}
	s := &Server{Deps: d, started: time.Now(), mux: http.NewServeMux()}
	sub, _ := fs.Sub(webFS, "web")
	s.mux.Handle("GET /", http.FileServerFS(sub))
	s.mux.HandleFunc("POST /api/login", s.login)
	s.mux.Handle("GET /api/status", s.auth(s.status))
	s.mux.Handle("GET /api/queries", s.auth(s.queries))
	s.mux.Handle("GET /api/rules", s.auth(s.getRules))
	s.mux.Handle("POST /api/rules", s.auth(s.addRule))
	s.mux.Handle("DELETE /api/rules", s.auth(s.delRule))
	s.mux.Handle("POST /api/policies", s.auth(s.setPolicy))
	s.mux.Handle("POST /api/lists/refresh", s.auth(s.refreshLists))
	s.routes()
	s.mux.Handle("GET /api/stream", s.auth(s.stream))
	s.mux.Handle("GET /api/history", s.auth(s.historyQuery))
	s.mux.Handle("POST /api/history/unlock", s.auth(s.historyUnlock))
	s.mux.Handle("GET /api/settings", s.auth(s.getSettings))
	s.mux.Handle("POST /api/settings/home", s.auth(s.setHome))
	s.mux.Handle("DELETE /api/settings/home", s.auth(s.resetHome))
	s.mux.Handle("POST /api/settings/home/detect", s.auth(s.detectHome))
	return s
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

func (s *Server) tokenOK(r *http.Request) bool {
	tok := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = h[len("Bearer "):]
	} else if c, err := r.Cookie(cookieName); err == nil {
		tok = c.Value
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) == 1
}

// auth requires a valid token. Anything that changes state must also carry the
// X-Shepherd header, which a cross-site request cannot add without a CORS
// preflight (the portal answers none).
func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenOK(r) {
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
		time.Sleep(400 * time.Millisecond)
		http.Error(w, "wrong token", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.Token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: 30 * 24 * 3600,
	})
	writeJSON(w, map[string]bool{"ok": true})
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
	h("GET /api/groups", s.listGroups)
	h("POST /api/groups", s.createGroup)
	h("PATCH /api/groups/{id}", s.patchGroup)
	h("DELETE /api/groups/{id}", s.deleteGroup)

	h("GET /api/catalog", s.getCatalog)
	h("GET /api/policy", s.getPolicy)
	h("POST /api/policy/items", s.setPolicyItem)
	h("POST /api/policy/rules", s.addPolicyRule)
	h("DELETE /api/policy/rules", s.deletePolicyRule)
	h("POST /api/policy/switches", s.setPolicySwitch)
	h("POST /api/policy/custom-lists", s.addCustomList)
	h("DELETE /api/policy/custom-lists/{id}", s.deleteCustomList)
	h("POST /api/policy/refresh", s.refreshPolicy)

	h("GET /api/accountability/contacts", s.listContacts)
	h("POST /api/accountability/contacts", s.addContact)
	h("DELETE /api/accountability/contacts/{id}", s.deleteContact)
	h("GET /api/accountability/subscriptions", s.listSubscriptions)
	h("POST /api/accountability/subscriptions", s.addSubscription)
	h("DELETE /api/accountability/subscriptions/{id}", s.deleteSubscription)

	h("GET /api/upstreams", s.getUpstreams)
	h("POST /api/upstreams/test", s.testUpstream)
	h("POST /api/upstreams", s.addUpstream)
	h("DELETE /api/upstreams", s.deleteUpstream)
	h("PUT /api/upstreams", s.putUpstreams)
	h("PUT /api/upstreams/bootstrap", s.putBootstrap)
}
