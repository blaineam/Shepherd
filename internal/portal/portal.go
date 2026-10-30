// SPDX-License-Identifier: AGPL-3.0-or-later

// Package portal serves Shepherd's web interface and JSON API. Everything the
// underlying engines can do is controlled from here.
package portal

import (
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
	"time"

	"shepherd/internal/dnsengine"
)

//go:embed web
var webFS embed.FS

const cookieName = "shepherd_session"

type Deps struct {
	Engine  *dnsengine.Engine
	Lists   *dnsengine.ListManager
	Rules   *dnsengine.Rules
	Token   string
	Version string
}

type Server struct {
	Deps
	started time.Time
	mux     *http.ServeMux
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
	_, _, policies := s.Rules.Snapshot()
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

func (s *Server) getRules(w http.ResponseWriter, r *http.Request) {
	allow, block, policies := s.Rules.Snapshot()
	writeJSON(w, map[string]any{"allow": allow, "block": block, "policies": policies})
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
	if err := s.Rules.Add(b.Kind, b.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.getRules(w, r)
}

func (s *Server) delRule(w http.ResponseWriter, r *http.Request) {
	if err := s.Rules.Remove(r.URL.Query().Get("kind"), r.URL.Query().Get("domain")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	if err := s.Rules.SetPolicy(b.Name, b.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.getRules(w, r)
}

func (s *Server) refreshLists(w http.ResponseWriter, r *http.Request) {
	go s.Lists.Refresh(r.Context())
	w.WriteHeader(http.StatusAccepted)
}
