// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"shepherd/internal/dnsengine"
	"shepherd/internal/settings"
)

// stream sends every new query as a Server-Sent Event. A reconnecting browser
// resumes from its Last-Event-ID (or ?after=) without gaps.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")

	// Subscribe before replaying so nothing slips between the two.
	live, cancel := s.Engine.Log.Subscribe(1024)
	defer cancel()

	var last uint64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		last, _ = strconv.ParseUint(v, 10, 64)
	} else if v := r.URL.Query().Get("after"); v != "" {
		last, _ = strconv.ParseUint(v, 10, 64)
	}
	bw := bufio.NewWriter(w)
	send := func(e dnsengine.Entry) error {
		b, _ := json.Marshal(e)
		if _, err := fmt.Fprintf(bw, "id: %d\nevent: query\ndata: %s\n\n", e.ID, b); err != nil {
			return err
		}
		last = e.ID
		return bw.Flush()
	}
	fmt.Fprint(bw, ": shepherd stream\n\n")
	if last > 0 {
		missed, _ := s.Engine.Log.After(last, 1000)
		for _, e := range missed {
			if send(e) != nil {
				return
			}
		}
	}
	bw.Flush()
	fl.Flush()

	beat := time.NewTicker(s.Heartbeat)
	defer beat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-live:
			if e.ID <= last {
				continue // already sent during the replay
			}
			if send(e) != nil {
				return
			}
			fl.Flush()
		case <-beat.C:
			if _, err := fmt.Fprint(bw, ": keep-alive\n\n"); err != nil || bw.Flush() != nil {
				return
			}
			fl.Flush()
		}
	}
}

func parseTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}

// historyQuery searches past entries, from the encrypted store when enabled.
func (s *Server) historyQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, err1 := parseTime(q.Get("from"))
	to, err2 := parseTime(q.Get("to"))
	if err1 != nil || err2 != nil {
		http.Error(w, "from and to must be RFC 3339 times", http.StatusBadRequest)
		return
	}
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit < 1 {
		limit = 500
	}
	limit = min(limit, 5000)
	hq := dnsengine.HistoryQuery{
		From: from, To: to, Client: q.Get("client"), Action: q.Get("action"),
		Contains: q.Get("q"), Limit: limit,
	}
	entries, span, err := s.History.Query(hq)
	if errors.Is(err, dnsengine.ErrLocked) {
		w.WriteHeader(http.StatusLocked)
		writeJSON(w, map[string]any{"locked": true, "source": s.History.Mode(), "entries": []dnsengine.Entry{}})
		return
	}
	if err != nil {
		http.Error(w, "history unavailable", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []dnsengine.Entry{}
	}
	writeJSON(w, map[string]any{
		"entries": entries, "source": s.History.Mode(), "locked": false,
		"oldest": span.Oldest, "newest": span.Newest, "skipped": span.Skipped,
		"from": from, "to": to,
	})
}

func (s *Server) historyUnlock(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Passphrase string `json:"passphrase"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	err := s.History.Unlock(b.Passphrase)
	switch {
	case errors.Is(err, dnsengine.ErrNotSupported):
		http.Error(w, "history is not encrypted, so there is nothing to unlock", http.StatusBadRequest)
	case errors.Is(err, dnsengine.ErrWrongPassphrase):
		time.Sleep(400 * time.Millisecond)
		http.Error(w, "wrong passphrase", http.StatusUnauthorized)
	case err != nil:
		http.Error(w, "could not unlock the history", http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"ok": true, "locked": s.History.Locked()})
	}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	var home *settings.Home
	if s.Settings != nil {
		home = s.Settings.Home()
	} else {
		s.mu.Lock()
		home = s.memHome
		s.mu.Unlock()
	}
	geoStatus := map[string]any{"ready": false, "enabled": false}
	if s.Geo != nil {
		st := s.Geo.Status()
		geoStatus = map[string]any{"enabled": true, "ready": st.Ready, "updated": st.Updated, "error": st.Error, "attribution": st.Attribution}
	}
	_, pinSet := s.lockStore.pin()
	writeJSON(w, map[string]any{
		"home": home, "auto_home": s.DetectHome != nil,
		"history": map[string]any{
			"mode": s.History.Mode(), "locked": s.History.Locked(), "initialized": s.History.Initialized(),
		},
		"geo": geoStatus,
		"locking": map[string]any{
			"idle_lock_minutes":    s.idleLockMinutes(),
			"pin_set":              pinSet,
			"trusted_device_count": len(s.lockStore.trustedDevices()),
		},
	})
}

func (s *Server) setHome(w http.ResponseWriter, r *http.Request) {
	var h settings.Home
	if !readJSON(w, r, &h) {
		return
	}
	if s.Settings == nil {
		s.mu.Lock()
		cp := h
		s.memHome = &cp
		s.mu.Unlock()
	} else if err := s.Settings.SetHome(h); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.getSettings(w, r)
}

// resetHome removes the user's override so home follows the detected location.
func (s *Server) resetHome(w http.ResponseWriter, r *http.Request) {
	if s.Settings == nil {
		s.mu.Lock()
		s.memHome = nil
		s.mu.Unlock()
	} else if err := s.Settings.ClearHome(); err != nil {
		http.Error(w, "could not reset home", http.StatusInternalServerError)
		return
	}
	s.getSettings(w, r)
}

// detectHome works out home from the network's public address now.
func (s *Server) detectHome(w http.ResponseWriter, r *http.Request) {
	if s.DetectHome == nil {
		http.Error(w, "automatic home is turned off in the configuration", http.StatusBadRequest)
		return
	}
	if err := s.DetectHome(r.Context()); err != nil {
		http.Error(w, "could not detect home: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.getSettings(w, r)
}
