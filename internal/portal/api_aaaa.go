// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/http"

	"shepherd/internal/devices"
	"shepherd/internal/settings"
)

// AAAA filtering is set here rather than only in shepherd.toml because the
// device it exists for is found by watching the query log, and the person
// watching it should not have to edit a file and restart to act on what they
// see. The mode saved here wins over dns.filter_aaaa; a device's own switch
// (PATCH /api/devices/{id} with "aaaa") wins over both. See docs/IPV6.md.

// aaaaMode is the network's effective mode: what was saved in the portal,
// else dns.filter_aaaa, else "auto".
func (s *Server) aaaaMode() (mode string, fromConfig bool) {
	if s.Settings != nil {
		if m := s.Settings.AAAAMode(); settings.ValidAAAAMode(m) {
			return m, false
		}
	} else {
		s.mu.Lock()
		m := s.memAAAA
		s.mu.Unlock()
		if settings.ValidAAAAMode(m) {
			return m, false
		}
	}
	if settings.ValidAAAAMode(s.AAAAConfigMode) {
		return s.AAAAConfigMode, true
	}
	return settings.AAAAAuto, true
}

// aaaaExceptions lists the devices whose own switch overrides the network's,
// newest name order aside: the device list's own order, which is stable.
func (s *Server) aaaaExceptions() []map[string]any {
	out := []map[string]any{}
	for _, d := range s.Devices.List() {
		if d.AAAA == devices.AAAAAuto {
			continue
		}
		out = append(out, map[string]any{"id": d.ID, "name": d.DisplayName(), "aaaa": d.AAAA.String()})
	}
	return out
}

func (s *Server) aaaaView() map[string]any {
	mode, fromConfig := s.aaaaMode()
	view := map[string]any{
		"mode": mode,
		// from_config says the mode still comes from shepherd.toml, so the
		// screen can offer to go back to it once the portal has set one.
		"from_config": fromConfig,
		"config_mode": s.AAAAConfigMode,
		"exceptions":  s.aaaaExceptions(),
	}
	if s.AAAANetwork != nil {
		view["filtering"] = s.AAAANetwork()
	}
	if s.AAAAIPv6Usable != nil {
		view["ipv6_usable"] = s.AAAAIPv6Usable()
	}
	return view
}

func (s *Server) getAAAA(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.aaaaView()) }

func (s *Server) putAAAA(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	// An empty mode hands the decision back to shepherd.toml.
	if b.Mode == "" {
		if s.Settings == nil {
			s.mu.Lock()
			s.memAAAA = ""
			s.mu.Unlock()
		} else if err := s.Settings.ClearAAAAMode(); err != nil {
			serverFault(w, "could not save the IPv6 setting")
			return
		}
		s.getAAAA(w, r)
		return
	}
	if !settings.ValidAAAAMode(b.Mode) {
		bad(w, `mode must be "auto", "on" or "off"`)
		return
	}
	if s.Settings == nil {
		s.mu.Lock()
		s.memAAAA = b.Mode
		s.mu.Unlock()
	} else if err := s.Settings.SetAAAAMode(b.Mode); err != nil {
		serverFault(w, "could not save the IPv6 setting")
		return
	}
	s.getAAAA(w, r)
}
