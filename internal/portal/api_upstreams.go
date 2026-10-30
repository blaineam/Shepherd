// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"net/http"
	"time"

	"shepherd/internal/dnsengine"
)

type presetJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Provider    string   `json:"provider"`
	Description string   `json:"description"`
	Plain       []string `json:"plain"`
	DoH         string   `json:"doh"`
	DoT         string   `json:"dot"`
	Filtering   string   `json:"filtering"`
	Notes       string   `json:"notes"`
}

func presetsView() []presetJSON {
	ps := dnsengine.Presets()
	out := make([]presetJSON, len(ps))
	for i, p := range ps {
		dot := ""
		if u := p.Upstreams("dot"); len(u) > 0 {
			dot = u[0]
		}
		out[i] = presetJSON{
			ID: p.ID, Name: p.Name, Provider: p.Provider, Description: p.Description,
			Plain: orEmpty(p.Upstreams("ip")), DoH: p.DoH, DoT: dot, Filtering: string(p.Filtering), Notes: p.Privacy,
		}
	}
	return out
}

func (s *Server) upstreamView() map[string]any {
	pool := s.Upstreams.Pool()
	return map[string]any{
		"upstreams": pool.List(),
		"presets":   presetsView(),
		"bootstrap": orEmpty(pool.Bootstrap()),
	}
}

func (s *Server) getUpstreams(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.upstreamView()) }

const (
	maxUpstreams = 16
	maxBootstrap = 8
	maxAddrLen   = 512
)

// upstreamError maps a pool or store error to a response.
func upstreamError(w http.ResponseWriter, err error) {
	var save *dnsengine.SaveError
	switch {
	case errors.As(err, &save):
		serverFault(w, "could not save the upstream list")
	case errors.Is(err, dnsengine.ErrDuplicateUpstream), errors.Is(err, dnsengine.ErrLastUpstream):
		conflict(w, err.Error())
	case errors.Is(err, dnsengine.ErrUnknownUpstream):
		notFound(w, err.Error())
	default:
		bad(w, err.Error())
	}
}

func (s *Server) testUpstream(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Addr string `json:"addr"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if len(b.Addr) > maxAddrLen {
		bad(w, "address too long")
		return
	}
	if err := dnsengine.ValidateUpstream(b.Addr); err != nil {
		bad(w, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	writeJSON(w, s.Upstreams.Pool().Test(ctx, b.Addr))
}

func (s *Server) addUpstream(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Addr string `json:"addr"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if len(b.Addr) > maxAddrLen || len(s.Upstreams.Pool().List()) >= maxUpstreams {
		bad(w, "address too long or too many upstreams (limit 16)")
		return
	}
	if err := s.Upstreams.Add(b.Addr); err != nil {
		upstreamError(w, err)
		return
	}
	s.getUpstreams(w, r)
}

func (s *Server) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if addr == "" || len(addr) > maxAddrLen {
		bad(w, "addr is required")
		return
	}
	if err := s.Upstreams.Remove(addr); err != nil {
		upstreamError(w, err)
		return
	}
	s.getUpstreams(w, r)
}

func (s *Server) putUpstreams(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Addrs []string `json:"addrs"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if len(b.Addrs) == 0 || len(b.Addrs) > maxUpstreams {
		bad(w, "addrs must list between 1 and 16 upstreams")
		return
	}
	for _, a := range b.Addrs {
		if len(a) > maxAddrLen {
			bad(w, "address too long")
			return
		}
	}
	if err := s.Upstreams.Set(b.Addrs); err != nil {
		upstreamError(w, err)
		return
	}
	s.getUpstreams(w, r)
}

func (s *Server) putBootstrap(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Servers []string `json:"servers"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if len(b.Servers) == 0 || len(b.Servers) > maxBootstrap {
		bad(w, "servers must list between 1 and 8 resolvers")
		return
	}
	if err := s.Upstreams.SetBootstrap(b.Servers); err != nil {
		upstreamError(w, err)
		return
	}
	s.getUpstreams(w, r)
}
