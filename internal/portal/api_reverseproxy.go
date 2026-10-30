// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"shepherd/internal/reverseproxy"
)

// ReverseProxyStatus describes cmd/shepherd's [reverseproxy] listener for
// GET /api/reverseproxy. Its zero value means the listener is off, which
// does not stop the portal from editing hosts: an owner can line every
// host up first and switch the listener on afterwards.
type ReverseProxyStatus struct {
	Enabled bool
	Listen  string
	// Wildcard is the certificate's name ("*.example.com"), so the view can
	// warn about a host the certificate will not cover. Empty when unset.
	Wildcard string
	// Certificate returns the certificate in service, or nil before the
	// first issuance. Nil when the listener is off.
	Certificate func() *tls.Certificate
}

type proxyCertJSON struct {
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after"`
}

func (s *Server) getReverseProxy(w http.ResponseWriter, r *http.Request) {
	st := s.ReverseProxyStatus
	var cert *proxyCertJSON
	if st.Certificate != nil {
		if c := st.Certificate(); c != nil && c.Leaf != nil {
			cert = &proxyCertJSON{Names: orEmpty(c.Leaf.DNSNames), NotAfter: c.Leaf.NotAfter.UTC()}
		}
	}
	writeJSON(w, map[string]any{"enabled": st.Enabled, "listen": st.Listen, "wildcard": st.Wildcard, "certificate": cert})
}

// proxyHostError maps a reverseproxy error to a status: a bad definition is
// the caller's to fix (400), a clash with another host's domain is 409, an
// unknown id is 404, and a save the disk refused is the server's (500).
func proxyHostError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, reverseproxy.ErrNotFound):
		notFound(w, err.Error())
	case errors.Is(err, reverseproxy.ErrDuplicate):
		conflict(w, err.Error())
	case errors.Is(err, reverseproxy.ErrInvalid):
		bad(w, err.Error())
	default:
		serverFault(w, "could not save proxy hosts")
	}
}

// proxyHostBody is what POST and PUT accept. The id is never the client's
// to choose, so it is not a field; Enabled is a pointer so leaving it out
// means "on" for a new host and "unchanged" for an edit.
type proxyHostBody struct {
	Domain        string `json:"domain"`
	TargetScheme  string `json:"target_scheme"`
	TargetHost    string `json:"target_host"`
	TargetPort    int    `json:"target_port"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	Enabled       *bool  `json:"enabled"`
}

func (b proxyHostBody) host(enabled bool) reverseproxy.Host {
	if b.Enabled != nil {
		enabled = *b.Enabled
	}
	return reverseproxy.Host{Domain: b.Domain, TargetScheme: b.TargetScheme, TargetHost: b.TargetHost, TargetPort: b.TargetPort, SkipTLSVerify: b.SkipTLSVerify, Enabled: enabled}
}

func (s *Server) listProxyHosts(w http.ResponseWriter, r *http.Request) {
	hosts := s.ReverseProxy.List()
	if hosts == nil {
		hosts = []reverseproxy.Host{}
	}
	writeJSON(w, map[string]any{"hosts": hosts})
}

func (s *Server) addProxyHost(w http.ResponseWriter, r *http.Request) {
	var b proxyHostBody
	if !decode(w, r, &b, smallBody) {
		return
	}
	h, err := s.ReverseProxy.Add(b.host(true))
	if err != nil {
		proxyHostError(w, err)
		return
	}
	writeJSON(w, h)
}

func (s *Server) putProxyHost(w http.ResponseWriter, r *http.Request) {
	var b proxyHostBody
	if !decode(w, r, &b, smallBody) {
		return
	}
	id := r.PathValue("id")
	cur, ok := s.ReverseProxy.Get(id)
	if !ok {
		proxyHostError(w, reverseproxy.ErrNotFound)
		return
	}
	h, err := s.ReverseProxy.Update(id, b.host(cur.Enabled))
	if err != nil {
		proxyHostError(w, err)
		return
	}
	writeJSON(w, h)
}

func (s *Server) deleteProxyHost(w http.ResponseWriter, r *http.Request) {
	if err := s.ReverseProxy.Remove(r.PathValue("id")); err != nil {
		proxyHostError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
