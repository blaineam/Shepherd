// SPDX-License-Identifier: AGPL-3.0-or-later

package passkeys

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ErrNotConfigured means there is no HTTPS hostname to act as the relying
// party: [tls] is off or has no hostname. Passkeys cannot work without one.
var ErrNotConfigured = errors.New("passkeys need Shepherd's own HTTPS hostname: enable [tls] with a hostname (docs/TLS.md), then open the portal at that address")

// RelyingParty is who the portal is, in WebAuthn's terms. A passkey is bound
// to ID for life: one registered here works only on pages whose origin is in
// Origins, and never at the LAN IP, another hostname, or plain HTTP.
type RelyingParty struct {
	// ID is the RP ID: [tls]'s hostname, lowercase, e.g.
	// "shepherd.example.com".
	ID string
	// Origin is where to open the portal to use passkeys, e.g.
	// "https://shepherd.example.com:8443".
	Origin string
	// Origins are every origin a browser may report for a ceremony here:
	// Origin itself and, when the listener is not on 443, the same name on
	// the standard port (a container publishing 443 onto the listener's
	// port makes the browser report no port at all). Both are the same
	// hostname, whose cookies a browser already shares across ports.
	Origins []string
}

// NewRelyingParty builds the relying party from [tls]'s hostname and listen
// address. An empty hostname is ErrNotConfigured; anything WebAuthn cannot
// use as an RP ID (an IP address, a name with a port or scheme, a bare
// single label such as "localhost") is refused with a specific error.
func NewRelyingParty(hostname, listen string) (RelyingParty, error) {
	id := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if id == "" {
		return RelyingParty{}, ErrNotConfigured
	}
	if err := validRPID(id); err != nil {
		return RelyingParty{}, err
	}
	port := ""
	if listen != "" {
		_, p, err := net.SplitHostPort(listen)
		if err != nil {
			return RelyingParty{}, fmt.Errorf("passkeys: tls.listen %q: %w", listen, err)
		}
		port = p
	}
	base := "https://" + id
	if port == "" || port == "443" {
		return RelyingParty{ID: id, Origin: base, Origins: []string{base}}, nil
	}
	origin := base + ":" + port
	return RelyingParty{ID: id, Origin: origin, Origins: []string{origin, base}}, nil
}

// validRPID accepts a multi-label DNS name of letters, digits and hyphens.
func validRPID(id string) error {
	if net.ParseIP(strings.Trim(id, "[]")) != nil {
		return fmt.Errorf("passkeys: %q is an IP address; WebAuthn needs a real hostname, never an IP", id)
	}
	labels := strings.Split(id, ".")
	if len(labels) < 2 {
		return fmt.Errorf("passkeys: %q is not a fully qualified hostname", id)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("passkeys: %q is not a valid hostname", id)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("passkeys: %q is not a valid hostname", id)
			}
		}
	}
	return nil
}

// Serves reports whether r reached the portal over HTTPS at the relying
// party's hostname (any port), the only place a browser will run a ceremony
// for ID. It is the early, friendly refusal; the binding that actually
// matters is the library checking the origin and RP ID hash the
// authenticator signed, which no request header can forge.
func (rp RelyingParty) Serves(r *http.Request) bool {
	if rp.ID == "" || !requestIsHTTPS(r) {
		return false
	}
	return hostOnly(r.Host) == rp.ID
}

// requestIsHTTPS reports whether r reached the portal over a connection the
// browser itself sees as HTTPS: either Shepherd's own [tls] listener
// terminated it directly (r.TLS set), or [reverseproxy] did and forwarded
// it as a plain-HTTP request carrying X-Forwarded-Proto: https, the same
// header internal/reverseproxy.Proxy always sets on everything it forwards
// (never anything a client sent, see Proxy's own header handling) and the
// only way a request from reverseproxy ever reaches this backend, since
// [portal].listen is never itself exposed through reverseproxy.
//
// This is an availability gate, not the actual WebAuthn trust boundary: a
// forged header here only changes whether a ceremony is attempted, never
// whether one succeeds. The library independently verifies the real
// browser-signed origin in clientDataJSON against rp.Origins regardless of
// anything checked here, so trusting this header costs nothing a forged
// origin could not already have tried directly against [tls]'s own
// listener.
func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// RequestOrigin is the origin r was addressed to, for messages that tell the
// owner where they are versus where passkeys work.
func RequestOrigin(r *http.Request) string {
	scheme := "http"
	if requestIsHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func hostOnly(hostport string) string {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}
