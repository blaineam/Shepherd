// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"shepherd/internal/dhcp"
)

// The DHCP-mode screen's API (docs/DHCP.md). One GET that answers the whole
// screen, and a handful of POSTs for the things an operator does: confirm
// that Shepherd may serve here, add and remove reservations, pull the kill
// switch, and clear the record of another DHCP server once the router's own
// has been turned off.
//
// Every one of these works with the mode off, which is deliberate: the point
// of a feature that can take a household off the internet is that the whole
// arrangement can be set up and read before it is switched on.

// confirmPhrase is what has to be typed to let Shepherd serve DHCP. A typed
// phrase rather than a checkbox because this is the one action in the portal
// whose mistake is "the house has no internet and the person who did it has
// gone to bed".
const confirmPhrase = "serve dhcp"

// dhcpJSON is the whole screen. A nil service answers the same shape with
// available false, so the screen says why rather than failing.
func dhcpJSON(s dhcp.Status, set dhcp.SettingsView, leases []dhcp.LeaseView, res []dhcp.Reservation) map[string]any {
	if leases == nil {
		leases = []dhcp.LeaseView{}
	}
	if res == nil {
		res = []dhcp.Reservation{}
	}
	if s.Peers == nil {
		s.Peers = []dhcp.Peer{}
	}
	return map[string]any{
		"available": true, "status": s, "settings": set,
		"leases": leases, "reservations": res,
		"confirm_phrase": confirmPhrase,
	}
}

func (s *Server) getDHCP(w http.ResponseWriter, r *http.Request) {
	if s.DHCP == nil {
		writeJSON(w, map[string]any{
			"available": false,
			"reason":    "DHCP mode is not wired into this build. Set [dhcp] mode in shepherd.toml (docs/DHCP.md).",
			"status": dhcp.Status{Mode: string(dhcp.ModeOff),
				Blocked: "DHCP mode is not configured", Peers: []dhcp.Peer{}},
			"settings": dhcp.SettingsView{}, "leases": []dhcp.LeaseView{},
			"reservations": []dhcp.Reservation{}, "confirm_phrase": confirmPhrase,
		})
		return
	}
	writeJSON(w, dhcpJSON(s.DHCP.Status(), s.DHCP.SettingsView(), s.DHCP.Leases(), s.DHCP.Reservations()))
}

func (s *Server) dhcpOrNotFound(w http.ResponseWriter) bool {
	if s.DHCP == nil {
		notFound(w, "DHCP mode is not configured")
		return false
	}
	return true
}

// confirmDHCP records or withdraws the confirmation that Shepherd may serve
// DHCP on this network. Confirming needs the phrase; withdrawing does not,
// because stopping is always allowed to be easy.
func (s *Server) confirmDHCP(w http.ResponseWriter, r *http.Request) {
	if !s.dhcpOrNotFound(w) {
		return
	}
	var b struct {
		Confirm bool   `json:"confirm"`
		Phrase  string `json:"phrase"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if b.Confirm && !strings.EqualFold(strings.TrimSpace(b.Phrase), confirmPhrase) {
		bad(w, "type "+confirmPhrase+" to confirm that Shepherd may serve DHCP on this network")
		return
	}
	if err := s.DHCP.Confirm(r.Context(), b.Confirm); err != nil {
		serverFault(w, "the confirmation could not be saved")
		return
	}
	s.getDHCP(w, r)
}

// killDHCP is the kill switch. It stops routing, not leasing: every device
// keeps its address and gets the router's own address as its gateway at its
// next renewal, so the worst case is one lease interval rather than an
// outage.
func (s *Server) killDHCP(w http.ResponseWriter, r *http.Request) {
	if !s.dhcpOrNotFound(w) {
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength > 0 && !decode(w, r, &b, smallBody) {
		return
	}
	if hasControl(b.Reason) || len(b.Reason) > 200 {
		bad(w, "the reason must be plain text, up to 200 characters")
		return
	}
	if err := s.DHCP.Unroute(r.Context(), b.Reason); err != nil {
		// Routing stopped either way; what failed was recording it or
		// clearing the kernel's rules, and the operator needs to know
		// which rather than seeing a success.
		serverFault(w, "routing stopped, but the kill switch could not be completed: check the log")
		return
	}
	s.getDHCP(w, r)
}

func (s *Server) rearmDHCP(w http.ResponseWriter, r *http.Request) {
	if !s.dhcpOrNotFound(w) {
		return
	}
	if err := s.DHCP.Rearm(r.Context()); err != nil {
		serverFault(w, "the kill switch could not be re-armed")
		return
	}
	s.getDHCP(w, r)
}

// forgetDHCPPeers clears the sightings of other DHCP servers. This is what
// an operator does after turning the router's DHCP off: the interlock is
// right about the past and no longer right about the present, and waiting
// out the settle window for a server that is gone is pointless.
func (s *Server) forgetDHCPPeers(w http.ResponseWriter, r *http.Request) {
	if !s.dhcpOrNotFound(w) {
		return
	}
	s.DHCP.ForgetPeers(r.Context())
	s.getDHCP(w, r)
}

func (s *Server) putDHCPReservation(w http.ResponseWriter, r *http.Request) {
	if !s.dhcpOrNotFound(w) {
		return
	}
	var b struct {
		MAC      string `json:"mac"`
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		Note     string `json:"note"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if hasControl(b.Hostname) || hasControl(b.Note) {
		bad(w, "a hostname and a note must be plain text")
		return
	}
	res := dhcp.Reservation{MAC: b.MAC, Hostname: b.Hostname, Note: b.Note}
	if ip := strings.TrimSpace(b.IP); ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			bad(w, "the address must be an IPv4 address, or empty to reserve only a name")
			return
		}
		res.IP = a
	}
	if err := s.DHCP.SetReservation(res); err != nil {
		if errors.Is(err, dhcp.ErrReservation) {
			// Every one of these is something the operator typed, and
			// the message says which rule it broke.
			bad(w, strings.TrimPrefix(err.Error(), "dhcp: reservation: "))
			return
		}
		serverFault(w, "the reservation could not be saved")
		return
	}
	s.getDHCP(w, r)
}

func (s *Server) deleteDHCPReservation(w http.ResponseWriter, r *http.Request) {
	if !s.dhcpOrNotFound(w) {
		return
	}
	mac := dhcp.NormalizeMAC(r.PathValue("mac"))
	if mac == "" {
		bad(w, "the MAC address must be six hex pairs")
		return
	}
	ok, err := s.DHCP.DeleteReservation(mac)
	if err != nil {
		serverFault(w, "the reservation could not be removed")
		return
	}
	if !ok {
		notFound(w, "no reservation for "+mac)
		return
	}
	s.getDHCP(w, r)
}
