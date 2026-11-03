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
func dhcpJSON(s dhcp.Status, set dhcp.SettingsView, rng dhcp.RangeView, conflicts []dhcp.Conflict, leases []dhcp.LeaseView, res []dhcp.Reservation) map[string]any {
	if leases == nil {
		leases = []dhcp.LeaseView{}
	}
	if res == nil {
		res = []dhcp.Reservation{}
	}
	if s.Peers == nil {
		s.Peers = []dhcp.Peer{}
	}
	if conflicts == nil {
		conflicts = []dhcp.Conflict{}
	}
	return map[string]any{
		"available": true, "status": s, "settings": set,
		"range": rng, "conflicts": conflicts,
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
			"range": dhcp.RangeView{}, "conflicts": []dhcp.Conflict{},
			"reservations": []dhcp.Reservation{}, "confirm_phrase": confirmPhrase,
		})
		return
	}
	writeJSON(w, dhcpJSON(s.DHCP.Status(), s.DHCP.SettingsView(), s.DHCP.RangeView(), s.DHCP.Conflicts(), s.DHCP.Leases(), s.DHCP.Reservations()))
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

// putDHCPRange stores the range the operator wants the LAN to use. An empty
// subnet clears it, putting the configuration file and the interface back in
// charge.
//
// A range that does not fit the network yet is stored anyway, and the
// conflicts come back in the same answer. That is deliberate: the whole
// point is to write down where you are going and be told what has to change
// on the router first, and refusing to store it would make that impossible.
// Serving stops while a blocking conflict stands.
func (s *Server) putDHCPRange(w http.ResponseWriter, r *http.Request) {
	if !s.dhcpOrNotFound(w) {
		return
	}
	var b struct {
		Subnet    string `json:"subnet"`
		ServerIP  string `json:"server_ip"`
		Gateway   string `json:"gateway"`
		PoolStart string `json:"pool_start"`
		PoolEnd   string `json:"pool_end"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	var rng dhcp.Range
	if strings.TrimSpace(b.Subnet) != "" {
		p, err := netip.ParsePrefix(strings.TrimSpace(b.Subnet))
		if err != nil {
			bad(w, "the range must be in CIDR form, like 192.0.2.0/24")
			return
		}
		rng.Subnet = p
		for _, f := range []struct {
			name string
			val  string
			into *netip.Addr
		}{
			{"Shepherd's own address", b.ServerIP, &rng.ServerIP},
			{"the router's address", b.Gateway, &rng.Gateway},
			{"the pool start", b.PoolStart, &rng.Pool.Start},
			{"the pool end", b.PoolEnd, &rng.Pool.End},
		} {
			v := strings.TrimSpace(f.val)
			if v == "" {
				bad(w, f.name+" is required")
				return
			}
			a, err := netip.ParseAddr(v)
			if err != nil {
				bad(w, f.name+" must be an IPv4 address")
				return
			}
			*f.into = a
		}
	}
	if err := s.DHCP.SetRange(r.Context(), rng); err != nil {
		if errors.Is(err, dhcp.ErrRange) {
			bad(w, strings.TrimPrefix(err.Error(), "dhcp: range: "))
			return
		}
		serverFault(w, "the range could not be saved")
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
