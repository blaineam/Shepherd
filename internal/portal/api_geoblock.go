// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/http"

	"shepherd/internal/dnsengine"
)

// geoBlockView renders a snapshot the way the other scoped views do: a
// network list plus sparse group and device maps (a scope with nothing
// blocked is simply absent). Snapshot always returns non-nil maps.
func geoBlockView(sn dnsengine.GeoBlockSnapshot) map[string]any {
	return map[string]any{"network": orEmpty(sn.Network), "groups": sn.Groups, "devices": sn.Devices}
}

func (s *Server) getGeoBlock(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, geoBlockView(s.GeoBlock.Snapshot()))
}

func (s *Server) setGeoBlock(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Scope     scopeJSON `json:"scope"`
		Countries []string  `json:"countries"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	sc, ok := s.resolveScope(w, b.Scope.Kind, b.Scope.ID)
	if !ok {
		return
	}
	if err := s.GeoBlock.SetCountries(sc, b.Countries); err != nil {
		policyError(w, err)
		return
	}
	s.getGeoBlock(w, r)
}
