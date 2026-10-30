// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"net/http"
	"time"

	"shepherd/internal/portscan"
	"shepherd/internal/vulnscan"
)

type findingJSON struct {
	SignatureID string            `json:"signature_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    vulnscan.Severity `json:"severity"`
	Port        int               `json:"port"`
	Evidence    string            `json:"evidence,omitempty"`
	Active      bool              `json:"active"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
	NewlyFound  bool              `json:"newly_found,omitempty"`
}

func toFinding(f vulnscan.Finding) findingJSON {
	out := findingJSON{
		SignatureID: f.SignatureID, Name: f.Name, Description: f.Description, Severity: f.Severity,
		Port: f.Port, Evidence: f.Evidence, Active: f.Active, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
		NewlyFound: f.NewlyFound,
	}
	if !f.ResolvedAt.IsZero() {
		t := f.ResolvedAt
		out.ResolvedAt = &t
	}
	return out
}

type deviceFindingsJSON struct {
	DeviceID    string        `json:"device_id"`
	Name        string        `json:"name"`
	IP          string        `json:"ip"`
	LastScanned *time.Time    `json:"last_scanned,omitempty"`
	Findings    []findingJSON `json:"findings"`
}

func (s *Server) toDeviceFindings(ds vulnscan.DeviceFindings) deviceFindingsJSON {
	findings := make([]findingJSON, len(ds.Findings))
	for i, f := range ds.Findings {
		findings[i] = toFinding(f)
	}
	out := deviceFindingsJSON{DeviceID: ds.DeviceID, Name: s.deviceName(ds.DeviceID), IP: ds.IP, Findings: findings}
	if !ds.LastScanned.IsZero() {
		t := ds.LastScanned
		out.LastScanned = &t
	}
	return out
}

type signatureJSON struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Severity    vulnscan.Severity `json:"severity"`
	Description string            `json:"description"`
	Ports       []int             `json:"ports,omitempty"`
}

func (s *Server) getVulnscan(w http.ResponseWriter, r *http.Request) {
	sigs := vulnscan.BuiltinSignatures()
	out := make([]signatureJSON, len(sigs))
	for i, sig := range sigs {
		out[i] = signatureJSON{ID: sig.ID, Name: sig.Name, Severity: sig.Severity, Description: sig.Description, Ports: sig.Ports}
	}
	writeJSON(w, map[string]any{
		"enabled":    s.VulnscanEnabled,
		"signatures": out,
	})
}

func (s *Server) listVulnscanDevices(w http.ResponseWriter, r *http.Request) {
	results := s.Vulnscan.Results()
	out := make([]deviceFindingsJSON, len(results))
	for i, ds := range results {
		out[i] = s.toDeviceFindings(ds)
	}
	writeJSON(w, map[string]any{"devices": out})
}

func (s *Server) getVulnscanDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Devices.Get(id); !ok {
		notFound(w, "unknown device")
		return
	}
	ds, ok := s.Vulnscan.Result(id)
	if !ok {
		writeJSON(w, s.toDeviceFindings(vulnscan.DeviceFindings{DeviceID: id}))
		return
	}
	writeJSON(w, s.toDeviceFindings(ds))
}

// vulnscanAllTimeout and vulnscanOneTimeout bound a manual "scan now"
// request. They are shorter than portscan's own: this probe only re-checks
// ports portscan already found open (a handful of short banner/protocol
// reads), never a sweep of the whole port list.
const (
	vulnscanAllTimeout = 45 * time.Second
	vulnscanOneTimeout = 10 * time.Second
)

func (s *Server) vulnscanNow(w http.ResponseWriter, r *http.Request) {
	var b struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	var targets []vulnscan.Target
	timeout := vulnscanAllTimeout
	if b.DeviceID != "" {
		if _, ok := s.Devices.Get(b.DeviceID); !ok {
			notFound(w, "unknown device")
			return
		}
		found := false
		for _, ds := range s.Portscan.Results() {
			if ds.DeviceID == b.DeviceID {
				targets = vulnscan.TargetsFromPortscan([]portscan.DeviceScan{ds})
				found = true
			}
		}
		// A device portscan has never scanned at all has no open-port
		// picture to deepen; one it scanned and found nothing open on is a
		// perfectly good, if uneventful, scan (it just finds nothing).
		if !found {
			bad(w, "device has not been port-scanned yet (run a port scan first)")
			return
		}
		timeout = vulnscanOneTimeout
	} else {
		targets = vulnscan.TargetsFromPortscan(s.Portscan.Results())
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	results := s.Vulnscan.Scan(ctx, targets)
	out := make([]deviceFindingsJSON, len(results))
	for i, ds := range results {
		out[i] = s.toDeviceFindings(ds)
	}
	writeJSON(w, map[string]any{"devices": out})
}
