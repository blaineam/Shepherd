// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"shepherd/internal/devices"
	"shepherd/internal/portscan"
)

type portRecordJSON struct {
	Port        int       `json:"port"`
	Open        bool      `json:"open"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	NewlyOpened bool      `json:"newly_opened,omitempty"`
	Risky       bool      `json:"risky,omitempty"`
	RiskNote    string    `json:"risk_note,omitempty"`
}

func toPortRecord(p portscan.PortRecord) portRecordJSON {
	return portRecordJSON{
		Port: p.Port, Open: p.Open, FirstSeen: p.FirstSeen, LastSeen: p.LastSeen,
		NewlyOpened: p.NewlyOpened, Risky: p.Risky, RiskNote: p.RiskNote,
	}
}

type deviceScanJSON struct {
	DeviceID    string           `json:"device_id"`
	Name        string           `json:"name"`
	IP          string           `json:"ip"`
	LastScanned *time.Time       `json:"last_scanned,omitempty"`
	Ports       []portRecordJSON `json:"ports"`
}

// deviceName looks up a device's display name for the scan view; an id the
// registry no longer has (deleted since its last scan) just falls back to
// the id itself.
func (s *Server) deviceName(id string) string {
	if d, ok := s.Devices.Get(id); ok {
		return d.DisplayName()
	}
	return id
}

func (s *Server) toDeviceScan(ds portscan.DeviceScan) deviceScanJSON {
	ports := make([]portRecordJSON, len(ds.Ports))
	for i, p := range ds.Ports {
		ports[i] = toPortRecord(p)
	}
	out := deviceScanJSON{DeviceID: ds.DeviceID, Name: s.deviceName(ds.DeviceID), IP: ds.IP, Ports: ports}
	if !ds.LastScanned.IsZero() {
		t := ds.LastScanned
		out.LastScanned = &t
	}
	return out
}

func (s *Server) getPortscan(w http.ResponseWriter, r *http.Request) {
	risky := make(map[string]string, len(portscan.RiskyPorts))
	for p, note := range portscan.RiskyPorts {
		risky[strconv.Itoa(p)] = note
	}
	writeJSON(w, map[string]any{
		"enabled":     s.PortscanEnabled,
		"ports":       s.Portscan.Ports(),
		"risky_ports": risky,
	})
}

func (s *Server) listPortscanDevices(w http.ResponseWriter, r *http.Request) {
	results := s.Portscan.Results()
	out := make([]deviceScanJSON, len(results))
	for i, ds := range results {
		out[i] = s.toDeviceScan(ds)
	}
	writeJSON(w, map[string]any{"devices": out})
}

func (s *Server) getPortscanDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Devices.Get(id); !ok {
		notFound(w, "unknown device")
		return
	}
	ds, ok := s.Portscan.Result(id)
	if !ok {
		writeJSON(w, s.toDeviceScan(portscan.DeviceScan{DeviceID: id}))
		return
	}
	writeJSON(w, s.toDeviceScan(ds))
}

// scanAllTimeout and scanOneTimeout bound a manual "scan now" request: long
// enough for a full gentle scan to finish, short enough that the request
// does not hang forever if something upstream goes wrong.
const (
	scanAllTimeout = 90 * time.Second
	scanOneTimeout = 20 * time.Second
)

func (s *Server) scanNow(w http.ResponseWriter, r *http.Request) {
	var b struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	var targets []portscan.Target
	timeout := scanAllTimeout
	if b.DeviceID != "" {
		d, ok := s.Devices.Get(b.DeviceID)
		if !ok {
			notFound(w, "unknown device")
			return
		}
		targets = portscan.TargetsFromDevices([]devices.Device{d})
		if len(targets) == 0 {
			bad(w, "device has no known address to scan")
			return
		}
		timeout = scanOneTimeout
	} else {
		targets = portscan.TargetsFromDevices(s.Devices.List())
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	results := s.Portscan.Scan(ctx, targets)
	out := make([]deviceScanJSON, len(results))
	for i, ds := range results {
		out[i] = s.toDeviceScan(ds)
	}
	writeJSON(w, map[string]any{"devices": out})
}
