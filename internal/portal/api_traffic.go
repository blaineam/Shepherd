// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"shepherd/internal/devices"
	"shepherd/internal/traffic"
	"shepherd/internal/watch"
)

// The bandwidth API (docs/TRAFFIC.md): what is moving now, per device and
// in total, straight from Watch mode's live counters; and what moved over
// any range, per device, per group or for the whole network, from the
// traffic store. Groups and the network are sums over devices computed
// here from the registry's current membership.

// trafficScope parses "network", "device:<id>" or "group:<id>" into the
// device IDs to sum over: nil for the whole network.
func (s *Server) trafficScope(scope string) (ids []string, label string, ok bool) {
	switch {
	case scope == "" || scope == "network":
		return nil, "network", true
	case strings.HasPrefix(scope, "device:"):
		id := strings.TrimPrefix(scope, "device:")
		if _, found := s.Devices.Get(id); !found {
			return nil, "", false
		}
		return []string{id}, scope, true
	case strings.HasPrefix(scope, "group:"):
		gid := strings.TrimPrefix(scope, "group:")
		if _, found := s.Devices.GetGroup(gid); !found {
			return nil, "", false
		}
		ids = []string{}
		for _, d := range s.Devices.List() {
			if inGroup(&d, gid) {
				ids = append(ids, d.ID)
			}
		}
		return ids, scope, true
	}
	return nil, "", false
}

func inGroup(d *devices.Device, gid string) bool {
	for _, g := range d.Groups {
		if g == gid {
			return true
		}
	}
	return false
}

func parseTrafficBucket(r *http.Request, from, to time.Time) traffic.Bucket {
	if b, ok := traffic.ParseBucket(r.URL.Query().Get("bucket")); ok {
		return b
	}
	return traffic.DefaultBucket(from, to)
}

func retentionJSON(r traffic.Retention) map[string]any {
	return map[string]any{
		"minute_hours": int(r.Minute / time.Hour),
		"hour_days":    int(r.Hour / (24 * time.Hour)),
		"day_days":     int(r.Day / (24 * time.Hour)),
		"max_bytes":    r.MaxBytes,
	}
}

// getTraffic is the live picture: whether anything is being measured, the
// network's current rates and totals since Watch mode started, and every
// watched device's own, busiest first.
func (s *Server) getTraffic(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"enabled":         false,
		"measuring":       false,
		"retention":       retentionJSON(s.Traffic.Retention()),
		"devices_tracked": len(s.Traffic.Devices()),
		"live": map[string]any{
			"up_bytes_per_second": 0.0, "down_bytes_per_second": 0.0,
			"bytes_relayed": uint64(0), "bytes_received_est": uint64(0),
		},
		"devices": []map[string]any{},
		// Where the numbers come from, so the screen can say whether they
		// are measured by Watch mode or read from the owner's router.
		"router": s.routerUsageJSON(),
	}
	if s.Watch == nil {
		s.fillFromRouter(out)
		writeJSON(w, out)
		return
	}
	snap := s.Watch.Snapshot()
	out["enabled"] = snap.Enabled
	out["measuring"] = snap.Enabled && snap.Phase == watch.PhaseRunning && snap.Armed
	out["live"] = map[string]any{
		"up_bytes_per_second":   snap.Stats.BytesPerSecond,
		"down_bytes_per_second": snap.Stats.RxBytesPerSecond,
		"bytes_relayed":         snap.Stats.BytesRelayed,
		"bytes_received_est":    snap.Stats.BytesReceivedEst,
	}
	devs := make([]map[string]any, 0, len(snap.Devices))
	for _, d := range snap.Devices {
		if d.State != watch.StateSteered {
			continue
		}
		var groups []string
		if dev, ok := s.Devices.Get(d.DeviceID); ok {
			groups = dev.Groups
		}
		devs = append(devs, map[string]any{
			"device_id": d.DeviceID, "name": d.Name, "groups": orEmpty(groups),
			"up_bytes_per_second": d.BytesPerSecond, "down_bytes_per_second": d.RxBytesPerSecond,
			"bytes_relayed": d.BytesRelayed, "bytes_received_est": d.BytesReceivedEst,
		})
	}
	sort.SliceStable(devs, func(i, j int) bool {
		ri := devs[i]["up_bytes_per_second"].(float64) + devs[i]["down_bytes_per_second"].(float64)
		rj := devs[j]["up_bytes_per_second"].(float64) + devs[j]["down_bytes_per_second"].(float64)
		if ri != rj {
			return ri > rj
		}
		return devs[i]["bytes_relayed"].(uint64)+devs[i]["bytes_received_est"].(uint64) > devs[j]["bytes_relayed"].(uint64)+devs[j]["bytes_received_est"].(uint64)
	})
	out["devices"] = devs
	if !out["measuring"].(bool) {
		s.fillFromRouter(out)
	}
	writeJSON(w, out)
}

// fillFromRouter puts the router reader's last poll into the live card,
// for a network where Watch mode is not measuring. Watch mode's own
// numbers always win where it is running, because they are measured
// rather than sampled.
func (s *Server) fillFromRouter(out map[string]any) {
	if s.RouterUsage == nil {
		return
	}
	st := s.RouterUsage.Status()
	if st.Source == "" || !st.Enabled || st.LastPoll == nil || st.LastError != "" {
		return
	}
	var down, up float64
	var downTotal, upTotal uint64
	devs := []map[string]any{}
	for _, d := range s.RouterUsage.Live() {
		down += d.DownBitsPerSecond
		up += d.UpBitsPerSecond
		downTotal += d.DownBytes
		upTotal += d.UpBytes
		// Shepherd's own name for the device wins over the router's.
		name, groups := d.Name, []string(nil)
		if dev, ok := s.Devices.Get(d.DeviceID); ok {
			if n := dev.DisplayName(); n != "" {
				name = n
			}
			groups = dev.Groups
		}
		devs = append(devs, map[string]any{
			"device_id": d.DeviceID, "name": name, "groups": orEmpty(groups),
			// Bits per second on the wire, bytes per second in the API, as
			// everywhere else here.
			"up_bytes_per_second": d.UpBitsPerSecond / 8, "down_bytes_per_second": d.DownBitsPerSecond / 8,
			"bytes_relayed": d.UpBytes, "bytes_received_est": d.DownBytes,
		})
	}
	out["live"] = map[string]any{
		"up_bytes_per_second": up / 8, "down_bytes_per_second": down / 8,
		"bytes_relayed": upTotal, "bytes_received_est": downTotal,
	}
	out["devices"] = devs
}

// trafficSeries is the history for one scope over [from, to] at a bucket
// resolution: minute, hour or day, chosen from the span unless named.
func (s *Server) trafficSeries(w http.ResponseWriter, r *http.Request) {
	from, to, ok := parseTimeRange(r, 24*time.Hour)
	if !ok {
		bad(w, "from/to must be RFC 3339 timestamps")
		return
	}
	ids, label, ok := s.trafficScope(r.URL.Query().Get("scope"))
	if !ok {
		notFound(w, "scope must be network, device:<id> or group:<id> for a device or group that exists")
		return
	}
	bucket := parseTrafficBucket(r, from, to)
	writeJSON(w, map[string]any{
		"scope": label, "bucket": bucket, "from": from, "to": to,
		"points": s.Traffic.Series(ids, from, to, bucket),
	})
}

// trafficTop ranks devices and groups by bytes moved over [from, to],
// heaviest first, with the network total. A device that no longer exists
// in the registry still appears, by ID, so history is never silently
// missing from the total.
func (s *Server) trafficTop(w http.ResponseWriter, r *http.Request) {
	from, to, ok := parseTimeRange(r, 24*time.Hour)
	if !ok {
		bad(w, "from/to must be RFC 3339 timestamps")
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			bad(w, "limit must be a non-negative integer")
			return
		}
		limit = n
	}
	totals := s.Traffic.Totals(from, to)
	type row struct {
		id, name string
		groups   []string
		d        traffic.Delta
	}
	var rows []row
	var network traffic.Delta
	byGroup := map[string]traffic.Delta{}
	for id, d := range totals {
		rw := row{id: id, d: d}
		if dev, ok := s.Devices.Get(id); ok {
			rw.name = dev.DisplayName()
			rw.groups = dev.Groups
			for _, g := range dev.Groups {
				cur := byGroup[g]
				cur.Up += d.Up
				cur.Down += d.Down
				byGroup[g] = cur
			}
		}
		rows = append(rows, rw)
		network.Up += d.Up
		network.Down += d.Down
	}
	sort.Slice(rows, func(i, j int) bool {
		ti, tj := rows[i].d.Up+rows[i].d.Down, rows[j].d.Up+rows[j].d.Down
		if ti != tj {
			return ti > tj
		}
		return rows[i].id < rows[j].id
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	devs := make([]map[string]any, 0, len(rows))
	for _, rw := range rows {
		devs = append(devs, map[string]any{"device_id": rw.id, "name": rw.name, "groups": orEmpty(rw.groups), "up": rw.d.Up, "down": rw.d.Down})
	}
	groups := make([]map[string]any, 0, len(byGroup))
	for gid, d := range byGroup {
		name := gid
		if g, ok := s.Devices.GetGroup(gid); ok {
			name = g.Name
		}
		groups = append(groups, map[string]any{"group_id": gid, "name": name, "up": d.Up, "down": d.Down})
	}
	sort.Slice(groups, func(i, j int) bool {
		ti := groups[i]["up"].(uint64) + groups[i]["down"].(uint64)
		tj := groups[j]["up"].(uint64) + groups[j]["down"].(uint64)
		if ti != tj {
			return ti > tj
		}
		return groups[i]["group_id"].(string) < groups[j]["group_id"].(string)
	})
	writeJSON(w, map[string]any{
		"from": from, "to": to,
		"network": map[string]any{"up": network.Up, "down": network.Down},
		"devices": devs, "groups": groups,
	})
}
