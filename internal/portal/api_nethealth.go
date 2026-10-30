// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"net/http"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/nethealth"
)

// nethealthProbeTimeout/nethealthBufferbloatTimeout bound a manual "run
// now" request from the portal, the same convention
// cmd/shepherd/portscan.go and cmd/shepherd/vulnscan.go's own manual-scan
// endpoints use. Bufferbloat's own bound is longer: it needs to cover its
// own BufferbloatOptions.Duration (5s by default) plus the idle/loaded
// ping bursts around it.
const (
	nethealthProbeTimeout       = 10 * time.Second
	nethealthBufferbloatTimeout = 30 * time.Second
)

func targetResultJSON(r nethealth.TargetResult) map[string]any {
	return map[string]any{
		"host": r.Host, "probes": r.Probes, "successes": r.Successes,
		"avg_latency_ms": r.AvgLatencyMS, "jitter_ms": r.JitterMS, "loss_pct": r.LossPct,
	}
}

func sampleJSON(s nethealth.Sample) map[string]any {
	targets := make([]map[string]any, len(s.Targets))
	for i, t := range s.Targets {
		targets[i] = targetResultJSON(t)
	}
	return map[string]any{
		"time": s.Time, "latency_ms": s.LatencyMS, "jitter_ms": s.JitterMS, "loss_pct": s.LossPct,
		"reachable_targets": s.ReachableTargets, "total_targets": s.TotalTargets, "targets": targets,
	}
}

func bufferbloatJSON(b nethealth.Bufferbloat) map[string]any {
	out := map[string]any{
		"time": b.Time, "ping_target": b.PingTarget, "idle_ms": b.IdleMS, "loaded_ms": b.LoadedMS,
		"increase_ms": b.IncreaseMS, "grade": b.Grade,
	}
	if b.LoadError != "" {
		out["load_error"] = b.LoadError
	}
	return out
}

// nethealthDegraded reports whether alarms.TypeNetworkDegraded currently
// has an open (non-resolved) alarm, so the portal can show "degraded"
// without duplicating cmd/shepherd/nethealth.go's own threshold logic.
func (s *Server) nethealthDegraded() bool {
	if s.Alarms == nil {
		return false
	}
	page := s.Alarms.List(alarms.Query{
		Filter: alarms.Filter{Types: []string{alarms.TypeNetworkDegraded}, States: []alarms.State{alarms.StateNew, alarms.StateAcknowledged, alarms.StateMuted}},
		Limit:  1,
	})
	return page.Total > 0
}

func (s *Server) getNethealth(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"enabled":             s.NethealthEnabled,
		"bufferbloat_enabled": s.NethealthBufferbloatEnabled,
		"degraded":            s.nethealthDegraded(),
	}
	if cur, ok := s.Nethealth.Latest(); ok {
		out["current"] = sampleJSON(cur)
	}
	targets, _ := s.currentNethealthTargets()
	if targets == nil {
		targets = []string{}
	}
	out["targets"] = targets
	writeJSON(w, out)
}

// parseTimeRange reads from/to query parameters (RFC 3339), defaulting to
// [now-defaultSpan, now] when either is missing or unparseable.
func parseTimeRange(r *http.Request, defaultSpan time.Duration) (from, to time.Time, ok bool) {
	now := time.Now()
	from, to = now.Add(-defaultSpan), now
	if v := r.URL.Query().Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, time.Time{}, false
		}
		from = t
	}
	if v := r.URL.Query().Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, time.Time{}, false
		}
		to = t
	}
	return from, to, true
}

// defaultBucket picks a sensible resolution when the caller does not name
// one: raw detail for a short recent window (within the raw retention
// window this still has full resolution), hourly for anything out to a
// couple of months, daily beyond that — matching Store's own retention
// windows (docs/NETHEALTH.md's "Retention" section) so a request never
// silently gets an empty series by asking "raw" for a range that was
// already rolled up and away.
func defaultBucket(from, to time.Time) nethealth.Bucket {
	span := to.Sub(from)
	switch {
	case span <= 3*24*time.Hour:
		return nethealth.BucketRaw
	case span <= 60*24*time.Hour:
		return nethealth.BucketHour
	default:
		return nethealth.BucketDay
	}
}

func parseBucket(r *http.Request, from, to time.Time) nethealth.Bucket {
	switch r.URL.Query().Get("bucket") {
	case "raw":
		return nethealth.BucketRaw
	case "hour":
		return nethealth.BucketHour
	case "day":
		return nethealth.BucketDay
	default:
		return defaultBucket(from, to)
	}
}

func (s *Server) nethealthSeries(w http.ResponseWriter, r *http.Request) {
	from, to, ok := parseTimeRange(r, 24*time.Hour)
	if !ok {
		bad(w, "from/to must be RFC 3339 timestamps")
		return
	}
	bucket := parseBucket(r, from, to)
	points := s.Nethealth.Series(from, to, bucket)
	writeJSON(w, map[string]any{"bucket": bucket, "points": points})
}

func (s *Server) nethealthBufferbloat(w http.ResponseWriter, r *http.Request) {
	from, to, ok := parseTimeRange(r, 30*24*time.Hour)
	if !ok {
		bad(w, "from/to must be RFC 3339 timestamps")
		return
	}
	hist := s.Nethealth.BufferbloatHistory(from, to)
	out := make([]map[string]any, len(hist))
	for i, b := range hist {
		out[i] = bufferbloatJSON(b)
	}
	writeJSON(w, map[string]any{"points": out})
}

func (s *Server) nethealthProbeNow(w http.ResponseWriter, r *http.Request) {
	targets, ok := s.currentNethealthTargets()
	if !ok {
		bad(w, "no nethealth targets are configured (cmd/shepherd did not wire this feature in)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nethealthProbeTimeout)
	defer cancel()
	sample := s.Nethealth.ProbeNow(ctx, targets)
	writeJSON(w, sampleJSON(sample))
}

// currentNethealthTargets is the target list a manual probe or bufferbloat
// run uses: the most recent scheduled probe's own targets when one has
// run, falling back to s.NethealthTargets (what cmd/shepherd computed at
// startup — see docs/NETHEALTH.md) so manual checks work even when the
// scheduled probe is disabled, which is the default. Only truly empty
// (ok=false) when cmd/shepherd never wired Nethealth in at all.
func (s *Server) currentNethealthTargets() ([]string, bool) {
	if cur, ok := s.Nethealth.Latest(); ok && len(cur.Targets) > 0 {
		out := make([]string, len(cur.Targets))
		for i, t := range cur.Targets {
			out[i] = t.Host
		}
		return out, true
	}
	if len(s.NethealthTargets) > 0 {
		return append([]string(nil), s.NethealthTargets...), true
	}
	return nil, false
}

func (s *Server) nethealthBufferbloatNow(w http.ResponseWriter, r *http.Request) {
	targets, ok := s.currentNethealthTargets()
	if !ok || len(targets) == 0 {
		bad(w, "no nethealth targets are configured (cmd/shepherd did not wire this feature in)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nethealthBufferbloatTimeout)
	defer cancel()
	b := s.Nethealth.BufferbloatNow(ctx, targets[0], nethealth.BufferbloatOptions{})
	writeJSON(w, bufferbloatJSON(b))
}
