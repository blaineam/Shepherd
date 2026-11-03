// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"net/http"
	"time"

	"shepherd/internal/selftest"
)

// SelftestSource is what the portal needs from the DNS self-test
// (*selftest.Tester).
type SelftestSource interface {
	Latest() (selftest.Report, bool)
	RunOnce(ctx context.Context) selftest.Report
}

// getSelftest returns the latest self-test report, or says there is none
// yet (the first round runs a few seconds after start) or that the test is
// off.
func (s *Server) getSelftest(w http.ResponseWriter, r *http.Request) {
	if s.Selftest == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	rep, ok := s.Selftest.Latest()
	if !ok {
		writeJSON(w, map[string]any{"enabled": true})
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "report": rep})
}

// runSelftest runs a round now and returns it.
func (s *Server) runSelftest(w http.ResponseWriter, r *http.Request) {
	if s.Selftest == nil {
		bad(w, "the DNS self-test is off (selftest.enabled = false)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, map[string]any{"enabled": true, "report": s.Selftest.RunOnce(ctx)})
}
