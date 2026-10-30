// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shepherd/internal/importers"
)

// Synthetic eero credentials for the fake server below. None is real.
const (
	impTestLogin   = "owner@example.net"
	impTestCode    = "135790"
	impTestPending = "pending-xyz"
)

// newFakeEero starts a tiny stand-in for eero's cloud API, reproducing just
// enough of the shapes internal/importers' Client expects for one network
// with one device, one profile and one node.
func newFakeEero(t *testing.T) string { return newFakeEeroFailing(t, "") }

// newFakeEeroFailing is newFakeEero, except the given path (once past login
// and verify) always answers 500 - for testing what the portal does when a
// later eero call itself fails.
func newFakeEeroFailing(t *testing.T, failPath string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		write := func(code int, body string) { w.WriteHeader(code); fmt.Fprint(w, body) }
		ck := ""
		if c, err := r.Cookie("s"); err == nil {
			ck = c.Value
		}
		if failPath != "" && r.URL.Path == failPath {
			write(500, `{"meta":{"code":500,"error":"error.internal"}}`)
			return
		}
		switch {
		case r.URL.Path == "/2.2/login" && r.Method == http.MethodPost:
			var in struct {
				Login string `json:"login"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Login != impTestLogin {
				write(422, `{"meta":{"code":422,"error":"error.login.invalid"}}`)
				return
			}
			write(200, `{"meta":{"code":200},"data":{"user_token":"`+impTestPending+`"}}`)
		case r.URL.Path == "/2.2/login/verify" && r.Method == http.MethodPost:
			if ck != impTestPending {
				write(401, `{"meta":{"code":401,"error":"error.session.invalid"}}`)
				return
			}
			var in struct {
				Code string `json:"code"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			switch in.Code {
			case impTestCode:
				write(200, `{"meta":{"code":200},"data":{}}`)
			case "000000":
				write(401, `{"meta":{"code":401,"error":"error.verification.expired"}}`)
			default:
				write(401, `{"meta":{"code":401,"error":"error.verification.invalid"}}`)
			}
		case ck != impTestPending:
			write(401, `{"meta":{"code":401,"error":"error.session.refresh"}}`)
		case r.URL.Path == "/2.2/account":
			write(200, `{"meta":{"code":200},"data":{"networks":[{"url":"/2.2/networks/3001","name":"Home Base"}]}}`)
		case r.URL.Path == "/2.2/networks/3001/devices":
			write(200, `{"meta":{"code":200},"data":[{"url":"/2.2/networks/3001/devices/02:00:5e:aa:bb:01",
				"mac":"02:00:5E:AA:BB:01","nickname":"Kid iPad","hostname":"ipad-1","manufacturer":"ExampleCo",
				"wireless":true,"device_type":"tablet","profile":{"name":"Kids","url":"/2.2/networks/3001/profiles/501"}}]}`)
		case r.URL.Path == "/2.2/networks/3001/profiles":
			write(200, `{"meta":{"code":200},"data":[{"url":"/2.2/networks/3001/profiles/501","name":"Kids",
				"devices":[{"url":"/2.2/networks/3001/devices/02:00:5e:aa:bb:01","mac":"02:00:5e:aa:bb:01"}]}]}`)
		case r.URL.Path == "/2.2/networks/3001/eeros":
			write(200, `{"meta":{"code":200},"data":[{"url":"/2.2/eeros/10","location":"Office",
				"mac_address":"00:00:5e:aa:bb:02","ip_address":"203.0.113.5","gateway":true,"model":"eero 6"}]}`)
		default:
			write(404, `{"meta":{"code":404,"error":"error.not-found"}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// withEero points h's server at a fake eero API instead of the real one.
func (h *harness) withEero(base string) {
	h.srv.NewEeroClient = func() (*importers.Client, error) {
		return importers.NewTestClient(base, importers.ClientOptions{MinInterval: -1})
	}
}

func TestImportEeroFlow(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))

	h.expect("POST", "/api/import/eero/start", `{"login":""}`, 400)
	h.expect("POST", "/api/import/eero/start", `{"login":"not-an-account"}`, 400) // the fake server only knows impTestLogin

	m := h.ok("POST", "/api/import/eero/start", fmt.Sprintf(`{"login":%q}`, impTestLogin), 200)
	sid, _ := m["session_id"].(string)
	if sid == "" {
		t.Fatalf("no session_id: %v", m)
	}

	h.expect("POST", "/api/import/eero/preview", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, sid), 400) // not verified yet
	h.expect("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":"000000"}`, sid), 400)      // expired
	h.expect("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":"000001"}`, sid), 400)      // wrong

	m = h.ok("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":%q}`, sid, impTestCode), 200)
	nets, _ := m["networks"].([]any)
	if len(nets) != 1 {
		t.Fatalf("networks: %v", m)
	}
	net0 := nets[0].(map[string]any)
	if net0["id"] != "3001" || net0["name"] != "Home Base" {
		t.Fatalf("network: %v", net0)
	}

	h.expect("POST", "/api/import/eero/preview", fmt.Sprintf(`{"session_id":%q,"network_id":"nope"}`, sid), 400)
	h.expect("POST", "/api/import/eero/apply", fmt.Sprintf(`{"session_id":%q}`, sid), 400) // nothing previewed yet

	m = h.ok("POST", "/api/import/eero/preview", fmt.Sprintf(`{"session_id":%q,"network_id":"3001","overwrite_names":false}`, sid), 200)
	if dr, _ := m["dry_run"].(bool); !dr {
		t.Fatalf("preview should be a dry run: %v", m)
	}
	if created, _ := m["created"].(float64); created < 1 {
		t.Fatalf("expected a device to create: %v", m)
	}
	if gc, _ := m["groups_created"].(float64); gc < 1 {
		t.Fatalf("expected the Kids group to be created: %v", m)
	}
	if h.reg.Len() != 0 {
		t.Fatal("preview must not change the registry")
	}

	m = h.ok("POST", "/api/import/eero/apply", fmt.Sprintf(`{"session_id":%q}`, sid), 200)
	if dr, _ := m["dry_run"].(bool); dr {
		t.Fatalf("apply must not be a dry run: %v", m)
	}
	if ch, _ := m["changed"].(bool); !ch {
		t.Fatalf("apply should report a change: %v", m)
	}

	found := false
	for _, d := range h.reg.List() {
		if d.Alias == "Kid iPad" {
			found = true
			if len(d.Groups) != 1 {
				t.Fatalf("expected the device in one group: %+v", d)
			}
		}
	}
	if !found {
		t.Fatal("the imported device was not found in the registry")
	}

	// The session (and its eero token) is gone once applied.
	h.expect("POST", "/api/import/eero/apply", fmt.Sprintf(`{"session_id":%q}`, sid), 404)
	h.expect("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":%q}`, sid, impTestCode), 404)
}

func TestImportEeroCancel(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))
	m := h.ok("POST", "/api/import/eero/start", fmt.Sprintf(`{"login":%q}`, impTestLogin), 200)
	sid := m["session_id"].(string)
	h.ok("POST", "/api/import/eero/cancel", fmt.Sprintf(`{"session_id":%q}`, sid), 200)
	h.expect("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":%q}`, sid, impTestCode), 404)
	h.ok("POST", "/api/import/eero/cancel", fmt.Sprintf(`{"session_id":%q}`, sid), 200) // idempotent
	h.ok("POST", "/api/import/eero/cancel", `{}`, 200)                                  // unknown/empty id: still ok
}

func TestImportEeroMissingSession(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))
	h.expect("POST", "/api/import/eero/verify", `{"session_id":"nope","code":"123456"}`, 404)
	h.expect("POST", "/api/import/eero/preview", `{"session_id":"nope","network_id":"3001"}`, 404)
	h.expect("POST", "/api/import/eero/apply", `{"session_id":"nope"}`, 404)
}

func TestImportCSVFlow(t *testing.T) {
	h := newHarness(t)
	csv := "mac,name,groups\n02:00:5e:cc:dd:01,Office Printer,Office\nnot-a-mac,Bad Row,\n"

	h.expect("POST", "/api/import/csv/preview", `{"csv":""}`, 400)
	h.expect("POST", "/api/import/csv/preview", fmt.Sprintf(`{"csv":%q}`, "name\nonly a name\n"), 400) // no mac or ip column

	m := h.ok("POST", "/api/import/csv/preview", fmt.Sprintf(`{"csv":%q}`, csv), 200)
	if dr, _ := m["dry_run"].(bool); !dr {
		t.Fatalf("preview should be a dry run: %v", m)
	}
	if created, _ := m["created"].(float64); created != 1 {
		t.Fatalf("expected exactly one creatable device: %v", m)
	}
	rowErrs, _ := m["row_errors"].([]any)
	if len(rowErrs) != 2 { // the bad MAC itself, then the row being skipped for lack of any usable address
		t.Fatalf("expected two row errors for the bad MAC row: %v", m)
	}
	if h.reg.Len() != 0 {
		t.Fatal("preview must not change the registry")
	}

	m = h.ok("POST", "/api/import/csv/apply", fmt.Sprintf(`{"csv":%q}`, csv), 200)
	if dr, _ := m["dry_run"].(bool); dr {
		t.Fatalf("apply must not be a dry run: %v", m)
	}
	found := false
	for _, d := range h.reg.List() {
		if d.Alias == "Office Printer" {
			found = true
		}
	}
	if !found {
		t.Fatal("the imported device was not found in the registry")
	}
}

func TestImportCSVOverwriteNames(t *testing.T) {
	h := newHarness(t)
	id := h.addDevice("02:00:5e:cc:dd:02", "203.0.113.9", "")
	if err := h.reg.Rename(id, "My Name"); err != nil {
		t.Fatal(err)
	}
	csv := "mac,name\n02:00:5e:cc:dd:02,Imported Name\n"

	m := h.ok("POST", "/api/import/csv/preview", fmt.Sprintf(`{"csv":%q,"overwrite_names":false}`, csv), 200)
	conflicts, _ := m["conflicts"].([]any)
	if len(conflicts) != 1 {
		t.Fatalf("expected a kept-your-name conflict: %v", m)
	}

	h.ok("POST", "/api/import/csv/apply", fmt.Sprintf(`{"csv":%q,"overwrite_names":true}`, csv), 200)
	d, _ := h.reg.Get(id)
	if d.Alias != "Imported Name" {
		t.Fatalf("overwrite_names did not replace the name: %+v", d)
	}
}

func TestNewEeroClientDefault(t *testing.T) {
	s := &Server{}
	c, err := s.newEeroClient()
	if err != nil || c == nil {
		t.Fatalf("default eero client: %v", err)
	}
}

func TestEeroErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{importers.ErrEeroInvalidCode, http.StatusBadRequest},
		{importers.ErrEeroCodeExpired, http.StatusBadRequest},
		{importers.ErrEeroRateLimited, http.StatusTooManyRequests},
		{importers.ErrEeroUnauthorized, http.StatusUnauthorized},
		{importers.ErrEeroSessionExpire, http.StatusUnauthorized},
		{importers.ErrEeroNoSession, http.StatusUnauthorized},
		{importers.ErrEeroBadResponse, http.StatusBadRequest},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		eeroError(w, c.err)
		if w.Code != c.want {
			t.Errorf("%v: got %d, want %d", c.err, w.Code, c.want)
		}
	}
}

func TestImportMalformedJSON(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))
	for _, path := range []string{
		"/api/import/eero/start", "/api/import/eero/verify", "/api/import/eero/preview",
		"/api/import/eero/apply", "/api/import/eero/cancel",
		"/api/import/csv/preview", "/api/import/csv/apply",
	} {
		h.expect("POST", path, `{not json`, 400)
	}
}

func TestImportEeroVerifyBadCode(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEero(t))
	m := h.ok("POST", "/api/import/eero/start", fmt.Sprintf(`{"login":%q}`, impTestLogin), 200)
	sid := m["session_id"].(string)
	h.expect("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":""}`, sid), 400)
}

func TestImportEeroStartClientError(t *testing.T) {
	h := newHarness(t)
	h.srv.NewEeroClient = func() (*importers.Client, error) { return nil, fmt.Errorf("boom") }
	h.expect("POST", "/api/import/eero/start", fmt.Sprintf(`{"login":%q}`, impTestLogin), 500)
}

func TestImportEeroNetworksFails(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEeroFailing(t, "/2.2/account"))
	m := h.ok("POST", "/api/import/eero/start", fmt.Sprintf(`{"login":%q}`, impTestLogin), 200)
	sid := m["session_id"].(string)
	h.expect("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":%q}`, sid, impTestCode), 400)
}

func TestImportEeroSnapshotFails(t *testing.T) {
	h := newHarness(t)
	h.withEero(newFakeEeroFailing(t, "/2.2/networks/3001/devices"))
	m := h.ok("POST", "/api/import/eero/start", fmt.Sprintf(`{"login":%q}`, impTestLogin), 200)
	sid := m["session_id"].(string)
	h.ok("POST", "/api/import/eero/verify", fmt.Sprintf(`{"session_id":%q,"code":%q}`, sid, impTestCode), 200)
	h.expect("POST", "/api/import/eero/preview", fmt.Sprintf(`{"session_id":%q,"network_id":"3001"}`, sid), 400)
}

// TestImportCSVPlanTooLarge drives importers.ErrPlanTooLarge through both the
// preview and apply handlers' error branches with more distinct groups than
// Sanitize allows.
func TestImportCSVPlanTooLarge(t *testing.T) {
	h := newHarness(t)
	var b strings.Builder
	b.WriteString("mac,name,groups\n")
	for i := 0; i < importers.MaxGroups+1; i++ {
		fmt.Fprintf(&b, "02:00:5e:%02x:%02x:%02x,Device %d,Group %d\n", (i>>16)&0xff, (i>>8)&0xff, i&0xff, i, i)
	}
	csv := b.String()
	h.expect("POST", "/api/import/csv/preview", fmt.Sprintf(`{"csv":%q}`, csv), 400)
	h.expect("POST", "/api/import/csv/apply", fmt.Sprintf(`{"csv":%q}`, csv), 400)
}

func TestEeroSessionsExpiry(t *testing.T) {
	ss := newEeroSessions()
	c, err := importers.NewClient(importers.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := ss.create(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ss.get(id); !ok {
		t.Fatal("expected the session to be present")
	}
	ss.mu.Lock()
	ss.byID[id].expires = time.Now().Add(-time.Minute)
	ss.mu.Unlock()
	if _, ok := ss.get(id); ok {
		t.Fatal("expected the session to have expired")
	}
	ss.discard(id) // no-op: already swept
	ss.discard("") // no-op: unknown id
	if _, ok := ss.get(""); ok {
		t.Fatal("an empty id must never match")
	}
}
