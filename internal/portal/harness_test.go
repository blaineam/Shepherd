// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
)

// testPolicy opens a policy store over a small catalog whose list sources live
// at base (a loopback test server), so nothing ever reaches the real network.
func testPolicy(t *testing.T, f *dnsengine.Filter, dir, base string) *dnsengine.PolicyStore {
	t.Helper()
	src := func(n string) []dnsengine.Source {
		return []dnsengine.Source{{URL: base + "/" + n + ".txt", Format: "domains"}}
	}
	cat, err := dnsengine.NewCatalogSet([]dnsengine.CatalogEntry{
		{ID: "ads-main", Kind: dnsengine.KindList, Name: "Main ads", Category: "ads", Sources: src("ads-main"), Recommended: true,
			License: "Test license", Homepage: "https://lists.example", ApproxEntries: 3, Description: "Blocks ads."},
		{ID: "chatapp", Kind: dnsengine.KindApp, Name: "ChatApp", Category: "social", Sources: src("chatapp"), Description: "A chat app."},
		{ID: "gameapp", Kind: dnsengine.KindApp, Name: "GameApp", Category: "gaming", Sources: src("gameapp")},
		{ID: "ads", Kind: dnsengine.KindCategory, Name: "Ads and Trackers", Includes: []string{"ads-main"}},
		{ID: "social", Kind: dnsengine.KindCategory, Name: "Social", Includes: []string{"chatapp"}},
		{ID: "gaming", Kind: dnsengine.KindCategory, Name: "Gaming", Includes: []string{"gameapp"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := dnsengine.OpenPolicyStore(filepath.Join(dir, "policy.json"), f, dnsengine.PolicyOptions{Catalog: cat})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type harness struct {
	t        *testing.T
	ts       *httptest.Server
	srv      *Server
	filter   *dnsengine.Filter
	policy   *dnsengine.PolicyStore
	geoBlock *dnsengine.GeoBlockStore
	reg      *devices.Registry
	lists    *dnsengine.ListManager
	pool     *dnsengine.Pool
	engine   *dnsengine.Engine
	ups      *dnsengine.UpstreamStore
	alarms   *alarms.Engine
	dir      string
	listSrv  *httptest.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	listSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chatapp.txt":
			fmt.Fprint(w, "chat.example\n")
		case "/gameapp.txt":
			fmt.Fprint(w, "game.example\n")
		case "/ads-main.txt":
			fmt.Fprint(w, "ads.example\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(listSrv.Close)
	filter := dnsengine.NewFilter()
	policy := testPolicy(t, filter, dir, listSrv.URL)
	pool, err := dnsengine.NewPool([]string{"192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	engine := &dnsengine.Engine{Filter: filter, Pool: pool, Cache: dnsengine.NewCache(10), Log: dnsengine.NewQueryLog(50), Stats: dnsengine.NewStats()}
	lists := dnsengine.NewScopedListManager(filter, policy, dir, nil)
	reg := devices.New(devices.Options{NodeID: "test", Vendor: func(string) string { return "" }})
	ups := dnsengine.OpenUpstreamStore(filepath.Join(dir, "upstreams.json"), pool)
	alarmEngine, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { alarmEngine.Close() })
	geoBlock, err := dnsengine.OpenGeoBlockStore(filepath.Join(dir, "geoblock.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Deps{Engine: engine, Lists: lists, Policy: policy, Devices: reg, Upstreams: ups, Alarms: alarmEngine, GeoBlock: geoBlock, Token: strings.Repeat("t", 64), Version: "test"})
	engine.Clients = reg
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &harness{t: t, ts: ts, srv: srv, filter: filter, policy: policy, geoBlock: geoBlock, reg: reg, lists: lists, pool: pool, engine: engine, ups: ups, alarms: alarmEngine, dir: dir, listSrv: listSrv}
}

// call sends an authenticated request with the CSRF header.
func (h *harness) call(method, path, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.ts.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
	req.Header.Set("X-Shepherd", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// ok calls and requires status want, returning the decoded JSON object.
func (h *harness) ok(method, path, body string, want int) map[string]any {
	h.t.Helper()
	code, out := h.call(method, path, body)
	if code != want {
		h.t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, out)
	}
	var m map[string]any
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			h.t.Fatalf("%s %s: bad JSON %q: %v", method, path, out, err)
		}
	}
	return m
}

// expect requires status want, whatever the body.
func (h *harness) expect(method, path, body string, want int) {
	h.t.Helper()
	if code, out := h.call(method, path, body); code != want {
		h.t.Errorf("%s %s %s = %d, want %d: %s", method, path, body, code, want, out)
	}
}

// addDevice puts a synthetic device on the registry and returns its ID.
func (h *harness) addDevice(mac, ip, host string) string {
	h.t.Helper()
	src := devices.SourceNeighbor
	if host != "" {
		src = devices.SourceMDNS
	}
	id := h.reg.Observe(devices.Observation{Source: src, MAC: mac, IP: ip, Hostname: host, Time: time.Now()})
	if id == "" {
		h.t.Fatalf("observation of %s was rejected", ip)
	}
	return id
}
