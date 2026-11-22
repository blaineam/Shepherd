// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"shepherd/internal/backends"
	"shepherd/internal/devices"
	"shepherd/internal/importers"
	"shepherd/internal/namesync"
	"shepherd/internal/secrets"
)

func namesRegistry(t *testing.T) *devices.Registry {
	t.Helper()
	return devices.New(devices.Options{NodeID: "test", Vendor: func(string) string { return "ExampleCo" }})
}

func entryFor(t *testing.T, list []namesync.Entry, mac string) namesync.Entry {
	t.Helper()
	for _, e := range list {
		if e.MAC == mac {
			return e
		}
	}
	t.Fatalf("no entry for %s in %+v", mac, list)
	return namesync.Entry{}
}

func TestTheRegistryOffersTheAliasOrWhatTheDeviceCallsItself(t *testing.T) {
	reg := namesRegistry(t)
	named := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:01", IP: "192.0.2.1", Hostname: "tablet-1"})
	plain := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:02", IP: "192.0.2.2", Hostname: "tv"})
	reg.Observe(devices.Observation{IP: "192.0.2.3"}) // no MAC: nothing to match it by
	if err := reg.Rename(named, "Kids tablet"); err != nil {
		t.Fatal(err)
	}
	src := registryNames{reg}
	if src.ID() != "shepherd" || src.Label() != "Shepherd" || src.ReadOnly() != "" || src.MaxLen() != 128 {
		t.Fatal("the registry describes itself wrongly")
	}
	list, err := src.Entries(context.Background())
	if err != nil || len(list) != 2 {
		t.Fatalf("entries = %+v, %v", list, err)
	}
	a := entryFor(t, list, "02005e000001")
	if a.Name != "Kids tablet" || !a.Typed || a.Learned || a.Vendor != "ExampleCo" {
		t.Errorf("aliased = %+v", a)
	}
	b := entryFor(t, list, "02005e000002")
	if b.Name != "tv" || b.Typed || !b.Learned {
		t.Errorf("unaliased = %+v", b)
	}
	if err := src.Rename(context.Background(), b, "Den TV"); err != nil {
		t.Fatal(err)
	}
	if d, _ := reg.FindByMAC("02:00:5e:00:00:02"); d.Alias != "Den TV" || d.ID != plain {
		t.Fatalf("device = %+v", d)
	}
}

func TestTheBackendIsReadFromTheHubAndWrittenOnlyWhenChangesAreAllowed(t *testing.T) {
	if _, ok := newBackendNames(nil); ok {
		t.Fatal("no manager is still a source")
	}
	idle := &backendManager{parent: context.Background(), sec: testSecrets(t)}
	if _, ok := newBackendNames(idle); ok {
		t.Fatal("a manager with nothing running is a source")
	}

	m, msp, _ := connected(t, false)
	awaitBackend(t, "the first poll", func() bool { s, _ := m.Snapshot(); return len(s.Devices) == 1 })
	src, ok := newBackendNames(m)
	if !ok || src.ID() != "firewalla" || src.Label() != "Firewalla" || src.MaxLen() != 32 {
		t.Fatalf("source = %+v, %v", src, ok)
	}
	if !strings.Contains(src.ReadOnly(), "Allow changes is off") {
		t.Fatalf("read-only reason = %q", src.ReadOnly())
	}
	list, err := src.Entries(context.Background())
	if err != nil || len(list) != 1 || list[0].MAC != "02005e000001" || list[0].Name != "TV" {
		t.Fatalf("entries = %+v, %v", list, err)
	}
	if err := src.Rename(context.Background(), list[0], "Den TV"); !errors.Is(err, backends.ErrReadOnly) {
		t.Fatalf("rename while read-only = %v", err)
	}

	if _, err := m.sec.SetFirewallaWrites(true); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	src, _ = newBackendNames(m)
	if src.ReadOnly() != "" {
		t.Fatalf("still read-only: %q", src.ReadOnly())
	}
	if err := src.Rename(context.Background(), list[0], "Den TV"); err != nil {
		t.Fatal(err)
	}
	msp.mu.Lock()
	defer msp.mu.Unlock()
	if len(msp.writes) != 1 || msp.writes[0] != "PATCH /v2/boxes/box-1/devices/02:00:5E:00:00:01" {
		t.Fatalf("writes = %v", msp.writes)
	}

	m.Stop()
	if _, err := src.Entries(context.Background()); !errors.Is(err, errNoBackend) {
		t.Fatalf("entries after stopping = %v", err)
	}
}

func TestABackendThatCannotRenameSaysSoAndAFailedReadIsAnError(t *testing.T) {
	m, _, _ := connected(t, true)
	awaitBackend(t, "the first poll", func() bool { s, _ := m.Snapshot(); return len(s.Devices) == 1 })
	// A product with no rename, whatever the write switch says.
	m.mu.Lock()
	m.rename, m.name = false, "unifi"
	m.mu.Unlock()
	if m.canRename() {
		t.Fatal("canRename ignores the product")
	}
	if hasCap([]backends.Capability{backends.CapDevices}, backends.CapDeviceRename) {
		t.Fatal("hasCap found what is not there")
	}
	b := &backendNames{m: m, name: "opnsense"}
	if b.Label() != "opnsense" || (&backendNames{name: "unifi"}).Label() != "UniFi" {
		t.Fatal("labels")
	}
}

// fakeEeroNames is an eero account with one named and one unnamed device.
type fakeEeroNames struct {
	mu      sync.Mutex
	renames []string
	fail    int
}

func (f *fakeEeroNames) server(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fail != 0 {
			w.WriteHeader(f.fail)
			fmt.Fprintf(w, `{"meta":{"code":%d,"error":"error.session.refresh"}}`, f.fail)
			return
		}
		if r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			var in map[string]string
			_ = json.Unmarshal(body, &in)
			f.renames = append(f.renames, r.URL.Path+"="+in["nickname"])
			fmt.Fprint(w, `{"meta":{"code":200},"data":{}}`)
			return
		}
		fmt.Fprint(w, `{"meta":{"code":200},"data":[
		 {"mac":"02:00:5E:00:00:11","nickname":"Kids Tablet","hostname":"tablet-1","manufacturer":"ExampleCo"},
		 {"mac":"02:00:5e:00:00:12","nickname":null,"hostname":"tv","manufacturer":"ExampleCo"},
		 {"mac":"02:00:5e:00:00:13","nickname":"ExampleCo","hostname":"","manufacturer":"ExampleCo"},
		 {"mac":"02:00:5e:00:00:14","nickname":"printer","hostname":"printer"},
		 {"mac":"","nickname":"no mac"}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestEeroNamesKnowATypedNicknameFromAHostname(t *testing.T) {
	sec := testSecrets(t)
	f := &fakeEeroNames{}
	base := f.server(t)
	src := &eeroNames{sec: sec, open: func(s importers.TokenStore) (*importers.Client, error) {
		return importers.NewTestClient(base, importers.ClientOptions{TokenStore: s, MinInterval: -1})
	}}
	if src.ID() != "eero" || src.Label() != "eero" || src.ReadOnly() != "" || src.MaxLen() != 0 {
		t.Fatal("eero describes itself wrongly")
	}
	ctx := context.Background()
	if src.connected() {
		t.Fatal("connected with nothing stored")
	}
	if _, err := src.Entries(ctx); !errors.Is(err, importers.ErrEeroNoSession) {
		t.Fatalf("entries signed out = %v", err)
	}
	if err := src.Rename(ctx, namesync.Entry{Handle: "02005e000011"}, "x"); !errors.Is(err, importers.ErrEeroNoSession) {
		t.Fatalf("rename signed out = %v", err)
	}
	if _, err := sec.SetEero(secrets.Eero{Token: "eero-token-abc", NetworkID: "3001", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if !src.connected() {
		t.Fatal("a stored session with a network is a connection, switched on for bandwidth or not")
	}

	list, err := src.Entries(ctx)
	if err != nil || len(list) != 4 {
		t.Fatalf("entries = %+v, %v", list, err)
	}
	if e := entryFor(t, list, "02005e000011"); e.Name != "Kids Tablet" || !e.Typed || e.Learned {
		t.Errorf("nicknamed = %+v", e)
	}
	if e := entryFor(t, list, "02005e000012"); e.Name != "tv" || e.Typed || !e.Learned {
		t.Errorf("hostname only = %+v", e)
	}
	if e := entryFor(t, list, "02005e000013"); e.Typed || !e.Learned {
		t.Errorf("maker as nickname = %+v", e)
	}
	if e := entryFor(t, list, "02005e000014"); e.Typed || !e.Learned {
		t.Errorf("hostname as nickname = %+v", e)
	}

	if err := src.Rename(ctx, entryFor(t, list, "02005e000012"), "Den TV"); err != nil {
		t.Fatal(err)
	}
	if len(f.renames) != 1 || f.renames[0] != "/2.2/networks/3001/devices/02005e000012=Den TV" {
		t.Fatalf("renames = %v", f.renames)
	}

	f.mu.Lock()
	f.fail = 401
	f.mu.Unlock()
	if _, err := src.Entries(ctx); !errors.Is(err, importers.ErrEeroSessionExpire) {
		t.Fatalf("expired = %v", err)
	}
}

func TestEeroNamesReportAClientThatCannotBeOpened(t *testing.T) {
	sec := testSecrets(t)
	if _, err := sec.SetEero(secrets.Eero{Token: "eero-token-abc", NetworkID: "3001"}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("no client")
	src := &eeroNames{sec: sec, open: func(importers.TokenStore) (*importers.Client, error) { return nil, boom }}
	if _, err := src.Entries(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	// With no hook it builds the real client, which resumes the session.
	real := &eeroNames{sec: sec}
	if c, network, err := real.client(); err != nil || network != "3001" || !c.HasSession() {
		t.Fatalf("client = %v, %q, %v", c, network, err)
	}
}

func TestStartNamesSyncsTheRegistryWithWhatIsConnected(t *testing.T) {
	m, msp, _ := connected(t, true)
	awaitBackend(t, "the first poll", func() bool { s, _ := m.Snapshot(); return len(s.Devices) == 1 })
	reg := namesRegistry(t)
	id := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:01", IP: "192.0.2.5", Hostname: "tv"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := startNames(ctx, m.sec, reg, m, t.TempDir())

	// Firewalla's "TV" and the hostname "tv" are equally plain, so
	// Shepherd's, the earlier source, stays and is written to the Firewalla.
	rep, err := e.Preview(ctx)
	if err != nil || len(rep.Sources) != 2 || rep.Sources[1].ID != "firewalla" || rep.Written != 1 {
		t.Fatalf("preview = %+v, %v", rep, err)
	}
	// A rename in Shepherd is an edit, and reaches the Firewalla.
	if _, err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := reg.Rename(id, "Den TV"); err != nil {
		t.Fatal(err)
	}
	rep, err = e.Sync(ctx)
	if err != nil || rep.Written != 1 || rep.Changes[0].Reason != "edit" || rep.Changes[0].From != "shepherd" {
		t.Fatalf("sync = %+v, %v", rep, err)
	}
	msp.mu.Lock()
	defer msp.mu.Unlock()
	if len(msp.writes) != 2 {
		t.Fatalf("writes = %v", msp.writes)
	}
}
