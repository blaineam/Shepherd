// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
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
	"shepherd/internal/namesync"
	"shepherd/internal/secrets"
)

func TestTheRegistryOffersOneRealGroupPerDevice(t *testing.T) {
	reg := namesRegistry(t)
	tv := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:01", IP: "192.0.2.1", Hostname: "tv"})
	plug := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:02", IP: "192.0.2.2", Hostname: "plug"})
	loose := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:03", IP: "192.0.2.3", Hostname: "new"})
	reg.Observe(devices.Observation{IP: "192.0.2.4"}) // no MAC
	smart, _ := reg.CreateGroup("Smart Home", "")
	den, _ := reg.CreateGroup("Den", "")
	un, _ := reg.CreateGroup("Unassigned", "")
	q := reg.EnsureQuarantineGroup()
	for _, a := range []struct{ id, group string }{{tv, smart.ID}, {tv, den.ID}, {plug, un.ID}, {loose, q.ID}} {
		if _, err := reg.BulkAssignGroup([]string{a.id}, a.group); err != nil {
			t.Fatal(err)
		}
	}
	src := registryGroups{reg}
	if src.ID() != "shepherd" || src.Label() != "Shepherd" || src.ReadOnly() != "" || src.MaxLen() != 64 {
		t.Fatal("the registry describes itself wrongly")
	}
	ctx := context.Background()
	list, err := src.Entries(ctx)
	if err != nil || len(list) != 3 {
		t.Fatalf("entries = %+v, %v", list, err)
	}
	// In two groups: the first by ID is offered. Quarantine and
	// "Unassigned" are not groups to sync.
	if e := entryFor(t, list, "02005e000001"); e.Name != "Den" || !e.Typed {
		t.Errorf("tv = %+v", e)
	}
	if e := entryFor(t, list, "02005e000002"); e.Name != "" {
		t.Errorf("unassigned = %+v", e)
	}
	if e := entryFor(t, list, "02005e000003"); e.Name != "" {
		t.Errorf("quarantined = %+v", e)
	}

	groupsOf := func(id string) string {
		d, _ := reg.Get(id)
		return strings.Join(d.Groups, ",")
	}
	// Moving the TV: out of the group that was offered, into one that
	// exists (matched without regard to case); its other group is kept.
	if err := src.Rename(ctx, entryFor(t, list, "02005e000001"), "smart home"); err != nil {
		t.Fatal(err)
	}
	if got := groupsOf(tv); got != smart.ID {
		t.Errorf("tv is in %q", got)
	}
	// Into a group Shepherd does not have yet: it is made. Leaving
	// quarantine comes with being sorted somewhere real.
	if err := src.Rename(ctx, entryFor(t, list, "02005e000003"), "Kids"); err != nil {
		t.Fatal(err)
	}
	kids, ok := reg.GroupByName("Kids")
	if !ok || groupsOf(loose) != kids.ID {
		t.Errorf("new device is in %q", groupsOf(loose))
	}
	// Out of its group altogether.
	list, _ = src.Entries(ctx)
	if err := src.Rename(ctx, entryFor(t, list, "02005e000001"), "  "); err != nil {
		t.Fatal(err)
	}
	if got := groupsOf(tv); got != "" {
		t.Errorf("tv is still in %q", got)
	}
	// Moving to the group it is already in changes nothing and is not an error.
	list, _ = src.Entries(ctx)
	if err := src.Rename(ctx, entryFor(t, list, "02005e000003"), "Kids"); err != nil || groupsOf(loose) != kids.ID {
		t.Errorf("no-op move: %v, in %q", err, groupsOf(loose))
	}

	// What cannot be done is an error: a name too long to be a group, a
	// device that has gone, a group deleted under the move.
	if err := src.Rename(ctx, entryFor(t, list, "02005e000002"), strings.Repeat("x", 65)); !errors.Is(err, devices.ErrInvalid) {
		t.Errorf("long name = %v", err)
	}
	gone := namesync.Entry{Handle: groupHandle{device: "no-such-device"}}
	if err := src.Rename(ctx, gone, "Kids"); !errors.Is(err, devices.ErrNotFound) {
		t.Errorf("missing device = %v", err)
	}
	stale := namesync.Entry{Handle: groupHandle{device: loose, group: "deleted-group"}}
	if err := src.Rename(ctx, stale, ""); err != nil {
		t.Errorf("a group already gone should not stop a removal: %v", err)
	}

	if groupRank(namesync.Entry{Name: " "}) != namesync.Useless || groupRank(namesync.Entry{Name: "Den"}) <= namesync.Useless {
		t.Error("groupRank")
	}
}

// groupBox answers like a Firewalla's loopback API with device groups.
func groupBox(t *testing.T, writes *[]string, mu *sync.Mutex) http.RoundTripper {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		key := q.Get("command") + " " + q.Get("item")
		switch key {
		case "get tags":
			fmt.Fprint(w, `{"code":200,"data":{"tags":{"18":{"uid":"18","name":"Smart Home"}}}}`)
		case "get hosts":
			fmt.Fprint(w, `{"code":200,"data":{"hosts":[
			 {"mac":"02:00:5E:00:00:01","bname":"tv","tags":["18"]},
			 {"mac":"02:00:5E:00:00:02","bname":"plug","tags":[]}]}}`)
		case "cmd tag:create":
			fmt.Fprint(w, `{"code":200,"data":{"uid":"21","name":"Den"}}`)
		default:
			if q.Get("command") != "get" {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				*writes = append(*writes, key+" "+q.Get("target")+" "+string(body))
				mu.Unlock()
			}
			fmt.Fprint(w, `{"code":200,"data":{}}`)
		}
	}))
	t.Cleanup(srv.Close)
	target := strings.TrimPrefix(srv.URL, "http://")
	return rtFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Host = target
		return http.DefaultTransport.RoundTrip(r)
	})
}

func TestGroupsAreKeptTheSameInShepherdAndOnTheBox(t *testing.T) {
	if _, ok := newBackendGroups(nil); ok {
		t.Fatal("no manager is still a source")
	}
	sec := testSecrets(t)
	if _, err := sec.SetFirewalla(secrets.Firewalla{BaseURL: "http://127.0.0.1:8834", Local: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var (
		writes []string
		mu     sync.Mutex
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := namesRegistry(t)
	m := &backendManager{parent: ctx, sec: sec, reg: reg, dataDir: t.TempDir(), transport: groupBox(t, &writes, &mu)}
	t.Cleanup(m.Stop)
	if _, ok := newBackendGroups(m); ok {
		t.Fatal("a manager with nothing running is a source")
	}
	m.Reload()
	awaitBackend(t, "the first poll", func() bool { s, _ := m.Snapshot(); return len(s.Devices) == 2 && len(s.Groups) == 1 })

	// Changes off: groups are read but not written.
	src, ok := newBackendGroups(m)
	if !ok || src.ID() != "firewalla" || src.Label() != "Firewalla" || src.MaxLen() != 64 || !strings.Contains(src.ReadOnly(), "Allow changes is off") {
		t.Fatalf("source = %+v, %v", src, ok)
	}
	list, err := src.Entries(ctx)
	if err != nil || entryFor(t, list, "02005e000001").Name != "Smart Home" || entryFor(t, list, "02005e000002").Name != "" {
		t.Fatalf("entries = %+v, %v", list, err)
	}
	if err := src.Rename(ctx, entryFor(t, list, "02005e000002"), "Den"); !errors.Is(err, backends.ErrReadOnly) {
		t.Fatalf("move while read-only = %v", err)
	}

	if _, err := sec.SetFirewallaWrites(true); err != nil {
		t.Fatal(err)
	}
	m.Reload()
	src, _ = newBackendGroups(m)
	if src.ReadOnly() != "" {
		t.Fatalf("still read-only: %q", src.ReadOnly())
	}

	// The engine: the plug is in "Den" in Shepherd and in nothing on the
	// box, so the box makes the group and takes the plug; the TV is in a
	// group only on the box, so Shepherd makes it.
	plug := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:02", IP: "192.0.2.2", Hostname: "plug"})
	tv := reg.Observe(devices.Observation{MAC: "02:00:5e:00:00:01", IP: "192.0.2.1", Hostname: "tv"})
	den, _ := reg.CreateGroup("Den", "")
	if _, err := reg.BulkAssignGroup([]string{plug}, den.ID); err != nil {
		t.Fatal(err)
	}
	e := startGroups(ctx, reg, m, t.TempDir())
	rep, err := e.Sync(ctx)
	if err != nil || rep.Written != 2 || rep.Failed != 0 {
		t.Fatalf("sync = %+v, %v", rep, err)
	}
	mu.Lock()
	got := strings.Join(writes, "|")
	mu.Unlock()
	if got != `set policy 02:00:5E:00:00:02 {"tags":["21"]}` {
		t.Fatalf("writes = %s", got)
	}
	smart, ok := reg.GroupByName("Smart Home")
	d, _ := reg.Get(tv)
	if !ok || strings.Join(d.Groups, ",") != smart.ID {
		t.Fatalf("tv is in %v", d.Groups)
	}

	m.Stop()
	if _, err := src.Entries(ctx); !errors.Is(err, errNoBackend) {
		t.Fatalf("entries after stopping = %v", err)
	}
	if err := m.SetDeviceGroup(ctx, backends.DeviceRef{Native: "x"}, "Den"); !errors.Is(err, errNoBackend) {
		t.Fatalf("move with nothing connected = %v", err)
	}
	if (&backendGroups{name: "opnsense"}).Label() != "opnsense" {
		t.Fatal("label")
	}
}
