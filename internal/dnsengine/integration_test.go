// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

type fakeNamer struct {
	mu sync.Mutex
	m  map[string]DeviceInfo
}

func (f *fakeNamer) set(ip string, d DeviceInfo) {
	f.mu.Lock()
	f.m = map[string]DeviceInfo{ip: d}
	f.mu.Unlock()
}

func (f *fakeNamer) DeviceFor(ip string) DeviceInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[ip]
}

func TestEngineLabelsQueriesWithTheDeviceAndHonorsExclusion(t *testing.T) {
	var hits atomic.Int32
	pool, err := NewPool([]string{fakeUpstream(t, "192.0.2.9", &hits)})
	if err != nil {
		t.Fatal(err)
	}
	namer := &fakeNamer{}
	namer.set("127.0.0.1", DeviceInfo{ID: "d-1", Name: "Kitchen tablet"})
	var seen []string
	var seenMu sync.Mutex
	e := &Engine{Filter: NewFilter(), Pool: pool, Cache: NewCache(100), Log: NewQueryLog(50), Stats: NewStats(), Names: namer,
		ClientSeen: func(ip string) { seenMu.Lock(); seen = append(seen, ip); seenMu.Unlock() }}
	e.Filter.SetList("ads", set("ads.example"))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: e}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	addr := pc.LocalAddr().String()

	if r := ask(t, addr, "x.ads.example.", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "0.0.0.0" {
		t.Fatalf("blocked answer = %v", r.Answer)
	}
	last := e.Log.All()[0]
	if last.Device != "Kitchen tablet" || last.DeviceID != "d-1" || last.Action != "blocked" {
		t.Errorf("entry = %+v", last)
	}
	seenMu.Lock()
	if !slices.Equal(seen, []string{"127.0.0.1"}) {
		t.Errorf("ClientSeen calls = %v", seen)
	}
	seenMu.Unlock()

	// An excluded device opted out of protection: the block does not apply, and the
	// entry says why.
	namer.set("127.0.0.1", DeviceInfo{ID: "d-1", Name: "Kitchen tablet", Excluded: true})
	r := ask(t, addr, "y.ads.example.", dns.TypeA)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.9" {
		t.Fatalf("excluded device must be answered: %v", r.Answer)
	}
	all := e.Log.All()
	if got := all[len(all)-1]; got.Action != "allowed" || got.Reason != "excluded" || got.Device != "Kitchen tablet" {
		t.Errorf("excluded entry = %+v", got)
	}
}

func TestPoolErrorsMatchSentinelsAndKeepMessages(t *testing.T) {
	p, err := NewPool([]string{"192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add("192.0.2.1"); !errors.Is(err, ErrDuplicateUpstream) || !strings.Contains(err.Error(), "already configured") {
		t.Errorf("dup: %v", err)
	}
	if err := p.Remove("203.0.113.1"); !errors.Is(err, ErrUnknownUpstream) {
		t.Errorf("unknown: %v", err)
	}
	if err := p.Remove("192.0.2.1"); !errors.Is(err, ErrLastUpstream) || errors.Is(err, ErrUnknownUpstream) {
		t.Errorf("last: %v", err)
	}
	if got := p.Bootstrap(); !slices.Equal(got, DefaultBootstrapServers()) {
		t.Errorf("default bootstrap = %v", got)
	}
	if err := p.SetBootstrap([]string{"198.51.100.1:5300"}); err != nil {
		t.Fatal(err)
	}
	if got := p.Bootstrap(); !slices.Equal(got, []string{"198.51.100.1:5300"}) {
		t.Errorf("bootstrap = %v", got)
	}
	if err := p.SetBootstrap([]string{"dns.example"}); err == nil {
		t.Error("a hostname cannot be a bootstrap resolver")
	}
}

func TestUpstreamStorePersistsEditsAndWinsOverConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "upstreams.json")
	pool, _ := NewPool([]string{"192.0.2.1", "192.0.2.2"})
	st := OpenUpstreamStore(path, pool)
	if st.LoadProblem() != nil || st.Restored() || st.Pool() != pool {
		t.Fatalf("fresh store: %v %v", st.LoadProblem(), st.Restored())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("nothing is written before the first edit")
	}
	if err := st.Add("198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Set([]string{"198.51.100.7", "192.0.2.2", "tls://dns.example"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBootstrap([]string{"203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v %v", info, err)
	}

	// A new process seeds from config, and the file wins.
	pool2, _ := NewPool([]string{"192.0.2.99"})
	st2 := OpenUpstreamStore(path, pool2)
	if !st2.Restored() || st2.LoadProblem() != nil {
		t.Fatalf("restore: %v", st2.LoadProblem())
	}
	var got []string
	for _, u := range pool2.List() {
		got = append(got, u.Config)
	}
	if !slices.Equal(got, []string{"198.51.100.7", "192.0.2.2", "tls://dns.example"}) {
		t.Errorf("restored upstreams = %v", got)
	}
	if !slices.Equal(pool2.Bootstrap(), []string{"203.0.113.9"}) {
		t.Errorf("restored bootstrap = %v", pool2.Bootstrap())
	}
}

func TestUpstreamStoreFallsBackToConfigWhenFileIsInvalid(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not json":      "{nope",
		"wrong version": `{"version":9,"upstreams":["192.0.2.5"],"bootstrap":["9.9.9.9"]}`,
		"bad upstream":  `{"version":1,"upstreams":["ftp://x"],"bootstrap":["9.9.9.9"]}`,
		"empty":         `{"version":1,"upstreams":[],"bootstrap":["9.9.9.9"]}`,
		"dup":           `{"version":1,"upstreams":["192.0.2.5","192.0.2.5:53"],"bootstrap":["9.9.9.9"]}`,
		"bad bootstrap": `{"version":1,"upstreams":["192.0.2.5"],"bootstrap":["dns.example"]}`,
		"no bootstrap":  `{"version":1,"upstreams":["192.0.2.5"],"bootstrap":[]}`,
	}
	for name, body := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		os.WriteFile(path, []byte(body), 0o600)
		pool, _ := NewPool([]string{"192.0.2.1"})
		st := OpenUpstreamStore(path, pool)
		if st.LoadProblem() == nil || st.Restored() {
			t.Errorf("%s: expected the file to be ignored", name)
		}
		if l := pool.List(); len(l) != 1 || l[0].Config != "192.0.2.1" {
			t.Errorf("%s: pool changed to %+v", name, l)
		}
	}
	// A path that cannot be read (a directory) is reported too.
	pool, _ := NewPool([]string{"192.0.2.1"})
	if st := OpenUpstreamStore(dir, pool); st.LoadProblem() == nil {
		t.Error("unreadable path should be reported")
	}
}

func TestUpstreamStoreEditsAreAtomicAndRollBackOnSaveFailure(t *testing.T) {
	pool, _ := NewPool([]string{"192.0.2.1"})
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0o600)
	st := OpenUpstreamStore(filepath.Join(blocker, "upstreams.json"), pool)
	if err := st.Add("192.0.2.2"); err == nil || !strings.Contains(err.Error(), "saving") {
		t.Fatalf("save failure not reported: %v", err)
	}
	if l := pool.List(); len(l) != 1 {
		t.Errorf("failed save must roll back, pool = %+v", l)
	}
	if err := st.SetBootstrap([]string{"203.0.113.1"}); err == nil {
		t.Fatal("expected failure")
	}
	if !slices.Equal(pool.Bootstrap(), DefaultBootstrapServers()) {
		t.Errorf("bootstrap not rolled back: %v", pool.Bootstrap())
	}
	// Validation errors pass through untouched.
	if err := st.Add("ftp://nope"); err == nil || strings.Contains(err.Error(), "saving") {
		t.Errorf("validation error = %v", err)
	}
	// Memory-only store (no path) never writes.
	mem := OpenUpstreamStore("", pool)
	if err := mem.Add("192.0.2.3"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteAtomicErrors(t *testing.T) {
	dir := t.TempDir()
	// the temp name is a directory: opening it for writing fails
	os.Mkdir(filepath.Join(dir, "x.json.tmp"), 0o700)
	if err := writeAtomic(filepath.Join(dir, "x.json"), []byte("{}")); err == nil {
		t.Error("expected an error when the temp file cannot be created")
	}
}

func TestPolicyOptionsNoRecommendedKeepsOnlyMigratedLists(t *testing.T) {
	cat := testCatalog(t)
	legacy := &LegacyConfig{Lists: []ListConfig{{Name: "mine", URL: "https://lists.example/ads-extra.txt"}}, BlockPrivateRelay: true}
	s, _, _ := openStore(t, PolicyOptions{Catalog: cat, Legacy: legacy, NoRecommended: true})
	items := s.Snapshot().Network.Items
	if items["ads-main"] || !items["ads-extra"] || len(items) != 1 {
		t.Errorf("items = %v, want only the configured list", items)
	}
	// Without NoRecommended the recommended item joins it.
	s, _, _ = openStore(t, PolicyOptions{Catalog: cat, Legacy: legacy})
	if items := s.Snapshot().Network.Items; !items["ads-main"] || !items["ads-extra"] {
		t.Errorf("items = %v", items)
	}
	// A fresh install with NoRecommended and no legacy has nothing on.
	s, _, _ = openStore(t, PolicyOptions{Catalog: cat, NoRecommended: true})
	if len(s.Snapshot().Network.Items) != 0 || !s.Snapshot().Network.Policies[PolicyPrivateRelay] {
		t.Errorf("snapshot = %+v", s.Snapshot().Network)
	}
}

func TestSaveErrorMessageAndUnwrap(t *testing.T) {
	inner := errors.New("disk full")
	err := error(&SaveError{inner})
	if !strings.Contains(err.Error(), "saving upstreams") || !errors.Is(err, inner) {
		t.Errorf("SaveError = %v", err)
	}
}
