// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// listServer serves bodies by path and counts hits per path.
type listServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies map[string]string
	hits   map[string]int
}

func newListServer(t *testing.T, bodies map[string]string) *listServer {
	t.Helper()
	ls := &listServer{bodies: bodies, hits: map[string]int{}}
	ls.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.mu.Lock()
		ls.hits[r.URL.Path]++
		body, ok := ls.bodies[r.URL.Path]
		ls.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ls.Close)
	return ls
}

func (ls *listServer) hitCount(path string) int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.hits[path]
}

func (ls *listServer) set(path, body string) {
	ls.mu.Lock()
	ls.bodies[path] = body
	ls.mu.Unlock()
}

// httpCatalog is a catalog whose sources point at srv.
func httpCatalog(t *testing.T, srv *listServer) *CatalogSet {
	t.Helper()
	u := func(p string) []Source { return []Source{{URL: srv.URL + p, Format: "domains"}} }
	c, err := NewCatalogSet([]CatalogEntry{
		{ID: "ads-main", Kind: KindList, Name: "Main ads", Sources: u("/ads"), Recommended: true},
		{ID: "app-one", Kind: KindApp, Name: "App One", Sources: []Source{{URL: srv.URL + "/one-a"}, {URL: srv.URL + "/one-b"}}},
		{ID: "app-two", Kind: KindApp, Name: "App Two", Sources: u("/two")},
		{ID: "social", Kind: KindCategory, Name: "Social", Includes: []string{"app-one", "app-two"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func scopedSetup(t *testing.T) (*ListManager, *PolicyStore, *Filter, *listServer, string) {
	t.Helper()
	srv := newListServer(t, map[string]string{
		"/ads": "ads.example\n", "/one-a": "one.example\n", "/one-b": "uno.example\n", "/two": "two.example\n",
	})
	f := NewFilter()
	store, err := OpenPolicyStore(filepath.Join(t.TempDir(), "policy.json"), f, PolicyOptions{Catalog: httpCatalog(t, srv)})
	mustOK(t, err)
	dir := t.TempDir()
	return NewScopedListManager(f, store, dir, nil), store, f, srv, dir
}

func TestScopedManagerFetchesOnlyEnabledItems(t *testing.T) {
	m, store, f, srv, _ := scopedSetup(t)
	m.Refresh(context.Background())
	if srv.hitCount("/ads") != 1 || srv.hitCount("/one-a") != 0 || srv.hitCount("/two") != 0 {
		t.Fatalf("hits ads=%d one=%d two=%d: only enabled items may be fetched", srv.hitCount("/ads"), srv.hitCount("/one-a"), srv.hitCount("/two"))
	}
	if !f.Check("ads.example").Blocked || f.Check("one.example").Blocked {
		t.Error("ads must be loaded and app one not")
	}
	sts := m.Status()
	if len(sts) != 1 || sts[0].ID != "ads-main" || sts[0].Count != 1 || sts[0].Size == 0 || sts[0].Updated.IsZero() || sts[0].URL != srv.URL+"/ads" {
		t.Errorf("status = %+v", sts)
	}

	// Enabling a category at a device scope makes both apps wanted; sources merge into one item.
	mustOK(t, store.SetItem(DeviceScope("d"), "social", true))
	m.RefreshMissing(context.Background())
	if srv.hitCount("/ads") != 1 {
		t.Error("RefreshMissing refetched a loaded item")
	}
	if srv.hitCount("/one-a") != 1 || srv.hitCount("/one-b") != 1 || srv.hitCount("/two") != 1 {
		t.Errorf("new items not fetched: %d %d %d", srv.hitCount("/one-a"), srv.hitCount("/one-b"), srv.hitCount("/two"))
	}
	cs := fakeClients{"192.0.2.1": client("d")}
	expect(t, f, cs, "192.0.2.1", "uno.example", true, "app-one", "device:d")
	expect(t, f, cs, "192.0.2.2", "uno.example", false, "", "")
	if n, ok := f.ItemSize("app-one"); !ok || n != 2 {
		t.Errorf("app-one size = %d %v, want the union of both sources", n, ok)
	}

	// Disabling everywhere unloads it and prunes the cache.
	mustOK(t, store.SetItem(DeviceScope("d"), "social", false))
	m.Sync()
	if _, ok := f.ItemSize("app-one"); ok {
		t.Error("unwanted item still loaded")
	}
	if _, err := os.Stat(filepath.Join(m.dir, "app-one.txt")); err == nil {
		t.Error("cache of an unwanted item must be pruned")
	}
	if ids := statusIDs(m); len(ids) != 1 || ids[0] != "ads-main" {
		t.Errorf("status after sync = %v", ids)
	}
}

func statusIDs(m *ListManager) []string {
	var ids []string
	for _, s := range m.Status() {
		ids = append(ids, s.ID)
	}
	return ids
}

func TestScopedManagerOfflineStartAndPerItemRefresh(t *testing.T) {
	m, store, f, srv, dir := scopedSetup(t)
	mustOK(t, store.SetItem(NetworkScope(), "app-two", true))
	m.Refresh(context.Background())

	// A new process starts offline from the cache.
	f2 := NewFilter()
	store2, err := OpenPolicyStore(filepath.Join(t.TempDir(), "policy.json"), f2, PolicyOptions{Catalog: httpCatalog(t, srv)})
	mustOK(t, err)
	mustOK(t, store2.SetItem(NetworkScope(), "app-two", true))
	srv.Close()
	m2 := NewScopedListManager(f2, store2, dir, nil)
	m2.LoadCached()
	if !f2.Check("two.example").Blocked || !f2.Check("ads.example").Blocked {
		t.Error("cached lists not loaded offline")
	}
	m2.LoadCached() // a second call must not reload (and so not clobber) loaded items
	_ = f

	// Refreshing one item hits only that item.
	srv2 := newListServer(t, map[string]string{"/ads": "ads.example\nmore.example\n", "/two": "two.example\n"})
	m3, store3, f3, _, _ := scopedSetupOn(t, srv2)
	m3.Refresh(context.Background())
	before := srv2.hitCount("/ads")
	mustOK(t, store3.SetItem(NetworkScope(), "app-two", true))
	m3.RefreshItem(context.Background(), "app-two")
	if srv2.hitCount("/ads") != before || srv2.hitCount("/two") != 1 || !f3.Check("two.example").Blocked {
		t.Error("RefreshItem touched other items or did not load its own")
	}
}

func scopedSetupOn(t *testing.T, srv *listServer) (*ListManager, *PolicyStore, *Filter, *listServer, string) {
	t.Helper()
	f := NewFilter()
	store, err := OpenPolicyStore(filepath.Join(t.TempDir(), "policy.json"), f, PolicyOptions{Catalog: httpCatalog(t, srv)})
	mustOK(t, err)
	dir := t.TempDir()
	return NewScopedListManager(f, store, dir, nil), store, f, srv, dir
}

func TestScopedManagerGuardsApplyToAllItems(t *testing.T) {
	m, store, f, srv, _ := scopedSetup(t)
	m.Refresh(context.Background())
	// A custom list from the network is guarded like any other.
	srv.set("/mine", "google.com\nfine.example\n")
	cl, err := store.AddCustomList(CustomListInput{Name: "mine", URL: srv.URL + "/mine"})
	mustOK(t, err)
	m.Refresh(context.Background())
	var st ListStatus
	for _, s := range m.Status() {
		if s.ID == cl.ID {
			st = s
		}
	}
	if !strings.Contains(st.Error, "protected") || f.Check("fine.example").Blocked {
		t.Errorf("protected-domain guard missed a custom list: %+v", st)
	}
	// Shrink guard on a catalog item that was loaded fine before.
	big := make([]string, 0, 3000)
	for i := 0; i < 3000; i++ {
		big = append(big, fmt.Sprintf("d%d.example", i))
	}
	srv.set("/ads", strings.Join(big, "\n"))
	m.Refresh(context.Background())
	srv.set("/ads", "tiny.example\n")
	m.Refresh(context.Background())
	if e := statusOf(m, "Main ads").Error; !strings.Contains(e, "shrank") || !f.Check("d7.example").Blocked || f.Check("tiny.example").Blocked {
		t.Errorf("shrink guard: error=%q", e)
	}
}

func TestListManagerSizeCapRejectsInsteadOfTruncating(t *testing.T) {
	srv := newListServer(t, map[string]string{"/big": strings.Repeat("a.example\n", 100)})
	f := NewFilter()
	m := NewListManager(f, t.TempDir(), []ListConfig{{"big", srv.URL + "/big"}}, nil)
	m.MaxBytes = 100
	m.Refresh(context.Background())
	if e := statusOf(m, "big").Error; !strings.Contains(e, "larger than") || f.Check("a.example").Blocked {
		t.Errorf("oversized list: error=%q blocked=%v", e, f.Check("a.example").Blocked)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "big.txt")); err == nil {
		t.Error("an oversized download was cached")
	}
	m.MaxBytes = 1 << 20
	m.Refresh(context.Background())
	if statusOf(m, "big").Error != "" {
		t.Errorf("list within the cap failed: %+v", statusOf(m, "big"))
	}
}

func TestScopedManagerInlineAndMultiSourceErrors(t *testing.T) {
	f := NewFilter()
	srv := newListServer(t, map[string]string{"/good": "good.example\n"})
	specs := []ListSpec{
		{ID: "mixed", Name: "mixed", Sources: []ListSource{{Inline: "inline.example\n"}, {URL: srv.URL + "/good"}}},
		{ID: "halfbad", Name: "halfbad", Sources: []ListSource{{URL: srv.URL + "/good"}, {URL: srv.URL + "/missing"}}},
		{ID: "badinline", Name: "badinline", Sources: []ListSource{{Inline: strings.Repeat("a", 2<<20)}}},
		{ID: "../escape", Name: "escape", Sources: []ListSource{{URL: srv.URL + "/good"}}},
		{ID: "empty", Name: "empty"},
	}
	m := newManager(f, t.TempDir(), func() []ListSpec { return specs }, nil)
	m.Refresh(context.Background())
	if !f.Check("inline.example").Blocked || !f.Check("good.example").Blocked {
		t.Error("inline plus URL source not merged")
	}
	if e := statusOf(m, "halfbad").Error; !strings.Contains(e, "404") {
		t.Errorf("halfbad error = %q", e)
	}
	if statusOf(m, "badinline").Error == "" {
		t.Error("an unparsable inline source must be an error")
	}
	if statusOf(m, "empty").URL != "" {
		t.Error("a spec without sources has no URL")
	}
	if _, err := os.Stat(filepath.Join(m.dir, "halfbad.txt.tmp")); err == nil {
		t.Error("a failed multi-source refresh left a temp file")
	}
	if _, err := os.Stat(filepath.Join(m.dir, ".._escape.txt")); err != nil {
		t.Errorf("unsafe id not sanitised into the cache dir: %v", err)
	}
	if got := statusOf(m, "mixed"); got.URL != srv.URL+"/good" && got.URL != "(inline)" {
		t.Errorf("mixed status URL = %q", got.URL)
	}
	if got := specURL(ListSpec{Sources: []ListSource{{Inline: "x"}}}); got != "(inline)" {
		t.Errorf("inline spec URL = %q", got)
	}
}

func TestScopedManagerRenameFailureAndCacheDirErrors(t *testing.T) {
	srv := newListServer(t, map[string]string{"/a": "a.example\n"})
	f := NewFilter()
	dir := t.TempDir()
	m := newManager(f, dir, func() []ListSpec {
		return []ListSpec{{ID: "a", Name: "a", Sources: []ListSource{{URL: srv.URL + "/a"}}}}
	}, nil)
	// A directory sitting where the cache file belongs makes the final rename fail.
	mustOK(t, os.MkdirAll(filepath.Join(m.dir, "a.txt", "x"), 0o750))
	m.Refresh(context.Background())
	if statusOf(m, "a").Error == "" {
		t.Error("rename failure not recorded")
	}
	// An unwritable temp path fails the fetch.
	m2 := newManager(f, t.TempDir(), func() []ListSpec {
		return []ListSpec{{ID: "b", Name: "b", Sources: []ListSource{{URL: srv.URL + "/a"}}}}
	}, nil)
	mustOK(t, os.MkdirAll(filepath.Join(m2.dir, "b.txt.tmp"), 0o750))
	m2.Refresh(context.Background())
	if statusOf(m2, "b").Error == "" {
		t.Error("temp file failure not recorded")
	}
}

func TestScopedManagerRunReactsToStoreChanges(t *testing.T) {
	m, store, f, srv, _ := scopedSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, time.Hour); close(done) }()
	waitFor(t, func() bool { return f.Check("ads.example").Blocked })

	mustOK(t, store.SetItem(NetworkScope(), "app-two", true)) // OnChange kicks the manager
	waitFor(t, func() bool { return f.Check("two.example").Blocked })
	if srv.hitCount("/two") != 1 {
		t.Errorf("two fetched %d times", srv.hitCount("/two"))
	}
	mustOK(t, store.SetItem(NetworkScope(), "app-two", false))
	waitFor(t, func() bool { _, ok := f.ItemSize("app-two"); return !ok })

	m.Kick()
	m.Kick() // a full channel never blocks
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not reached in time")
	}
}

func TestScopedManagerRunRefreshesOnTick(t *testing.T) {
	srv := newListServer(t, map[string]string{"/ads": "ads.example\n", "/one-a": "x.example\n", "/one-b": "y.example\n", "/two": "z.example\n"})
	m, _, _, _, _ := scopedSetupOn(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, 20*time.Millisecond); close(done) }()
	waitFor(t, func() bool { return srv.hitCount("/ads") >= 3 })
	cancel()
	<-done
}

func TestFilterItemsForAndSizes(t *testing.T) {
	f := NewFilter()
	f.SetList("l1", set("a.example", "both.example"))
	f.SetList("l2", set("both.example"))
	if got := f.ItemsFor("Sub.Both.Example."); len(got) != 2 || got[0] != "l1" || got[1] != "l2" {
		t.Errorf("ItemsFor = %v", got)
	}
	if got := f.ItemsFor("nothing.example"); len(got) != 0 {
		t.Errorf("ItemsFor(unlisted) = %v", got)
	}
	if n, ok := f.ItemSize("l1"); !ok || n != 2 {
		t.Errorf("ItemSize = %d %v", n, ok)
	}
	if _, ok := f.ItemSize("zz"); ok {
		t.Error("unknown item has a size")
	}
}
