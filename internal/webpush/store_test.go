// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStore(t testing.TB) (*Store, *fakeClock) {
	c := newClock()
	return NewStore(StoreOptions{NodeID: "n1", Now: c.Now, Validate: AllowAnyEndpoint}), c
}

func ep(n int) string { return fmt.Sprintf("https://push.example.com/send/device-%d", n) }

func TestStoreAddListRenameRemove(t *testing.T) {
	s, c := testStore(t)
	d := newDevice(t)
	a, err := s.Add(d.browserSub(ep(1)), "  Alice's phone\n", "Mozilla/5.0 (iPhone)")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != DeviceID(ep(1)) || len(a.ID) != 12 || a.Name != "Alice's phone" || a.Service != "push.example.com" {
		t.Fatalf("a = %+v", a)
	}
	c.Advance(time.Minute)
	b, _ := s.Add(d.browserSub(ep(2)), "", "")
	if !strings.HasPrefix(b.Name, "Device ") {
		t.Fatalf("default name %q", b.Name)
	}
	list := s.List()
	if len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID || s.Count() != 2 {
		t.Fatalf("list = %+v", list)
	}
	if got, ok := s.Get(a.ID); !ok || got.Name != a.Name {
		t.Fatal("get")
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("get nope")
	}
	if err := s.Rename(a.ID, "Tablet"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(a.ID); got.Name != "Tablet" {
		t.Fatal("rename")
	}
	if err := s.Rename(a.ID, " \n"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty rename: %v", err)
	}
	if err := s.Rename("nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rename missing: %v", err)
	}
	if err := s.Remove(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double remove: %v", err)
	}
	if s.Count() != 1 || len(s.List()) != 1 {
		t.Fatal("remove")
	}
	// Re-subscribing the same browser revives it under the same ID.
	again, err := s.Add(d.browserSub(ep(1)), "Alice again", "")
	if err != nil || again.ID != a.ID || s.Count() != 2 {
		t.Fatalf("revive: %+v %v", again, err)
	}
	// Re-adding a live endpoint updates it and keeps its name when none is given.
	same, _ := s.Add(d.browserSub(ep(1)), "", "UA2")
	if same.Name != "Alice again" || same.UserAgent != "UA2" {
		t.Fatalf("update: %+v", same)
	}
}

func TestStoreAddValidation(t *testing.T) {
	s := NewStore(StoreOptions{}) // default validator
	d := newDevice(t)
	if _, err := s.Add(d.browserSub("http://push.example.com/x"), "", ""); !errors.Is(err, ErrEndpoint) {
		t.Fatalf("http: %v", err)
	}
	if _, err := s.Add(d.browserSub("https://127.0.0.1/x"), "", ""); !errors.Is(err, ErrEndpoint) {
		t.Fatalf("loopback: %v", err)
	}
	bad := d.browserSub(ep(1))
	bad.Keys.Auth = "short"
	if _, err := s.Add(bad, "", ""); !errors.Is(err, ErrBadSubscription) {
		t.Fatalf("keys: %v", err)
	}
	if s.Count() != 0 {
		t.Fatal("rejected subscriptions were stored")
	}
	ok, err := s.Add(d.browserSub(ep(1)), strings.Repeat("é", 100), strings.Repeat("u", 500))
	if err != nil {
		t.Fatal(err)
	}
	if len(ok.Name) > maxName || len(ok.UserAgent) > maxUserAgent {
		t.Fatalf("not bounded: %d %d", len(ok.Name), len(ok.UserAgent))
	}
}

func TestStoreCapacity(t *testing.T) {
	s, _ := testStore(t)
	d := newDevice(t)
	for i := 0; i < maxSubs; i++ {
		if _, err := s.Add(d.browserSub(ep(i)), "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Add(d.browserSub(ep(9999)), "", ""); !errors.Is(err, ErrTooMany) {
		t.Fatalf("err = %v", err)
	}
	// Updating an existing one is still fine, and removing frees a slot.
	if _, err := s.Add(d.browserSub(ep(0)), "renamed", ""); err != nil {
		t.Fatal(err)
	}
	s.Remove(DeviceID(ep(1)))
	if _, err := s.Add(d.browserSub(ep(9999)), "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestStoreMarkAndRetire(t *testing.T) {
	s, c := testStore(t)
	d := newDevice(t)
	dev, _ := s.Add(d.browserSub(ep(1)), "", "")
	s.MarkError(dev.ID, errors.New("push service answered 503"))
	s.MarkError(dev.ID, errors.New("push service answered 503"))
	s.MarkError(dev.ID, nil)
	got, _ := s.Get(dev.ID)
	if got.Failures != 2 || got.LastError == "" || got.LastErrorAt.IsZero() {
		t.Fatalf("after errors: %+v", got)
	}
	c.Advance(time.Hour)
	s.MarkOK(dev.ID)
	got, _ = s.Get(dev.ID)
	if got.Failures != 0 || got.LastError != "" || !got.LastOK.Equal(c.Now()) {
		t.Fatalf("after ok: %+v", got)
	}
	s.MarkOK("missing")
	s.MarkError("missing", errors.New("x"))
	s.MarkError(dev.ID, errors.New(strings.Repeat("e", 1000)))
	if got, _ := s.Get(dev.ID); len(got.LastError) > maxLastError {
		t.Fatal("last error not bounded")
	}
	s.Retire(dev.ID, "gone")
	if s.Count() != 0 {
		t.Fatal("retire")
	}
	snap := s.Export()
	if !snap.Subscriptions[0].Deleted || snap.Subscriptions[0].RetiredReason != "gone" {
		t.Fatalf("tombstone: %+v", snap.Subscriptions[0])
	}
	s.Retire(dev.ID, "again") // no-op on a tombstone
	// Reviving clears the retirement and the old error.
	if _, err := s.Add(d.browserSub(ep(1)), "", ""); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(dev.ID)
	if got.LastError != "" || got.Failures != 0 {
		t.Fatalf("revived: %+v", got)
	}
	if recs := s.Records(); len(recs) != 1 || recs[0].RetiredReason != "" || recs[0].Subscription().Endpoint != ep(1) {
		t.Fatalf("records: %+v", recs)
	}
}

func TestStorePurgeTombstones(t *testing.T) {
	s, c := testStore(t)
	d := newDevice(t)
	a, _ := s.Add(d.browserSub(ep(1)), "", "")
	s.Add(d.browserSub(ep(2)), "", "")
	s.Remove(a.ID)
	if n := s.PurgeTombstones(time.Hour); n != 0 {
		t.Fatalf("purged %d fresh tombstones", n)
	}
	c.Advance(2 * time.Hour)
	if n := s.PurgeTombstones(time.Hour); n != 1 {
		t.Fatalf("purged %d", n)
	}
	if len(s.Export().Subscriptions) != 1 {
		t.Fatal("live record purged")
	}
}

type xorCodec struct{}

func (xorCodec) Encode(b []byte) ([]byte, error) { return xor(b), nil }
func (xorCodec) Decode(b []byte) ([]byte, error) { return xor(b), nil }
func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5a
	}
	return out
}

type failCodec struct{}

func (failCodec) Encode([]byte) ([]byte, error) { return nil, errors.New("no key") }
func (failCodec) Decode([]byte) ([]byte, error) { return nil, errors.New("no key") }

func TestStorePersistence(t *testing.T) {
	c := newClock()
	mk := func(cod Codec) *Store {
		return NewStore(StoreOptions{NodeID: "n1", Now: c.Now, Codec: cod, Validate: AllowAnyEndpoint})
	}
	path := filepath.Join(t.TempDir(), "push.json")
	d := newDevice(t)

	s := mk(xorCodec{})
	a, _ := s.Add(d.browserSub(ep(1)), "One", "UA")
	b, _ := s.Add(d.browserSub(ep(2)), "Two", "")
	s.Remove(b.ID)
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "push.example.com") || strings.Contains(string(raw), d.authB64()) {
		t.Fatal("codec output leaks the endpoint or the secrets")
	}
	// A different codec cannot read it; the right one restores everything, tombstones included.
	if err := mk(PlainCodec{}).Load(path); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("plain load of encoded file: %v", err)
	}
	r := mk(xorCodec{})
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := r.List(); len(got) != 1 || got[0].ID != a.ID || got[0].Name != "One" {
		t.Fatalf("restored: %+v", got)
	}
	if len(r.Export().Subscriptions) != 2 {
		t.Fatal("tombstone lost")
	}
	// Errors: missing, failing codecs, bad version, bad JSON.
	if err := r.Load(filepath.Join(t.TempDir(), "none")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if err := mk(failCodec{}).Save(path); err == nil {
		t.Fatal("encode error swallowed")
	}
	if err := mk(failCodec{}).Load(path); err == nil || errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("decode error: %v", err)
	}
	os.WriteFile(path, []byte(`{"version":9}`), 0o600)
	if err := mk(nil).Load(path); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("version: %v", err)
	}
	os.WriteFile(path, []byte(`nope`), 0o600)
	if err := mk(nil).Load(path); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("json: %v", err)
	}
	if err := s.Save(filepath.Join(t.TempDir(), "no", "dir", "x")); err == nil {
		t.Fatal("unwritable path")
	}
}

func TestStoreImportConvergesInAnyOrder(t *testing.T) {
	c := newClock()
	mk := func(node string) *Store {
		return NewStore(StoreOptions{NodeID: node, Now: c.Now, Validate: AllowAnyEndpoint})
	}
	d := newDevice(t)
	a, b := mk("a"), mk("b")
	a.Add(d.browserSub(ep(1)), "from a", "")
	c.Advance(time.Second)
	b.Add(d.browserSub(ep(1)), "from b", "")
	b.Add(d.browserSub(ep(2)), "only b", "")
	c.Advance(time.Second)
	a.Remove(DeviceID(ep(1)))

	x, y := mk("x"), mk("y")
	sa, sb := a.Export(), b.Export()
	x.Import(sa)
	x.Import(sb)
	y.Import(sb)
	y.Import(sa)
	if fmt.Sprint(x.Export().Subscriptions[0], x.Export().Subscriptions[1]) != fmt.Sprint(y.Export().Subscriptions[0], y.Export().Subscriptions[1]) {
		t.Fatal("replicas diverged")
	}
	if n := x.Import(sa); n != 0 {
		t.Fatalf("import is not idempotent: %d", n)
	}
	if x.Count() != 1 {
		t.Fatalf("removal (the later write) must win: %d live", x.Count())
	}
	// Records with a wrong ID, nil entries and empty IDs are ignored.
	if n := x.Import(Snapshot{Subscriptions: []*Record{nil, {}, {ID: "bogus", Endpoint: ep(7)}}}); n != 0 {
		t.Fatalf("junk imported: %d", n)
	}
	// Tie on HLC: the higher node ID wins, deterministically.
	t1 := mk("t")
	rec := Record{ID: DeviceID(ep(3)), Endpoint: ep(3), Name: "n1", Node: "a"}
	rec2 := rec
	rec2.Name, rec2.Node = "n2", "b"
	t1.Import(Snapshot{Subscriptions: []*Record{&rec}})
	t1.Import(Snapshot{Subscriptions: []*Record{&rec2}})
	if got, _ := t1.Get(rec.ID); got.Name != "n2" {
		t.Fatalf("tie-break: %+v", got)
	}
}

func TestHLCCompare(t *testing.T) {
	cases := []struct {
		a, b HLC
		want int
	}{{HLC{1, 0}, HLC{2, 0}, -1}, {HLC{2, 0}, HLC{1, 0}, 1}, {HLC{1, 1}, HLC{1, 2}, -1}, {HLC{1, 2}, HLC{1, 1}, 1}, {HLC{1, 1}, HLC{1, 1}, 0}}
	for _, c := range cases {
		if got := c.a.Compare(c.b); got != c.want {
			t.Errorf("%v vs %v = %d", c.a, c.b, got)
		}
	}
}

func TestStoreHLCStrictlyIncreases(t *testing.T) {
	s, _ := testStore(t) // the clock never moves: the counter must break ties
	d := newDevice(t)
	dev, _ := s.Add(d.browserSub(ep(1)), "", "")
	prev := s.Export().Subscriptions[0].Updated
	for i := 0; i < 5; i++ {
		s.Rename(dev.ID, fmt.Sprint("n", i))
		cur := s.Export().Subscriptions[0].Updated
		if cur.Compare(prev) <= 0 {
			t.Fatalf("stamp did not advance: %v then %v", prev, cur)
		}
		prev = cur
	}
}

func TestStoreConcurrency(t *testing.T) {
	s, _ := testStore(t)
	d := newDevice(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				dev, _ := s.Add(d.browserSub(ep(i*100+j)), "x", "")
				s.MarkOK(dev.ID)
				s.List()
				s.Records()
				s.Export()
				if j%3 == 0 {
					s.Remove(dev.ID)
				}
			}
		}()
	}
	wg.Wait()
}

func TestStoreDefaults(t *testing.T) {
	s := NewStore(StoreOptions{})
	if s.node != "local" || s.now == nil || s.codec == nil || s.validate == nil {
		t.Fatal("defaults")
	}
}

func TestPlainCodecAndAtomicWriteFailure(t *testing.T) {
	b, err := PlainCodec{}.Encode([]byte("x"))
	if err != nil || string(b) != "x" {
		t.Fatal("encode")
	}
	// Renaming over a directory fails; the temp file must not be left behind.
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.Mkdir(target, 0o700)
	os.WriteFile(filepath.Join(target, "keep"), nil, 0o600)
	if err := writeFileAtomic(target, []byte("x")); err == nil {
		t.Fatal("expected error")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".webpush-*")); len(left) != 0 {
		t.Fatalf("temp file left: %v", left)
	}
}
