// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// xorCodec is a fake "encryption" codec.
type xorCodec struct{ fail string }

func (c xorCodec) Encode(b []byte) ([]byte, error) {
	if c.fail == "encode" {
		return nil, errors.New("boom")
	}
	return c.x(b), nil
}

func (c xorCodec) Decode(b []byte) ([]byte, error) {
	if c.fail == "decode" {
		return nil, errors.New("boom")
	}
	return c.x(b), nil
}

func (xorCodec) x(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5a
	}
	return out
}

func TestSaveLoadRoundTripWithCodec(t *testing.T) {
	r, clk := newReg(t)
	r.codec = xorCodec{}
	a, b, _ := seed(t, r)
	r.CreateGroup("Kids", "#abc")
	r.BulkAssignGroup([]string{a, b}, "kids")
	r.Rename(a, "Alpha")
	r.Delete(b)
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", st, err)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("Alpha")) {
		t.Fatal("codec not applied: plaintext on disk")
	}
	// Overwrite is atomic and leaves no temp files.
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 1 {
		t.Fatalf("temp files left: %v", ents)
	}

	r2, _ := newReg(t)
	r2.codec = xorCodec{}
	if err := r2.Load(path); err != nil {
		t.Fatal(err)
	}
	_ = clk
	if r2.Len() != r.Len() {
		t.Fatalf("len %d vs %d", r2.Len(), r.Len())
	}
	d := mustDevice(t, r2, a)
	eq(t, d.Alias, "Alpha")
	eq(t, d.Groups, []string{"kids"})
	if _, ok := r2.Get(b); ok {
		t.Fatal("tombstone resurrected")
	}
	if dev, groups := r2.ScopesFor("192.0.2.1"); dev != a || len(groups) != 1 {
		t.Fatal("scope index not rebuilt")
	}
	g, _ := r2.GetGroup("kids")
	eq(t, g.Color, "#abc")
	// The tombstone was carried: a snapshot export contains it.
	found := false
	for _, e := range r2.Export().Devices {
		if e.ID == b && e.Deleted {
			found = true
		}
	}
	if !found {
		t.Fatal("tombstone lost")
	}
}

func TestSaveLoadErrors(t *testing.T) {
	r, _ := newReg(t)
	seed(t, r)
	dir := t.TempDir()
	if err := r.Load(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if err := r.Save(filepath.Join(dir, "no", "such", "dir", "d.json")); err == nil {
		t.Fatal("save into missing dir")
	}
	if err := os.Mkdir(filepath.Join(dir, "isdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(filepath.Join(dir, "isdir")); err == nil {
		t.Fatal("save over a directory")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temp file leaked on failure: %v", ents)
	}

	enc := New(Options{Codec: xorCodec{fail: "encode"}})
	if err := enc.Save(filepath.Join(dir, "x.json")); err == nil {
		t.Fatal("encode error ignored")
	}
	dec := New(Options{Codec: xorCodec{fail: "decode"}})
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{}"), 0o600)
	if err := dec.Load(bad); err == nil {
		t.Fatal("decode error ignored")
	}
	if err := r.Load(bad); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("wrong version accepted: %v", err)
	}
	os.WriteFile(bad, []byte("not json"), 0o600)
	if err := r.Load(bad); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("garbage accepted: %v", err)
	}
	p, _ := PlainCodec{}.Decode([]byte("x"))
	eq(t, string(p), "x")
}

func TestImportLastWriterWins(t *testing.T) {
	a, ca := newReg(t)
	b, cb := newReg(t)
	b.node = "node-b"
	id := a.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	b.Import(a.Export())
	eq(t, mustDevice(t, b, id).MACs, []string{macA})

	// b renames later; a renames earlier: b's name wins on both replicas.
	ca.Advance(1)
	a.Rename(id, "from-a")
	cb.Advance(5000)
	b.Rename(id, "from-b")
	a.Import(b.Export())
	b.Import(a.Export())
	eq(t, mustDevice(t, a, id).Alias, "from-b")
	eq(t, mustDevice(t, b, id).Alias, "from-b")

	// Re-importing is a no-op.
	if n := a.Import(b.Export()); n != 0 {
		t.Fatalf("idempotence: %d changes", n)
	}
	// Tie on HLC breaks by node ID, same result either order.
	x, _ := newReg(t)
	y, _ := newReg(t)
	y.node = "node-z"
	xi := x.Observe(Observation{IP: "192.0.2.9"})
	y.devices = map[string]*Device{}
	snap := x.Export()
	zd := snap.Devices[0].clone()
	zd.Node, zd.Alias = "node-z", "z-wins"
	snap2 := Snapshot{Version: 1, Devices: []*Device{zd}}
	x.Import(snap2)
	eq(t, mustDevice(t, x, xi).Alias, "z-wins")
	// Nil and empty-ID records are ignored.
	x.Import(Snapshot{Devices: []*Device{nil, {}}, Groups: []*Group{nil, {}}})

	// A remote clock ahead of ours is witnessed, so later local writes sort after it.
	far := Snapshot{Clock: HLC{Wall: 1 << 50}, Devices: []*Device{{ID: "far", MACs: []string{macC}, Updated: HLC{Wall: 1 << 50}, Node: "n"}}}
	x.Import(far)
	x.Rename("far", "local-after")
	if mustDevice(t, x, "far").Updated.Compare(HLC{Wall: 1 << 50}) <= 0 {
		t.Fatal("local stamp did not advance past witnessed remote")
	}
}

func TestImportConvergesAnyOrder(t *testing.T) {
	mk := func() (*Registry, string) {
		r, clk := newReg(t)
		clk.Advance(1)
		return r, r.Observe(Observation{MAC: macA, IP: "192.0.2.1"})
	}
	a, id := mk()
	b, _ := mk()
	b.node = "node-b"
	a.Rename(id, "x")
	a.CreateGroup("G", "")
	a.BulkAssignGroup([]string{id}, "g")
	b.SetNotes(id, "note")
	b.CreateGroup("G", "red")
	b.Delete(id)

	ab, ba := New(Options{NodeID: "c1"}), New(Options{NodeID: "c2"})
	sa, sb := a.Export(), b.Export()
	ab.Import(sa)
	ab.Import(sb)
	ba.Import(sb)
	ba.Import(sa)
	ea, eb := ab.Export(), ba.Export()
	ea.Node, eb.Node, ea.Clock, eb.Clock = "", "", HLC{}, HLC{}
	ja, jb := mustJSON(t, ea), mustJSON(t, eb)
	if ja != jb {
		t.Fatalf("replicas diverged:\n%s\n%s", ja, jb)
	}
}

func TestImportReconcilesDuplicateMACs(t *testing.T) {
	// Two replicas learned the same MAC under different IDs (one began as
	// IP-only and was later keyed by MAC).
	a, _ := newReg(t)
	d1 := &Device{ID: "d-1", MACs: []string{macA}, IPs: []string{"192.0.2.1"}, Alias: "one", Updated: HLC{Wall: 10}, Node: "n1",
		IPSeen: map[string]time0{"192.0.2.1": time0Date(2026, 1, 1)}}
	d2 := &Device{ID: "d-2", MACs: []string{macA}, IPs: []string{"192.0.2.1", "192.0.2.2"}, Hostname: "two", Updated: HLC{Wall: 11}, Node: "n2",
		IPSeen: map[string]time0{"192.0.2.1": time0Date(2026, 1, 2), "192.0.2.2": time0Date(2026, 1, 2)}}
	a.Import(Snapshot{Devices: []*Device{d2, d1}})
	if a.Len() != 1 {
		t.Fatalf("duplicate MAC not reconciled: %d devices", a.Len())
	}
	d := mustDevice(t, a, "d-1")
	eq(t, d.Alias, "one")
	eq(t, d.Hostname, "two")
	if dev, _ := a.ScopesFor("192.0.2.2"); dev != "d-1" {
		t.Fatal("scope after reconcile")
	}
	if got, ok := a.FindByMAC(macA); !ok || got.ID != "d-1" {
		t.Fatal("MAC index")
	}

	// An IP claimed by two different devices stays with the later sighting;
	// an unparsable stored address is dropped.
	b, _ := newReg(t)
	e1 := &Device{ID: "e-1", MACs: []string{macA}, IPs: []string{"192.0.2.5", "bogus"}, Updated: HLC{Wall: 1}, Node: "n",
		IPSeen: map[string]time0{"192.0.2.5": time0Date(2026, 1, 1)}}
	e2 := &Device{ID: "e-2", MACs: []string{macB}, IPs: []string{"192.0.2.5"}, Updated: HLC{Wall: 1}, Node: "n",
		IPSeen: map[string]time0{"192.0.2.5": time0Date(2026, 2, 1)}}
	b.Import(Snapshot{Devices: []*Device{e1, e2}})
	if dev, _ := b.ScopesFor("192.0.2.5"); dev != "e-2" {
		t.Fatalf("later sighting should win the IP, got %s", dev)
	}
	e1b := mustDevice(t, b, "e-1")
	if len(e1b.IPs) != 0 {
		t.Fatalf("loser kept the IP: %v", e1b.IPs)
	}
	// Reverse: the earlier id has the later sighting.
	c, _ := newReg(t)
	f1 := &Device{ID: "f-1", MACs: []string{macA}, IPs: []string{"192.0.2.6"}, Updated: HLC{Wall: 1}, Node: "n",
		IPSeen: map[string]time0{"192.0.2.6": time0Date(2026, 3, 1)}}
	f2 := &Device{ID: "f-2", MACs: []string{macB}, IPs: []string{"192.0.2.6"}, Updated: HLC{Wall: 1}, Node: "n",
		IPSeen: map[string]time0{"192.0.2.6": time0Date(2026, 1, 1)}}
	c.Import(Snapshot{Devices: []*Device{f1, f2}})
	if dev, _ := c.ScopesFor("192.0.2.6"); dev != "f-1" {
		t.Fatalf("got %s", dev)
	}
}

func TestPurgeTombstones(t *testing.T) {
	r, clk := newReg(t)
	a, _, _ := seed(t, r)
	r.CreateGroup("G", "")
	r.Delete(a)
	r.DeleteGroup("g")
	if r.PurgeTombstones(24*time0Hour) != 0 {
		t.Fatal("purged too early")
	}
	clk.Advance(48 * time0Hour)
	if n := r.PurgeTombstones(24 * time0Hour); n != 2 {
		t.Fatalf("purged %d", n)
	}
}

func TestStaleGroupReferencesHidden(t *testing.T) {
	// A device synced before its group definition: the reference is hidden
	// until the group arrives.
	r, _ := newReg(t)
	r.Import(Snapshot{Devices: []*Device{{ID: "d-1", IPs: []string{"192.0.2.1"}, Groups: []string{"later"}, Updated: HLC{Wall: 1}, Node: "n"}}})
	if d := mustDevice(t, r, "d-1"); len(d.Groups) != 0 {
		t.Fatal("dangling group visible")
	}
	if _, g := r.ScopesFor("192.0.2.1"); g != nil {
		t.Fatal("dangling group scoped")
	}
	r.Import(Snapshot{Groups: []*Group{{ID: "later", Name: "Later", Updated: HLC{Wall: 2}, Node: "n"}}})
	if _, g := r.ScopesFor("192.0.2.1"); len(g) != 1 {
		t.Fatal("group not scoped once defined")
	}
}
