// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeMACAcceptsEverySpellingAndRefusesTheRest(t *testing.T) {
	for _, in := range []string{"02:00:5E:01:02:03", "02-00-5e-01-02-03", "02005e010203", " 02:00:5e:01:02:03 "} {
		if got := NormalizeMAC(in); got != macA {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, macA)
		}
	}
	for _, bad := range []string{"", "02:00:5e:01:02", "02:00:5e:01:02:03:04", "not a mac", "zz:zz:zz:zz:zz:zz"} {
		if got := NormalizeMAC(bad); got != "" {
			t.Errorf("NormalizeMAC(%q) = %q, want empty", bad, got)
		}
	}
}

func TestLeasesStoreAndLookUpByMACAndAddress(t *testing.T) {
	c := newClock()
	s := NewLeases()
	l := Lease{MAC: "02:00:5E:01:02:03", IP: poolStart, Origin: OriginShepherd, Allocated: c.now(), Expires: c.now().Add(time.Minute)}
	s.Put(l)
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
	got, ok := s.Get("02-00-5e-01-02-03")
	if !ok {
		t.Fatal("a lease stored under one spelling must be found under another")
	}
	if got.MAC != macA {
		t.Errorf("stored MAC = %q, want the normalized %q", got.MAC, macA)
	}
	if _, ok := s.ByIP(poolStart); !ok {
		t.Error("ByIP should find the lease")
	}
	if _, ok := s.ByIP(poolEnd); ok {
		t.Error("ByIP should not invent a lease")
	}
	if !got.Active(c.now()) {
		t.Error("a lease a minute from now is active")
	}
	c.advance(2 * time.Minute)
	if got.Active(c.now()) {
		t.Error("a lease two minutes past its expiry is not active")
	}
}

func TestLeasesIgnoresAnUnusableMACRatherThanStoringItUnderAnEmptyKey(t *testing.T) {
	s := NewLeases()
	s.Put(Lease{MAC: "nonsense", IP: poolStart})
	if s.Len() != 0 {
		t.Fatalf("Len = %d, want 0: a lease with no usable MAC has no key", s.Len())
	}
	if s.Delete("nonsense") {
		t.Error("Delete should report nothing removed")
	}
}

// The decline count is the store's memory of an address that turned out to be
// in use by something Shepherd cannot see. Losing it on a re-Put would mean
// offering the address again immediately.
func TestDeclineCountSurvivesAFreshLeaseForTheSameAddress(t *testing.T) {
	c := newClock()
	s := NewLeases()
	s.Put(Lease{MAC: macA, IP: poolStart, Expires: c.now().Add(time.Minute)})
	s.Decline(macA, poolStart)
	got, _ := s.Get(macA)
	if got.Declines != 1 {
		t.Fatalf("Declines = %d, want 1", got.Declines)
	}
	if got.Active(c.now()) {
		t.Error("a declined lease is no longer active")
	}
	s.Put(Lease{MAC: macA, IP: poolStart, Expires: c.now().Add(time.Minute)})
	got, _ = s.Get(macA)
	if got.Declines != 1 {
		t.Errorf("Declines = %d after a re-Put, want the count carried forward", got.Declines)
	}
	// A decline naming a different address, or an unknown MAC, changes
	// nothing: it is not evidence about the lease that is held.
	s.Decline(macA, poolEnd)
	s.Decline(macB, poolStart)
	got, _ = s.Get(macA)
	if got.Declines != 1 {
		t.Errorf("Declines = %d, want it unchanged by a mismatched decline", got.Declines)
	}
}

func TestPurgeKeepsRecentlyExpiredLeasesSoADeviceGetsItsAddressBack(t *testing.T) {
	c := newClock()
	s := NewLeases()
	s.Put(Lease{MAC: macA, IP: poolStart, Expires: c.now().Add(-time.Hour)})
	s.Put(Lease{MAC: macB, IP: poolEnd, Expires: c.now().Add(time.Hour)})
	if n := s.Purge(c.now(), 24*time.Hour); n != 0 {
		t.Fatalf("Purge dropped %d leases; an hour-old expiry is still worth remembering", n)
	}
	if n := s.Purge(c.now(), 30*time.Minute); n != 1 {
		t.Fatalf("Purge = %d, want 1", n)
	}
	if _, ok := s.Get(macA); ok {
		t.Error("the long-expired lease should be gone")
	}
	if _, ok := s.Get(macB); !ok {
		t.Error("the live lease must stay")
	}
}

func TestRoutedListsOnlyActiveShepherdLeasesPointingAtShepherd(t *testing.T) {
	c := newClock()
	s := NewLeases()
	own := []netip.Addr{shepherdA}
	live := c.now().Add(time.Hour)
	s.Put(Lease{MAC: macA, IP: poolStart, Router: shepherdA, Origin: OriginShepherd, Expires: live})
	s.Put(Lease{MAC: macB, IP: poolEnd, Router: gatewayA, Origin: OriginShepherd, Expires: live})
	s.Put(Lease{MAC: "02:00:5e:01:02:05", IP: netip.MustParseAddr("192.0.2.102"), Router: shepherdA, Origin: OriginShepherd, Expires: c.now().Add(-time.Minute)})
	s.Put(Lease{MAC: "02:00:5e:01:02:06", IP: netip.MustParseAddr("192.0.2.103"), Router: shepherdA, Origin: OriginObserved, Expires: live})

	got := s.Routed(c.now(), own)
	if len(got) != 1 || got[0] != poolStart {
		t.Fatalf("Routed = %v, want just %v: an expired lease and an observed one are not Shepherd's to translate", got, poolStart)
	}
}

func TestAllSortsNewestAllocationFirst(t *testing.T) {
	c := newClock()
	s := NewLeases()
	s.Put(Lease{MAC: macA, IP: poolStart, Allocated: c.now()})
	s.Put(Lease{MAC: macB, IP: poolEnd, Allocated: c.now().Add(time.Minute)})
	all := s.All()
	if len(all) != 2 || all[0].MAC != macB {
		t.Fatalf("All = %+v, want the newer allocation first", all)
	}
}

func TestSaveAndLoadRoundTripAndSkipAnUnchangedStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp-leases.json")
	c := newClock()
	s := NewLeases()
	s.Put(Lease{MAC: macA, IP: poolStart, Hostname: "printer", Router: shepherdA, Origin: OriginShepherd,
		Allocated: c.now(), Expires: c.now().Add(time.Hour), Fingerprint: "1,3,6,15"})
	if !s.Dirty() {
		t.Fatal("a store with a new lease is dirty")
	}
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if s.Dirty() {
		t.Error("Save should clear the dirty flag so a periodic saver can skip a write")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("lease file mode = %o, want 600", perm)
	}

	back := NewLeases()
	if err := back.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := back.Get(macA)
	if !ok {
		t.Fatal("the lease did not survive the round trip")
	}
	if got.Hostname != "printer" || got.IP != poolStart || got.Router != shepherdA || got.Fingerprint != "1,3,6,15" {
		t.Errorf("round trip lost something: %+v", got)
	}
	if !back.Loaded() {
		t.Error("Loaded should be true after a successful load")
	}
}

func TestLoadTreatsAMissingFileAsAnEmptyStoreAndStillCountsAsLoaded(t *testing.T) {
	s := NewLeases()
	if err := s.Load(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("a missing lease file is not an error: %v", err)
	}
	if !s.Loaded() {
		t.Error("an absent file still means the store is loaded: there is nothing to recover")
	}
}

// Refusing to start over a corrupt cache of something every client re-asks
// for would turn a small problem into an outage, so the file is set aside.
func TestLoadOrResetSetsABadFileAsideAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp-leases.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewLeases()
	reset, err := s.LoadOrReset(path)
	if err != nil {
		t.Fatalf("LoadOrReset: %v", err)
	}
	if !reset {
		t.Fatal("LoadOrReset must report that the file was set aside")
	}
	if _, err := os.Stat(path + ".bad"); err != nil {
		t.Errorf("the unreadable file should be kept as %s.bad: %v", path, err)
	}
	if !s.Loaded() || s.Len() != 0 {
		t.Errorf("after a reset the store is loaded and empty, got loaded=%v len=%d", s.Loaded(), s.Len())
	}
}

func TestLoadRefusesAVersionThisBuildDoesNotKnow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp-leases.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"leases":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := NewLeases().Load(path)
	if !errors.Is(err, ErrBadLeases) {
		t.Fatalf("Load error = %v, want one wrapping ErrBadLeases", err)
	}
}

func TestLoadSkipsRecordsWithNoUsableMAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp-leases.json")
	body := `{"version":1,"leases":[null,{"mac":"","ip":"192.0.2.100"},{"mac":"02:00:5e:01:02:03","ip":"192.0.2.100"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewLeases()
	if err := s.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1: a record with no key cannot be stored", s.Len())
	}
}

func TestLoadOrResetPassesThroughAnErrorThatIsNotAParseFailure(t *testing.T) {
	dir := t.TempDir()
	// A directory where a file is expected: the read fails, and it is not a
	// parse failure, so it must not be "set aside" and started over.
	path := filepath.Join(dir, "leases-dir")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s := NewLeases()
	reset, err := s.LoadOrReset(path)
	if err == nil {
		t.Fatal("reading a directory as a lease file must be an error")
	}
	if reset {
		t.Error("a read failure is not a parse failure and nothing should be renamed")
	}
}

func TestLeaseRoutedNeedsOneOfShepherdsOwnAddresses(t *testing.T) {
	l := Lease{Router: shepherdA}
	if !l.Routed([]netip.Addr{shepherdA}) {
		t.Error("a lease naming Shepherd is routed")
	}
	if l.Routed([]netip.Addr{gatewayA}) {
		t.Error("a lease naming something that is not Shepherd's is not routed")
	}
	if (Lease{}).Routed([]netip.Addr{shepherdA}) {
		t.Error("a lease with no router option is not routed")
	}
}

func TestWriteFileAtomicRefusesADirectoryItCannotWriteTo(t *testing.T) {
	if err := writeFileAtomic(filepath.Join(t.TempDir(), "absent-dir", "f.json"), []byte("{}")); err == nil {
		t.Fatal("writing into a directory that does not exist must fail")
	}
}

func TestSaveReportsAFailedWrite(t *testing.T) {
	s := NewLeases()
	s.Put(Lease{MAC: macA, IP: poolStart})
	if err := s.Save(filepath.Join(t.TempDir(), "no-such-dir", "leases.json")); err == nil {
		t.Fatal("Save must report a write it could not make")
	}
	if !s.Dirty() {
		t.Error("and leave the store dirty, so the next save tries again")
	}
}

func TestSaveWritesValidJSONForAnEmptyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	if err := NewLeases().Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	back := NewLeases()
	if err := back.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if back.Len() != 0 {
		t.Errorf("Len = %d", back.Len())
	}
}

func TestRoutedIgnoresALeaseWithNoAddress(t *testing.T) {
	c := newClock()
	s := NewLeases()
	s.Put(Lease{MAC: macA, Router: shepherdA, Origin: OriginShepherd, Expires: c.now().Add(time.Hour)})
	if got := s.Routed(c.now(), []netip.Addr{shepherdA}); len(got) != 0 {
		t.Errorf("Routed = %v; a lease with no address is nothing to translate", got)
	}
}

func TestMarkLoadedStandsInForALoad(t *testing.T) {
	s := NewLeases()
	if s.Loaded() {
		t.Fatal("a fresh store has not been loaded")
	}
	s.MarkLoaded()
	if !s.Loaded() {
		t.Error("MarkLoaded is how an in-memory store says there was nothing to read")
	}
}

func TestWriteFileAtomicCleansUpAfterARenameItCannotMake(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should go: the write and the sync succeed
	// and the rename does not, which is the path that must not leave a
	// temporary file behind.
	target := filepath.Join(dir, "in-the-way")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(target, []byte("{}")); err == nil {
		t.Fatal("renaming a file onto a directory must fail")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

func TestWriteAndSyncReportsAClosedFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeAndSync(f, []byte("data")); err == nil {
		t.Fatal("writing to a closed file must fail")
	}
}
