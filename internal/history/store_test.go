// SPDX-License-Identifier: AGPL-3.0-or-later

package history

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shepherd/internal/dnsengine"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func entry(at time.Time, client, name, action string) dnsengine.Entry {
	return dnsengine.Entry{Time: at, Client: client, Name: name, Type: "A", Action: action, Rcode: "NOERROR"}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func open(t *testing.T, dir string, mutate func(*Options)) *Store {
	t.Helper()
	o := Options{Dir: dir, Keys: &FileKey{Path: filepath.Join(dir, "k", "history.key")}}
	if mutate != nil {
		mutate(&o)
	}
	s, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func names(es []dnsengine.Entry) string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name)
	}
	return strings.Join(out, ",")
}

func TestRoundTripAndReopen(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	s.Append(entry(t0, "192.0.2.10", "a.example.com", "allowed"))
	s.Append(entry(t0.Add(time.Second), "192.0.2.11", "b.example.com", "blocked"))
	s.Append(entry(t0.Add(2*time.Second), "192.0.2.10", "c.example.net", "cached"))
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := open(t, dir, nil)
	defer s2.Close()
	got, span, err := s2.Query(dnsengine.HistoryQuery{})
	if err != nil || names(got) != "a.example.com,b.example.com,c.example.net" {
		t.Fatalf("reopen got %q err %v", names(got), err)
	}
	if !span.Oldest.Equal(t0) || !span.Newest.Equal(t0.Add(2*time.Second)) {
		t.Errorf("span = %+v", span)
	}
	cases := []struct {
		name string
		q    dnsengine.HistoryQuery
		want string
	}{
		{"client", dnsengine.HistoryQuery{Client: "192.0.2.10"}, "a.example.com,c.example.net"},
		{"action", dnsengine.HistoryQuery{Action: "blocked"}, "b.example.com"},
		{"contains", dnsengine.HistoryQuery{Contains: "EXAMPLE.NET"}, "c.example.net"},
		{"from", dnsengine.HistoryQuery{From: t0.Add(time.Second)}, "b.example.com,c.example.net"},
		{"to", dnsengine.HistoryQuery{To: t0}, "a.example.com"},
		{"limit keeps newest", dnsengine.HistoryQuery{Limit: 2}, "b.example.com,c.example.net"},
		{"nothing", dnsengine.HistoryQuery{Client: "198.51.100.1"}, ""},
	}
	for _, c := range cases {
		got, _, err := s2.Query(c.q)
		if err != nil || names(got) != c.want {
			t.Errorf("%s: got %q (err %v), want %q", c.name, names(got), err, c.want)
		}
	}
}

func TestUnflushedEntriesAreQueryable(t *testing.T) {
	s := open(t, t.TempDir(), nil)
	defer s.Close()
	s.Append(entry(t0, "192.0.2.10", "pending.example.com", "allowed"))
	got, _, err := s.Query(dnsengine.HistoryQuery{})
	if err != nil || names(got) != "pending.example.com" {
		t.Errorf("pending not visible: %q %v", names(got), err)
	}
	if st := s.Stats(); st.Pending != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestDestsSurviveStorage(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	e := entry(t0, "192.0.2.10", "geo.example.com", "allowed")
	e.Dests = []dnsengine.Dest{{IP: "198.51.100.7", Lat: 48.85, Lon: 2.35, City: "Paris", Country: "FR"}}
	s.Append(e)
	s.Close()
	s2 := open(t, dir, nil)
	defer s2.Close()
	got, _, _ := s2.Query(dnsengine.HistoryQuery{})
	if len(got) != 1 || len(got[0].Dests) != 1 || got[0].Dests[0].City != "Paris" {
		t.Errorf("dests lost: %+v", got)
	}
}

func TestNothingIsReadableOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	for i := 0; i < 50; i++ {
		s.Append(entry(t0.Add(time.Duration(i)*time.Second), "192.0.2.77", "very-secret-lookup.example.com", "allowed"))
	}
	s.Close()
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasSuffix(p, "history.key") {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, secret := range []string{"very-secret-lookup", "192.0.2.77", "example.com"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("%s contains plaintext %q", p, secret)
			}
		}
		if strings.Contains(filepath.Base(p), "2026") {
			t.Errorf("file name %s leaks a date", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFilesArePrivate(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	s.Append(entry(t0, "192.0.2.1", "a.example.com", "allowed"))
	s.Close()
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || p == dir {
			return err
		}
		if info.IsDir() {
			if info.Mode().Perm()&0o077 != 0 && !strings.HasSuffix(p, "k") {
				t.Errorf("directory %s mode %v is not private", p, info.Mode().Perm())
			}
		} else if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("file %s mode %v is not private", p, info.Mode().Perm())
		}
		return nil
	})
}

func TestRotationBySizeAndTimeRangeSkipping(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, func(o *Options) { o.SegmentMaxBytes = 300; o.FlushEntries = 2 })
	defer s.Close()
	for i := 0; i < 20; i++ {
		s.Append(entry(t0.Add(time.Duration(i)*time.Hour), "192.0.2.5", fmt.Sprintf("h%02d.example.com", i), "allowed"))
	}
	s.Flush()
	if st := s.Stats(); st.Segments < 3 || st.Entries != 20 {
		t.Fatalf("expected several segments holding 20 entries: %+v", st)
	}
	got, _, err := s.Query(dnsengine.HistoryQuery{From: t0.Add(5 * time.Hour), To: t0.Add(7 * time.Hour)})
	if err != nil || names(got) != "h05.example.com,h06.example.com,h07.example.com" {
		t.Errorf("range across segments = %q (%v)", names(got), err)
	}
	all, _, _ := s.Query(dnsengine.HistoryQuery{})
	if len(all) != 20 || all[0].Name != "h00.example.com" || all[19].Name != "h19.example.com" {
		t.Errorf("segments must merge in time order, got %d first %s", len(all), all[0].Name)
	}
}

func TestRotationByAge(t *testing.T) {
	c := &clock{t: t0}
	s := open(t, t.TempDir(), func(o *Options) { o.Now = c.now; o.SegmentMaxAge = time.Hour })
	defer s.Close()
	s.Append(entry(t0, "192.0.2.5", "one.example.com", "allowed"))
	s.Flush()
	c.add(2 * time.Hour)
	s.Append(entry(c.now(), "192.0.2.5", "two.example.com", "allowed"))
	s.Flush()
	if st := s.Stats(); st.Segments != 2 {
		t.Errorf("age rotation: %+v", st)
	}
}

func firstSegment(t *testing.T, dir string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "segments", "*"+ext))
	if len(files) == 0 {
		t.Fatal("no segments")
	}
	return files[0]
}

func TestTamperedFrameIsDetectedNotTrusted(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, func(o *Options) { o.SegmentMaxBytes = 1; o.FlushEntries = 1 }) // one segment per entry
	for i := 0; i < 3; i++ {
		s.Append(entry(t0.Add(time.Duration(i)*time.Second), "192.0.2.5", fmt.Sprintf("n%d.example.com", i), "allowed"))
	}
	s.Close()
	victim := firstSegment(t, dir)
	b, _ := os.ReadFile(victim)
	b[len(b)-3] ^= 0xFF // flip a ciphertext byte
	os.WriteFile(victim, b, 0o600)

	s2 := open(t, dir, nil)
	defer s2.Close()
	got, span, err := s2.Query(dnsengine.HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || span.Skipped != 1 {
		t.Errorf("tampered segment must be skipped and counted: got %d entries, skipped %d", len(got), span.Skipped)
	}
}

func TestTruncatedTailKeepsEarlierFrames(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	s.Append(entry(t0, "192.0.2.5", "first.example.com", "allowed"))
	s.Flush()
	s.Append(entry(t0.Add(time.Second), "192.0.2.5", "second.example.com", "allowed"))
	s.Flush()
	s.Close()
	seg := firstSegment(t, dir)
	b, _ := os.ReadFile(seg)
	os.WriteFile(seg, b[:len(b)-7], 0o600) // an interrupted write

	s2 := open(t, dir, nil)
	defer s2.Close()
	got, span, err := s2.Query(dnsengine.HistoryQuery{})
	if err != nil || names(got) != "first.example.com" || span.Skipped != 0 {
		t.Errorf("truncated tail: got %q skipped %d err %v", names(got), span.Skipped, err)
	}
}

func TestSegmentsCannotBeReordered(t *testing.T) {
	// Frames are bound to their position and segment, so splicing one segment's frame
	// into another's slot fails authentication instead of being accepted.
	dir := t.TempDir()
	s := open(t, dir, func(o *Options) { o.SegmentMaxBytes = 1; o.FlushEntries = 1 })
	s.Append(entry(t0, "192.0.2.5", "a.example.com", "allowed"))
	s.Append(entry(t0.Add(time.Second), "192.0.2.5", "b.example.com", "allowed"))
	s.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "segments", "*"+ext))
	a, _ := os.ReadFile(files[0])
	b, _ := os.ReadFile(files[1])
	os.WriteFile(files[0], append(append([]byte(nil), a[:headerLen]...), b[headerLen:]...), 0o600)
	s2 := open(t, dir, nil)
	defer s2.Close()
	got, span, _ := s2.Query(dnsengine.HistoryQuery{})
	if span.Skipped == 0 || len(got) != 1 {
		t.Errorf("spliced frame accepted: %d entries, skipped %d", len(got), span.Skipped)
	}
}

func TestWrongKeyRefusesToOpenExistingData(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	s.Append(entry(t0, "192.0.2.5", "a.example.com", "allowed"))
	s.Close()
	_, err := Open(Options{Dir: dir, Keys: &FileKey{Path: filepath.Join(t.TempDir(), "other.key")}})
	if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Errorf("a different key must not silently replace the history: %v", err)
	}
}

func TestManifestLossAndCorruptionAreRebuilt(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, func(o *Options) { o.SegmentMaxBytes = 1; o.FlushEntries = 1 })
	for i := 0; i < 3; i++ {
		s.Append(entry(t0.Add(time.Duration(i)*time.Minute), "192.0.2.5", fmt.Sprintf("m%d.example.com", i), "allowed"))
	}
	s.Close()
	for _, damage := range []func(){
		func() { os.Remove(filepath.Join(dir, "manifest.shm")) },
		func() {
			os.WriteFile(filepath.Join(dir, "manifest.shm"), []byte("garbage-garbage-garbage-garbage"), 0o600)
		},
		func() { os.WriteFile(filepath.Join(dir, "manifest.shm"), []byte("x"), 0o600) },
	} {
		damage()
		s2 := open(t, dir, nil)
		got, _, err := s2.Query(dnsengine.HistoryQuery{})
		if err != nil || len(got) != 3 {
			t.Fatalf("after manifest damage: %d entries, err %v", len(got), err)
		}
		s2.Close()
	}
}

func fastPass(dir string) *PassphraseKey { return &PassphraseKey{Dir: dir, Time: 1, MemoryKiB: 8} }

func TestPassphraseLifecycle(t *testing.T) {
	dir := t.TempDir()
	keys := fastPass(filepath.Join(dir, "keys"))
	s, err := Open(Options{Dir: dir, Keys: keys, LockedBuffer: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Locked() || s.Initialized() || s.Mode() != "encrypted" {
		t.Fatalf("fresh passphrase store: locked=%v initialized=%v", s.Locked(), s.Initialized())
	}
	for i := 0; i < 5; i++ { // more than the locked buffer holds
		s.Append(entry(t0.Add(time.Duration(i)*time.Second), "192.0.2.5", fmt.Sprintf("w%d.example.com", i), "allowed"))
	}
	if _, _, err := s.Query(dnsengine.HistoryQuery{}); !errors.Is(err, dnsengine.ErrLocked) {
		t.Errorf("locked query must say so: %v", err)
	}
	if err := s.Unlock(""); !errors.Is(err, dnsengine.ErrWrongPassphrase) {
		t.Errorf("empty passphrase: %v", err)
	}
	if err := s.Unlock("correct horse"); err != nil { // first use creates it
		t.Fatal(err)
	}
	if s.Locked() || !s.Initialized() {
		t.Error("unlocked state wrong")
	}
	got, _, err := s.Query(dnsengine.HistoryQuery{})
	if err != nil || names(got) != "w2.example.com,w3.example.com,w4.example.com" {
		t.Errorf("entries held while locked must be written after unlock (newest 3): %q %v", names(got), err)
	}
	if err := s.Unlock("whatever"); !errors.Is(err, dnsengine.ErrWrongPassphrase) {
		t.Errorf("an unlocked store still rejects a wrong passphrase, got %v", err)
	}
	if err := s.Unlock("correct horse"); err != nil {
		t.Errorf("unlocking an unlocked store with the right passphrase is a no-op, got %v", err)
	}
	s.Close()

	s2, err := Open(Options{Dir: dir, Keys: fastPass(filepath.Join(dir, "keys"))})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !s2.Locked() || !s2.Initialized() {
		t.Error("reopened store must be locked but initialized")
	}
	if err := s2.Unlock("wrong horse"); !errors.Is(err, dnsengine.ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if !s2.Locked() {
		t.Error("a wrong passphrase must not unlock")
	}
	if err := s2.Unlock("correct horse"); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s2.Query(dnsengine.HistoryQuery{}); len(got) != 3 {
		t.Errorf("history unreadable after reopen+unlock: %d", len(got))
	}
}

func TestPassphraseFilesAreSecretAndSalted(t *testing.T) {
	dir := t.TempDir()
	k := fastPass(dir)
	if err := k.Unlock("hunter2"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"key.salt", "key.check"} {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, err, info)
		}
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if bytes.Contains(b, []byte("hunter2")) {
			t.Errorf("%s contains the passphrase", f)
		}
	}
	// A different install derives a different key from the same passphrase.
	other := fastPass(t.TempDir())
	other.Unlock("hunter2")
	a, _ := k.Key()
	b, _ := other.Key()
	if bytes.Equal(a, b) {
		t.Error("salt must make keys differ between installs")
	}
}

func TestFileKeyBehavior(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "k.key")
	k := &FileKey{Path: path}
	if k.Initialized() {
		t.Error("not initialized before first use")
	}
	key1, err := k.Key()
	if err != nil || len(key1) != 32 {
		t.Fatalf("key %v %v", key1, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 || !k.Initialized() {
		t.Errorf("key file mode %v", info.Mode().Perm())
	}
	key2, _ := (&FileKey{Path: path}).Key()
	if !bytes.Equal(key1, key2) {
		t.Error("the key must be stable across loads")
	}
	if err := k.Unlock("x"); !errors.Is(err, dnsengine.ErrNotSupported) {
		t.Errorf("file keys have no passphrase: %v", err)
	}
	os.WriteFile(path, []byte("not hex"), 0o600)
	if _, err := (&FileKey{Path: path}).Key(); err == nil {
		t.Error("a malformed key file must be an error")
	}
	if _, err := (&FileKey{Path: dir}).Key(); err == nil {
		t.Error("a directory where the key file belongs must be an error")
	}
	blocker := filepath.Join(dir, "afile")
	os.WriteFile(blocker, []byte("x"), 0o600)
	if _, err := (&FileKey{Path: filepath.Join(blocker, "sub", "k.key")}).Key(); err == nil {
		t.Error("an uncreatable key directory must be an error")
	}
}

func TestOpenValidation(t *testing.T) {
	if _, err := Open(Options{Dir: t.TempDir()}); err == nil {
		t.Error("a key source is required")
	}
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0o600)
	if _, err := Open(Options{Dir: filepath.Join(blocker, "sub"), Keys: &FileKey{Path: filepath.Join(t.TempDir(), "k")}}); err == nil {
		t.Error("an uncreatable directory must be an error")
	}
	bad := &FileKey{Path: t.TempDir()} // a directory as key file
	if _, err := Open(Options{Dir: t.TempDir(), Keys: bad}); err == nil {
		t.Error("a broken key source must be an error")
	}
}

func TestRetentionByAgeAndSize(t *testing.T) {
	c := &clock{t: t0}
	dir := t.TempDir()
	s := open(t, dir, func(o *Options) {
		o.Now = c.now
		o.RetentionDays = 7
		o.SegmentMaxBytes = 1
		o.FlushEntries = 1
	})
	defer s.Close()
	s.Append(entry(t0, "192.0.2.5", "ancient.example.com", "allowed"))
	c.add(10 * 24 * time.Hour)
	s.Append(entry(c.now(), "192.0.2.5", "recent.example.com", "allowed"))
	s.Append(entry(c.now().Add(time.Second), "192.0.2.5", "newest.example.com", "allowed"))
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Query(dnsengine.HistoryQuery{})
	if names(got) != "recent.example.com,newest.example.com" {
		t.Errorf("age retention kept %q", names(got))
	}
	files, _ := filepath.Glob(filepath.Join(dir, "segments", "*"+ext))
	if len(files) != 2 {
		t.Errorf("the pruned segment file must be deleted from disk, have %d files", len(files))
	}

	s.o.MaxBytes = 1 // force the size cap
	s.Append(entry(c.now().Add(2*time.Second), "192.0.2.5", "extra.example.com", "allowed"))
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.Segments != 1 {
		t.Errorf("size cap should leave only the newest segment: %+v", st)
	}
	if err := s.Prune(); err != nil { // nothing left to do
		t.Fatal(err)
	}
}

func TestPruneWhileLockedDoesNothing(t *testing.T) {
	s, _ := Open(Options{Dir: t.TempDir(), Keys: fastPass(t.TempDir()), RetentionDays: 1})
	defer s.Close()
	if err := s.Prune(); err != nil {
		t.Errorf("locked prune must be a no-op: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Errorf("locked flush must be a no-op: %v", err)
	}
}

func TestRunFlushesPeriodicallyAndOnShutdown(t *testing.T) {
	s := open(t, t.TempDir(), func(o *Options) { o.FlushEvery = 10 * time.Millisecond; o.FlushEntries = 1000 })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	s.Append(entry(t0, "192.0.2.5", "tick.example.com", "allowed"))
	deadline := time.Now().Add(3 * time.Second)
	for s.Stats().Pending != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Stats().Pending != 0 {
		t.Fatal("the periodic flush never ran")
	}
	s.Append(entry(t0.Add(time.Second), "192.0.2.5", "last.example.com", "allowed"))
	cancel()
	<-done
	if s.Stats().Pending != 0 {
		t.Error("shutdown must flush")
	}
	s.Close()
}

func TestConcurrentAppendAndQuery(t *testing.T) {
	s := open(t, t.TempDir(), func(o *Options) { o.FlushEntries = 5; o.SegmentMaxBytes = 2000 })
	defer s.Close()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				s.Append(entry(t0.Add(time.Duration(w*1000+i)*time.Second), "192.0.2.5", fmt.Sprintf("c%d-%d.example.com", w, i), "allowed"))
			}
		}()
	}
	for q := 0; q < 2; q++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, _, err := s.Query(dnsengine.HistoryQuery{Limit: 10}); err != nil {
					t.Error(err)
				}
				s.Prune()
			}
		}()
	}
	wg.Wait()
	s.Flush()
	got, span, err := s.Query(dnsengine.HistoryQuery{})
	if err != nil || len(got) != 400 || span.Skipped != 0 {
		t.Errorf("concurrent writes lost data: %d entries, skipped %d, err %v", len(got), span.Skipped, err)
	}
}

func TestScanRejectsNonSegments(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x"+ext)
	os.WriteFile(p, []byte("this is not a segment at all, just text"), 0o600)
	if skipped, err := scanSegment(p, make([]byte, 32), func(dnsengine.Entry) {}); err == nil || skipped != 1 {
		t.Errorf("garbage accepted: skipped=%d err=%v", skipped, err)
	}
	if _, err := scanSegment(filepath.Join(t.TempDir(), "missing"+ext), make([]byte, 32), func(dnsengine.Entry) {}); err == nil {
		t.Error("a missing file must be an error")
	}
	// A valid header followed by a nonsense frame length stops the scan and is counted.
	hdr := append([]byte(magic), make([]byte, 16)...)
	os.WriteFile(p, append(hdr, 0xFF, 0xFF, 0xFF, 0xFF), 0o600)
	if skipped, _ := scanSegment(p, make([]byte, 32), func(dnsengine.Entry) {}); skipped != 1 {
		t.Errorf("an absurd frame length must be counted, skipped=%d", skipped)
	}
}

func TestMissingSegmentFileIsToleratedByQuery(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, func(o *Options) { o.SegmentMaxBytes = 1; o.FlushEntries = 1 })
	s.Append(entry(t0, "192.0.2.5", "a.example.com", "allowed"))
	s.Append(entry(t0.Add(time.Second), "192.0.2.5", "b.example.com", "allowed"))
	s.Flush()
	os.Remove(firstSegment(t, dir))
	got, _, err := s.Query(dnsengine.HistoryQuery{})
	if err != nil || len(got) != 1 {
		t.Errorf("a deleted segment must not break queries: %d %v", len(got), err)
	}
	s.Close()
}
