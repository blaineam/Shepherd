// SPDX-License-Identifier: AGPL-3.0-or-later

package history

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shepherd/internal/dnsengine"
)

// readOnly makes dir unwritable for the rest of the test (and restores it).
func readOnly(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission faults cannot be injected as root")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
}

func TestFlushReportsDiskFailuresAndKeepsEntries(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, func(o *Options) { o.FlushEntries = 1 })
	defer s.Close()
	readOnly(t, filepath.Join(dir, "segments"))
	s.Append(entry(t0, "192.0.2.5", "kept.example.com", "allowed")) // flush fails, logged
	if err := s.Flush(); err == nil {
		t.Fatal("expected a flush error on an unwritable directory")
	}
	got, _, _ := s.Query(dnsengine.HistoryQuery{})
	if len(got) != 1 {
		t.Errorf("a failed flush must not lose the entry, have %d", len(got))
	}
	os.Chmod(filepath.Join(dir, "segments"), 0o700)
	if err := s.Flush(); err != nil {
		t.Errorf("flush must recover once the disk is writable: %v", err)
	}
	if st := s.Stats(); st.Pending != 0 || st.Entries != 1 {
		t.Errorf("stats after recovery = %+v", st)
	}
}

func TestFlushFailsCleanlyWhenTheSegmentFileIsGone(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	s.Append(entry(t0, "192.0.2.5", "a.example.com", "allowed"))
	s.Flush()
	s.active.f.Close() // simulate the descriptor dying under us
	s.Append(entry(t0.Add(time.Second), "192.0.2.5", "b.example.com", "allowed"))
	if err := s.Flush(); err == nil {
		t.Error("writing to a closed segment must be an error")
	}
}

func TestManifestWriteFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	defer s.Close()
	os.Remove(filepath.Join(dir, "manifest.shm"))
	os.MkdirAll(filepath.Join(dir, "manifest.shm", "blocker"), 0o700) // a directory where the file belongs
	s.Append(entry(t0, "192.0.2.5", "a.example.com", "allowed"))
	if err := s.Flush(); err == nil {
		t.Error("an unwritable manifest must be an error")
	}
}

func TestOpenSegmentFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	defer s.Close()
	os.RemoveAll(filepath.Join(dir, "segments"))
	s.Append(entry(t0, "192.0.2.5", "a.example.com", "allowed"))
	if err := s.Flush(); err == nil {
		t.Error("a missing segments directory must be an error, not a panic")
	}
}

func TestCrashLeavesAnUnsealedSegmentThatIsSealedOnReopen(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, nil)
	s.Append(entry(t0, "192.0.2.5", "before.example.com", "allowed"))
	s.Flush() // never closed: the manifest still says the segment is open

	s2 := open(t, dir, nil)
	s2.Append(entry(t0.Add(time.Second), "192.0.2.5", "after.example.com", "allowed"))
	s2.Flush()
	if st := s2.Stats(); st.Segments != 2 {
		t.Errorf("new writes must go to a fresh segment, have %d", st.Segments)
	}
	got, _, _ := s2.Query(dnsengine.HistoryQuery{})
	if names(got) != "before.example.com,after.example.com" {
		t.Errorf("after crash recovery: %q", names(got))
	}
	s2.Close()
}

func TestPassphraseDefaultsAndBadFiles(t *testing.T) {
	dir := t.TempDir()
	k := &PassphraseKey{Dir: dir} // default Argon2id cost
	if err := k.Unlock("a strong passphrase"); err != nil {
		t.Fatal(err)
	}
	if tm, mem := k.params(); tm != 3 || mem != 64*1024 {
		t.Errorf("default Argon2id cost = %d/%d", tm, mem)
	}
	if _, err := (&PassphraseKey{Dir: dir}).Key(); !errors.Is(err, dnsengine.ErrLocked) {
		t.Errorf("a fresh key object starts locked: %v", err)
	}

	// A corrupt check file reads as a wrong passphrase, never a crash.
	os.WriteFile(filepath.Join(dir, "key.check"), []byte("xx"), 0o600)
	if err := (&PassphraseKey{Dir: dir}).Unlock("a strong passphrase"); !errors.Is(err, dnsengine.ErrWrongPassphrase) {
		t.Errorf("corrupt check file: %v", err)
	}
	// A missing salt is an error, not a guess.
	os.Remove(filepath.Join(dir, "key.salt"))
	if err := (&PassphraseKey{Dir: dir}).Unlock("a strong passphrase"); err == nil {
		t.Error("missing salt must be an error")
	}
	// A salt present but check missing means "uninitialized" and can be re-created.
	os.Remove(filepath.Join(dir, "key.check"))
	if (&PassphraseKey{Dir: dir}).Initialized() {
		t.Error("without a check file the passphrase is not initialized")
	}
	// The directory cannot be created.
	blocker := filepath.Join(t.TempDir(), "f")
	os.WriteFile(blocker, []byte("x"), 0o600)
	if err := (&PassphraseKey{Dir: filepath.Join(blocker, "sub"), Time: 1, MemoryKiB: 8}).Unlock("x"); err == nil {
		t.Error("an uncreatable key directory must be an error")
	}
	// Check file unreadable (a directory in its place).
	d2 := t.TempDir()
	k2 := fastPass(d2)
	k2.Unlock("pw")
	os.Remove(filepath.Join(d2, "key.check"))
	os.MkdirAll(filepath.Join(d2, "key.check"), 0o700)
	if err := fastPass(d2).Unlock("pw"); err == nil {
		t.Error("an unreadable check file must be an error")
	}
	// Salt and check files cannot be written.
	d3 := t.TempDir()
	readOnly(t, d3)
	if err := fastPass(d3).Unlock("pw"); err == nil {
		t.Error("unwritable key files must be an error")
	}
}

func TestUnlockRefusesToReplaceUndecryptableHistory(t *testing.T) {
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	s1, _ := Open(Options{Dir: dir, Keys: fastPass(keyDir)})
	s1.Unlock("first passphrase")
	s1.Append(entry(t0, "192.0.2.5", "precious.example.com", "allowed"))
	s1.Close()

	// Someone deletes the key files and sets a new passphrase: the old data must
	// not be silently discarded or overwritten.
	os.RemoveAll(keyDir)
	s2, err := Open(Options{Dir: dir, Keys: fastPass(keyDir)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Unlock("second passphrase"); err == nil {
		t.Fatal("unlocking with a key that cannot read the existing history must fail")
	}
	if !s2.Locked() {
		t.Error("the store must stay locked after a failed unlock")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "segments", "*"+ext))
	if len(files) != 1 {
		t.Errorf("existing segments must be left alone, found %d", len(files))
	}
}

func TestRunPrunesOnItsInterval(t *testing.T) {
	c := &clock{t: t0}
	s := open(t, t.TempDir(), func(o *Options) {
		o.Now = c.now
		o.RetentionDays = 1
		o.SegmentMaxBytes = 1
		o.FlushEntries = 1
		o.FlushEvery = time.Hour
		o.PruneEvery = 10 * time.Millisecond
	})
	s.Append(entry(t0, "192.0.2.5", "old.example.com", "allowed"))
	c.add(72 * time.Hour)
	s.Append(entry(c.now(), "192.0.2.5", "new.example.com", "allowed"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for s.Stats().Segments > 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if st := s.Stats(); st.Segments != 1 {
		t.Errorf("the prune tick never removed the expired segment: %+v", st)
	}
	s.Close()
}

func TestCloseWhileLockedKeepsPendingInMemoryOnly(t *testing.T) {
	s, _ := Open(Options{Dir: t.TempDir(), Keys: fastPass(t.TempDir())})
	s.Append(entry(t0, "192.0.2.5", "a.example.com", "allowed"))
	if err := s.Close(); err != nil {
		t.Errorf("closing a locked store: %v", err)
	}
}
