// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dial := fakeDial(map[string]bool{addr("192.0.2.200", 23): true})
	s := New(Options{Dial: dial, Ports: []int{22, 23}, Concurrency: 2, Timeout: time.Second})
	s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.200"}})

	path := filepath.Join(t.TempDir(), "portscan.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("saved file mode = %v, want 0600", info.Mode().Perm())
	}

	loaded := New(Options{})
	if err := loaded.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := loaded.Result("d1")
	if !ok {
		t.Fatal("loaded scanner has no record for d1")
	}
	p := findPort(t, got.Ports, 23)
	if !p.Open || !p.Risky {
		t.Fatalf("loaded record = %+v, want port 23 open and risky", p)
	}
}

func TestLoadMissingFileIsNotExist(t *testing.T) {
	s := New(Options{})
	err := s.Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() = %v, want an os.IsNotExist error", err)
	}
}

func TestSaveFailsWhenDirectoryIsMissing(t *testing.T) {
	s := New(Options{})
	err := s.Save(filepath.Join(t.TempDir(), "no-such-dir", "portscan.json"))
	if err == nil {
		t.Fatal("Save() into a missing directory returned nil error")
	}
}

func TestLoadRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portscan.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Options{})
	if err := s.Load(path); err == nil {
		t.Fatal("Load() of a corrupt file returned nil error")
	}
}
