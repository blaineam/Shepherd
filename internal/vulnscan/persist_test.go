// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoadRoundTrip(t *testing.T) {
	s := New(Options{Dial: dialByAddress(connScript{addr("192.0.2.200", 23): nil}), Concurrency: 2, Timeout: time.Second})
	s.Scan(context.Background(), []Target{{DeviceID: "d1", IP: "192.0.2.200", Ports: []int{23}}})

	dir := t.TempDir()
	path := filepath.Join(dir, "vulnscan.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}

	s2 := New(Options{})
	if err := s2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := s2.Result("d1")
	if !ok || len(got.Findings) != 1 || got.Findings[0].SignatureID != "telnet-exposed" {
		t.Fatalf("Result after Load = %+v, %v", got, ok)
	}
}

func TestLoadMissingFile(t *testing.T) {
	s := New(Options{})
	err := s.Load(filepath.Join(t.TempDir(), "missing.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("Load missing file: %v, want os.IsNotExist", err)
	}
}

func TestLoadCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Options{})
	if err := s.Load(path); err == nil {
		t.Fatal("Load of corrupt JSON must error")
	}
}
