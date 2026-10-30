// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateAccountKeyGeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")

	key1, err := LoadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("account key mode = %o, want 0600", perm)
	}

	key2, err := LoadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !key1.Equal(key2) {
		t.Error("second call generated a new key instead of loading the saved one")
	}
}

func TestLoadOrCreateAccountKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateAccountKey(path); err == nil {
		t.Fatal("expected an error loading a non-PEM file")
	}
}

func TestLoadOrCreateAccountKeyRejectsWrongPEMType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")
	body := "-----BEGIN RSA PRIVATE KEY-----\nbm90IGEgcmVhbCBrZXk=\n-----END RSA PRIVATE KEY-----\n" // leakcheck:allow fabricated test fixture, not a real key
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateAccountKey(path); err == nil {
		t.Fatal("expected an error loading a non-EC PEM block")
	}
}
