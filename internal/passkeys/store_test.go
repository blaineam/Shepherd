// SPDX-License-Identifier: AGPL-3.0-or-later

package passkeys

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func cred(id string) webauthn.Credential {
	return webauthn.Credential{ID: []byte(id), PublicKey: []byte("public-key-" + id), Authenticator: webauthn.Authenticator{SignCount: 1}}
}

func TestStoreMissingFileStartsEmptyAndWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys.json")
	s, err := Open(path, "tokenhash")
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 || len(s.List()) != 0 {
		t.Errorf("a fresh store has %d passkeys", s.Len())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("opening must not create the file before the first edit: %v", err)
	}
}

func TestStoreAddPersistsAt0600AndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")
	s, err := Open(path, "tokenhash")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := s.UserHandle()
	if err != nil {
		t.Fatal(err)
	}
	if len(handle) != 64 {
		t.Errorf("user handle is %d bytes, want 64 random bytes", len(handle))
	}
	again, _ := s.UserHandle()
	if !bytes.Equal(handle, again) {
		t.Error("the user handle must be stable once created")
	}
	pk, err := s.Add("  My phone  ", cred("c1"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if pk.ID == "" || pk.Name != "My phone" || !pk.Created.Equal(t0) || !pk.LastUsed.IsZero() {
		t.Errorf("added = %+v", pk)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error("the temporary file must not be left behind")
	}

	re, err := Open(path, "tokenhash")
	if err != nil {
		t.Fatal(err)
	}
	if re.Len() != 1 {
		t.Fatalf("reloaded %d passkeys", re.Len())
	}
	got := re.List()[0]
	if got.ID != pk.ID || got.Name != "My phone" || !bytes.Equal(got.Credential.ID, []byte("c1")) || !bytes.Equal(got.Credential.PublicKey, []byte("public-key-c1")) {
		t.Errorf("reloaded = %+v", got)
	}
	h2, _ := re.UserHandle()
	if !bytes.Equal(h2, handle) {
		t.Error("the user handle must survive a restart: every passkey is bound to it")
	}
	if creds := re.Credentials(); len(creds) != 1 || !bytes.Equal(creds[0].ID, []byte("c1")) {
		t.Errorf("Credentials = %v", creds)
	}
}

func TestStoreDefaultsAndValidatesNames(t *testing.T) {
	s, _ := Open("", "h")
	pk, err := s.Add("", cred("c1"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if pk.Name != "Passkey" {
		t.Errorf("an empty name = %q, want the default", pk.Name)
	}
	if _, err := s.Add(strings.Repeat("x", 65), cred("c2"), t0); !errors.Is(err, ErrInvalid) {
		t.Errorf("a 65-character name: err = %v", err)
	}
	if _, err := s.Add("bad\x00name", cred("c3"), t0); !errors.Is(err, ErrInvalid) {
		t.Errorf("a control character: err = %v", err)
	}
	if _, err := s.Add(strings.Repeat("é", 64), cred("c4"), t0); err != nil {
		t.Errorf("64 runes must fit, whatever their byte length: %v", err)
	}
}

func TestStoreRefusesADuplicateCredentialAndCapsTheCount(t *testing.T) {
	s, _ := Open("", "h")
	if _, err := s.Add("a", cred("same"), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("b", cred("same"), t0); !errors.Is(err, ErrDuplicate) {
		t.Errorf("the same credential twice: err = %v", err)
	}
	for i := 1; i < MaxPasskeys; i++ {
		if _, err := s.Add("k", cred(string(rune('A'+i))), t0); err != nil {
			t.Fatalf("passkey %d: %v", i, err)
		}
	}
	if _, err := s.Add("one too many", cred("overflow"), t0); !errors.Is(err, ErrTooMany) {
		t.Errorf("past the cap: err = %v", err)
	}
}

func TestStoreRenameAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys.json")
	s, _ := Open(path, "h")
	a, _ := s.Add("a", cred("c1"), t0)
	b, _ := s.Add("b", cred("c2"), t0)
	if _, err := s.Rename(a.ID, "Laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rename(a.ID, strings.Repeat("x", 65)); !errors.Is(err, ErrInvalid) {
		t.Errorf("rename to an invalid name: err = %v", err)
	}
	if _, err := s.Rename("nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rename unknown: err = %v", err)
	}
	if err := s.Remove(b.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(b.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove twice: err = %v", err)
	}
	re, _ := Open(path, "h")
	list := re.List()
	if len(list) != 1 || list[0].Name != "Laptop" {
		t.Errorf("after rename and remove: %+v", list)
	}
	if _, ok := re.ByCredentialID([]byte("c2")); ok {
		t.Error("a removed passkey must not be found by its credential id")
	}
	if got, ok := re.ByCredentialID([]byte("c1")); !ok || got.ID != a.ID {
		t.Errorf("ByCredentialID(c1) = %+v, %v", got, ok)
	}
}

func TestStoreRecordLoginUpdatesTheCredentialAndLastUsed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys.json")
	s, _ := Open(path, "h")
	a, _ := s.Add("a", cred("c1"), t0)
	updated := cred("c1")
	updated.Authenticator.SignCount = 7
	later := t0.Add(time.Hour)
	pk, err := s.RecordLogin(updated, later)
	if err != nil {
		t.Fatal(err)
	}
	if pk.ID != a.ID || !pk.LastUsed.Equal(later) || pk.Credential.Authenticator.SignCount != 7 {
		t.Errorf("after login = %+v", pk)
	}
	re, _ := Open(path, "h")
	if got := re.List()[0]; got.Credential.Authenticator.SignCount != 7 || !got.LastUsed.Equal(later) {
		t.Errorf("the new sign count must be persisted, or the next login cannot detect a clone: %+v", got)
	}
	if _, err := s.RecordLogin(cred("unknown"), later); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown credential: err = %v", err)
	}
}

func TestStoreWipesEverythingWhenTheTokenRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys.json")
	s, _ := Open(path, "old-token")
	handle, _ := s.UserHandle()
	if _, err := s.Add("a", cred("c1"), t0); err != nil {
		t.Fatal(err)
	}
	re, err := Open(path, "new-token")
	if err != nil {
		t.Fatal(err)
	}
	if re.Len() != 0 {
		t.Errorf("a rotated token must revoke every passkey, found %d", re.Len())
	}
	h2, _ := re.UserHandle()
	if bytes.Equal(h2, handle) {
		t.Error("a rotated token starts a fresh identity")
	}
	// And the wipe is on disk, not just in memory.
	b, _ := os.ReadFile(path)
	if bytes.Contains(b, []byte("public-key-c1")) {
		t.Error("the wiped passkey is still in the file")
	}
	again, _ := Open(path, "new-token")
	if again.Len() != 0 {
		t.Error("reopening under the new token must stay empty")
	}
}

func TestStoreRefusesACorruptOrFutureFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passkeys.json")
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := Open(path, "h"); err == nil {
		t.Error("a corrupt file must be an error, never a silent fresh start the next edit overwrites")
	}
	os.WriteFile(path, []byte(`{"version":99}`), 0o600)
	if _, err := Open(path, "h"); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("a future version: err = %v", err)
	}
	os.WriteFile(path, []byte(`{"version":1,"token_hash":"h","passkeys":[{"id":"","name":"x","credential":{"id":"YQ=="}}]}`), 0o600)
	if _, err := Open(path, "h"); err == nil {
		t.Error("a passkey without an id must be refused")
	}
	os.WriteFile(path, []byte(`{"version":1,"token_hash":"h","passkeys":[{"id":"a","name":"x","credential":{"id":"YQ=="}},{"id":"a","name":"y","credential":{"id":"Yg=="}}]}`), 0o600)
	if _, err := Open(path, "h"); err == nil {
		t.Error("a repeated id must be refused")
	}
	sub := filepath.Join(dir, "unreadable")
	os.Mkdir(sub, 0o700)
	if _, err := Open(sub, "h"); err == nil {
		t.Error("a path that cannot be read as a file must be an error")
	}
}

func TestStoreAFailedSaveChangesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "passkeys.json")
	s, _ := Open(path, "h")
	if _, err := s.Add("a", cred("c1"), t0); err != nil {
		t.Fatal(err)
	}
	// Make the directory unwritable so the next save fails.
	os.Chmod(filepath.Join(dir, "sub"), 0o500)
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "sub"), 0o700) })
	if _, err := s.Add("b", cred("c2"), t0); err == nil {
		t.Skip("running with permissions that ignore directory modes")
	}
	if s.Len() != 1 {
		t.Errorf("a failed save must leave memory unchanged, have %d", s.Len())
	}
}

func TestStoreMemoryOnly(t *testing.T) {
	s, err := Open("", "h")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("a", cred("c1"), t0); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Error("an empty path keeps passkeys in memory")
	}
}
