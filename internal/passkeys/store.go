// SPDX-License-Identifier: AGPL-3.0-or-later

package passkeys

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
)

// MaxPasskeys caps how many passkeys can be registered at once, the same
// cap the portal puts on PIN-trusted browsers.
const MaxPasskeys = 20

// maxNameRunes bounds a passkey's display name.
const maxNameRunes = 64

const fileVersion = 1

var (
	// ErrNotFound means no passkey has the given id or credential id.
	ErrNotFound = errors.New("passkey not found")
	// ErrDuplicate means that credential is already registered.
	ErrDuplicate = errors.New("that passkey is already registered")
	// ErrTooMany means MaxPasskeys are already registered.
	ErrTooMany = fmt.Errorf("at most %d passkeys can be registered; remove one before adding another", MaxPasskeys)
	// ErrInvalid means a name the store will not keep.
	ErrInvalid = errors.New("invalid passkey name")
)

// Passkey is one registered credential. Credential is the library's own
// credential record (credential id, COSE public key, sign count, flags,
// AAGUID, attestation data) stored exactly as the library returned it, so
// nothing it checks at login is lost in translation. None of it is secret:
// the private key never leaves the authenticator.
type Passkey struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Created    time.Time           `json:"created"`
	LastUsed   time.Time           `json:"last_used,omitzero"`
	Credential webauthn.Credential `json:"credential"`
}

type file struct {
	Version int `json:"version"`
	// TokenHash is the portal token's hash when this file was written; a
	// different token at startup means it was rotated, which revokes every
	// passkey (docs/LOCKING.md says the same of PINs and trusted browsers).
	TokenHash string `json:"token_hash"`
	// UserHandle is the WebAuthn user.id of the portal's one owner: 64
	// random bytes, created on the first registration. Every passkey is
	// bound to it.
	UserHandle []byte    `json:"user_handle,omitempty"`
	Passkeys   []Passkey `json:"passkeys"`
}

// Store persists registered passkeys in a JSON file (mode 0600), written
// atomically on every change and only then made visible, so memory and disk
// never disagree; the same shape as reverseproxy.Store. An empty path keeps
// everything in memory. Nothing is written until the first change.
type Store struct {
	path string

	mu   sync.RWMutex
	data file
}

// Open loads path and reconciles it against the current token's hash. A
// missing file starts empty. A file that cannot be read or parsed is an
// error, never a fresh start: an empty store's first save would silently
// destroy what was there. A file written under a different token is wiped,
// on disk as well as in memory, before anything can use it.
func Open(path, tokenHash string) (*Store, error) {
	s := &Store{path: path, data: file{Version: fileVersion, TokenHash: tokenHash}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("%s: unsupported version %d", path, f.Version)
	}
	ids := map[string]bool{}
	for _, p := range f.Passkeys {
		if p.ID == "" || ids[p.ID] {
			return nil, fmt.Errorf("%s: a passkey has a missing or repeated id", path)
		}
		ids[p.ID] = true
	}
	if f.TokenHash != tokenHash {
		f = file{Version: fileVersion, TokenHash: tokenHash}
		if err := s.save(f); err != nil {
			return nil, err
		}
	}
	s.data = f
	return s, nil
}

// UserHandle returns the owner's WebAuthn user handle, creating and saving
// it the first time.
func (s *Store) UserHandle() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.UserHandle) == 0 {
		next := s.data
		next.UserHandle = randBytes(64)
		if err := s.save(next); err != nil {
			return nil, err
		}
		s.data = next
	}
	return slices.Clone(s.data.UserHandle), nil
}

// Len reports how many passkeys are registered.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Passkeys)
}

// List returns every passkey, in the order they were added.
func (s *Store) List() []Passkey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.data.Passkeys)
}

// Credentials returns every passkey's credential record, for the library.
func (s *Store) Credentials() []webauthn.Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]webauthn.Credential, len(s.data.Passkeys))
	for i, p := range s.data.Passkeys {
		out[i] = p.Credential
	}
	return out
}

// ByCredentialID finds the passkey holding a credential id.
func (s *Store) ByCredentialID(credID []byte) (Passkey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.data.Passkeys {
		if bytes.Equal(p.Credential.ID, credID) {
			return p, true
		}
	}
	return Passkey{}, false
}

// Add registers a credential under name (empty means "Passkey").
func (s *Store) Add(name string, cred webauthn.Credential, now time.Time) (Passkey, error) {
	n, err := normalizeName(name)
	if err != nil {
		return Passkey{}, err
	}
	p := Passkey{ID: hex.EncodeToString(randBytes(8)), Name: n, Created: now, Credential: cred}
	return p, s.mutate(func(list []Passkey) ([]Passkey, error) {
		if len(list) >= MaxPasskeys {
			return nil, ErrTooMany
		}
		for _, q := range list {
			if bytes.Equal(q.Credential.ID, cred.ID) {
				return nil, ErrDuplicate
			}
		}
		return append(list, p), nil
	})
}

// Rename changes a passkey's display name.
func (s *Store) Rename(id, name string) (Passkey, error) {
	n, err := normalizeName(name)
	if err != nil {
		return Passkey{}, err
	}
	var out Passkey
	return out, s.mutate(func(list []Passkey) ([]Passkey, error) {
		i := slices.IndexFunc(list, func(p Passkey) bool { return p.ID == id })
		if i < 0 {
			return nil, ErrNotFound
		}
		list[i].Name = n
		out = list[i]
		return list, nil
	})
}

// Remove revokes a passkey: it can never unlock the portal again, even
// though the authenticator itself still holds it.
func (s *Store) Remove(id string) error {
	return s.mutate(func(list []Passkey) ([]Passkey, error) {
		i := slices.IndexFunc(list, func(p Passkey) bool { return p.ID == id })
		if i < 0 {
			return nil, ErrNotFound
		}
		return slices.Delete(list, i, i+1), nil
	})
}

// RecordLogin stores the credential record the library returned after a
// successful login (its new sign count and flags) and the time it was used.
func (s *Store) RecordLogin(cred webauthn.Credential, now time.Time) (Passkey, error) {
	var out Passkey
	return out, s.mutate(func(list []Passkey) ([]Passkey, error) {
		i := slices.IndexFunc(list, func(p Passkey) bool { return bytes.Equal(p.Credential.ID, cred.ID) })
		if i < 0 {
			return nil, ErrNotFound
		}
		list[i].Credential = cred
		list[i].LastUsed = now
		out = list[i]
		return list, nil
	})
}

// mutate applies fn to a copy of the list, saves, and only then swaps it in.
// fn may replace elements of the copy but never shares their slices with
// the live list, since every element is replaced whole.
func (s *Store) mutate(fn func([]Passkey) ([]Passkey, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := fn(slices.Clone(s.data.Passkeys))
	if err != nil {
		return err
	}
	next := s.data
	next.Passkeys = list
	if err := s.save(next); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *Store) save(f file) error {
	if s.path == "" {
		return nil
	}
	if f.Passkeys == nil {
		f.Passkeys = []Passkey{}
	}
	b, _ := json.MarshalIndent(f, "", "  ") // strings, times, numbers and byte slices only: cannot fail
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func normalizeName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "Passkey", nil
	}
	if utf8.RuneCountInString(n) > maxNameRunes {
		return "", fmt.Errorf("%w: at most %d characters", ErrInvalid, maxNameRunes)
	}
	for _, c := range n {
		if unicode.IsControl(c) {
			return "", fmt.Errorf("%w: no control characters", ErrInvalid)
		}
	}
	return n, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return b
}
