// SPDX-License-Identifier: AGPL-3.0-or-later

// Package history is Shepherd's encrypted, on-disk record of past queries. It
// is append-only: entries are written to immutable, individually keyed
// AES-256-GCM segments that can be searched later to trace a problem. Nothing
// on disk is readable without the key.
package history

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"

	"crypto/hkdf"

	"shepherd/internal/dnsengine"
)

// KeySource provides the 32-byte master key from which every segment key is derived.
type KeySource interface {
	// Key returns the master key, or dnsengine.ErrLocked if it must be unlocked first.
	Key() ([]byte, error)
	// Unlock supplies a passphrase. For a passphrase source that has none yet,
	// the first call creates it.
	Unlock(passphrase string) error
	// Initialized reports whether a key or passphrase already exists.
	Initialized() bool
}

// randBytes returns n random bytes. crypto/rand.Read cannot fail (the runtime
// aborts the process if the system source is broken), so there is no error.
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// aeadFor derives a 256-bit key for info from master and returns an AES-GCM
// AEAD. HKDF and AES-GCM cannot fail for a 32-byte key, so an error here is a
// programming bug and panics.
func aeadFor(master []byte, info string) cipher.AEAD {
	k, err := hkdf.Key(sha256.New, master, nil, "shepherd history "+info, 32)
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

func writeFile0600(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// FileKey keeps a random master key in a file (created on first use, mode
// 0600). Point Path at a different volume or a removable drive so the key is
// not stored beside the data it protects.
type FileKey struct {
	Path string
	mu   sync.Mutex
	key  []byte
}

func (f *FileKey) Key() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.key != nil {
		return f.key, nil
	}
	b, err := os.ReadFile(f.Path)
	switch {
	case err == nil:
		k, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("key file %s is not a 32-byte hex key", f.Path)
		}
		f.key = k
	case errors.Is(err, os.ErrNotExist):
		k := randBytes(32)
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
			return nil, err
		}
		if err := writeFile0600(f.Path, []byte(hex.EncodeToString(k)+"\n")); err != nil {
			return nil, err
		}
		f.key = k
	default:
		return nil, err
	}
	return f.key, nil
}

func (f *FileKey) Unlock(string) error { return dnsengine.ErrNotSupported }

func (f *FileKey) Initialized() bool {
	_, err := os.Stat(f.Path)
	return err == nil
}

// PassphraseKey derives the master key from a passphrase with Argon2id. Until a
// passphrase is supplied (in the portal or from the environment) the history is
// locked and entries wait in memory. The key itself is never stored; a small
// check file proves a passphrase is right without revealing anything.
type PassphraseKey struct {
	Dir string
	// Argon2id cost. Zero values use strong defaults.
	Time, MemoryKiB uint32

	mu  sync.Mutex
	key []byte
}

const checkText = "shepherd history key check"

func (p *PassphraseKey) params() (t, m uint32) {
	t, m = p.Time, p.MemoryKiB
	if t == 0 {
		t = 3
	}
	if m == 0 {
		m = 64 * 1024
	}
	return
}

func (p *PassphraseKey) saltPath() string  { return filepath.Join(p.Dir, "key.salt") }
func (p *PassphraseKey) checkPath() string { return filepath.Join(p.Dir, "key.check") }

func (p *PassphraseKey) Initialized() bool {
	_, err := os.Stat(p.checkPath())
	return err == nil
}

func (p *PassphraseKey) Key() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == nil {
		return nil, dnsengine.ErrLocked
	}
	return p.key, nil
}

func (p *PassphraseKey) Unlock(passphrase string) error {
	if passphrase == "" {
		return dnsengine.ErrWrongPassphrase
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	t, m := p.params()
	if !p.Initialized() { // first use: this creates the passphrase
		if err := os.MkdirAll(p.Dir, 0o700); err != nil {
			return err
		}
		salt := randBytes(16)
		master := argon2.IDKey([]byte(passphrase), salt, t, m, 1, 32)
		check := sealCheck(master)
		if err := writeFile0600(p.saltPath(), salt); err != nil {
			return err
		}
		if err := writeFile0600(p.checkPath(), check); err != nil {
			return err
		}
		p.key = master
		return nil
	}
	salt, err := os.ReadFile(p.saltPath())
	if err != nil {
		return err
	}
	check, err := os.ReadFile(p.checkPath())
	if err != nil {
		return err
	}
	master := argon2.IDKey([]byte(passphrase), salt, t, m, 1, 32)
	if err := openCheck(master, check); err != nil {
		return dnsengine.ErrWrongPassphrase
	}
	p.key = master
	return nil
}

func sealCheck(master []byte) []byte {
	g := aeadFor(master, "check")
	nonce := randBytes(g.NonceSize())
	return g.Seal(nonce, nonce, []byte(checkText), nil)
}

func openCheck(master, blob []byte) error {
	g := aeadFor(master, "check")
	if len(blob) < g.NonceSize() {
		return errors.New("short check file")
	}
	pt, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], nil)
	if err != nil || string(pt) != checkText {
		return errors.New("check failed")
	}
	return nil
}
