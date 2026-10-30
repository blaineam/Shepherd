// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const lockFileVersion = 1

const (
	// maxTrustedDevices caps how many browsers can hold a PIN-unlock cookie at
	// once, so a PIN leak cannot be ground against many registered devices to
	// dodge any one device's lockout.
	maxTrustedDevices = 20
	// PIN lockout: growing delays start at 5 wrong tries in a row, and the
	// trusted device is revoked outright at 10 so a stolen cookie cannot be
	// ground against forever.
	pinFailsLockout = 5
	pinFailsRevoke  = 10
	pinLockoutFor   = 15 * time.Minute
	// maxSessionAge caps a session cookie's absolute lifetime even with
	// auto-lock off (docs/LOCKING.md).
	maxSessionAge = 30 * 24 * time.Hour
	// trustedCookieMaxAge is how long a trusted-browser cookie is kept by the
	// browser. Unlike a session, trust is meant to last until it is revoked,
	// the PIN is turned off or the token rotates, not on a timer, so this is
	// generous (about 13 months, the longest most browsers will keep a cookie).
	trustedCookieMaxAge = 400 * 24 * 3600
)

var (
	errTooManyTrustedDevices = errors.New("too many trusted browsers; revoke one before adding another")
	errTrustedDeviceNotFound = errors.New("trusted browser not found")
)

// pinRecord is the PIN's Argon2id hash. The Argon2 cost is stored alongside
// it so a cost change in a later release does not break PINs set under the
// old one.
type pinRecord struct {
	Salt      []byte `json:"salt"`
	Hash      []byte `json:"hash"`
	ArgonTime uint32 `json:"argon_time"`
	ArgonMem  uint32 `json:"argon_mem_kib"`
}

// trustedDevice is a browser that may unlock with the PIN. Only a salted hash
// of its random secret is stored, never the secret itself.
type trustedDevice struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	SecretHash  []byte    `json:"secret_hash"`
	Created     time.Time `json:"created"`
	LastUsed    time.Time `json:"last_used"`
	Fails       int       `json:"fails,omitempty"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
}

type lockFile struct {
	Version         int             `json:"version"`
	TokenHash       string          `json:"token_hash"`
	IdleLockMinutes *int            `json:"idle_lock_minutes,omitempty"`
	PIN             *pinRecord      `json:"pin,omitempty"`
	TrustedDevices  []trustedDevice `json:"trusted_devices,omitempty"`
}

// lockStore persists portal-locking state (the idle-lock override, the PIN
// and the trusted-browser registry) the same way dnsengine.UpstreamStore
// persists upstream edits: an empty path keeps everything in memory only,
// and every change is written atomically. Rotating the token (detected by
// its hash no longer matching the file from a previous run) wipes the PIN
// and every trusted browser, since both are only meaningful alongside the
// token they were set up under.
type lockStore struct {
	path string
	mu   sync.Mutex
	data lockFile
}

// openLockStore loads path (ignoring a missing or corrupt file, which just
// starts fresh) and reconciles it against the current token's hash. An empty
// path keeps everything in memory for the life of the process.
func openLockStore(path, tokenHash string) *lockStore {
	s := &lockStore{path: path}
	if path != "" {
		if err := s.load(); err != nil {
			s.data = lockFile{}
		}
	}
	if s.data.TokenHash != "" && s.data.TokenHash != tokenHash {
		s.data.PIN = nil
		s.data.TrustedDevices = nil
	}
	if s.data.TokenHash != tokenHash {
		s.data.TokenHash = tokenHash
		s.data.Version = lockFileVersion
		_ = s.save() // best effort: an unwritable data dir just stays in-memory
	}
	return s
}

func (s *lockStore) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f lockFile
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("parsing %s: %w", s.path, err)
	}
	if f.Version != 0 && f.Version != lockFileVersion {
		return fmt.Errorf("%s: unsupported version %d", s.path, f.Version)
	}
	s.data = f
	return nil
}

func (s *lockStore) save() error {
	if s.path == "" {
		return nil
	}
	b, _ := json.MarshalIndent(s.data, "", "  ") // strings and byte slices only: cannot fail
	return writeFileAtomic(s.path, b)
}

// edit applies fn (which mutates s.data by replacing fields and slices, never
// by mutating a slice element in place) and saves, undoing the change if the
// save fails so memory and disk never disagree.
func (s *lockStore) edit(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.data
	if err := fn(); err != nil {
		return err
	}
	if err := s.save(); err != nil {
		s.data = prev
		return err
	}
	return nil
}

func (s *lockStore) idleLockMinutes(fallback int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.IdleLockMinutes != nil {
		return *s.data.IdleLockMinutes
	}
	return fallback
}

func (s *lockStore) setIdleLockMinutes(n int) error {
	if n < 0 {
		return errors.New("idle_lock_minutes must not be negative")
	}
	return s.edit(func() error { v := n; s.data.IdleLockMinutes = &v; return nil })
}

func (s *lockStore) pin() (pinRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.PIN == nil {
		return pinRecord{}, false
	}
	return *s.data.PIN, true
}

func (s *lockStore) setPIN(p pinRecord) error {
	return s.edit(func() error { rec := p; s.data.PIN = &rec; return nil })
}

// clearPIN removes the PIN and every trusted browser (useless without a PIN)
// and returns the ids that were revoked, so callers can also drop sessions.
func (s *lockStore) clearPIN() ([]string, error) {
	var ids []string
	err := s.edit(func() error {
		for _, d := range s.data.TrustedDevices {
			ids = append(ids, d.ID)
		}
		s.data.PIN = nil
		s.data.TrustedDevices = nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail; the runtime aborts first
	return b
}

// addTrustedDevice registers a new browser and returns its id and the random
// secret to put in its cookie (the store keeps only a hash of it).
func (s *lockStore) addTrustedDevice(name string, now time.Time) (id string, secret []byte, err error) {
	secret = randBytes(32)
	id = hex.EncodeToString(randBytes(16))
	h := sha256.Sum256(secret)
	dev := trustedDevice{ID: id, Name: name, SecretHash: h[:], Created: now, LastUsed: now}
	err = s.edit(func() error {
		if len(s.data.TrustedDevices) >= maxTrustedDevices {
			return errTooManyTrustedDevices
		}
		s.data.TrustedDevices = append(append([]trustedDevice{}, s.data.TrustedDevices...), dev)
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return id, secret, nil
}

func (s *lockStore) findTrustedDevice(id string) (trustedDevice, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.data.TrustedDevices {
		if d.ID == id {
			return d, true
		}
	}
	return trustedDevice{}, false
}

func (s *lockStore) trustedDevices() []trustedDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]trustedDevice, len(s.data.TrustedDevices))
	copy(out, s.data.TrustedDevices)
	return out
}

func (s *lockStore) revokeTrustedDevice(id string) error {
	return s.edit(func() error {
		next := make([]trustedDevice, 0, len(s.data.TrustedDevices))
		found := false
		for _, d := range s.data.TrustedDevices {
			if d.ID == id {
				found = true
				continue
			}
			next = append(next, d)
		}
		if !found {
			return errTrustedDeviceNotFound
		}
		s.data.TrustedDevices = next
		return nil
	})
}

// recordPINSuccess clears a device's failure count and bumps its last-used time.
func (s *lockStore) recordPINSuccess(id string, now time.Time) error {
	return s.edit(func() error {
		next := append([]trustedDevice{}, s.data.TrustedDevices...)
		for i := range next {
			if next[i].ID == id {
				next[i].Fails = 0
				next[i].LockedUntil = time.Time{}
				next[i].LastUsed = now
				s.data.TrustedDevices = next
				return nil
			}
		}
		return errTrustedDeviceNotFound
	})
}

// recordPINFailure counts a wrong PIN against a device, locking it out at
// pinFailsLockout and revoking it outright at pinFailsRevoke.
func (s *lockStore) recordPINFailure(id string, now time.Time) (fails int, revoked bool, err error) {
	err = s.edit(func() error {
		next := append([]trustedDevice{}, s.data.TrustedDevices...)
		idx := -1
		for i := range next {
			if next[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return errTrustedDeviceNotFound
		}
		next[idx].Fails++
		fails = next[idx].Fails
		if fails >= pinFailsRevoke {
			revoked = true
			next = append(next[:idx], next[idx+1:]...)
		} else if fails >= pinFailsLockout {
			next[idx].LockedUntil = now.Add(pinLockoutFor)
		}
		s.data.TrustedDevices = next
		return nil
	})
	return fails, revoked, err
}

// lockedUntil reports whether id is currently locked out from PIN attempts.
func (s *lockStore) lockedUntil(id string, now time.Time) (bool, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.data.TrustedDevices {
		if d.ID == id {
			return !d.LockedUntil.IsZero() && now.Before(d.LockedUntil), d.LockedUntil
		}
	}
	return false, time.Time{}
}

// writeFileAtomic writes data to path through a temporary file, mode 0600.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// validatePIN enforces the 6-12 character, letters-and-digits rule and
// rejects obviously guessable PINs (all one character, or a simple run).
func validatePIN(pin string) error {
	if len(pin) < 6 || len(pin) > 12 {
		return errors.New("PIN must be 6 to 12 characters")
	}
	for i := 0; i < len(pin); i++ {
		c := pin[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return errors.New("PIN must be letters and digits only")
		}
	}
	if weakPIN(pin) {
		return errors.New("choose a less predictable PIN")
	}
	return nil
}

func weakPIN(pin string) bool {
	same := true
	for i := 1; i < len(pin); i++ {
		if pin[i] != pin[0] {
			same = false
			break
		}
	}
	if same {
		return true
	}
	digits := true
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' {
			digits = false
			break
		}
	}
	if digits {
		asc, desc := true, true
		for i := 1; i < len(pin); i++ {
			if pin[i] != pin[i-1]+1 {
				asc = false
			}
			if pin[i] != pin[i-1]-1 {
				desc = false
			}
		}
		if asc || desc {
			return true
		}
	}
	return false
}
