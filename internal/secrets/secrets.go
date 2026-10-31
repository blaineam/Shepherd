// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secrets keeps the bring-your-own credentials Shepherd needs and
// cannot generate for itself — today a DNS provider API token (for ACME
// DNS-01 certificates, shared by [tls] and [reverseproxy]) and an outgoing
// SMTP relay (for accountability email) — in one portal-managed file,
// <data_dir>/secrets.json.
//
// It follows the persistence shape every other portal-owned store in this
// project already uses (reverseproxy.Store, devices.Registry, the policy
// store): JSON, loaded once on startup, saved atomically (a temp file in the
// same directory, fsync, rename) on every edit, mode 0600, and nothing is
// written until there is something to write. Its security model is exactly
// theirs too: the file's 0600 permissions are the whole protection, the same
// honest limit docs/TLS.md states for the ACME keys and docs/DEVICES.md and
// docs/HISTORY.md state for the portal token and the history key. There is
// no encryption at rest here.
//
// Values are write-only from the portal's point of view: nothing in this
// package formats a secret into a string (DNSProvider and SMTP implement
// fmt.Stringer with redacted output), and the portal API never returns one.
//
// shepherd.toml's old secret fields are read-once seeds (see Seed*): a value
// is imported only while the portal has never owned that secret, and once it
// has — by importing it, saving one, or clearing it — shepherd.toml is
// ignored for it from then on.
package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileName is the store's file inside the data directory.
const FileName = "secrets.json"

// ProviderCloudflare is the only DNS provider implemented today. The field
// exists so another provider can be added later without changing the file
// format or the API.
const ProviderCloudflare = "cloudflare"

// Where a stored value came from.
const (
	// SourcePortal: saved (or cleared) from the portal.
	SourcePortal = "portal"
	// SourceConfig: imported once from shepherd.toml.
	SourceConfig = "shepherd.toml"
)

// ErrInvalid wraps every validation failure, so callers can tell "fix your
// input" from "the disk refused the write".
var ErrInvalid = errors.New("invalid")

const fileVersion = 1

// maxLen bounds every field: generous for any real token, password or host,
// small enough that nothing absurd is ever persisted.
const maxLen = 2048

// Meta records where a value came from and when it last changed.
type Meta struct {
	Source    string    `json:"source"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DNSProvider is the one DNS provider credential Shepherd's ACME DNS-01
// flows share. An empty APIToken with a non-zero Meta means the owner
// cleared it in the portal.
type DNSProvider struct {
	Provider string `json:"provider"`
	APIToken string `json:"api_token"`
	Meta
}

// Configured reports whether a token is actually set.
func (d DNSProvider) Configured() bool { return d.APIToken != "" }

// String never includes the token, so a stray %v in a log line cannot leak it.
func (d DNSProvider) String() string {
	if !d.Configured() {
		return "dns provider (not set)"
	}
	return fmt.Sprintf("dns provider %s (token set, from %s)", d.Provider, d.Source)
}

// GoString redacts the same way for %#v.
func (d DNSProvider) GoString() string { return d.String() }

func (d DNSProvider) validate() error {
	if d.Provider != ProviderCloudflare {
		return fmt.Errorf("%w: unknown DNS provider %q (only %q is supported)", ErrInvalid, d.Provider, ProviderCloudflare)
	}
	if d.APIToken == "" {
		return fmt.Errorf("%w: the API token must not be empty", ErrInvalid)
	}
	return checkField("API token", d.APIToken, true)
}

// SMTP is the outgoing mail relay accountability email is sent through. An
// empty Host with a non-zero Meta means the owner cleared it in the portal.
type SMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	// TLS is "starttls", "tls" or "none" (accountability.TLSMode).
	TLS string `json:"tls"`
	Meta
}

// Configured reports whether a relay is actually set.
func (s SMTP) Configured() bool { return s.Host != "" }

// String never includes the password.
func (s SMTP) String() string {
	if !s.Configured() {
		return "smtp relay (not set)"
	}
	pw := "no password"
	if s.Password != "" {
		pw = "password set"
	}
	return fmt.Sprintf("smtp relay %s:%d (%s, %s, from %s)", s.Host, s.Port, s.TLS, pw, s.Source)
}

// GoString redacts the same way for %#v.
func (s SMTP) GoString() string { return s.String() }

// TLS modes an SMTP relay accepts, mirroring accountability.TLSMode.
var smtpTLSModes = map[string]bool{"starttls": true, "tls": true, "none": true}

func (s SMTP) validate() error {
	if s.Host == "" {
		return fmt.Errorf("%w: the relay host is required", ErrInvalid)
	}
	if s.Port <= 0 || s.Port > 65535 {
		return fmt.Errorf("%w: port %d is not between 1 and 65535", ErrInvalid, s.Port)
	}
	if s.From == "" {
		return fmt.Errorf("%w: the From address is required", ErrInvalid)
	}
	if !smtpTLSModes[s.TLS] {
		return fmt.Errorf(`%w: tls must be "starttls", "tls" or "none", got %q`, ErrInvalid, s.TLS)
	}
	if strings.ContainsAny(s.Host, " /:@") {
		return fmt.Errorf("%w: the relay host is a bare name or address, with no scheme, port or path", ErrInvalid)
	}
	if !strings.Contains(s.From, "@") {
		return fmt.Errorf("%w: the From address must be an email address", ErrInvalid)
	}
	for name, v := range map[string]string{"relay host": s.Host, "username": s.Username, "From address": s.From} {
		if err := checkField(name, v, true); err != nil {
			return err
		}
	}
	// A password may contain spaces (some providers' app passwords do), but
	// never a control character: it is sent inside an SMTP AUTH line.
	return checkField("password", s.Password, false)
}

// checkField rejects control characters (a CR or LF in a header or SMTP
// command would be an injection) and, when noSpace, any whitespace at all.
func checkField(name, v string, noSpace bool) error {
	if len(v) > maxLen {
		return fmt.Errorf("%w: the %s is longer than %d characters", ErrInvalid, name, maxLen)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: the %s contains a control character", ErrInvalid, name)
		}
		if noSpace && r == ' ' {
			return fmt.Errorf("%w: the %s must not contain spaces", ErrInvalid, name)
		}
	}
	return nil
}

type file struct {
	Version int `json:"version"`
	// A nil record means "never owned": shepherd.toml may still seed it.
	DNSProvider *DNSProvider `json:"dns_provider,omitempty"`
	SMTP        *SMTP        `json:"smtp,omitempty"`
}

// Store owns secrets.json. It is safe for concurrent use. An empty path
// keeps everything in memory (portal tests, and a portal built without
// cmd/shepherd's wiring).
type Store struct {
	path string
	now  func() time.Time

	mu   sync.RWMutex
	data file
}

// Open loads path. A missing file starts empty. A file that cannot be read
// or validated is an error rather than a fresh start, for the same reason
// reverseproxy.Open refuses one: carrying on empty would let the first edit,
// or the next startup's seeding, overwrite credentials the owner had.
func Open(path string) (*Store, error) {
	s := &Store{path: path, now: time.Now, data: file{Version: fileVersion}}
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
	if d := f.DNSProvider; d != nil && d.Configured() {
		if err := d.validate(); err != nil {
			return nil, fmt.Errorf("%s: dns_provider: %w", path, err)
		}
	}
	if m := f.SMTP; m != nil && m.Configured() {
		if err := m.validate(); err != nil {
			return nil, fmt.Errorf("%s: smtp: %w", path, err)
		}
	}
	s.data = f
	return s, nil
}

// DNSProvider returns the stored DNS provider credential and whether a token
// is actually set.
func (s *Store) DNSProvider() (DNSProvider, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.DNSProvider == nil {
		return DNSProvider{}, false
	}
	d := *s.data.DNSProvider
	return d, d.Configured()
}

// DNSProviderManaged reports whether the portal owns the DNS provider
// credential (it was imported, saved or cleared), so shepherd.toml no
// longer seeds it.
func (s *Store) DNSProviderManaged() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.DNSProvider != nil
}

// Normalize trims d and validates it, without storing anything: what the
// portal runs before it spends a network round trip checking a token that
// could never be saved anyway.
func (d DNSProvider) Normalize() (DNSProvider, error) {
	d.APIToken = strings.TrimSpace(d.APIToken)
	d.Provider = strings.TrimSpace(d.Provider)
	if err := d.validate(); err != nil {
		return DNSProvider{}, err
	}
	return d, nil
}

// SetDNSProvider validates and saves d as the owner's choice from the portal.
func (s *Store) SetDNSProvider(d DNSProvider) (DNSProvider, error) {
	d, err := d.Normalize()
	if err != nil {
		return DNSProvider{}, err
	}
	d.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return d, s.mutate(func(f *file) { f.DNSProvider = &d })
}

// ClearDNSProvider removes the token and remembers that it was removed on
// purpose, so a token still in shepherd.toml is not imported again.
func (s *Store) ClearDNSProvider() error {
	return s.mutate(func(f *file) {
		f.DNSProvider = &DNSProvider{Meta: Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}}
	})
}

// SeedDNSProvider imports d from shepherd.toml, but only while the portal
// has never owned the DNS provider credential. It reports whether d was
// imported. An empty token imports nothing.
func (s *Store) SeedDNSProvider(d DNSProvider) (bool, error) {
	d.APIToken = strings.TrimSpace(d.APIToken)
	if d.APIToken == "" {
		return false, nil
	}
	if err := d.validate(); err != nil {
		return false, err
	}
	d.Meta = Meta{Source: SourceConfig, UpdatedAt: s.now().UTC()}
	return s.seed(func(f *file) bool {
		if f.DNSProvider != nil {
			return false
		}
		f.DNSProvider = &d
		return true
	})
}

// SMTP returns the stored relay and whether one is actually set.
func (s *Store) SMTP() (SMTP, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.SMTP == nil {
		return SMTP{}, false
	}
	m := *s.data.SMTP
	return m, m.Configured()
}

// SMTPManaged reports whether the portal owns the SMTP relay.
func (s *Store) SMTPManaged() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.SMTP != nil
}

// Normalize trims m and validates it, without storing anything.
func (m SMTP) Normalize() (SMTP, error) {
	m = trimSMTP(m)
	if err := m.validate(); err != nil {
		return SMTP{}, err
	}
	return m, nil
}

// SetSMTP validates and saves m as the owner's choice from the portal.
func (s *Store) SetSMTP(m SMTP) (SMTP, error) {
	m, err := m.Normalize()
	if err != nil {
		return SMTP{}, err
	}
	m.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return m, s.mutate(func(f *file) { f.SMTP = &m })
}

// ClearSMTP removes the relay and remembers that it was removed on purpose.
func (s *Store) ClearSMTP() error {
	return s.mutate(func(f *file) {
		f.SMTP = &SMTP{Meta: Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}}
	})
}

// SeedSMTP imports m from shepherd.toml, but only while the portal has never
// owned the relay. It reports whether m was imported. An empty host imports
// nothing.
func (s *Store) SeedSMTP(m SMTP) (bool, error) {
	m = trimSMTP(m)
	if m.Host == "" {
		return false, nil
	}
	if err := m.validate(); err != nil {
		return false, err
	}
	m.Meta = Meta{Source: SourceConfig, UpdatedAt: s.now().UTC()}
	return s.seed(func(f *file) bool {
		if f.SMTP != nil {
			return false
		}
		f.SMTP = &m
		return true
	})
}

// trimSMTP trims surrounding whitespace from every field but the password,
// which is taken exactly as given.
func trimSMTP(m SMTP) SMTP {
	m.Host = strings.TrimSpace(m.Host)
	m.Username = strings.TrimSpace(m.Username)
	m.From = strings.TrimSpace(m.From)
	m.TLS = strings.TrimSpace(m.TLS)
	return m
}

// seed applies fn to a copy and saves it only when fn reports a change.
func (s *Store) seed(fn func(*file) bool) (bool, error) {
	changed := false
	err := s.mutate(func(f *file) { changed = fn(f) }, func() bool { return changed })
	return changed && err == nil, err
}

// mutate applies fn to a copy, saves the copy, and only then makes it live,
// so memory and disk never disagree. Optional want gates the save (used by
// seed so an import that changes nothing writes nothing).
func (s *Store) mutate(fn func(*file), want ...func() bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data
	if next.DNSProvider != nil {
		d := *next.DNSProvider
		next.DNSProvider = &d
	}
	if next.SMTP != nil {
		m := *next.SMTP
		next.SMTP = &m
	}
	fn(&next)
	for _, w := range want {
		if !w() {
			return nil
		}
	}
	if s.path != "" {
		if err := s.save(next); err != nil {
			return err
		}
	}
	s.data = next
	return nil
}

func (s *Store) save(f file) error {
	f.Version = fileVersion
	b, _ := json.MarshalIndent(f, "", "  ") // strings, ints and times only: cannot fail
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := writeSynced(tmp, b); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// writeSynced writes b to a new 0600 file and fsyncs it before closing, so
// the rename that follows can never publish a half-written file.
func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
