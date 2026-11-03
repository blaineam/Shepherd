// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secrets keeps the bring-your-own credentials Shepherd needs and
// cannot generate for itself — today a DNS provider API token (for ACME
// DNS-01 certificates, shared by [tls] and [reverseproxy]), an outgoing
// SMTP relay (for accountability email), the router connections the
// Bandwidth screen reads and the ntfy server alarms are published to — in
// one portal-managed file,
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

	"shepherd/internal/ntfy"
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

// Ntfy is the ntfy server alarm notifications are published to
// (docs/ALARMS.md). It is the same shape as SMTP and for the same reason:
// it is a service only the owner can name, so it belongs in the portal
// rather than in shepherd.toml. Enabled is the owner's switch; the server
// and credentials stay stored while it is off, so turning delivery back on
// costs no re-typing. An empty Server with a non-zero Meta means the owner
// cleared it in the portal.
type Ntfy struct {
	Server string `json:"server"`
	Topic  string `json:"topic"`
	// Token authenticates with a bearer token and wins over Username and
	// Password, which is ntfy.Client's own rule; the store refuses both so
	// nobody has to know that.
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
	Meta
}

// Configured reports whether a server is actually set.
func (n Ntfy) Configured() bool { return n.Server != "" }

// String never includes the token or the password.
func (n Ntfy) String() string {
	if !n.Configured() {
		return "ntfy (not set)"
	}
	auth := "no credentials"
	switch {
	case n.Token != "":
		auth = "token set"
	case n.Username != "":
		auth = "username and password set"
	}
	return fmt.Sprintf("ntfy %s (topic %s, %s, enabled %v, from %s)", n.Server, n.Topic, auth, n.Enabled, n.Source)
}

// GoString redacts the same way for %#v.
func (n Ntfy) GoString() string { return n.String() }

// validate reuses internal/ntfy's own server and topic rules, so the portal,
// shepherd.toml and the publisher all agree on what is acceptable.
func (n Ntfy) validate() error {
	if n.Server == "" {
		return fmt.Errorf("%w: the ntfy server is required", ErrInvalid)
	}
	if _, err := ntfy.BaseURL(n.Server); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	if !ntfy.ValidTopic(n.Topic) {
		return fmt.Errorf("%w: the topic must be 1 to 64 letters, digits, - or _, got %q", ErrInvalid, n.Topic)
	}
	if n.Token != "" && (n.Username != "" || n.Password != "") {
		return fmt.Errorf("%w: use either a token or a username and password, not both", ErrInvalid)
	}
	for name, v := range map[string]string{"ntfy server": n.Server, "topic": n.Topic, "token": n.Token, "username": n.Username} {
		if err := checkField(name, v, true); err != nil {
			return err
		}
	}
	// A password may contain spaces; a control character would be an
	// injection into the Authorization header.
	return checkField("password", n.Password, false)
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

// Eero is the owner's kept-signed-in eero session, used to read per-device
// usage for the Bandwidth screen. Enabled is the owner's switch; the token
// stays stored while it is off, so turning it back on needs no new sign-in.
type Eero struct {
	Token     string `json:"token"`
	NetworkID string `json:"network_id"`
	Enabled   bool   `json:"enabled"`
	Meta
}

// Configured reports whether a session token is actually stored.
func (e Eero) Configured() bool { return e.Token != "" }

// String never includes the token.
func (e Eero) String() string {
	if !e.Configured() {
		return "eero session (not set)"
	}
	return fmt.Sprintf("eero session (token set, network %s, enabled %v, from %s)", e.NetworkID, e.Enabled, e.Source)
}

// GoString redacts the same way for %#v.
func (e Eero) GoString() string { return e.String() }

func (e Eero) validate() error {
	if e.Token == "" {
		return fmt.Errorf("%w: the eero session token must not be empty", ErrInvalid)
	}
	if err := checkField("eero session token", e.Token, true); err != nil {
		return err
	}
	return checkField("eero network id", e.NetworkID, true)
}

// UniFi is a UniFi Network controller Shepherd reads per-device byte
// counters from. Unlike the eero session this is a username and password
// the owner holds; a read-only controller account is enough.
type UniFi struct {
	BaseURL         string `json:"base_url"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	Site            string `json:"site"`
	AllowSelfSigned bool   `json:"allow_self_signed"`
	Enabled         bool   `json:"enabled"`
	Meta
}

// Configured reports whether a controller is actually set.
func (u UniFi) Configured() bool { return u.BaseURL != "" }

// String never includes the password.
func (u UniFi) String() string {
	if !u.Configured() {
		return "unifi controller (not set)"
	}
	return fmt.Sprintf("unifi controller %s (site %s, enabled %v, from %s)", u.BaseURL, u.Site, u.Enabled, u.Source)
}

// GoString redacts the same way for %#v.
func (u UniFi) GoString() string { return u.String() }

func (u UniFi) validate() error {
	if u.BaseURL == "" {
		return fmt.Errorf("%w: the controller address is required", ErrInvalid)
	}
	if !strings.HasPrefix(u.BaseURL, "http://") && !strings.HasPrefix(u.BaseURL, "https://") {
		return fmt.Errorf("%w: the controller address must start with http:// or https://", ErrInvalid)
	}
	if u.Username == "" {
		return fmt.Errorf("%w: the controller username is required", ErrInvalid)
	}
	for name, v := range map[string]string{"controller address": u.BaseURL, "username": u.Username, "site": u.Site} {
		if err := checkField(name, v, true); err != nil {
			return err
		}
	}
	// A password may contain spaces, never a control character.
	return checkField("password", u.Password, false)
}

type file struct {
	Version int `json:"version"`
	// A nil record means "never owned": shepherd.toml may still seed it.
	DNSProvider *DNSProvider `json:"dns_provider,omitempty"`
	SMTP        *SMTP        `json:"smtp,omitempty"`
	Eero        *Eero        `json:"eero,omitempty"`
	UniFi       *UniFi       `json:"unifi,omitempty"`
	Ntfy        *Ntfy        `json:"ntfy,omitempty"`
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
	if e := f.Eero; e != nil && e.Configured() {
		if err := e.validate(); err != nil {
			return nil, fmt.Errorf("%s: eero: %w", path, err)
		}
	}
	if u := f.UniFi; u != nil && u.Configured() {
		if err := u.validate(); err != nil {
			return nil, fmt.Errorf("%s: unifi: %w", path, err)
		}
	}
	if n := f.Ntfy; n != nil && n.Configured() {
		if err := n.validate(); err != nil {
			return nil, fmt.Errorf("%s: ntfy: %w", path, err)
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

// Ntfy returns the stored ntfy server and whether one is actually set.
func (s *Store) Ntfy() (Ntfy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.Ntfy == nil {
		return Ntfy{}, false
	}
	n := *s.data.Ntfy
	return n, n.Configured()
}

// NtfyManaged reports whether the portal owns ntfy delivery. Once it does,
// shepherd.toml's [alarms.ntfy] is no longer read.
func (s *Store) NtfyManaged() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Ntfy != nil
}

// Normalize trims n, validates it and stores the server in internal/ntfy's
// own canonical form (no trailing slash), so the same server typed two ways
// is one stored value.
func (n Ntfy) Normalize() (Ntfy, error) {
	n = trimNtfy(n)
	if err := n.validate(); err != nil {
		return Ntfy{}, err
	}
	base, err := ntfy.BaseURL(n.Server)
	if err != nil {
		return Ntfy{}, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	n.Server = base
	return n, nil
}

// SetNtfy validates and saves n as the owner's choice from the portal.
func (s *Store) SetNtfy(n Ntfy) (Ntfy, error) {
	n, err := n.Normalize()
	if err != nil {
		return Ntfy{}, err
	}
	n.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return n, s.mutate(func(f *file) { f.Ntfy = &n })
}

// SetNtfyEnabled flips the switch without disturbing the server or the
// credentials, so turning delivery off and on again costs no re-typing. It
// reports false when no server is stored: there is nothing to turn on.
func (s *Store) SetNtfyEnabled(on bool) (bool, error) {
	n, ok := s.Ntfy()
	if !ok {
		return false, nil
	}
	n.Enabled = on
	n.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return true, s.mutate(func(f *file) { f.Ntfy = &n })
}

// ClearNtfy forgets the server and remembers that it was removed on purpose,
// so shepherd.toml's copy is not imported again at the next start.
func (s *Store) ClearNtfy() error {
	return s.mutate(func(f *file) {
		f.Ntfy = &Ntfy{Meta: Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}}
	})
}

// SeedNtfy imports n from shepherd.toml's [alarms.ntfy], but only while the
// portal has never owned ntfy delivery. It reports whether n was imported.
// An empty server imports nothing.
func (s *Store) SeedNtfy(n Ntfy) (bool, error) {
	if strings.TrimSpace(n.Server) == "" {
		return false, nil
	}
	n, err := n.Normalize()
	if err != nil {
		return false, err
	}
	n.Meta = Meta{Source: SourceConfig, UpdatedAt: s.now().UTC()}
	return s.seed(func(f *file) bool {
		if f.Ntfy != nil {
			return false
		}
		f.Ntfy = &n
		return true
	})
}

// trimNtfy trims every field but the password, which is taken as given.
func trimNtfy(n Ntfy) Ntfy {
	n.Server = strings.TrimSpace(n.Server)
	n.Topic = strings.TrimSpace(n.Topic)
	n.Token = strings.TrimSpace(n.Token)
	n.Username = strings.TrimSpace(n.Username)
	return n
}

// Path is the file this store saves to, empty for a memory-only store.
func (s *Store) Path() string { return s.path }

// Eero returns the stored eero session and whether a token is actually set.
func (s *Store) Eero() (Eero, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.Eero == nil {
		return Eero{}, false
	}
	e := *s.data.Eero
	return e, e.Configured()
}

// SetEero validates and saves e as the owner's choice from the portal.
func (s *Store) SetEero(e Eero) (Eero, error) {
	e.Token = strings.TrimSpace(e.Token)
	e.NetworkID = strings.TrimSpace(e.NetworkID)
	if err := e.validate(); err != nil {
		return Eero{}, err
	}
	e.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return e, s.mutate(func(f *file) { f.Eero = &e })
}

// SetEeroEnabled flips the switch without touching the stored token. It
// returns false when no session is stored.
func (s *Store) SetEeroEnabled(on bool) (bool, error) {
	e, ok := s.Eero()
	if !ok {
		return false, nil
	}
	e.Enabled = on
	e.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return true, s.mutate(func(f *file) { f.Eero = &e })
}

// SetEeroConnection records the network to read and switches the reader
// on, in one write, without touching the stored token. It is what the
// portal calls once a sign-in has been kept: two separate writes could
// leave a network chosen but the reader off if the second one failed.
// It returns false when no session is stored.
func (s *Store) SetEeroConnection(networkID string, enabled bool) (bool, error) {
	e, ok := s.Eero()
	if !ok {
		return false, nil
	}
	e.NetworkID = strings.TrimSpace(networkID)
	e.Enabled = enabled
	if err := e.validate(); err != nil {
		return false, err
	}
	e.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return true, s.mutate(func(f *file) { f.Eero = &e })
}

// SetEeroNetwork records which of the account's networks to read, without
// touching the stored token. It returns false when no session is stored.
func (s *Store) SetEeroNetwork(networkID string) (bool, error) {
	e, ok := s.Eero()
	if !ok {
		return false, nil
	}
	e.NetworkID = strings.TrimSpace(networkID)
	if err := e.validate(); err != nil {
		return false, err
	}
	e.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return true, s.mutate(func(f *file) { f.Eero = &e })
}

// ClearEero forgets the session entirely.
func (s *Store) ClearEero() error {
	return s.mutate(func(f *file) {
		f.Eero = &Eero{Meta: Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}}
	})
}

// UniFi returns the stored controller and whether one is actually set.
func (s *Store) UniFi() (UniFi, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.UniFi == nil {
		return UniFi{}, false
	}
	u := *s.data.UniFi
	return u, u.Configured()
}

// SetUniFi validates and saves u as the owner's choice from the portal.
func (s *Store) SetUniFi(u UniFi) (UniFi, error) {
	u.BaseURL = strings.TrimRight(strings.TrimSpace(u.BaseURL), "/")
	u.Username = strings.TrimSpace(u.Username)
	u.Site = strings.TrimSpace(u.Site)
	if u.Site == "" {
		u.Site = "default"
	}
	if err := u.validate(); err != nil {
		return UniFi{}, err
	}
	u.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return u, s.mutate(func(f *file) { f.UniFi = &u })
}

// SetUniFiEnabled flips the switch without disturbing the credentials.
// It returns false when no controller is stored.
func (s *Store) SetUniFiEnabled(on bool) (bool, error) {
	u, ok := s.UniFi()
	if !ok {
		return false, nil
	}
	u.Enabled = on
	u.Meta = Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}
	return true, s.mutate(func(f *file) { f.UniFi = &u })
}

// ClearUniFi forgets the controller and its credentials.
func (s *Store) ClearUniFi() error {
	return s.mutate(func(f *file) {
		f.UniFi = &UniFi{Meta: Meta{Source: SourcePortal, UpdatedAt: s.now().UTC()}}
	})
}

// EeroTokenStore adapts the stored session to the eero client's TokenStore,
// so a signed-in client can keep or resume its token across restarts. Saving
// a token keeps the stored network and switch.
type EeroTokenStore struct{ S *Store }

// Load returns the stored token, or "" when none is stored.
func (t EeroTokenStore) Load() (string, error) {
	e, _ := t.S.Eero()
	return e.Token, nil
}

// Save stores tok, keeping the network and switch already chosen.
func (t EeroTokenStore) Save(tok string) error {
	e, _ := t.S.Eero()
	e.Token = tok
	_, err := t.S.SetEero(e)
	return err
}

// Delete forgets the session.
func (t EeroTokenStore) Delete() error { return t.S.ClearEero() }

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
	if next.Eero != nil {
		e := *next.Eero
		next.Eero = &e
	}
	if next.UniFi != nil {
		u := *next.UniFi
		next.UniFi = &u
	}
	if next.Ntfy != nil {
		n := *next.Ntfy
		next.Ntfy = &n
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
