// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testToken    = "cf-test-token-0123"
	testPassword = "app password with spaces"
)

func testSMTP() SMTP {
	return SMTP{Host: "smtp.example.com", Port: 587, Username: "shepherd@example.com", Password: testPassword, From: "shepherd@example.com", TLS: "starttls"}
}

func openAt(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNothingIsWrittenUntilTheFirstEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s := openAt(t, path)
	if _, ok := s.DNSProvider(); ok {
		t.Error("a new store has no DNS provider")
	}
	if _, ok := s.SMTP(); ok {
		t.Error("a new store has no SMTP relay")
	}
	if s.DNSProviderManaged() || s.SMTPManaged() {
		t.Error("a new store manages nothing yet")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("opening must not create the file: %v", err)
	}
	// A seed with nothing to import writes nothing either.
	if ok, err := s.SeedDNSProvider(DNSProvider{Provider: ProviderCloudflare}); ok || err != nil {
		t.Errorf("empty seed = %v, %v", ok, err)
	}
	if ok, err := s.SeedSMTP(SMTP{}); ok || err != nil {
		t.Errorf("empty seed = %v, %v", ok, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("an empty seed must not create the file: %v", err)
	}
}

func TestRoundTripPermissionsAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", FileName) // the directory is created on save
	s := openAt(t, path)
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }
	d, err := s.SetDNSProvider(DNSProvider{Provider: ProviderCloudflare, APIToken: "  " + testToken + "\n"})
	if err != nil {
		t.Fatal(err)
	}
	if d.APIToken != testToken || d.Source != SourcePortal || !d.UpdatedAt.Equal(at) {
		t.Errorf("saved = %+v", d.Meta)
	}
	if _, err := s.SetSMTP(testSMTP()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("secrets file mode %v, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temp file must not be left behind")
	}

	r := openAt(t, path)
	got, ok := r.DNSProvider()
	if !ok || got.APIToken != testToken || got.Provider != ProviderCloudflare || got.Source != SourcePortal {
		t.Errorf("reloaded dns provider: ok=%v source=%q", ok, got.Source)
	}
	m, ok := r.SMTP()
	if !ok || m.Password != testPassword || m.Host != "smtp.example.com" || m.Port != 587 || m.TLS != "starttls" {
		t.Errorf("reloaded smtp: ok=%v %v", ok, m)
	}
}

func TestStringNeverRevealsASecret(t *testing.T) {
	d := DNSProvider{Provider: ProviderCloudflare, APIToken: testToken, Meta: Meta{Source: SourcePortal}}
	m := testSMTP()
	for _, s := range []string{
		fmt.Sprint(d), fmt.Sprintf("%v %+v %#v %s", d, d, d, d),
		fmt.Sprint(m), fmt.Sprintf("%v %+v %#v %s", m, m, m, m),
		fmt.Sprint(DNSProvider{}), fmt.Sprint(SMTP{}), fmt.Sprint(SMTP{Host: "h", Port: 1}),
	} {
		if strings.Contains(s, testToken) || strings.Contains(s, testPassword) {
			t.Errorf("formatted value leaks a secret: %s", s)
		}
	}
	if !strings.Contains(fmt.Sprint(m), "password set") || !strings.Contains(fmt.Sprint(d), "token set") {
		t.Errorf("the redacted form still says whether a secret is set: %s / %s", m, d)
	}
}

func TestValidation(t *testing.T) {
	s := openAt(t, "")
	for name, d := range map[string]DNSProvider{
		"unknown provider": {Provider: "route53", APIToken: testToken},
		"no provider":      {APIToken: testToken},
		"empty token":      {Provider: ProviderCloudflare, APIToken: "   "},
		"space in token":   {Provider: ProviderCloudflare, APIToken: "a b"},
		"newline in token": {Provider: ProviderCloudflare, APIToken: "a\nb"},
		"huge token":       {Provider: ProviderCloudflare, APIToken: strings.Repeat("x", maxLen+1)},
	} {
		if _, err := s.SetDNSProvider(d); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	mod := func(f func(*SMTP)) SMTP { m := testSMTP(); f(&m); return m }
	for name, m := range map[string]SMTP{
		"no host":          mod(func(m *SMTP) { m.Host = "" }),
		"host with port":   mod(func(m *SMTP) { m.Host = "smtp.example.com:587" }),
		"host with scheme": mod(func(m *SMTP) { m.Host = "smtp://smtp.example.com" }),
		"port zero":        mod(func(m *SMTP) { m.Port = 0 }),
		"port too big":     mod(func(m *SMTP) { m.Port = 70000 }),
		"no from":          mod(func(m *SMTP) { m.From = "" }),
		"from not email":   mod(func(m *SMTP) { m.From = "shepherd" }),
		"bad tls":          mod(func(m *SMTP) { m.TLS = "ssl" }),
		"crlf in from":     mod(func(m *SMTP) { m.From = "a@example.com\r\nBcc: x@example.com" }),
		"crlf in password": mod(func(m *SMTP) { m.Password = "pw\r\nQUIT" }),
		"space in user":    mod(func(m *SMTP) { m.Username = "a b" }),
	} {
		if _, err := s.SetSMTP(m); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, ok := s.SMTP(); ok {
		t.Error("nothing invalid may be stored")
	}
	if _, err := s.SetSMTP(mod(func(m *SMTP) { m.Username, m.Password, m.TLS = "", "", "none" })); err != nil {
		t.Errorf("a relay without authentication is valid: %v", err)
	}
}

func TestClearIsRememberedAndBlocksReseeding(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s := openAt(t, path)
	if _, err := s.SetDNSProvider(DNSProvider{Provider: ProviderCloudflare, APIToken: testToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSMTP(testSMTP()); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearDNSProvider(); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearSMTP(); err != nil {
		t.Fatal(err)
	}
	r := openAt(t, path)
	if _, ok := r.DNSProvider(); ok {
		t.Error("a cleared token must stay cleared after a restart")
	}
	if _, ok := r.SMTP(); ok {
		t.Error("a cleared relay must stay cleared after a restart")
	}
	if !r.DNSProviderManaged() || !r.SMTPManaged() {
		t.Error("a cleared secret is still the portal's: shepherd.toml must not bring it back")
	}
	if ok, err := r.SeedDNSProvider(DNSProvider{Provider: ProviderCloudflare, APIToken: "from-toml"}); ok || err != nil {
		t.Errorf("seeding over a cleared token = %v, %v; want nothing imported", ok, err)
	}
	if ok, err := r.SeedSMTP(testSMTP()); ok || err != nil {
		t.Errorf("seeding over a cleared relay = %v, %v; want nothing imported", ok, err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), testToken) || strings.Contains(string(b), testPassword) {
		t.Error("clearing must remove the secret from disk, not just hide it")
	}
}

func TestSeedImportsOnceThenThePortalOwnsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s := openAt(t, path)
	ok, err := s.SeedDNSProvider(DNSProvider{Provider: ProviderCloudflare, APIToken: "from-toml\n"})
	if !ok || err != nil {
		t.Fatalf("first seed = %v, %v", ok, err)
	}
	ok, err = s.SeedSMTP(testSMTP())
	if !ok || err != nil {
		t.Fatalf("first smtp seed = %v, %v", ok, err)
	}
	d, _ := s.DNSProvider()
	if d.APIToken != "from-toml" || d.Source != SourceConfig {
		t.Errorf("seeded = source %q", d.Source)
	}

	// The next startup offers a different value from shepherd.toml: ignored.
	r := openAt(t, path)
	if ok, err := r.SeedDNSProvider(DNSProvider{Provider: ProviderCloudflare, APIToken: "edited-toml"}); ok || err != nil {
		t.Errorf("second seed = %v, %v; want nothing imported", ok, err)
	}
	if d, _ := r.DNSProvider(); d.APIToken != "from-toml" {
		t.Error("a later shepherd.toml value must never replace an imported one")
	}
	// The portal can still change it, and that is the value from then on.
	if _, err := r.SetDNSProvider(DNSProvider{Provider: ProviderCloudflare, APIToken: "from-portal"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := openAt(t, path).DNSProvider(); d.APIToken != "from-portal" || d.Source != SourcePortal {
		t.Errorf("after a portal edit: source %q", d.Source)
	}
	// An invalid seed is refused rather than stored.
	if _, err := openAt(t, "").SeedDNSProvider(DNSProvider{Provider: "nope", APIToken: "x"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid seed: %v", err)
	}
	if _, err := openAt(t, "").SeedSMTP(SMTP{Host: "smtp.example.com"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid smtp seed: %v", err)
	}
}

func TestOpenRefusesWhatItCannotTrust(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"corrupt":       "{nope",
		"version":       `{"version":2}`,
		"bad provider":  `{"version":1,"dns_provider":{"provider":"x","api_token":"t"}}`,
		"bad smtp":      `{"version":1,"smtp":{"host":"smtp.example.com","port":0,"from":"a@example.com","tls":"starttls"}}`,
		"injected from": `{"version":1,"smtp":{"host":"smtp.example.com","port":25,"from":"a@example.com\r\nX: y","tls":"none"}}`,
	}
	for name, body := range cases {
		p := filepath.Join(dir, name+".json")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := Open(p); err == nil {
			t.Errorf("%s: Open accepted %s", name, body)
		}
	}
	if _, err := Open(dir); err == nil { // a directory where the file belongs
		t.Error("an unreadable path must be an error")
	}
	// A cleared record (empty value) is valid on disk.
	p := filepath.Join(dir, "cleared.json")
	os.WriteFile(p, []byte(`{"version":1,"dns_provider":{"provider":"","api_token":"","source":"portal"},"smtp":{"host":"","port":0,"from":"","tls":""}}`), 0o600)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s.DNSProviderManaged() || !s.SMTPManaged() {
		t.Error("cleared records load as managed")
	}
}

func TestAFailedSaveChangesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	s := openAt(t, path)
	if _, err := s.SetDNSProvider(DNSProvider{Provider: ProviderCloudflare, APIToken: testToken}); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(path+".tmp", 0o700) // a directory where the temp file goes: every write fails
	os.WriteFile(filepath.Join(path+".tmp", "x"), nil, 0o600)
	if _, err := s.SetDNSProvider(DNSProvider{Provider: ProviderCloudflare, APIToken: "other"}); err == nil {
		t.Fatal("a failed write must be an error")
	}
	if err := s.ClearDNSProvider(); err == nil {
		t.Fatal("a failed write must be an error")
	}
	if _, err := s.SetSMTP(testSMTP()); err == nil {
		t.Fatal("a failed write must be an error")
	}
	if ok, err := s.SeedSMTP(testSMTP()); ok || err == nil {
		t.Fatalf("a failed seed write = %v, %v", ok, err)
	}
	if d, ok := s.DNSProvider(); !ok || d.APIToken != testToken {
		t.Error("a failed save must not change the value in memory")
	}
	if s.SMTPManaged() {
		t.Error("a failed save must not change the value in memory")
	}
	if d, _ := openAt(t, path).DNSProvider(); d.APIToken != testToken {
		t.Error("a failed save must leave the file as it was")
	}

	// A parent that is a file, not a directory, fails before the write.
	blocked := openAt(t, "")
	blocked.path = filepath.Join(path, "nested", FileName)
	if _, err := blocked.SetSMTP(testSMTP()); err == nil {
		t.Error("an unwritable directory must be an error")
	}
}

func TestRenameFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	os.MkdirAll(filepath.Join(path, "x"), 0o700) // the target is a non-empty directory: rename fails
	s := openAt(t, filepath.Join(dir, "elsewhere.json"))
	s.path = path
	if _, err := s.SetSMTP(testSMTP()); err == nil {
		t.Error("a failed rename must be an error")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("a failed rename must not leave the temp file behind")
	}
}

func TestMemoryOnlyStore(t *testing.T) {
	s := openAt(t, "")
	if _, err := s.SetSMTP(testSMTP()); err != nil {
		t.Fatal(err)
	}
	if m, ok := s.SMTP(); !ok || m.Source != SourcePortal {
		t.Errorf("memory store: %v", m)
	}
}

func TestNormalizeValidatesWithoutStoring(t *testing.T) {
	d, err := DNSProvider{Provider: " cloudflare ", APIToken: " " + testToken + " "}.Normalize()
	if err != nil || d.APIToken != testToken || d.Provider != ProviderCloudflare {
		t.Errorf("Normalize = %v, %v", d, err)
	}
	if _, err := (DNSProvider{Provider: ProviderCloudflare}).Normalize(); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty token: %v", err)
	}
	m := testSMTP()
	m.Host = "  smtp.example.com "
	if n, err := m.Normalize(); err != nil || n.Host != "smtp.example.com" || n.Password != testPassword {
		t.Errorf("Normalize = %v, %v", n, err)
	}
	if _, err := (SMTP{}).Normalize(); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty relay: %v", err)
	}
}

func TestNtfyIsStoredSwitchedAndForgotten(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), FileName))
	if _, ok := s.Ntfy(); ok || s.NtfyManaged() {
		t.Fatal("a new store holds no ntfy server")
	}
	saved, err := s.SetNtfy(Ntfy{Server: " https://ntfy.example.com/ ", Topic: " shepherd-abc ", Token: " tok-ntfy-1 ", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server != "https://ntfy.example.com" || saved.Topic != "shepherd-abc" || saved.Token != "tok-ntfy-1" {
		t.Errorf("saved = %+v (the fields should be trimmed)", saved)
	}
	if saved.Source != SourcePortal {
		t.Errorf("source = %q", saved.Source)
	}
	// Switching off keeps the credentials, so turning it back on costs no
	// re-typing.
	if ok, err := s.SetNtfyEnabled(false); !ok || err != nil {
		t.Fatalf("SetNtfyEnabled = %v %v", ok, err)
	}
	n, ok := s.Ntfy()
	if !ok || n.Enabled || n.Token != "tok-ntfy-1" {
		t.Errorf("after switching off = %s", n)
	}
	// It survives a reload, which is what "managed by the portal" means.
	again := openAt(t, s.Path())
	if n, ok := again.Ntfy(); !ok || n.Token != "tok-ntfy-1" || !again.NtfyManaged() {
		t.Errorf("after reload = %s", n)
	}
	if err := s.ClearNtfy(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Ntfy(); ok {
		t.Error("cleared, so nothing is configured")
	}
	if !s.NtfyManaged() {
		t.Error("a deliberate clear has to be remembered, or the config would seed it again")
	}
	// There is nothing to switch on once it is gone.
	if ok, err := s.SetNtfyEnabled(true); ok || err != nil {
		t.Errorf("SetNtfyEnabled with nothing stored = %v %v", ok, err)
	}
}

func TestNtfyRefusesWhatThePublisherCouldNotUse(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), FileName))
	for _, bad := range []Ntfy{
		{Topic: "t"},
		{Server: "ntfy.example.com", Topic: "t"},
		{Server: "https://u:p@ntfy.example.com", Topic: "t"}, // leakcheck:allow fixture: credentials-in-URL test value
		{Server: "https://ntfy.example.com", Topic: "no spaces allowed"},
		{Server: "https://ntfy.example.com", Topic: ""},
		{Server: "https://ntfy.example.com", Topic: "t", Token: "x", Username: "u"},
		{Server: "https://ntfy.example.com", Topic: "t", Token: "with space"},
		{Server: "https://ntfy.example.com", Topic: "t", Password: "line\nbreak"},
	} {
		if _, err := s.SetNtfy(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("SetNtfy(%+v) = %v, want ErrInvalid", bad, err)
		}
	}
	if s.NtfyManaged() {
		t.Error("a refused value must not count as the portal owning it")
	}
}

func TestNtfyNeverFormatsItsCredentials(t *testing.T) {
	n := Ntfy{Server: "https://ntfy.example.com", Topic: "t", Token: "tok-ntfy-1", Enabled: true,
		Meta: Meta{Source: SourcePortal}}
	for _, got := range []string{n.String(), n.GoString(), fmt.Sprintf("%v %s %#v", n, n, n)} {
		if strings.Contains(got, "tok-ntfy-1") {
			t.Errorf("the token was formatted: %s", got)
		}
		if !strings.Contains(got, "token set") {
			t.Errorf("it should still say a token is set: %s", got)
		}
	}
	withPassword := Ntfy{Server: "https://ntfy.example.com", Topic: "t", Username: "u", Password: "pw-secret-1"}
	if got := withPassword.String(); strings.Contains(got, "pw-secret-1") || !strings.Contains(got, "username and password set") {
		t.Errorf("String with a password = %s", got)
	}
	if got := (Ntfy{}).String(); got != "ntfy (not set)" {
		t.Errorf("empty String = %s", got)
	}
}

func TestNtfySeedImportsOnceThenThePortalOwnsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s := openAt(t, path)
	seed := Ntfy{Server: "https://ntfy.example.com", Topic: "shepherd-abc", Token: "tok-ntfy-1", Enabled: true}
	if imported, err := s.SeedNtfy(Ntfy{}); imported || err != nil {
		t.Errorf("an empty seed imports nothing: %v %v", imported, err)
	}
	imported, err := s.SeedNtfy(seed)
	if !imported || err != nil {
		t.Fatalf("SeedNtfy = %v %v", imported, err)
	}
	n, _ := s.Ntfy()
	if n.Source != SourceConfig || n.Token != "tok-ntfy-1" {
		t.Errorf("imported = %s", n)
	}
	// A second seed, with something else in it, changes nothing: the
	// portal owns it from the first import on.
	seed.Topic = "shepherd-other"
	if imported, err := s.SeedNtfy(seed); imported || err != nil {
		t.Errorf("a second seed must not import: %v %v", imported, err)
	}
	if n, _ := s.Ntfy(); n.Topic != "shepherd-abc" {
		t.Errorf("the stored topic changed: %s", n)
	}
	if _, err := s.SeedNtfy(Ntfy{Server: "nonsense", Topic: "t"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("an unusable seed = %v, want ErrInvalid", err)
	}
}

func TestAStoredNtfyServerThatIsNotValidRefusesToLoad(t *testing.T) {
	// Carrying on with an empty store would let the next save or seed
	// overwrite a server the owner still has in the file.
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(`{"version":1,"ntfy":{"server":"not a url","topic":"t"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("a stored server that cannot be used should refuse to load")
	}
}
