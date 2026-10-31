// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shepherd/internal/accountability"
	"shepherd/internal/config"
	"shepherd/internal/secrets"
)

// Every token and password here is synthetic.
const (
	legacyToken    = "cf-legacy-token-01"
	portalToken    = "cf-portal-token-02"
	legacyPassword = "legacy-smtp-pw-01"
)

// fakeCF stands in for the Cloudflare API v4 endpoints certificate issuance
// and the token check use. It binds loopback only (httptest) and records
// the bearer token of every request, so a test can prove which token the
// wiring actually used. accepted lists the tokens it treats as valid.
type fakeCF struct {
	srv      *httptest.Server
	mu       sync.Mutex
	accepted map[string]bool
	bearers  []string
	writes   int
}

func newFakeCF(t *testing.T, accepted ...string) *fakeCF {
	t.Helper()
	f := &fakeCF{accepted: map[string]bool{}}
	for _, a := range accepted {
		f.accepted[a] = true
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		f.bearers = append(f.bearers, tok)
		ok := f.accepted[tok]
		if r.Method != http.MethodGet {
			f.writes++
		}
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 9109, "message": "Invalid access token"}}})
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			var result []map[string]string
			if n := r.URL.Query().Get("name"); n == "example.com" || n == "" {
				result = []map[string]string{{"id": "zone-1"}}
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
		default: // record create and delete
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "rec-1"}})
		}
	}))
	t.Cleanup(f.srv.Close)
	old := cloudflareBaseURL
	cloudflareBaseURL = f.srv.URL
	t.Cleanup(func() { cloudflareBaseURL = old })
	return f
}

func (f *fakeCF) sawBearer(tok string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.bearers {
		if b == tok {
			return true
		}
	}
	return false
}

func (f *fakeCF) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// captureLog collects log output for the rest of the test.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return buf
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func writeSecretFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// loadConfigText writes body as shepherd.toml (with data_dir under dir) and
// loads it the way run() does.
func loadConfigText(t *testing.T, dir, body string) config.Config {
	t.Helper()
	path := filepath.Join(dir, "shepherd.toml")
	full := fmt.Sprintf("data_dir = %q\n", filepath.Join(dir, "data")) + body
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func assertNoSecretInLog(t *testing.T, logs string, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(logs, v) {
			t.Errorf("a secret value reached the log:\n%s", logs)
		}
	}
}

// TestUpgradeKeepsSecretsConfiguredInShepherdToml is the upgrade path a
// live deployment takes the first time it runs this version: the
// Cloudflare token in a cloudflare_api_token_file (named by both [tls] and
// [reverseproxy]) and the SMTP password in a password_file must arrive in
// the portal-managed store without anyone re-entering them, and from then
// on the store wins.
func TestUpgradeKeepsSecretsConfiguredInShepherdToml(t *testing.T) {
	logs := captureLog(t)
	dir := t.TempDir()
	tokenFile := writeSecretFile(t, dir, "cloudflare-api-token", legacyToken+"\n")
	passwordFile := writeSecretFile(t, dir, "smtp-password", legacyPassword+"\n")
	toml := fmt.Sprintf(`[tls]
enabled = true
hostname = "shepherd.example.com"
listen = "127.0.0.1:0"
cloudflare_api_token_file = %q
[reverseproxy]
enabled = true
domain = "example.com"
cloudflare_api_token_file = %q
[accountability.smtp]
host = "smtp.example.com"
port = 465
username = "shepherd@example.com"
password_file = %q
from = "shepherd@example.com"
tls = "tls"
`, tokenFile, tokenFile, passwordFile)
	cfg := loadConfigText(t, dir, toml)
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// First run of the new version.
	sec, err := openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := sec.DNSProvider()
	if !ok || d.APIToken != legacyToken || d.Provider != secrets.ProviderCloudflare || d.Source != secrets.SourceConfig {
		t.Fatalf("the token in cloudflare_api_token_file was not imported (ok=%v source=%q)", ok, d.Source)
	}
	m, ok := sec.SMTP()
	if !ok || m.Password != legacyPassword || m.Host != "smtp.example.com" || m.Port != 465 || m.TLS != "tls" || m.Username != "shepherd@example.com" {
		t.Fatalf("the relay and the password in password_file were not imported: %v", m)
	}
	path := filepath.Join(cfg.DataDir, secrets.FileName)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secrets.json must exist with mode 0600: %v %v", err, info)
	}
	if strings.Contains(logs.String(), "different Cloudflare tokens") {
		t.Error("the same file in both sections is not a conflict")
	}
	if !strings.Contains(logs.String(), "imported the DNS provider token") || !strings.Contains(logs.String(), "imported the SMTP relay") {
		t.Errorf("the import must be logged:\n%s", logs)
	}

	// The token file is rotated and the password file changed by hand, the
	// way the old docs said to: the portal owns both now, so neither is
	// read again, and a startup line says so.
	writeSecretFile(t, dir, "cloudflare-api-token", "rotated-in-the-file\n")
	writeSecretFile(t, dir, "smtp-password", "changed-in-the-file\n")
	sec2, err := openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := sec2.DNSProvider(); d.APIToken != legacyToken {
		t.Error("after the import, shepherd.toml must never change the token")
	}
	if m, _ := sec2.SMTP(); m.Password != legacyPassword {
		t.Error("after the import, shepherd.toml must never change the relay")
	}
	for _, want := range []string{"tls.cloudflare_api_token_file is ignored", "reverseproxy.cloudflare_api_token_file is ignored", "[accountability.smtp] is ignored"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs)
		}
	}

	// The owner tidies up shepherd.toml and deletes the old files: the
	// imported values keep working.
	os.Remove(tokenFile)
	os.Remove(passwordFile)
	sec3, err := openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := sec3.DNSProvider(); !ok || d.APIToken != legacyToken {
		t.Error("removing the old token file must not lose the imported token")
	}
	if m, ok := sec3.SMTP(); !ok || m.Password != legacyPassword {
		t.Error("removing the old password file must not lose the imported relay")
	}
	assertNoSecretInLog(t, logs.String(), legacyToken, legacyPassword, "rotated-in-the-file", "changed-in-the-file")
}

// TestUpgradeEndToEndIssuesWithTheImportedToken runs the whole binary
// twice against an existing data directory whose shepherd.toml names a
// cloudflare_api_token_file: the first run imports it and the reverse
// proxy's certificate is issued with it (the fake Cloudflare sees exactly
// that bearer token); the portal reports it as set but never returns it;
// and a second run, with the file now holding something else, still uses
// the imported token.
func TestUpgradeEndToEndIssuesWithTheImportedToken(t *testing.T) {
	cf := newFakeCF(t, legacyToken)
	resetReverseProxySeams(t)
	rproxyEvery = 10 * time.Millisecond
	rproxyACMEClient = newFakeTLSACME("*.example.com")
	rproxyPropagationCheck = func(context.Context, string, string) error { return nil }
	// rproxyDNS01 stays nil: the real Cloudflare provider is built from the
	// portal-managed token, pointed at the fake API.

	tokenDir := t.TempDir()
	tokenFile := writeSecretFile(t, tokenDir, "cloudflare-api-token", legacyToken+"\n")
	extra := fmt.Sprintf("[reverseproxy]\nenabled = true\nlisten=\"127.0.0.1:%d\"\ndomain = \"example.com\"\ncloudflare_api_token_file = %q\n", freePort(t), tokenFile)
	cfgPath := writeConfig(t, freePort(t), freePort(t), extra)
	dataDir := filepath.Join(filepath.Dir(cfgPath), "data")
	// An install that predates this version: it already has a portal token.
	os.MkdirAll(dataDir, 0o750)
	os.WriteFile(filepath.Join(dataDir, "portal-token"), []byte(strings.Repeat("a", 64)+"\n"), 0o600)

	r := start(t, cfgPath)
	waitFor(t, "a certificate issued with the imported token", func() bool {
		code, body := r.api("GET", "/api/reverseproxy", "")
		return code == 200 && strings.Contains(body, `"not_after"`)
	})
	if !cf.sawBearer(legacyToken) {
		t.Fatal("issuance did not use the token imported from cloudflare_api_token_file")
	}
	code, body := r.api("GET", "/api/dns-provider", "")
	if code != 200 || !strings.Contains(body, `"configured":true`) || !strings.Contains(body, `"source":"shepherd.toml"`) || !strings.Contains(body, `"used_by":["reverseproxy"]`) {
		t.Errorf("GET /api/dns-provider = %d %s", code, body)
	}
	if strings.Contains(body, legacyToken) {
		t.Error("the portal must never return the token")
	}
	r.stop()

	// Second run: the file changed, the imported token still rules.
	writeSecretFile(t, tokenDir, "cloudflare-api-token", "not-a-token-cloudflare-knows\n")
	os.RemoveAll(filepath.Join(dataDir, "reverseproxy", "tls")) // force a fresh issuance
	r2 := start(t, cfgPath)
	defer r2.stop()
	waitFor(t, "a second certificate", func() bool {
		_, body := r2.api("GET", "/api/reverseproxy", "")
		return strings.Contains(body, `"not_after"`)
	})
	if cf.sawBearer("not-a-token-cloudflare-knows") {
		t.Error("after the import, the token file must never be used again")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSeedConflictPrefersTLSAndSaysSo(t *testing.T) {
	logs := captureLog(t)
	dir := t.TempDir()
	cfg := loadConfigText(t, dir, "[tls]\ncloudflare_api_token = \"tls-token\"\n[reverseproxy]\ncloudflare_api_token = \"rp-token\"\n")
	sec, err := openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := sec.DNSProvider(); d.APIToken != "tls-token" {
		t.Errorf("imported %q, want [tls]'s", d.APIToken)
	}
	if !strings.Contains(logs.String(), "tls.cloudflare_api_token and reverseproxy.cloudflare_api_token hold different Cloudflare tokens") {
		t.Errorf("the conflict must be logged by setting name:\n%s", logs)
	}
	assertNoSecretInLog(t, logs.String(), "tls-token", "rp-token")
}

func TestSeedFromReverseProxyAloneAndDisabledSections(t *testing.T) {
	// Seeding does not depend on the section being enabled: a token set
	// for later is kept for later.
	dir := t.TempDir()
	cfg := loadConfigText(t, dir, "[reverseproxy]\ncloudflare_api_token = \"rp-only\"\n")
	sec, err := openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := sec.DNSProvider(); d.APIToken != "rp-only" {
		t.Errorf("imported %q", d.APIToken)
	}
}

func TestAnUnreadableSeedIsRetriedNotLost(t *testing.T) {
	logs := captureLog(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "not-yet-there")
	passwordFile := filepath.Join(dir, "also-not-yet")
	cfg := loadConfigText(t, dir, fmt.Sprintf("[tls]\ncloudflare_api_token_file = %q\n[accountability.smtp]\nhost = \"smtp.example.com\"\nfrom = \"a@example.com\"\npassword_file = %q\nusername = \"u\"\n", tokenFile, passwordFile))
	sec, err := openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if sec.DNSProviderManaged() || sec.SMTPManaged() {
		t.Fatal("an unreadable seed must record nothing, so the next start tries again")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, secrets.FileName)); !os.IsNotExist(err) {
		t.Error("nothing to import, nothing written")
	}
	if !strings.Contains(logs.String(), "tried again at the next start") {
		t.Errorf("the retry must be logged:\n%s", logs)
	}
	// The files appear (a volume mounted late, a typo fixed): imported.
	writeSecretFile(t, dir, "not-yet-there", legacyToken)
	writeSecretFile(t, dir, "also-not-yet", legacyPassword)
	sec, err = openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := sec.DNSProvider(); !ok || d.APIToken != legacyToken {
		t.Error("the token must be imported once it can be read")
	}
	if m, ok := sec.SMTP(); !ok || m.Password != legacyPassword {
		t.Error("the relay must be imported once its password can be read")
	}
}

func TestAnInvalidSeedIsLoggedNotImportedAndNeverFatal(t *testing.T) {
	logs := captureLog(t)
	dir := t.TempDir()
	cfg := loadConfigText(t, dir, "[tls]\ncloudflare_api_token = \"two words\"\n")
	// [accountability.smtp] that config.Validate accepts but the store
	// refuses (a From that is not an address).
	cfg.Accountability.SMTP = config.AccountabilitySMTP{Host: "smtp.example.com", Port: 587, From: "shepherd", TLS: "starttls"}
	sec, err := openSecrets(cfg)
	if err != nil {
		t.Fatalf("an unusable seed must not stop startup: %v", err)
	}
	if sec.DNSProviderManaged() || sec.SMTPManaged() {
		t.Error("an invalid seed must not be stored")
	}
	if !strings.Contains(logs.String(), "not importing tls.cloudflare_api_token") || !strings.Contains(logs.String(), "not importing [accountability.smtp]") {
		t.Errorf("the refusal must be logged:\n%s", logs)
	}
	assertNoSecretInLog(t, logs.String(), "two words")
}

func TestAPortalClearIsNotUndoneByShepherdToml(t *testing.T) {
	dir := t.TempDir()
	cfg := loadConfigText(t, dir, "[tls]\ncloudflare_api_token = \"from-toml\"\n[accountability.smtp]\nhost = \"smtp.example.com\"\nfrom = \"a@example.com\"\n")
	sec, err := openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sec.ClearDNSProvider()
	sec.ClearSMTP()
	sec, err = openSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sec.DNSProvider(); ok {
		t.Error("a token cleared in the portal must stay cleared")
	}
	if _, ok := sec.SMTP(); ok {
		t.Error("a relay cleared in the portal must stay cleared")
	}
}

func TestOpenSecretsErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := loadConfigText(t, dir, "")
	os.MkdirAll(cfg.DataDir, 0o750)
	os.WriteFile(filepath.Join(cfg.DataDir, secrets.FileName), []byte("{broken"), 0o600)
	if _, err := openSecrets(cfg); err == nil || !strings.Contains(err.Error(), "secrets") {
		t.Errorf("a corrupt secrets.json must stop startup: %v", err)
	}

	// A seed that cannot be saved is an error, not a silent loss.
	dir2 := t.TempDir()
	cfg2 := loadConfigText(t, dir2, "[tls]\ncloudflare_api_token = \"t\"\n")
	os.MkdirAll(filepath.Join(cfg2.DataDir, secrets.FileName+".tmp", "x"), 0o700)
	if _, err := openSecrets(cfg2); err == nil {
		t.Error("a DNS provider seed that cannot be saved must be an error")
	}
	dir3 := t.TempDir()
	cfg3 := loadConfigText(t, dir3, "[accountability.smtp]\nhost = \"smtp.example.com\"\nfrom = \"a@example.com\"\n")
	os.MkdirAll(filepath.Join(cfg3.DataDir, secrets.FileName+".tmp", "x"), 0o700)
	if _, err := openSecrets(cfg3); err == nil {
		t.Error("a relay seed that cannot be saved must be an error")
	}
}

func TestRunRefusesACorruptSecretsFile(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	dataDir := filepath.Join(filepath.Dir(cfg), "data")
	os.MkdirAll(dataDir, 0o750)
	os.WriteFile(filepath.Join(dataDir, secrets.FileName), []byte("{broken"), 0o600)
	if err := run(context.Background(), cfg, false, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), secrets.FileName) {
		t.Errorf("a corrupt secrets.json must stop startup rather than be overwritten: %v", err)
	}
}

func storeWithToken(t *testing.T, token string) *secrets.Store {
	t.Helper()
	sec, err := secrets.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		if _, err := sec.SetDNSProvider(secrets.DNSProvider{Provider: secrets.ProviderCloudflare, APIToken: token}); err != nil {
			t.Fatal(err)
		}
	}
	return sec
}

func TestStartTLSIssuesWithThePortalToken(t *testing.T) {
	cf := newFakeCF(t, portalToken)
	resetTLSSeams(t)
	tlsEvery = 10 * time.Millisecond
	tlsACMEClient = newFakeTLSACME("shepherd.example.com")
	tlsPropagationCheck = func(context.Context, string, string) error { return nil }
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	// The config file holds a different token: only a seed, ignored here.
	cfg.TLS = config.TLS{Enabled: true, Hostname: "shepherd.example.com", Listen: "127.0.0.1:0", CloudflareAPIToken: legacyToken}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr, err := startTLS(ctx, cfg, storeWithToken(t, portalToken))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a certificate", func() bool { return mgr.Certificate() != nil })
	if !cf.sawBearer(portalToken) || cf.sawBearer(legacyToken) {
		t.Error("[tls] must publish its challenge with the portal-managed token")
	}
}

func TestStartReverseProxyIssuesWithThePortalToken(t *testing.T) {
	cf := newFakeCF(t, portalToken)
	resetReverseProxySeams(t)
	rproxyEvery = 10 * time.Millisecond
	rproxyACMEClient = newFakeTLSACME("*.example.com")
	rproxyPropagationCheck = func(context.Context, string, string) error { return nil }
	cfg := reverseProxyConfig(t) // its CloudflareAPIToken is a seed, ignored here
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rp, err := startReverseProxy(ctx, cfg, openTestStore(t, cfg), storeWithToken(t, portalToken), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rp.Close()
	waitForCert(t, rp)
	if !cf.sawBearer(portalToken) || cf.sawBearer("unused-fake") {
		t.Error("[reverseproxy] must publish its challenge with the same portal-managed token")
	}
}

func TestATokenSavedLaterIsUsedRightAwayWithoutARestart(t *testing.T) {
	logs := captureLog(t)
	cf := newFakeCF(t, portalToken)
	resetTLSSeams(t)
	tlsEvery = time.Hour // only a kick can trigger a second attempt within this test
	tlsACMEClient = newFakeTLSACME("shepherd.example.com")
	tlsPropagationCheck = func(context.Context, string, string) error { return nil }
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.TLS = config.TLS{Enabled: true, Hostname: "shepherd.example.com", Listen: "127.0.0.1:0"}
	sec := storeWithToken(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr, err := startTLS(ctx, cfg, sec)
	if err != nil {
		t.Fatalf("no token yet must not stop startup: %v", err)
	}
	waitFor(t, "the failed first attempt to be logged", func() bool { return strings.Contains(logs.String(), errNoDNSProvider.Error()) })
	if !strings.Contains(logs.String(), "no DNS provider token is set yet") {
		t.Errorf("startup must say a token is needed:\n%s", logs)
	}
	if mgr.Certificate() != nil {
		t.Fatal("no certificate without a token")
	}

	// What the portal does on PUT /api/dns-provider: save, then notify.
	kicker := &certKicker{}
	kicker.add(mgr)
	kicker.add(nil) // a feature that is off adds nothing
	if _, err := sec.SetDNSProvider(secrets.DNSProvider{Provider: secrets.ProviderCloudflare, APIToken: portalToken}); err != nil {
		t.Fatal(err)
	}
	secretsChanged(sec, nil, kicker)("dns_provider")
	waitFor(t, "a certificate right after the token was saved", func() bool { return mgr.Certificate() != nil })
	if !cf.sawBearer(portalToken) {
		t.Error("the token saved in the portal must be the one used")
	}
}

func TestPortalDNS01WithoutAToken(t *testing.T) {
	p := portalDNS01{store: storeWithToken(t, "")}
	if _, err := p.Present(context.Background(), "_acme-challenge.example.com", "v"); !errors.Is(err, errNoDNSProvider) {
		t.Errorf("Present = %v", err)
	}
	if err := p.CleanUp(context.Background(), "_acme-challenge.example.com", "r"); !errors.Is(err, errNoDNSProvider) {
		t.Errorf("CleanUp = %v", err)
	}
	if _, err := newDNSProvider(secrets.DNSProvider{Provider: "other", APIToken: "t"}); err == nil {
		t.Error("an unknown provider must be refused")
	}
	if _, err := startCertManager(context.Background(), certSpec{logPrefix: "x", dir: t.TempDir(), hostname: "h.example.com"}); err == nil {
		t.Error("the real DNS-01 provider needs a secrets store")
	}
}

func TestVerifyDNSProviderChecksTheEnabledNamesWithoutWriting(t *testing.T) {
	cf := newFakeCF(t, portalToken)
	cfg := config.Default()
	cfg.TLS = config.TLS{Enabled: true, Hostname: "shepherd.example.com"}
	cfg.ReverseProxy = config.ReverseProxy{Enabled: true, Domain: "example.com"}
	if got := strings.Join(dnsProviderNames(cfg), ","); got != "shepherd.example.com,*.example.com" {
		t.Errorf("names = %s", got)
	}
	if got := strings.Join(dnsProviderUsers(cfg), ","); got != "tls,reverseproxy" {
		t.Errorf("users = %s", got)
	}
	verify := verifyDNSProvider(cfg)
	if err := verify(context.Background(), secrets.DNSProvider{Provider: secrets.ProviderCloudflare, APIToken: portalToken}); err != nil {
		t.Errorf("a working token: %v", err)
	}
	err := verify(context.Background(), secrets.DNSProvider{Provider: secrets.ProviderCloudflare, APIToken: "bad"})
	if err == nil || !strings.Contains(err.Error(), "Cloudflare did not accept that token") || !strings.Contains(err.Error(), "Invalid access token") {
		t.Errorf("a rejected token: %v", err)
	}
	if err := verify(context.Background(), secrets.DNSProvider{Provider: "other", APIToken: "t"}); err == nil {
		t.Error("an unknown provider must fail the check")
	}
	if cf.writeCount() != 0 {
		t.Error("the check must never create or delete a record")
	}
	// Neither feature on: any zone at all will do.
	if err := verifyDNSProvider(config.Default())(context.Background(), secrets.DNSProvider{Provider: secrets.ProviderCloudflare, APIToken: portalToken}); err != nil {
		t.Errorf("no names: %v", err)
	}
	if len(dnsProviderUsers(config.Default())) != 0 {
		t.Error("nothing enabled, nothing uses it")
	}
}

func TestVerifySMTPExplainsEachOutcome(t *testing.T) {
	old := smtpVerify
	t.Cleanup(func() { smtpVerify = old })
	relay := secrets.SMTP{Host: "smtp.example.com", Port: 587, Username: "u", Password: legacyPassword, From: "a@example.com", TLS: "starttls"}
	var got accountability.SMTPConfig
	for outcome, want := range map[accountability.Outcome]string{
		accountability.OutcomeOK:               "",
		accountability.OutcomeAuthFailed:       "refused that username or password",
		accountability.OutcomeConnectionFailed: "could not connect",
		accountability.OutcomeTransient:        "check failed",
	} {
		smtpVerify = func(_ context.Context, c accountability.SMTPConfig) accountability.Result {
			got = c
			return accountability.Result{Outcome: outcome, Err: errors.New("detail")}
		}
		err := verifySMTP(context.Background(), relay)
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%v: %v, want %q", outcome, err, want)
		}
		if err != nil && strings.Contains(err.Error(), legacyPassword) {
			t.Error("the password must never appear in the error")
		}
	}
	if got.Host != "smtp.example.com" || got.Password != legacyPassword || got.TLS != accountability.TLSStartTLS || got.Timeout == 0 {
		t.Errorf("the check must use the relay as entered, with a timeout: %+v", got.Host)
	}

	// The real check, against a loopback port nothing listens on.
	smtpVerify = nil
	if err := verifySMTP(context.Background(), secrets.SMTP{Host: "127.0.0.1", Port: closedPort(t), From: "a@example.com", TLS: "none"}); err == nil || !strings.Contains(err.Error(), "could not connect") {
		t.Errorf("nothing listening: %v", err)
	}
	if err := verifySMTP(context.Background(), secrets.SMTP{Host: "127.0.0.1", Port: 25, From: "a@example.com", TLS: "bogus"}); err == nil {
		t.Error("an unusable relay must fail before connecting")
	}
}

func closedPort(t *testing.T) int {
	t.Helper()
	return freePort(t) // freePort closes its listener: nothing is there now
}

func TestRunWiresTheChecksAndAppliesSavesLive(t *testing.T) {
	cf := newFakeCF(t, portalToken)
	old := smtpVerify
	t.Cleanup(func() { smtpVerify = old })
	var smtpChecks int
	var mu sync.Mutex
	smtpVerify = func(context.Context, accountability.SMTPConfig) accountability.Result {
		mu.Lock()
		defer mu.Unlock()
		smtpChecks++
		return accountability.Result{Outcome: accountability.OutcomeOK}
	}
	r := start(t, writeConfig(t, freePort(t), freePort(t), ""))
	defer r.stop()

	// Accountability is on by default with no relay: the tab works.
	if code, body := r.api("GET", "/api/accountability/contacts", ""); code != 200 {
		t.Errorf("contacts with no relay yet = %d %s, want 200 (the 404 that looked broken is gone)", code, body)
	}
	code, body := r.api("GET", "/api/accountability/smtp", "")
	if code != 200 || !strings.Contains(body, `"enabled":true`) || !strings.Contains(body, `"active":false`) {
		t.Errorf("relay before setup = %d %s", code, body)
	}

	code, body = r.api("PUT", "/api/dns-provider", `{"api_token":"bad-token"}`)
	if code != 422 || !strings.Contains(body, "Invalid access token") {
		t.Errorf("a bad token through run() = %d %s, want 422 from the real (faked) Cloudflare check", code, body)
	}
	if code, body := r.api("PUT", "/api/dns-provider", `{"api_token":"`+portalToken+`"}`); code != 200 || strings.Contains(body, portalToken) {
		t.Errorf("a good token = %d %s", code, body)
	}
	if !cf.sawBearer(portalToken) {
		t.Error("run() must wire the real Cloudflare check")
	}

	code, body = r.api("PUT", "/api/accountability/smtp", `{"host":"smtp.example.com","port":587,"username":"u@example.com","password":"`+legacyPassword+`","from":"u@example.com","tls":"starttls"}`)
	if code != 200 || !strings.Contains(body, `"active":true`) || strings.Contains(body, legacyPassword) {
		t.Errorf("saving a relay = %d %s, want it active at once", code, body)
	}
	mu.Lock()
	n := smtpChecks
	mu.Unlock()
	if n != 1 {
		t.Errorf("the relay check ran %d times, want 1", n)
	}
}
