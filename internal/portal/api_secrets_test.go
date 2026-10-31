// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"shepherd/internal/secrets"
)

const (
	portalTestToken    = "cf-portal-test-tok"
	portalTestPassword = "relay-app-pw-xyz"
)

// secretsRig records every verification call and change notification, and
// lets a test script verification failures. No network is ever involved:
// the verifiers here stand in for the Cloudflare and SMTP checks
// cmd/shepherd wires in (whose own tests use local fakes).
type secretsRig struct {
	mu        sync.Mutex
	dnsChecks []secrets.DNSProvider
	smtpCheck []secrets.SMTP
	changed   []string
	dnsErr    error
	smtpErr   error
}

// snapshot returns copies of what the rig recorded, under its lock (the
// handlers run on the test server's goroutines).
func (r *secretsRig) snapshot() (dns []secrets.DNSProvider, smtp []secrets.SMTP, changed []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]secrets.DNSProvider(nil), r.dnsChecks...), append([]secrets.SMTP(nil), r.smtpCheck...), append([]string(nil), r.changed...)
}

func (r *secretsRig) set(f func(*secretsRig)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r)
}

func (r *secretsRig) dns() []secrets.DNSProvider { d, _, _ := r.snapshot(); return d }
func (r *secretsRig) smtp() []secrets.SMTP       { _, m, _ := r.snapshot(); return m }
func (r *secretsRig) changes() []string          { _, _, c := r.snapshot(); return c }

func (h *harness) withSecrets() (*secrets.Store, *secretsRig) {
	h.t.Helper()
	store, err := secrets.Open(filepath.Join(h.dir, secrets.FileName))
	if err != nil {
		h.t.Fatal(err)
	}
	rig := &secretsRig{}
	h.srv.Secrets = store
	h.srv.DNSProviderUsers = []string{"tls", "reverseproxy"}
	h.srv.VerifyDNSProvider = func(_ context.Context, d secrets.DNSProvider) error {
		rig.mu.Lock()
		defer rig.mu.Unlock()
		rig.dnsChecks = append(rig.dnsChecks, d)
		return rig.dnsErr
	}
	h.srv.VerifySMTP = func(_ context.Context, m secrets.SMTP) error {
		rig.mu.Lock()
		defer rig.mu.Unlock()
		rig.smtpCheck = append(rig.smtpCheck, m)
		return rig.smtpErr
	}
	h.srv.OnSecretsChanged = func(kind string) {
		rig.mu.Lock()
		defer rig.mu.Unlock()
		rig.changed = append(rig.changed, kind)
	}
	return store, rig
}

// noSecretIn fails when any response body carries a stored secret.
func noSecretIn(t *testing.T, body string, secretsToHide ...string) {
	t.Helper()
	for _, s := range secretsToHide {
		if strings.Contains(body, s) {
			t.Errorf("a secret came back in a response: %s", body)
		}
	}
}

func TestDNSProviderStartsEmptyAndSaysWhoUsesIt(t *testing.T) {
	h := newHarness(t)
	h.withSecrets()
	got := h.ok("GET", "/api/dns-provider", "", 200)
	if got["configured"] != false || got["provider"] != "cloudflare" {
		t.Errorf("empty = %+v", got)
	}
	if used, _ := got["used_by"].([]any); len(used) != 2 {
		t.Errorf("used_by = %+v", got["used_by"])
	}
	if _, has := got["source"]; has {
		t.Error("nothing saved yet: no source")
	}
}

func TestDNSProviderSaveIsCheckedWriteOnlyAndApplied(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()

	code, body := h.call("PUT", "/api/dns-provider", `{"provider":"cloudflare","api_token":"  `+portalTestToken+`  "}`)
	if code != 200 {
		t.Fatalf("PUT = %d %s", code, body)
	}
	noSecretIn(t, body, portalTestToken)
	if !strings.Contains(body, `"configured":true`) || !strings.Contains(body, `"source":"portal"`) || !strings.Contains(body, `"updated_at"`) {
		t.Errorf("PUT answer = %s", body)
	}
	if len(rig.dns()) != 1 || rig.dns()[0].APIToken != portalTestToken {
		t.Errorf("the token must be checked (trimmed) before saving: %+v", len(rig.dns()))
	}
	if strings.Join(rig.changes(), ",") != SecretDNSProvider {
		t.Errorf("changed = %v, want the running process told once", rig.changes())
	}
	if d, ok := store.DNSProvider(); !ok || d.APIToken != portalTestToken {
		t.Error("the token must be stored")
	}
	_, body = h.call("GET", "/api/dns-provider", "")
	noSecretIn(t, body, portalTestToken)
	if b, err := os.ReadFile(filepath.Join(h.dir, secrets.FileName)); err != nil || !strings.Contains(string(b), portalTestToken) {
		t.Errorf("the token must persist to secrets.json: %v", err)
	}

	// The provider defaults to cloudflare.
	h.ok("PUT", "/api/dns-provider", `{"api_token":"second-token"}`, 200)
	if d, _ := store.DNSProvider(); d.APIToken != "second-token" || d.Provider != secrets.ProviderCloudflare {
		t.Errorf("after a second save: provider %q", d.Provider)
	}
}

func TestDNSProviderRefusesWhatDoesNotWork(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	h.ok("PUT", "/api/dns-provider", `{"api_token":"`+portalTestToken+`"}`, 200)
	rig.set(func(r *secretsRig) { r.changed = nil })

	rig.set(func(r *secretsRig) {
		r.dnsErr = errors.New("Cloudflare did not accept that token: 9109: invalid token")
	})
	code, body := h.call("PUT", "/api/dns-provider", `{"api_token":"a-bad-token"}`)
	if code != 422 || !strings.Contains(body, "invalid token") || !strings.Contains(body, "Nothing was saved") {
		t.Errorf("a token that fails the check = %d %s, want 422 with the reason", code, body)
	}
	if d, _ := store.DNSProvider(); d.APIToken != portalTestToken {
		t.Error("a refused token must leave the working one in place")
	}
	if len(rig.changes()) != 0 {
		t.Error("nothing changed, so nothing may be applied")
	}

	rig.set(func(r *secretsRig) { r.dnsErr = nil })
	checks := len(rig.dns())
	h.expect("PUT", "/api/dns-provider", `{"api_token":""}`, 400)
	h.expect("PUT", "/api/dns-provider", `{"provider":"route53","api_token":"x"}`, 400)
	h.expect("PUT", "/api/dns-provider", `{"api_token":"has space"}`, 400)
	h.expect("PUT", "/api/dns-provider", `{"api_token":"x","extra":1}`, 400)
	if len(rig.dns()) != checks {
		t.Error("input that could never be saved must not cost a network check")
	}
}

func TestDNSProviderClear(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	h.ok("PUT", "/api/dns-provider", `{"api_token":"`+portalTestToken+`"}`, 200)
	got := h.ok("DELETE", "/api/dns-provider", "", 200)
	if got["configured"] != false || got["source"] != "portal" {
		t.Errorf("after clearing = %+v", got)
	}
	if _, ok := store.DNSProvider(); ok || !store.DNSProviderManaged() {
		t.Error("clearing removes the token and keeps shepherd.toml from re-importing it")
	}
	if strings.Join(rig.changes(), ",") != "dns_provider,dns_provider" {
		t.Errorf("changed = %v", rig.changes())
	}
}

func TestDNSProviderSaveFailureIs500(t *testing.T) {
	h := newHarness(t)
	h.withSecrets()
	path := filepath.Join(h.dir, secrets.FileName)
	os.MkdirAll(filepath.Join(path+".tmp", "x"), 0o700) // every write fails
	h.expect("PUT", "/api/dns-provider", `{"api_token":"`+portalTestToken+`"}`, 500)
	h.expect("DELETE", "/api/dns-provider", "", 500)
	h.expect("PUT", "/api/accountability/smtp", `{"host":"smtp.example.com","port":587,"from":"a@example.com","tls":"starttls"}`, 500)
	h.expect("DELETE", "/api/accountability/smtp", "", 500)
}

func TestSecretsWorkWithoutAnyWiring(t *testing.T) {
	// A portal built with no Secrets store (or verifiers) still answers,
	// in memory, and needs no network to do it.
	h := newHarness(t)
	h.ok("PUT", "/api/dns-provider", `{"api_token":"`+portalTestToken+`"}`, 200)
	if got := h.ok("GET", "/api/dns-provider", "", 200); got["configured"] != true {
		t.Errorf("memory store = %+v", got)
	}
	h.ok("PUT", "/api/accountability/smtp", `{"host":"smtp.example.com","port":25,"from":"a@example.com","tls":"none"}`, 200)
}

func TestSMTPRelayStartsBlankWithDefaults(t *testing.T) {
	h := newHarness(t)
	h.withSecrets()
	got := h.ok("GET", "/api/accountability/smtp", "", 200)
	if got["configured"] != false || got["active"] != false || got["enabled"] != false || got["port"] != float64(587) || got["tls"] != "starttls" || got["password_set"] != false {
		t.Errorf("blank relay = %+v", got)
	}
	h.withAccountability()
	if got := h.ok("GET", "/api/accountability/smtp", "", 200); got["enabled"] != true || got["active"] != false {
		t.Errorf("enabled, no relay yet = %+v", got)
	}
}

const relayBody = `{"host":"smtp.example.com","port":587,"username":"shepherd@example.com","password":"` + portalTestPassword + `","from":"shepherd@example.com","tls":"starttls"}`

func TestSMTPRelaySaveIsCheckedWriteOnlyAndApplied(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	h.withAccountability()

	code, body := h.call("PUT", "/api/accountability/smtp", relayBody)
	if code != 200 {
		t.Fatalf("PUT = %d %s", code, body)
	}
	noSecretIn(t, body, portalTestPassword)
	for _, want := range []string{`"configured":true`, `"active":true`, `"password_set":true`, `"host":"smtp.example.com"`, `"source":"portal"`} {
		if !strings.Contains(body, want) {
			t.Errorf("PUT answer %s lacks %s", body, want)
		}
	}
	if len(rig.smtp()) != 1 || rig.smtp()[0].Password != portalTestPassword {
		t.Error("the relay must be checked, with its password, before saving")
	}
	if strings.Join(rig.changes(), ",") != SecretSMTP {
		t.Errorf("changed = %v", rig.changes())
	}
	_, body = h.call("GET", "/api/accountability/smtp", "")
	noSecretIn(t, body, portalTestPassword)
	if m, ok := store.SMTP(); !ok || m.Password != portalTestPassword {
		t.Error("the relay must be stored")
	}

	// Saving again with the password left blank keeps it, for the same
	// host and username: the form never has to show it.
	h.ok("PUT", "/api/accountability/smtp", `{"host":"smtp.example.com","port":465,"username":"shepherd@example.com","from":"shepherd@example.com","tls":"tls"}`, 200)
	if m, _ := store.SMTP(); m.Password != portalTestPassword || m.Port != 465 || m.TLS != "tls" {
		t.Errorf("a blank password must keep the saved one: port %d tls %s", m.Port, m.TLS)
	}
	if last := rig.smtp()[len(rig.smtp())-1]; last.Password != portalTestPassword {
		t.Error("the check must use the kept password")
	}
}

func TestSMTPRelayNeverSendsASavedPasswordToANewServer(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	h.ok("PUT", "/api/accountability/smtp", relayBody, 200)
	checks := len(rig.smtp())
	for _, body := range []string{
		`{"host":"mail.example.net","port":587,"username":"shepherd@example.com","from":"shepherd@example.com"}`,
		`{"host":"smtp.example.com","port":587,"username":"someone-else@example.com","from":"shepherd@example.com"}`,
	} {
		code, out := h.call("PUT", "/api/accountability/smtp", body)
		if code != 400 || !strings.Contains(out, "password again") {
			t.Errorf("%s = %d %s, want 400 asking for the password", body, code, out)
		}
	}
	if len(rig.smtp()) != checks {
		t.Error("the saved password must never reach a check against a different server")
	}
	// Explicitly clearing the password is allowed (an unauthenticated relay).
	h.ok("PUT", "/api/accountability/smtp", `{"host":"relay.example.net","port":25,"from":"shepherd@example.com","tls":"none","clear_password":true}`, 200)
	if m, _ := store.SMTP(); m.Password != "" || m.Username != "" {
		t.Error("clear_password must drop the password")
	}
}

func TestSMTPRelayRefusesWhatDoesNotWork(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	h.ok("PUT", "/api/accountability/smtp", relayBody, 200)
	rig.set(func(r *secretsRig) { r.changed = nil })

	rig.set(func(r *secretsRig) { r.smtpErr = errors.New("the relay refused that username or password") })
	code, body := h.call("PUT", "/api/accountability/smtp", strings.Replace(relayBody, portalTestPassword, "wrong", 1))
	if code != 422 || !strings.HasPrefix(body, "The relay refused") || !strings.Contains(body, "Nothing was saved") {
		t.Errorf("a failed check = %d %s", code, body)
	}
	if m, _ := store.SMTP(); m.Password != portalTestPassword {
		t.Error("a refused relay must leave the working one in place")
	}
	if len(rig.changes()) != 0 {
		t.Error("nothing changed, so nothing may be applied")
	}

	rig.set(func(r *secretsRig) { r.smtpErr = nil })
	checks := len(rig.smtp())
	for _, b := range []string{
		`{"host":"","port":587,"from":"a@example.com"}`,
		`{"host":"smtp.example.com","port":0,"from":"a@example.com"}`,
		`{"host":"smtp.example.com","port":587,"from":""}`,
		`{"host":"smtp.example.com","port":587,"from":"a@example.com","tls":"ssl"}`,
		`{"host":"smtp.example.com","port":587,"from":"a@example.com\r\nBcc: b@example.com"}`,
		`{"host":"smtp.example.com","port":587,"from":"a@example.com","bogus":true}`,
	} {
		h.expect("PUT", "/api/accountability/smtp", b, 400)
	}
	if len(rig.smtp()) != checks {
		t.Error("input that could never be saved must not cost a network check")
	}
}

func TestSMTPRelayClear(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	h.withAccountability()
	h.ok("PUT", "/api/accountability/smtp", relayBody, 200)
	got := h.ok("DELETE", "/api/accountability/smtp", "", 200)
	if got["configured"] != false || got["active"] != false || got["source"] != "portal" {
		t.Errorf("after clearing = %+v", got)
	}
	if _, ok := store.SMTP(); ok || !store.SMTPManaged() {
		t.Error("clearing removes the relay and keeps shepherd.toml from re-importing it")
	}
	if strings.Join(rig.changes(), ",") != "smtp,smtp" {
		t.Errorf("changed = %v", rig.changes())
	}
}

func TestAccountabilityRoutesStillAnswerTheRelayWhenTheFeatureIsOff(t *testing.T) {
	// Contacts 404 only when accountability is turned off; the relay
	// screen always answers, so the tab can say what is going on.
	h := newHarness(t)
	h.withSecrets()
	code, body := h.call("GET", "/api/accountability/contacts", "")
	if code != 404 || !strings.Contains(body, "enabled = false") {
		t.Errorf("contacts with the feature off = %d %s", code, body)
	}
	h.ok("GET", "/api/accountability/smtp", "", 200)
}
