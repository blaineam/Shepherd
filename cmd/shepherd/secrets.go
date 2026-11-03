// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"shepherd/internal/accountability"
	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/ntfy"
	"shepherd/internal/secrets"
	"shepherd/internal/tlscert"
)

// Test seams. Production leaves both at their zero value: the real
// Cloudflare API, and a real SMTP connection for the relay check.
var (
	// cloudflareBaseURL points every CloudflareProvider this package builds
	// (certificate issuance and the portal's token check) somewhere other
	// than tlscert.CloudflareBaseURL. Empty means production.
	cloudflareBaseURL string
	// smtpVerify replaces the portal's real connect-and-authenticate relay
	// check. Nil means (*accountability.SMTPSender).Verify.
	smtpVerify func(ctx context.Context, cfg accountability.SMTPConfig) accountability.Result
	// ntfyPublish replaces the real publish behind the portal's ntfy check
	// and its test button. Nil means a real request to the owner's server.
	ntfyPublish func(ctx context.Context, n secrets.Ntfy) error
)

// errNoDNSProvider is what a certificate attempt reports while no DNS
// provider token is set anywhere.
var errNoDNSProvider = errors.New("no DNS provider token is set: add one in the portal's Proxy tab")

// openSecrets opens <data_dir>/secrets.json, the portal-managed home of the
// DNS provider token and the accountability SMTP relay, and imports
// shepherd.toml's old secret fields into it.
//
// The import follows the [[lists]]/no_default_lists precedent — the config
// file seeds, the portal owns — applied per secret: a value from
// shepherd.toml is imported only while the portal has never owned that
// secret (never imported, saved or cleared it). After that, shepherd.toml's
// copy is ignored and a startup line says so if it differs. A seed that
// cannot be read right now (a token file that is missing or unreadable) is
// not an error: it is logged, nothing is recorded, and the next startup
// tries again, so a transient problem during an upgrade can never lose a
// credential that is still sitting in shepherd.toml.
func openSecrets(cfg config.Config) (*secrets.Store, error) {
	store, err := secrets.Open(filepath.Join(cfg.DataDir, secrets.FileName))
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	if err := seedDNSProvider(store, cfg); err != nil {
		return nil, err
	}
	if err := seedSMTP(store, cfg); err != nil {
		return nil, err
	}
	if err := seedNtfy(store, cfg); err != nil {
		return nil, err
	}
	return store, nil
}

// tokenSeed is one shepherd.toml section's Cloudflare token, read.
type tokenSeed struct {
	section string // "tls" or "reverseproxy"
	setting string // the key it came from, for log lines (never the value)
	token   string
}

func readTokenSeed(section, direct, file string) (tokenSeed, error) {
	setting := section + ".cloudflare_api_token"
	if file != "" {
		setting += "_file"
	}
	tok, err := tokenFrom(direct, file, setting)
	return tokenSeed{section: section, setting: setting, token: tok}, err
}

// seedDNSProvider imports the Cloudflare token from [tls] or [reverseproxy]
// (whichever is set; [tls]'s when both are set and differ, with a warning
// naming the conflict) as the one shared DNS provider credential.
func seedDNSProvider(store *secrets.Store, cfg config.Config) error {
	var seeds []tokenSeed
	unreadable := false
	for _, s := range []struct{ section, direct, file string }{
		{"tls", cfg.TLS.CloudflareAPIToken, cfg.TLS.CloudflareAPITokenFile},
		{"reverseproxy", cfg.ReverseProxy.CloudflareAPIToken, cfg.ReverseProxy.CloudflareAPITokenFile},
	} {
		if s.direct == "" && s.file == "" {
			continue
		}
		seed, err := readTokenSeed(s.section, s.direct, s.file)
		if err != nil {
			log.Printf("secrets: could not read the DNS provider token from shepherd.toml: %v", err)
			unreadable = true
			continue
		}
		if seed.token != "" {
			seeds = append(seeds, seed)
		}
	}

	if store.DNSProviderManaged() {
		cur, _ := store.DNSProvider()
		for _, s := range seeds {
			if s.token != cur.APIToken {
				log.Printf("secrets: shepherd.toml's %s is ignored: the DNS provider token is managed in the portal's Proxy tab (since %s); change it there", s.setting, cur.UpdatedAt.Format(time.DateOnly))
			}
		}
		return nil
	}
	if len(seeds) == 0 {
		if unreadable {
			log.Printf("secrets: nothing imported for the DNS provider token; it will be tried again at the next start")
		}
		return nil
	}
	chosen := seeds[0] // [tls] first
	if len(seeds) == 2 && seeds[0].token != seeds[1].token {
		log.Printf("secrets: %s and %s hold different Cloudflare tokens; importing [tls]'s as the one shared DNS provider token (check the Proxy tab)", seeds[0].setting, seeds[1].setting)
	}
	imported, err := store.SeedDNSProvider(secrets.DNSProvider{Provider: secrets.ProviderCloudflare, APIToken: chosen.token})
	if errors.Is(err, secrets.ErrInvalid) {
		log.Printf("secrets: not importing %s from shepherd.toml: %v", chosen.setting, err)
		return nil
	}
	if err != nil {
		return fmt.Errorf("secrets: saving the DNS provider token imported from shepherd.toml: %w", err)
	}
	if imported {
		log.Printf("secrets: imported the DNS provider token from shepherd.toml's %s; the portal manages it from now on and shepherd.toml's copy is no longer read", chosen.setting)
	}
	return nil
}

// seedSMTP imports [accountability.smtp] as the portal-managed relay.
func seedSMTP(store *secrets.Store, cfg config.Config) error {
	c := cfg.Accountability.SMTP
	if c.Host == "" {
		return nil
	}
	password, err := smtpPassword(c)
	if err != nil {
		if !store.SMTPManaged() {
			log.Printf("secrets: could not import the SMTP relay from shepherd.toml: %v; it will be tried again at the next start", err)
		}
		return nil
	}
	seed := secrets.SMTP{Host: c.Host, Port: c.Port, Username: c.Username, Password: password, From: c.From, TLS: c.TLS}
	if store.SMTPManaged() {
		cur, _ := store.SMTP()
		if cur.Host != seed.Host || cur.Port != seed.Port || cur.Username != seed.Username || cur.Password != seed.Password || cur.From != seed.From || cur.TLS != seed.TLS {
			log.Printf("secrets: shepherd.toml's [accountability.smtp] is ignored: the mail relay is managed in the portal's Accountability tab (since %s); change it there", cur.UpdatedAt.Format(time.DateOnly))
		}
		return nil
	}
	imported, err := store.SeedSMTP(seed)
	if errors.Is(err, secrets.ErrInvalid) {
		log.Printf("secrets: not importing [accountability.smtp] from shepherd.toml: %v", err)
		return nil
	}
	if err != nil {
		return fmt.Errorf("secrets: saving the SMTP relay imported from shepherd.toml: %w", err)
	}
	if imported {
		log.Printf("secrets: imported the SMTP relay from shepherd.toml's [accountability.smtp]; the portal manages it from now on and shepherd.toml's copy is no longer read")
	}
	return nil
}

// seedNtfy imports [alarms.ntfy] as the portal-managed ntfy connection. The
// owner's standing rule is that no feature should require editing
// shepherd.toml, so the portal owns this; the config section stays a
// one-time seed so installs already running it keep working.
func seedNtfy(store *secrets.Store, cfg config.Config) error {
	c := cfg.Alarms.Ntfy
	if c.Server == "" {
		return nil
	}
	seed := secrets.Ntfy{Server: c.Server, Topic: c.Topic, Token: c.Token,
		Username: c.Username, Password: c.Password, Enabled: c.Enabled}
	if store.NtfyManaged() {
		cur, _ := store.Ntfy()
		if cur.Server != seed.Server || cur.Topic != seed.Topic || cur.Token != seed.Token ||
			cur.Username != seed.Username || cur.Password != seed.Password {
			log.Printf("secrets: shepherd.toml's [alarms.ntfy] is ignored: ntfy delivery is managed in the portal's Alarms screen (since %s); change it there", cur.UpdatedAt.Format(time.DateOnly))
		}
		return nil
	}
	imported, err := store.SeedNtfy(seed)
	if errors.Is(err, secrets.ErrInvalid) {
		log.Printf("secrets: not importing [alarms.ntfy] from shepherd.toml: %v", err)
		return nil
	}
	if err != nil {
		return fmt.Errorf("secrets: saving the ntfy connection imported from shepherd.toml: %w", err)
	}
	if imported {
		log.Printf("secrets: imported ntfy delivery from shepherd.toml's [alarms.ntfy]; the portal manages it from now on and shepherd.toml's copy is no longer read")
	}
	return nil
}

// portalDNS01 publishes DNS-01 challenges with whichever DNS provider token
// the portal holds at that moment, read fresh on every call, so a token
// saved or rotated in the portal is used by the very next issuance or
// renewal with no restart. It is the DNS01Provider for both [tls] and
// [reverseproxy]: one credential, shared.
type portalDNS01 struct{ store *secrets.Store }

var _ tlscert.DNS01Provider = portalDNS01{}

func (p portalDNS01) provider() (tlscert.DNS01Provider, error) {
	d, ok := p.store.DNSProvider()
	if !ok {
		return nil, errNoDNSProvider
	}
	return newDNSProvider(d)
}

func (p portalDNS01) Present(ctx context.Context, fqdn, value string) (string, error) {
	dp, err := p.provider()
	if err != nil {
		return "", err
	}
	return dp.Present(ctx, fqdn, value)
}

func (p portalDNS01) CleanUp(ctx context.Context, fqdn, recordID string) error {
	dp, err := p.provider()
	if err != nil {
		return err
	}
	return dp.CleanUp(ctx, fqdn, recordID)
}

// newDNSProvider builds the implementation for d.Provider. Cloudflare is the
// only one today; secrets.Store refuses any other name, so the default case
// is defensive.
func newDNSProvider(d secrets.DNSProvider) (*tlscert.CloudflareProvider, error) {
	if d.Provider != secrets.ProviderCloudflare {
		return nil, fmt.Errorf("unsupported DNS provider %q", d.Provider)
	}
	return &tlscert.CloudflareProvider{APIToken: d.APIToken, BaseURL: cloudflareBaseURL, HTTPClient: &http.Client{Timeout: 30 * time.Second}}, nil
}

// dnsProviderNames are the certificate names the DNS provider token must be
// able to publish challenges for: [tls]'s hostname and [reverseproxy]'s
// wildcard, for whichever of the two is enabled.
func dnsProviderNames(cfg config.Config) []string {
	var names []string
	if cfg.TLS.Enabled && cfg.TLS.Hostname != "" {
		names = append(names, cfg.TLS.Hostname)
	}
	if cfg.ReverseProxy.Enabled && cfg.ReverseProxy.Wildcard() != "" {
		names = append(names, cfg.ReverseProxy.Wildcard())
	}
	return names
}

// dnsProviderUsers names the enabled features that use the DNS provider
// token, for the portal to show.
func dnsProviderUsers(cfg config.Config) []string {
	users := []string{}
	if cfg.TLS.Enabled {
		users = append(users, "tls")
	}
	if cfg.ReverseProxy.Enabled {
		users = append(users, "reverseproxy")
	}
	return users
}

// verifyDNSProvider is the portal's check before saving a token: read-only
// zone lookups (tlscert.CloudflareProvider.Verify) for every name the token
// will be used for, or, when neither feature is enabled yet, a check that it
// authenticates and sees at least one zone.
func verifyDNSProvider(cfg config.Config) func(context.Context, secrets.DNSProvider) error {
	names := dnsProviderNames(cfg)
	return func(ctx context.Context, d secrets.DNSProvider) error {
		p, err := newDNSProvider(d)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := p.Verify(ctx, names...); err != nil {
			return fmt.Errorf("Cloudflare did not accept that token: %w", err)
		}
		return nil
	}
}

// smtpConfig is the accountability package's view of a stored relay.
func smtpConfig(m secrets.SMTP) accountability.SMTPConfig {
	return accountability.SMTPConfig{
		Host: m.Host, Port: m.Port, Username: m.Username, Password: m.Password,
		From: m.From, TLS: accountability.TLSMode(m.TLS),
	}
}

// verifySMTP is the portal's check before saving a relay: connect, negotiate
// TLS, authenticate, quit — never MAIL FROM, so nothing is ever sent.
func verifySMTP(ctx context.Context, m secrets.SMTP) error {
	cfg := smtpConfig(m)
	cfg.Timeout = 20 * time.Second
	var res accountability.Result
	if smtpVerify != nil {
		res = smtpVerify(ctx, cfg)
	} else {
		sender, err := accountability.NewSMTPSender(cfg)
		if err != nil {
			return err
		}
		res = sender.Verify(ctx)
	}
	switch res.Outcome {
	case accountability.OutcomeOK:
		return nil
	case accountability.OutcomeAuthFailed:
		return fmt.Errorf("the relay refused that username or password (%v)", res.Err)
	case accountability.OutcomeConnectionFailed:
		return fmt.Errorf("could not connect to the relay, or it would not use the chosen TLS mode (%v)", res.Err)
	default:
		return fmt.Errorf("the relay check failed (%s: %v)", res.Outcome, res.Err)
	}
}

// verifyNtfy publishes one notification to n. It is both the portal's check
// before an ntfy server is saved and its "send a test notification" action,
// because ntfy offers no way to ask whether a server and token would work
// without publishing something -- and for a notification channel, one
// notification arriving is the clearest confirmation there is. It goes out
// over exactly the path a real alarm takes (internal/ntfy's client, with the
// stored credentials), so a success here means alarms will arrive.
func verifyNtfy(ctx context.Context, n secrets.Ntfy) error {
	if ntfyPublish != nil {
		return ntfyPublish(ctx, n)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, err := ntfyClient(n).Publish(ctx, ntfy.Message{
		Topic: n.Topic,
		Title: "Shepherd is connected",
		Body:  "This is the test notification from Shepherd's Alarms screen. Alarms will arrive here.",
		Tags:  []string{"white_check_mark"},
	})
	if err != nil {
		return fmt.Errorf("ntfy did not accept the notification: %w", err)
	}
	return nil
}

// applySMTP points relay at whatever relay the store holds now (or none).
func applySMTP(relay *accountability.RelaySender, store *secrets.Store) error {
	m, ok := store.SMTP()
	if !ok {
		relay.Set(nil)
		return nil
	}
	sender, err := accountability.NewSMTPSender(smtpConfig(m))
	if err != nil {
		relay.Set(nil)
		return fmt.Errorf("accountability: the stored mail relay is unusable: %w", err)
	}
	relay.Set(sender)
	return nil
}

// certKicker collects the running certificate managers so a DNS provider
// token saved in the portal can make each one check right away (see
// tlscert.Manager.Kick). The portal is built before the managers start, so
// they are added as they come up.
type certKicker struct {
	mu   sync.Mutex
	mgrs []*tlscert.Manager
}

func (k *certKicker) add(m *tlscert.Manager) {
	if m == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.mgrs = append(k.mgrs, m)
}

func (k *certKicker) kick() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, m := range k.mgrs {
		m.Kick()
	}
}

// secretsChanged is the portal's OnSecretsChanged: it applies a saved or
// cleared secret to the running process, so nothing needs a restart.
func secretsChanged(store *secrets.Store, relay *accountability.RelaySender, kicker *certKicker, router *alarms.Router) func(kind string) {
	return func(kind string) {
		switch kind {
		case "dns_provider":
			kicker.kick()
		case "ntfy":
			if router == nil {
				return // the alarm engine is off in shepherd.toml
			}
			router.SetNtfy(ntfyPublisherFor(store))
		case "smtp":
			if relay == nil {
				return // accountability is off in shepherd.toml: stored, not used
			}
			if err := applySMTP(relay, store); err != nil {
				log.Print(err)
			}
		}
	}
}
