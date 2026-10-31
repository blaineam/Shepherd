// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/secrets"
	"shepherd/internal/tlscert"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
)

// Test seams, in the same style as portscanEvery/portscanDial. Production
// leaves every one of these at its default: tlsEvery zero (use
// tlscert.DefaultCheckInterval), and the ACME/Cloudflare seams nil (build
// the real golang.org/x/crypto/acme.Client and the real CloudflareProvider),
// so tests never need a real network call to Let's Encrypt or Cloudflare to
// exercise this wiring.
var (
	tlsEvery            time.Duration
	tlsACMEClient       tlscert.ACMEClient
	tlsDNS01            tlscert.DNS01Provider
	tlsPropagationCheck func(ctx context.Context, fqdn, value string) error
	// txtLookupExchange is a test seam for dnsLookupTXT's underlying DNS
	// exchange, in the same style as internal/dnsengine's bootstrap.query.
	// Production leaves it nil (use realTXTExchange, a real UDP query).
	txtLookupExchange func(ctx context.Context, server string, m *dns.Msg) (*dns.Msg, error)
)

// letsEncryptDirectoryURL is the production ACME directory.
const letsEncryptDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

// startTLS builds the certificate manager for [tls] (docs/TLS.md): it loads
// whatever certificate is already cached in <data_dir>/tls (cheap, local
// disk only, so this step never touches the network), then starts the
// scheduled obtain/renew loop in a goroutine. Obtaining or renewing a
// certificate over the network never blocks Shepherd's startup — the same
// "never block on something outside Shepherd's control" convention
// startARP and startGeoBlock already follow: if Cloudflare or Let's
// Encrypt cannot be reached, this logs a clear warning, the portal keeps
// working over plain HTTP, and the next scheduled attempt tries again.
// Returns (nil, nil) when [tls].enabled is false, so cmd/shepherd's main
// just skips starting the HTTPS listener entirely.
//
// The DNS-01 challenge is published with the DNS provider token the portal
// manages (sec, shared with [reverseproxy]; see cmd/shepherd/secrets.go),
// read fresh at every attempt. With no token set yet this still starts: the
// attempt fails with a clear log line, and saving a token in the portal
// kicks the loop to try again at once.
func startTLS(ctx context.Context, cfg config.Config, sec *secrets.Store) (*tlscert.Manager, error) {
	if !cfg.TLS.Enabled {
		return nil, nil
	}
	mgr, err := startCertManager(ctx, certSpec{
		logPrefix: "tls",
		dir:       filepath.Join(cfg.DataDir, "tls"),
		hostname:  cfg.TLS.Hostname,
		email:     cfg.TLS.Email,
		secrets:   sec,
		bootstrap: cfg.DNS.Bootstrap,
		acme:      tlsACMEClient,
		dns01:     tlsDNS01,
		propagate: tlsPropagationCheck,
		every:     tlsEvery,
	})
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return mgr, nil
}

// certSpec is everything startCertManager needs for one certificate. The
// acme, dns01, propagate and every fields are the calling feature's own
// test seams, passed through as they are: nil or zero builds the real
// thing, so production never sets them.
type certSpec struct {
	logPrefix string
	dir       string
	hostname  string
	// extraHostnames are additional names on the same certificate as
	// hostname — see tlscert.Obtainer.ExtraHostnames. Empty for [tls],
	// which only ever has the one name; startReverseProxy sets it to the
	// bare base domain, since a wildcard never covers that on its own.
	extraHostnames []string
	email          string
	// secrets holds the shared DNS provider token the real DNS-01
	// provider reads at every attempt (unused when dns01 is a test fake).
	secrets   *secrets.Store
	bootstrap []string
	acme      tlscert.ACMEClient
	dns01     tlscert.DNS01Provider
	propagate func(ctx context.Context, fqdn, value string) error
	every     time.Duration
}

// startCertManager is the shared half of startTLS and startReverseProxy:
// publish challenges through the portal-managed DNS provider token and use
// the real ACME client unless a test supplied fakes, load any cached
// certificate from spec.dir (local disk only), and start the renewal loop
// in the background so an unreachable Cloudflare or Let's Encrypt, or a
// token nobody has entered yet, never delays startup.
func startCertManager(ctx context.Context, spec certSpec) (*tlscert.Manager, error) {
	dns01 := spec.dns01
	if dns01 == nil {
		if spec.secrets == nil {
			return nil, errors.New("no secrets store to read the DNS provider token from")
		}
		dns01 = portalDNS01{store: spec.secrets}
		if _, ok := spec.secrets.DNSProvider(); !ok {
			log.Printf("%s: no DNS provider token is set yet; add one in the portal's Proxy tab and the certificate for %s is requested right away", spec.logPrefix, spec.hostname)
		}
	}

	acmeClient := spec.acme
	if acmeClient == nil {
		accountKey, err := tlscert.LoadOrCreateAccountKey(filepath.Join(spec.dir, "account.key"))
		if err != nil {
			return nil, err
		}
		acmeClient = &acme.Client{Key: accountKey, DirectoryURL: letsEncryptDirectoryURL}
	}

	propagationCheck := spec.propagate
	if propagationCheck == nil {
		propagationCheck = tlscert.WaitForDNSPropagation(dnsLookupTXT(spec.bootstrap), 2*time.Minute, 5*time.Second)
	}

	obtainer := &tlscert.Obtainer{
		ACME:             acmeClient,
		DNS01:            dns01,
		Hostname:         spec.hostname,
		ExtraHostnames:   spec.extraHostnames,
		Contact:          spec.email,
		PropagationCheck: propagationCheck,
		OnCleanupError:   func(err error) { log.Printf("%s: %v", spec.logPrefix, err) },
	}
	mgr, err := tlscert.New(tlscert.Options{
		Hostname: spec.hostname,
		Dir:      spec.dir,
		Obtainer: obtainer,
		OnError:  func(err error) { log.Printf("%s: %v", spec.logPrefix, err) },
		OnObtained: func(notAfter time.Time) {
			log.Printf("%s: certificate for %s is valid until %s", spec.logPrefix, spec.hostname, notAfter.Format(time.RFC3339))
		},
	})
	if err != nil {
		return nil, err
	}
	if err := mgr.LoadCached(); err != nil {
		log.Printf("%s: ignoring an unreadable cached certificate in %s: %v", spec.logPrefix, spec.dir, err)
	}

	every := tlscert.DefaultCheckInterval
	if spec.every > 0 {
		every = spec.every
	}
	go mgr.Run(ctx, every)
	return mgr, nil
}

// dnsLookupTXT looks up name's TXT records directly against servers (plain
// IP addresses, e.g. cfg.DNS.Bootstrap) over UDP, never the system resolver.
// This matters specifically here: on a typical Shepherd deployment the
// host's own system resolver is configured to use Shepherd itself (that is
// the point of running it), so net.DefaultResolver.LookupTXT would route
// this exact lookup back through Shepherd's own DNS engine and cache
// instead of checking what the public internet (and so Let's Encrypt) can
// actually see — the same "a resolver that depends on itself for DNS would
// deadlock the network" problem internal/dnsengine's own bootstrap resolver
// exists to avoid for tls:// and https:// upstream hostnames. A live DNS-01
// attempt against a real Cloudflare-hosted zone hit this directly: a public
// resolver had the fresh TXT record within seconds while Shepherd's own DNS
// server never returned it at all, so the propagation check could never
// succeed.
func dnsLookupTXT(servers []string) func(ctx context.Context, name string) ([]string, error) {
	return func(ctx context.Context, name string) ([]string, error) {
		exchange := txtLookupExchange
		if exchange == nil {
			exchange = realTXTExchange
		}
		fqdn := dns.Fqdn(name)
		var lastErr error
		for _, server := range servers {
			addr := server
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr = net.JoinHostPort(addr, "53")
			}
			m := new(dns.Msg)
			m.SetQuestion(fqdn, dns.TypeTXT)
			m.RecursionDesired = true
			resp, err := exchange(ctx, addr, m)
			if err != nil {
				lastErr = err
				continue
			}
			if resp.Rcode != dns.RcodeSuccess {
				lastErr = fmt.Errorf("%s answered %s for %s", server, dns.RcodeToString[resp.Rcode], name)
				continue
			}
			var txts []string
			for _, rr := range resp.Answer {
				if t, ok := rr.(*dns.TXT); ok {
					txts = append(txts, strings.Join(t.Txt, ""))
				}
			}
			return txts, nil
		}
		if lastErr == nil {
			lastErr = errors.New("no bootstrap resolver reachable")
		}
		return nil, fmt.Errorf("dns: looking up TXT records for %s: %w", name, lastErr)
	}
}

func realTXTExchange(ctx context.Context, server string, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	return resp, err
}

// tokenFrom returns direct, or the trimmed contents of file when one is
// named; setting names the file's config key for the error message. It
// only ever runs to import shepherd.toml's read-once seeds (openSecrets);
// certificates themselves read the portal-managed token.
func tokenFrom(direct, file, setting string) (string, error) {
	if file == "" {
		return direct, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", setting, err)
	}
	return strings.TrimSpace(string(b)), nil
}
