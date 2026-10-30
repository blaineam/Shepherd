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
func startTLS(ctx context.Context, cfg config.Config) (*tlscert.Manager, error) {
	if !cfg.TLS.Enabled {
		return nil, nil
	}
	dir := filepath.Join(cfg.DataDir, "tls")

	dns01 := tlsDNS01
	if dns01 == nil {
		token, err := cloudflareAPIToken(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		dns01 = &tlscert.CloudflareProvider{APIToken: token}
	}

	acmeClient := tlsACMEClient
	if acmeClient == nil {
		accountKey, err := tlscert.LoadOrCreateAccountKey(filepath.Join(dir, "account.key"))
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		acmeClient = &acme.Client{Key: accountKey, DirectoryURL: letsEncryptDirectoryURL}
	}

	propagationCheck := tlsPropagationCheck
	if propagationCheck == nil {
		propagationCheck = tlscert.WaitForDNSPropagation(dnsLookupTXT(cfg.DNS.Bootstrap), 2*time.Minute, 5*time.Second)
	}

	obtainer := &tlscert.Obtainer{
		ACME:             acmeClient,
		DNS01:            dns01,
		Hostname:         cfg.TLS.Hostname,
		Contact:          cfg.TLS.Email,
		PropagationCheck: propagationCheck,
		OnCleanupError:   func(err error) { log.Printf("tls: %v", err) },
	}
	mgr, err := tlscert.New(tlscert.Options{
		Hostname: cfg.TLS.Hostname,
		Dir:      dir,
		Obtainer: obtainer,
		OnError:  func(err error) { log.Printf("tls: %v", err) },
		OnObtained: func(notAfter time.Time) {
			log.Printf("tls: certificate for %s is valid until %s", cfg.TLS.Hostname, notAfter.Format(time.RFC3339))
		},
	})
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	if err := mgr.LoadCached(); err != nil {
		log.Printf("tls: ignoring an unreadable cached certificate in %s: %v", dir, err)
	}

	every := tlscert.DefaultCheckInterval
	if tlsEvery > 0 {
		every = tlsEvery
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

// cloudflareAPIToken resolves [tls]'s Cloudflare API token:
// CloudflareAPITokenFile, when set, is read fresh (and trimmed) on every
// startup; config.Validate already rejects setting both it and
// CloudflareAPIToken, so there is never a "which one wins" question. Mirrors
// cmd/shepherd/accountability.go's smtpPassword exactly.
func cloudflareAPIToken(t config.TLS) (string, error) {
	if t.CloudflareAPITokenFile == "" {
		return t.CloudflareAPIToken, nil
	}
	b, err := os.ReadFile(t.CloudflareAPITokenFile)
	if err != nil {
		return "", fmt.Errorf("reading tls.cloudflare_api_token_file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
