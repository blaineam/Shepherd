// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// DNS01Provider creates and removes the TXT record a DNS-01 challenge is
// validated against. Present and CleanUp are always called in sequence, one
// authorization at a time, never concurrently with each other, so an
// implementation needs no locking of its own beyond what its backing API
// already requires. See CloudflareProvider, the only implementation this
// project ships.
type DNS01Provider interface {
	// Present publishes fqdn (e.g. "_acme-challenge.shepherd.example.com",
	// no trailing dot) as a TXT record holding value, and returns an opaque
	// id CleanUp can later use to remove exactly that record.
	Present(ctx context.Context, fqdn, value string) (recordID string, err error)
	// CleanUp removes the record Present created. Obtain treats a CleanUp
	// failure as non-fatal (a leftover challenge TXT record is harmless) but
	// still reports it through OnCleanupError when set.
	CleanUp(ctx context.Context, fqdn, recordID string) error
}

// ACMEClient is the subset of golang.org/x/crypto/acme.Client's RFC 8555
// (ACME v2) methods Obtainer needs to run the DNS-01 issuance flow.
// *acme.Client satisfies it directly — see the compile-time assertion below
// — so production code needs no wrapper at all; tests inject a fake
// implementing this same small interface so the whole acquire/renew
// lifecycle is exercised without any real network call to Let's Encrypt.
type ACMEClient interface {
	Register(ctx context.Context, acct *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error)
	AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	CreateCertFromOrder(ctx context.Context, order *acme.Order, csr []byte, bundle bool) (der [][]byte, certURL string, err error)
	DNS01ChallengeRecord(token string) (string, error)
}

// Compile-time check: the real client this project wires up in production
// (cmd/shepherd/tls.go) satisfies ACMEClient with no adapter needed.
var _ ACMEClient = (*acme.Client)(nil)

// Obtainer runs one full DNS-01 issuance for Hostname: register the ACME
// account (a no-op if the account key is already registered), authorize an
// order, publish and clean up the Cloudflare TXT record for every
// authorization's dns-01 challenge, wait for the CA to validate it, and
// finalize the order into a certificate.
type Obtainer struct {
	ACME  ACMEClient
	DNS01 DNS01Provider
	// Hostname may be a wildcard ("*.example.com"): the order, the CSR and
	// the challenge record all handle the prefix, so one certificate can
	// cover every direct subdomain (docs/REVERSEPROXY.md).
	Hostname string
	// ExtraHostnames, when set, are additional names on the same order and
	// the same certificate as Hostname — e.g. the bare base domain
	// alongside its wildcard, since "*.example.com" never covers
	// "example.com" itself. Each gets its own authorization and its own
	// dns-01 challenge record, satisfied the same way Hostname's is; Go's
	// DNS-01 propagation check and the Cloudflare TXT record are both
	// per-name already, so this needs no special casing beyond asking
	// for every name up front. Hostname is always the certificate's
	// CommonName; order within ExtraHostnames does not matter.
	ExtraHostnames []string
	// Contact is an optional "mailto:" address used only on first account
	// registration (Let's Encrypt uses it for expiry notices). Empty omits it.
	Contact string
	// PropagationCheck, when set, is called after the TXT record is
	// published and before the CA is asked to validate it, to wait until
	// fqdn actually resolves to value — so a real validation attempt is not
	// wasted on DNS that has not propagated yet. Nil skips the wait
	// entirely (the CA's own WaitAuthorization polling retries regardless,
	// just less efficiently); tests always leave this nil so nothing here
	// performs a real DNS lookup. See WaitForDNSPropagation for the
	// production implementation cmd/shepherd/tls.go wires in.
	PropagationCheck func(ctx context.Context, fqdn, value string) error
	// OnCleanupError, when set, is called with any error CleanUp returns.
	// Never fatal to Obtain; cmd/shepherd uses this only to log it.
	OnCleanupError func(error)
}

// Obtain runs the full flow and returns a certificate with Leaf already
// parsed and set, so callers (Manager) never need to re-parse the chain
// just to read NotAfter.
func (o *Obtainer) Obtain(ctx context.Context) (tls.Certificate, error) {
	var contacts []string
	if o.Contact != "" {
		contacts = []string{"mailto:" + o.Contact}
	}
	if _, err := o.ACME.Register(ctx, &acme.Account{Contact: contacts}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return tls.Certificate{}, fmt.Errorf("tlscert: registering ACME account: %w", err)
	}

	names := append([]string{o.Hostname}, o.ExtraHostnames...)
	order, err := o.ACME.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscert: authorizing order for %s: %w", o.Hostname, err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := o.satisfyAuthorization(ctx, authzURL); err != nil {
			return tls.Certificate{}, err
		}
	}

	order, err = o.ACME.WaitOrder(ctx, order.URI)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscert: waiting for the order to become ready: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscert: generating a certificate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: o.Hostname},
		DNSNames: names,
	}, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscert: creating the certificate request: %w", err)
	}

	der, _, err := o.ACME.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscert: finalizing the order: %w", err)
	}
	if len(der) == 0 {
		return tls.Certificate{}, errors.New("tlscert: the ACME server returned no certificate")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlscert: parsing the issued certificate: %w", err)
	}
	return tls.Certificate{Certificate: der, PrivateKey: key, Leaf: leaf}, nil
}

// satisfyAuthorization drives one authorization's dns-01 challenge to
// completion. The TXT record is always cleaned up again, whether validation
// succeeded or failed, so a retried or abandoned issuance never leaves
// challenge records behind.
func (o *Obtainer) satisfyAuthorization(ctx context.Context, authzURL string) error {
	authz, err := o.ACME.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("tlscert: fetching authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil // already satisfied; nothing to publish or wait for
	}

	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("tlscert: no dns-01 challenge offered for %s", authz.Identifier.Value)
	}

	value, err := o.ACME.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return fmt.Errorf("tlscert: computing the dns-01 record value: %w", err)
	}
	// A wildcard order's challenge lives at the base domain. RFC 8555 has
	// the CA strip the "*." itself, but trimming it here too costs nothing
	// and keeps a CA that echoes the full name from publishing a record
	// DNS-01 can never validate.
	fqdn := "_acme-challenge." + strings.TrimPrefix(authz.Identifier.Value, "*.")

	recordID, err := o.DNS01.Present(ctx, fqdn, value)
	if err != nil {
		return fmt.Errorf("tlscert: publishing the dns-01 TXT record: %w", err)
	}
	defer func() {
		if cerr := o.DNS01.CleanUp(ctx, fqdn, recordID); cerr != nil && o.OnCleanupError != nil {
			o.OnCleanupError(fmt.Errorf("tlscert: removing the dns-01 TXT record for %s: %w", fqdn, cerr))
		}
	}()

	if o.PropagationCheck != nil {
		if err := o.PropagationCheck(ctx, fqdn, value); err != nil {
			return fmt.Errorf("tlscert: waiting for the dns-01 record to propagate: %w", err)
		}
	}

	if _, err := o.ACME.Accept(ctx, chal); err != nil {
		return fmt.Errorf("tlscert: accepting the dns-01 challenge: %w", err)
	}
	if _, err := o.ACME.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("tlscert: waiting for the authorization to validate: %w", err)
	}
	return nil
}

// WaitForDNSPropagation returns a PropagationCheck that polls the system
// resolver for fqdn's TXT records until one matches value, so the CA's
// first validation attempt is not wasted on DNS that a secondary (or
// Cloudflare's own eventually-consistent edge) has not caught up to yet.
// cmd/shepherd/tls.go wires this in for production; tests never call it, so
// no test here performs a real DNS lookup.
func WaitForDNSPropagation(lookupTXT func(ctx context.Context, name string) ([]string, error), timeout, interval time.Duration) func(ctx context.Context, fqdn, value string) error {
	return func(ctx context.Context, fqdn, value string) error {
		deadline := time.Now().Add(timeout)
		for {
			if txts, err := lookupTXT(ctx, fqdn); err == nil {
				for _, t := range txts {
					if t == value {
						return nil
					}
				}
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("timed out after %s waiting for %s to carry the expected TXT record", timeout, fqdn)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
	}
}
