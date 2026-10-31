// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// wildcardOrder mirrors what RFC 8555 section 7.1.4 says a CA returns for a
// "*.example.com" order: the authorization's identifier is the bare base
// domain, with Wildcard set, never the "*."-prefixed name itself.
func wildcardOrder(identifier string) (*acme.Order, map[string]*acme.Authorization) {
	order, authz := pendingOrder(identifier, "wild-tok")
	for _, a := range authz {
		a.Wildcard = true
	}
	return order, authz
}

func TestObtainWildcardRoundTripsThroughTheCSR(t *testing.T) {
	const wildcard = "*.example.com"
	order, authz := wildcardOrder("example.com")
	acmeClient := &fakeACME{
		order: order, authz: authz, dns01Value: "the-digest",
		waitOrderResult: &acme.Order{URI: order.URI, FinalizeURL: order.FinalizeURL, Status: acme.StatusReady},
		certDER:         [][]byte{makeCertDER(t, wildcard)},
	}
	dns01 := &fakeDNS01{presentRecordID: "rec1"}
	o := &Obtainer{ACME: acmeClient, DNS01: dns01, Hostname: wildcard}

	cert, err := o.Obtain(context.Background())
	if err != nil {
		t.Fatalf("Obtain: %v", err)
	}

	if want := []acme.AuthzID{{Type: "dns", Value: wildcard}}; !slices.Equal(acmeClient.authorizeIDs, want) {
		t.Errorf("AuthorizeOrder ids = %+v, want %+v", acmeClient.authorizeIDs, want)
	}
	if len(dns01.presentCalls) != 1 || dns01.presentCalls[0].fqdn != "_acme-challenge.example.com" {
		t.Errorf("Present calls = %+v, want one for _acme-challenge.example.com", dns01.presentCalls)
	}
	csr, err := x509.ParseCertificateRequest(acmeClient.csr)
	if err != nil {
		t.Fatalf("parsing the CSR Obtain sent: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature: %v", err)
	}
	if !slices.Equal(csr.DNSNames, []string{wildcard}) || csr.Subject.CommonName != wildcard {
		t.Errorf("CSR names = %v (CN %q), want [%s]", csr.DNSNames, csr.Subject.CommonName, wildcard)
	}
	if err := cert.Leaf.VerifyHostname("jellyfin.example.com"); err != nil {
		t.Errorf("a wildcard leaf must cover a direct subdomain: %v", err)
	}
}

// A CA that (against RFC 8555) echoed the "*."-prefixed name back as the
// identifier must still get its challenge published at the base domain:
// "_acme-challenge.*.example.com" is not a name DNS-01 can ever validate.
func TestObtainWildcardStripsAStrayPrefixFromTheIdentifier(t *testing.T) {
	order, authz := wildcardOrder("*.example.com")
	acmeClient := &fakeACME{
		order: order, authz: authz, dns01Value: "the-digest",
		waitOrderResult: &acme.Order{URI: order.URI, FinalizeURL: order.FinalizeURL, Status: acme.StatusReady},
		certDER:         [][]byte{makeCertDER(t, "*.example.com")},
	}
	dns01 := &fakeDNS01{presentRecordID: "rec1"}
	o := &Obtainer{ACME: acmeClient, DNS01: dns01, Hostname: "*.example.com"}
	if _, err := o.Obtain(context.Background()); err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	if len(dns01.presentCalls) != 1 || dns01.presentCalls[0].fqdn != "_acme-challenge.example.com" {
		t.Errorf("Present calls = %+v, want one for _acme-challenge.example.com", dns01.presentCalls)
	}
}

// TestObtainExtraHostnamesCoverTheBareBaseDomainToo proves the fix for the
// real gap a wildcard-only certificate leaves: "*.example.com" never
// covers "example.com" itself, so a reverse-proxied host pointed directly
// at the bare base domain gets a certificate-name mismatch in every
// browser unless the same order and the same certificate also ask for it.
func TestObtainExtraHostnamesCoverTheBareBaseDomainToo(t *testing.T) {
	const (
		wildcard = "*.example.com"
		base     = "example.com"
	)
	order, authz := multiNameOrder([]string{wildcard, base}, []string{"wild-tok", "base-tok"})
	for _, a := range authz {
		if a.Identifier.Value == base {
			continue // the non-wildcard authorization's identifier is the name itself, not Wildcard
		}
		a.Identifier.Value = base // RFC 8555: the wildcard authz's identifier is the bare base
		a.Wildcard = true
	}
	acmeClient := &fakeACME{
		order: order, authz: authz, dns01Value: "the-digest",
		waitOrderResult: &acme.Order{URI: order.URI, FinalizeURL: order.FinalizeURL, Status: acme.StatusReady},
		certDER:         [][]byte{makeCertDERMulti(t, wildcard, []string{wildcard, base})},
	}
	dns01 := &fakeDNS01{presentRecordID: "rec1"}
	o := &Obtainer{ACME: acmeClient, DNS01: dns01, Hostname: wildcard, ExtraHostnames: []string{base}}

	cert, err := o.Obtain(context.Background())
	if err != nil {
		t.Fatalf("Obtain: %v", err)
	}

	if want := []acme.AuthzID{{Type: "dns", Value: wildcard}, {Type: "dns", Value: base}}; !slices.Equal(acmeClient.authorizeIDs, want) {
		t.Errorf("AuthorizeOrder ids = %+v, want %+v", acmeClient.authorizeIDs, want)
	}
	if len(dns01.presentCalls) != 2 {
		t.Fatalf("Present calls = %+v, want one per name", dns01.presentCalls)
	}
	gotFQDNs := []string{dns01.presentCalls[0].fqdn, dns01.presentCalls[1].fqdn}
	if !slices.Contains(gotFQDNs, "_acme-challenge.example.com") {
		t.Errorf("Present calls = %+v, want a challenge record for the base domain too", dns01.presentCalls)
	}
	csr, err := x509.ParseCertificateRequest(acmeClient.csr)
	if err != nil {
		t.Fatalf("parsing the CSR Obtain sent: %v", err)
	}
	if !slices.Equal(csr.DNSNames, []string{wildcard, base}) || csr.Subject.CommonName != wildcard {
		t.Errorf("CSR names = %v (CN %q), want [%s %s] (CN %s)", csr.DNSNames, csr.Subject.CommonName, wildcard, base, wildcard)
	}
	if err := cert.Leaf.VerifyHostname(base); err != nil {
		t.Errorf("the leaf must cover the bare base domain directly, not just its wildcard: %v", err)
	}
	if err := cert.Leaf.VerifyHostname("jellyfin.example.com"); err != nil {
		t.Errorf("the leaf must still cover a direct subdomain via the wildcard: %v", err)
	}
}

// multiNameOrder builds an order and its authorizations for more than one
// name at once, each with its own authorization URL and challenge token,
// mirroring what a real multi-SAN ACME order looks like.
func multiNameOrder(names, tokens []string) (*acme.Order, map[string]*acme.Authorization) {
	order := &acme.Order{URI: "https://acme.example/order/1", FinalizeURL: "https://acme.example/finalize/1"}
	authz := map[string]*acme.Authorization{}
	for i, name := range names {
		authzURL := fmt.Sprintf("https://acme.example/authz/%d", i+1)
		order.AuthzURLs = append(order.AuthzURLs, authzURL)
		authz[authzURL] = &acme.Authorization{
			URI:        authzURL,
			Status:     acme.StatusPending,
			Identifier: acme.AuthzID{Type: "dns", Value: name},
			Challenges: []*acme.Challenge{{Type: "dns-01", Token: tokens[i], URI: authzURL + "/dns-01"}},
		}
	}
	return order, authz
}

// makeCertDERMulti is makeCertDER with more than one DNS SAN.
func makeCertDERMulti(t *testing.T, cn string, names []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
