// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"context"
	"crypto/x509"
	"slices"
	"testing"

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
