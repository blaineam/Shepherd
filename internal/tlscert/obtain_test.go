// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// fakeACME implements ACMEClient entirely in memory: no test in this file
// ever makes a real network call to an ACME server.
type fakeACME struct {
	registerErr error

	order             *acme.Order
	authorizeOrderErr error

	authz               map[string]*acme.Authorization
	getAuthorizationErr error

	acceptErr   error
	acceptCalls []string // challenge tokens Accept was called with

	waitAuthorizationErr error

	waitOrderResult *acme.Order
	waitOrderErr    error

	certDER       [][]byte
	createCertErr error

	dns01Value string
	dns01Err   error
}

func (f *fakeACME) Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error) {
	if f.registerErr != nil {
		return nil, f.registerErr
	}
	return &acme.Account{}, nil
}

func (f *fakeACME) AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error) {
	if f.authorizeOrderErr != nil {
		return nil, f.authorizeOrderErr
	}
	return f.order, nil
}

func (f *fakeACME) GetAuthorization(_ context.Context, url string) (*acme.Authorization, error) {
	if f.getAuthorizationErr != nil {
		return nil, f.getAuthorizationErr
	}
	return f.authz[url], nil
}

func (f *fakeACME) Accept(_ context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	f.acceptCalls = append(f.acceptCalls, chal.Token)
	if f.acceptErr != nil {
		return nil, f.acceptErr
	}
	return chal, nil
}

func (f *fakeACME) WaitAuthorization(_ context.Context, url string) (*acme.Authorization, error) {
	if f.waitAuthorizationErr != nil {
		return nil, f.waitAuthorizationErr
	}
	return f.authz[url], nil
}

func (f *fakeACME) WaitOrder(context.Context, string) (*acme.Order, error) {
	if f.waitOrderErr != nil {
		return nil, f.waitOrderErr
	}
	return f.waitOrderResult, nil
}

func (f *fakeACME) CreateCertFromOrder(context.Context, *acme.Order, []byte, bool) ([][]byte, string, error) {
	if f.createCertErr != nil {
		return nil, "", f.createCertErr
	}
	return f.certDER, "https://acme.example/cert/1", nil
}

func (f *fakeACME) DNS01ChallengeRecord(string) (string, error) {
	if f.dns01Err != nil {
		return "", f.dns01Err
	}
	return f.dns01Value, nil
}

var _ ACMEClient = (*fakeACME)(nil)

// fakeDNS01 implements DNS01Provider entirely in memory.
type fakeDNS01 struct {
	presentErr      error
	presentRecordID string
	presentCalls    []struct{ fqdn, value string }

	cleanUpErr   error
	cleanUpCalls []struct{ fqdn, recordID string }
}

func (f *fakeDNS01) Present(_ context.Context, fqdn, value string) (string, error) {
	f.presentCalls = append(f.presentCalls, struct{ fqdn, value string }{fqdn, value})
	if f.presentErr != nil {
		return "", f.presentErr
	}
	return f.presentRecordID, nil
}

func (f *fakeDNS01) CleanUp(_ context.Context, fqdn, recordID string) error {
	f.cleanUpCalls = append(f.cleanUpCalls, struct{ fqdn, recordID string }{fqdn, recordID})
	return f.cleanUpErr
}

var _ DNS01Provider = (*fakeDNS01)(nil)

// makeCertDER builds a real, minimal self-signed certificate's DER bytes
// for hostname, standing in for what a CA would return from
// CreateCertFromOrder. It never touches the network.
func makeCertDER(t *testing.T, hostname string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// pendingOrder builds a single-authorization order for hostname with a
// dns-01 challenge, plus the fakeACME wired to satisfy it successfully.
func pendingOrder(hostname, token string) (*acme.Order, map[string]*acme.Authorization) {
	authzURL := "https://acme.example/authz/1"
	order := &acme.Order{
		URI:         "https://acme.example/order/1",
		AuthzURLs:   []string{authzURL},
		FinalizeURL: "https://acme.example/finalize/1",
	}
	authz := map[string]*acme.Authorization{
		authzURL: {
			URI:        authzURL,
			Status:     acme.StatusPending,
			Identifier: acme.AuthzID{Type: "dns", Value: hostname},
			Challenges: []*acme.Challenge{{Type: "dns-01", Token: token, URI: authzURL + "/dns-01"}},
		},
	}
	return order, authz
}

func TestObtainSuccess(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	acmeClient := &fakeACME{
		order: order, authz: authz, dns01Value: "the-digest",
		waitOrderResult: &acme.Order{URI: order.URI, FinalizeURL: order.FinalizeURL, Status: acme.StatusReady},
		certDER:         [][]byte{makeCertDER(t, hostname)},
	}
	dns01 := &fakeDNS01{presentRecordID: "rec1"}
	var propagationCalls []string
	o := &Obtainer{
		ACME: acmeClient, DNS01: dns01, Hostname: hostname,
		PropagationCheck: func(_ context.Context, fqdn, value string) error {
			propagationCalls = append(propagationCalls, fqdn+"="+value)
			return nil
		},
	}

	cert, err := o.Obtain(context.Background())
	if err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != hostname {
		t.Fatalf("Leaf = %+v", cert.Leaf)
	}
	if cert.PrivateKey == nil {
		t.Fatal("PrivateKey not set")
	}

	wantFQDN := "_acme-challenge." + hostname
	if len(dns01.presentCalls) != 1 || dns01.presentCalls[0].fqdn != wantFQDN || dns01.presentCalls[0].value != "the-digest" {
		t.Errorf("Present calls = %+v", dns01.presentCalls)
	}
	if len(dns01.cleanUpCalls) != 1 || dns01.cleanUpCalls[0].fqdn != wantFQDN || dns01.cleanUpCalls[0].recordID != "rec1" {
		t.Errorf("CleanUp calls = %+v", dns01.cleanUpCalls)
	}
	if len(propagationCalls) != 1 || propagationCalls[0] != wantFQDN+"=the-digest" {
		t.Errorf("propagation calls = %v", propagationCalls)
	}
	if len(acmeClient.acceptCalls) != 1 || acmeClient.acceptCalls[0] != "tok1" {
		t.Errorf("Accept calls = %v", acmeClient.acceptCalls)
	}
}

func TestObtainAccountAlreadyExistsIsNotAnError(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	acmeClient := &fakeACME{
		registerErr: acme.ErrAccountAlreadyExists,
		order:       order, authz: authz, dns01Value: "v",
		waitOrderResult: &acme.Order{URI: order.URI, FinalizeURL: order.FinalizeURL},
		certDER:         [][]byte{makeCertDER(t, hostname)},
	}
	o := &Obtainer{ACME: acmeClient, DNS01: &fakeDNS01{}, Hostname: hostname}
	if _, err := o.Obtain(context.Background()); err != nil {
		t.Fatalf("Obtain: %v", err)
	}
}

func TestObtainRegisterError(t *testing.T) {
	o := &Obtainer{ACME: &fakeACME{registerErr: errors.New("boom")}, DNS01: &fakeDNS01{}, Hostname: "shepherd.example.com"}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestObtainAuthorizeOrderError(t *testing.T) {
	o := &Obtainer{ACME: &fakeACME{authorizeOrderErr: errors.New("boom")}, DNS01: &fakeDNS01{}, Hostname: "shepherd.example.com"}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestObtainNoDNS01ChallengeOffered(t *testing.T) {
	hostname := "shepherd.example.com"
	authzURL := "https://acme.example/authz/1"
	order := &acme.Order{URI: "o1", AuthzURLs: []string{authzURL}, FinalizeURL: "f1"}
	authz := map[string]*acme.Authorization{
		authzURL: {URI: authzURL, Status: acme.StatusPending, Challenges: []*acme.Challenge{{Type: "http-01", Token: "tok"}}},
	}
	o := &Obtainer{ACME: &fakeACME{order: order, authz: authz}, DNS01: &fakeDNS01{}, Hostname: hostname}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error when no dns-01 challenge is offered")
	}
}

func TestObtainAlreadyValidAuthorizationSkipsChallenge(t *testing.T) {
	hostname := "shepherd.example.com"
	authzURL := "https://acme.example/authz/1"
	order := &acme.Order{URI: "o1", AuthzURLs: []string{authzURL}, FinalizeURL: "f1"}
	authz := map[string]*acme.Authorization{
		authzURL: {URI: authzURL, Status: acme.StatusValid, Challenges: []*acme.Challenge{{Type: "dns-01", Token: "tok"}}},
	}
	dns01 := &fakeDNS01{}
	acmeClient := &fakeACME{order: order, authz: authz, waitOrderResult: &acme.Order{URI: "o1", FinalizeURL: "f1"}, certDER: [][]byte{makeCertDER(t, hostname)}}
	o := &Obtainer{ACME: acmeClient, DNS01: dns01, Hostname: hostname}

	if _, err := o.Obtain(context.Background()); err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	if len(dns01.presentCalls) != 0 {
		t.Errorf("Present should not be called for an already-valid authorization, got %+v", dns01.presentCalls)
	}
}

func TestObtainPropagationCheckFailureStillCleansUp(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	dns01 := &fakeDNS01{presentRecordID: "rec1"}
	o := &Obtainer{
		ACME:             &fakeACME{order: order, authz: authz},
		DNS01:            dns01,
		Hostname:         hostname,
		PropagationCheck: func(context.Context, string, string) error { return errors.New("never showed up") },
	}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if len(dns01.cleanUpCalls) != 1 {
		t.Errorf("CleanUp should still run after a propagation failure, got %+v", dns01.cleanUpCalls)
	}
}

func TestObtainPresentError(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	o := &Obtainer{ACME: &fakeACME{order: order, authz: authz}, DNS01: &fakeDNS01{presentErr: errors.New("cloudflare down")}, Hostname: hostname}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestObtainAcceptError(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	o := &Obtainer{ACME: &fakeACME{order: order, authz: authz, acceptErr: errors.New("boom")}, DNS01: &fakeDNS01{}, Hostname: hostname}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestObtainWaitAuthorizationError(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	o := &Obtainer{ACME: &fakeACME{order: order, authz: authz, waitAuthorizationErr: errors.New("boom")}, DNS01: &fakeDNS01{}, Hostname: hostname}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestObtainWaitOrderError(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	o := &Obtainer{ACME: &fakeACME{order: order, authz: authz, waitOrderErr: errors.New("boom")}, DNS01: &fakeDNS01{}, Hostname: hostname}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestObtainCreateCertError(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	acmeClient := &fakeACME{order: order, authz: authz, waitOrderResult: &acme.Order{URI: order.URI, FinalizeURL: order.FinalizeURL}, createCertErr: errors.New("boom")}
	o := &Obtainer{ACME: acmeClient, DNS01: &fakeDNS01{}, Hostname: hostname}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestObtainEmptyCertificateChain(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	acmeClient := &fakeACME{order: order, authz: authz, waitOrderResult: &acme.Order{URI: order.URI, FinalizeURL: order.FinalizeURL}, certDER: nil}
	o := &Obtainer{ACME: acmeClient, DNS01: &fakeDNS01{}, Hostname: hostname}
	if _, err := o.Obtain(context.Background()); err == nil {
		t.Fatal("expected an error for an empty certificate chain")
	}
}

func TestObtainCleanupErrorIsReportedNotFatal(t *testing.T) {
	hostname := "shepherd.example.com"
	order, authz := pendingOrder(hostname, "tok1")
	acmeClient := &fakeACME{order: order, authz: authz, waitOrderResult: &acme.Order{URI: order.URI, FinalizeURL: order.FinalizeURL}, certDER: [][]byte{makeCertDER(t, hostname)}}
	var reported error
	o := &Obtainer{
		ACME: acmeClient, DNS01: &fakeDNS01{cleanUpErr: errors.New("record already gone")}, Hostname: hostname,
		OnCleanupError: func(err error) { reported = err },
	}
	if _, err := o.Obtain(context.Background()); err != nil {
		t.Fatalf("a CleanUp failure must not fail Obtain: %v", err)
	}
	if reported == nil {
		t.Error("expected OnCleanupError to be called")
	}
}

func TestObtainMultipleAuthorizations(t *testing.T) {
	hostname := "shepherd.example.com"
	authzURL1, authzURL2 := "https://acme.example/authz/1", "https://acme.example/authz/2"
	order := &acme.Order{URI: "o1", AuthzURLs: []string{authzURL1, authzURL2}, FinalizeURL: "f1"}
	authz := map[string]*acme.Authorization{
		authzURL1: {URI: authzURL1, Status: acme.StatusPending, Challenges: []*acme.Challenge{{Type: "dns-01", Token: "tok1"}}},
		authzURL2: {URI: authzURL2, Status: acme.StatusPending, Challenges: []*acme.Challenge{{Type: "dns-01", Token: "tok2"}}},
	}
	acmeClient := &fakeACME{order: order, authz: authz, dns01Value: "v", waitOrderResult: &acme.Order{URI: "o1", FinalizeURL: "f1"}, certDER: [][]byte{makeCertDER(t, hostname)}}
	dns01 := &fakeDNS01{}
	o := &Obtainer{ACME: acmeClient, DNS01: dns01, Hostname: hostname}

	if _, err := o.Obtain(context.Background()); err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	if len(dns01.presentCalls) != 2 {
		t.Errorf("expected 2 Present calls, got %d", len(dns01.presentCalls))
	}
	if len(acmeClient.acceptCalls) != 2 {
		t.Errorf("expected 2 Accept calls, got %v", acmeClient.acceptCalls)
	}
}

func TestWaitForDNSPropagation(t *testing.T) {
	calls := 0
	lookup := func(context.Context, string) ([]string, error) {
		calls++
		if calls < 3 {
			return []string{"not-yet"}, nil
		}
		return []string{"not-yet", "expected-value"}, nil
	}
	check := WaitForDNSPropagation(lookup, time.Second, time.Millisecond)
	if err := check(context.Background(), "_acme-challenge.shepherd.example.com", "expected-value"); err != nil {
		t.Fatalf("check: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestWaitForDNSPropagationTimesOut(t *testing.T) {
	lookup := func(context.Context, string) ([]string, error) { return []string{"nope"}, nil }
	check := WaitForDNSPropagation(lookup, 20*time.Millisecond, 5*time.Millisecond)
	if err := check(context.Background(), "_acme-challenge.shepherd.example.com", "expected-value"); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestWaitForDNSPropagationRespectsContextCancellation(t *testing.T) {
	lookup := func(context.Context, string) ([]string, error) { return []string{"nope"}, nil }
	check := WaitForDNSPropagation(lookup, time.Minute, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := check(ctx, "_acme-challenge.shepherd.example.com", "expected-value"); err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
}
