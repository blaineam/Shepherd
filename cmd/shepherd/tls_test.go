// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/tlscert"

	"golang.org/x/crypto/acme"
)

// fakeTLSACME and fakeTLSDNS01 implement tlscert.ACMEClient and
// tlscert.DNS01Provider entirely in memory, so startTLS can be exercised
// end to end (register, authorize, satisfy the dns-01 challenge, finalize)
// without ever making a real network call to Let's Encrypt or Cloudflare —
// see the tlsACMEClient/tlsDNS01 test seams in tls.go.
type fakeTLSACME struct {
	hostname  string
	authzURL  string
	finalized bool
}

func newFakeTLSACME(hostname string) *fakeTLSACME {
	return &fakeTLSACME{hostname: hostname, authzURL: "https://acme.example/authz/1"}
}

func (f *fakeTLSACME) Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error) {
	return &acme.Account{}, nil
}
func (f *fakeTLSACME) AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error) {
	return &acme.Order{URI: "https://acme.example/order/1", AuthzURLs: []string{f.authzURL}, FinalizeURL: "https://acme.example/finalize/1"}, nil
}
func (f *fakeTLSACME) GetAuthorization(context.Context, string) (*acme.Authorization, error) {
	return &acme.Authorization{
		URI: f.authzURL, Status: acme.StatusPending, Identifier: acme.AuthzID{Type: "dns", Value: f.hostname},
		Challenges: []*acme.Challenge{{Type: "dns-01", Token: "test-token"}},
	}, nil
}
func (f *fakeTLSACME) Accept(_ context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	return chal, nil
}
func (f *fakeTLSACME) WaitAuthorization(context.Context, string) (*acme.Authorization, error) {
	return &acme.Authorization{URI: f.authzURL, Status: acme.StatusValid}, nil
}
func (f *fakeTLSACME) WaitOrder(context.Context, string) (*acme.Order, error) {
	f.finalized = true
	return &acme.Order{URI: "https://acme.example/order/1", FinalizeURL: "https://acme.example/finalize/1", Status: acme.StatusReady}, nil
}
func (f *fakeTLSACME) CreateCertFromOrder(_ context.Context, _ *acme.Order, csr []byte, _ bool) ([][]byte, string, error) {
	der, err := makeTestCertDER(f.hostname, csr)
	if err != nil {
		return nil, "", err
	}
	return [][]byte{der}, "https://acme.example/cert/1", nil
}
func (f *fakeTLSACME) DNS01ChallengeRecord(string) (string, error) { return "the-digest", nil }

var _ tlscert.ACMEClient = (*fakeTLSACME)(nil)

type fakeTLSDNS01 struct{ presentCalls int }

func (f *fakeTLSDNS01) Present(context.Context, string, string) (string, error) {
	f.presentCalls++
	return "rec1", nil
}
func (f *fakeTLSDNS01) CleanUp(context.Context, string, string) error { return nil }

var _ tlscert.DNS01Provider = (*fakeTLSDNS01)(nil)

// makeTestCertDER stands in for what a real CA returns from
// CreateCertFromOrder: a certificate embedding exactly the public key the
// CSR asked for (so it matches the private key Obtain generated and kept),
// signed by an unrelated throwaway issuer key — a real CA's signature
// would of course chain to a trusted root, but tls.X509KeyPair only checks
// that the leaf's public key matches the supplied private key, never the
// chain, so this is enough to exercise the save/load round trip faithfully.
func makeTestCertDER(hostname string, csrDER []byte) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, issuerKey)
}

// resetTLSSeams saves and restores every tls.go test seam, so tests never
// leak overrides into each other.
func resetTLSSeams(t *testing.T) {
	t.Helper()
	oldEvery, oldACME, oldDNS01, oldProp := tlsEvery, tlsACMEClient, tlsDNS01, tlsPropagationCheck
	t.Cleanup(func() { tlsEvery, tlsACMEClient, tlsDNS01, tlsPropagationCheck = oldEvery, oldACME, oldDNS01, oldProp })
}

func TestStartTLSDisabledReturnsNilManager(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.TLS.Enabled = false
	mgr, err := startTLS(context.Background(), cfg)
	if err != nil || mgr != nil {
		t.Fatalf("startTLS(disabled) = %v, %v; want nil, nil", mgr, err)
	}
}

func TestStartTLSObtainsACertificateInTheBackground(t *testing.T) {
	resetTLSSeams(t)
	hostname := "shepherd.example.com"
	tlsEvery = 10 * time.Millisecond
	tlsACMEClient = newFakeTLSACME(hostname)
	fakeDNS := &fakeTLSDNS01{}
	tlsDNS01 = fakeDNS
	tlsPropagationCheck = func(context.Context, string, string) error { return nil }

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.TLS = config.TLS{Enabled: true, Hostname: hostname, Listen: "127.0.0.1:0", CloudflareAPIToken: "unused-fake"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr, err := startTLS(ctx, cfg)
	if err != nil {
		t.Fatalf("startTLS: %v", err)
	}
	if mgr == nil {
		t.Fatal("startTLS returned a nil Manager while enabled")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.Certificate() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cert := mgr.Certificate()
	if cert == nil {
		t.Fatal("no certificate was obtained within the deadline")
	}
	if cert.Leaf.Subject.CommonName != hostname {
		t.Errorf("CommonName = %q, want %q", cert.Leaf.Subject.CommonName, hostname)
	}
	if fakeDNS.presentCalls == 0 {
		t.Error("the DNS-01 provider was never asked to publish a record")
	}

	// It is also persisted, so a restart would reuse it without any network.
	if _, err := tlscert.LoadCertificate(filepath.Join(cfg.DataDir, "tls")); err != nil {
		t.Errorf("certificate was not persisted: %v", err)
	}
}

func TestStartTLSNeverBlocksStartupWhenUnreachable(t *testing.T) {
	resetTLSSeams(t)
	tlsEvery = time.Hour // never ticks again within this test
	tlsACMEClient = failingACME{}
	tlsDNS01 = &fakeTLSDNS01{}

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.TLS = config.TLS{Enabled: true, Hostname: "shepherd.example.com", Listen: "127.0.0.1:0", CloudflareAPIToken: "x"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		if _, err := startTLS(ctx, cfg); err != nil {
			t.Errorf("startTLS: %v", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startTLS blocked on an unreachable ACME server instead of returning immediately")
	}
}

type failingACME struct{}

func (failingACME) Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error) {
	return nil, errors.New("acme server unreachable")
}
func (failingACME) AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error) {
	return nil, errors.New("unreachable")
}
func (failingACME) GetAuthorization(context.Context, string) (*acme.Authorization, error) {
	return nil, errors.New("unreachable")
}
func (failingACME) Accept(context.Context, *acme.Challenge) (*acme.Challenge, error) {
	return nil, errors.New("unreachable")
}
func (failingACME) WaitAuthorization(context.Context, string) (*acme.Authorization, error) {
	return nil, errors.New("unreachable")
}
func (failingACME) WaitOrder(context.Context, string) (*acme.Order, error) {
	return nil, errors.New("unreachable")
}
func (failingACME) CreateCertFromOrder(context.Context, *acme.Order, []byte, bool) ([][]byte, string, error) {
	return nil, "", errors.New("unreachable")
}
func (failingACME) DNS01ChallengeRecord(string) (string, error) { return "", errors.New("unreachable") }

var _ tlscert.ACMEClient = failingACME{}

func TestCloudflareAPITokenDirect(t *testing.T) {
	token, err := cloudflareAPIToken(config.TLS{CloudflareAPIToken: "direct-token"})
	if err != nil || token != "direct-token" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}

func TestCloudflareAPITokenFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := cloudflareAPIToken(config.TLS{CloudflareAPITokenFile: path})
	if err != nil || token != "file-token" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}

func TestCloudflareAPITokenFileMissing(t *testing.T) {
	if _, err := cloudflareAPIToken(config.TLS{CloudflareAPITokenFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("expected an error for a missing token file")
	}
}

func TestStartTLSBadTokenFileFailsFast(t *testing.T) {
	resetTLSSeams(t)
	// tlsDNS01 left nil so startTLS actually resolves the token itself.
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.TLS = config.TLS{Enabled: true, Hostname: "shepherd.example.com", Listen: "127.0.0.1:0", CloudflareAPITokenFile: filepath.Join(t.TempDir(), "missing")}
	if _, err := startTLS(context.Background(), cfg); err == nil {
		t.Fatal("expected an error for a missing Cloudflare token file")
	}
}
