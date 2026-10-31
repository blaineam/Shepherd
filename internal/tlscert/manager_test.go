// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeObtainer implements CertObtainer entirely in memory.
type fakeObtainer struct {
	mu       sync.Mutex
	calls    int
	err      error
	hostname string
	validFor time.Duration
}

func (f *fakeObtainer) Obtain(context.Context) (tls.Certificate, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return tls.Certificate{}, f.err
	}
	return newSelfSignedCert(f.hostname, f.validFor)
}

func (f *fakeObtainer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newTestManager(t *testing.T, obt CertObtainer) *Manager {
	t.Helper()
	m, err := New(Options{Hostname: "shepherd.example.com", Dir: filepath.Join(t.TempDir(), "tls"), Obtainer: obt})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestNewValidatesOptions(t *testing.T) {
	cases := []Options{
		{Dir: "x", Obtainer: &fakeObtainer{}},
		{Hostname: "h", Obtainer: &fakeObtainer{}},
		{Hostname: "h", Dir: "x"},
	}
	for i, opts := range cases {
		if _, err := New(opts); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestGetCertificateBeforeAnyObtainReturnsError(t *testing.T) {
	m := newTestManager(t, &fakeObtainer{})
	if _, err := m.GetCertificate(nil); err == nil {
		t.Fatal("expected an error before any certificate has been obtained")
	}
}

func TestEnsureFreshObtainsWhenNoneCached(t *testing.T) {
	obt := &fakeObtainer{hostname: "shepherd.example.com", validFor: 90 * 24 * time.Hour}
	m := newTestManager(t, obt)

	if err := m.EnsureFresh(context.Background()); err != nil {
		t.Fatalf("EnsureFresh: %v", err)
	}
	if obt.callCount() != 1 {
		t.Errorf("Obtain calls = %d, want 1", obt.callCount())
	}
	cert, err := m.GetCertificate(nil)
	if err != nil || cert == nil {
		t.Fatalf("GetCertificate: %v, %v", cert, err)
	}
	if m.Certificate() != cert {
		t.Error("Certificate() must return the same pointer GetCertificate does")
	}
}

func TestEnsureFreshSkipsNetworkWhenComfortablyValid(t *testing.T) {
	obt := &fakeObtainer{hostname: "shepherd.example.com", validFor: 90 * 24 * time.Hour}
	m := newTestManager(t, obt)
	if err := m.EnsureFresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureFresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if obt.callCount() != 1 {
		t.Errorf("Obtain calls = %d, want 1 (second call should have skipped it)", obt.callCount())
	}
}

func TestEnsureFreshRenewsWhenCloseToExpiry(t *testing.T) {
	obt := &fakeObtainer{hostname: "shepherd.example.com", validFor: 90 * 24 * time.Hour}
	m, err := New(Options{Hostname: "shepherd.example.com", Dir: filepath.Join(t.TempDir(), "tls"), Obtainer: obt, RenewBefore: 100 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureFresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// RenewBefore (100 days) exceeds the certificate's whole lifetime (90
	// days), so every check must renew, never skip.
	if err := m.EnsureFresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if obt.callCount() != 2 {
		t.Errorf("Obtain calls = %d, want 2", obt.callCount())
	}
}

func TestEnsureFreshFailureKeepsServingTheOldCertificate(t *testing.T) {
	obt := &fakeObtainer{hostname: "shepherd.example.com", validFor: 90 * 24 * time.Hour}
	m, err := New(Options{Hostname: "shepherd.example.com", Dir: filepath.Join(t.TempDir(), "tls"), Obtainer: obt, RenewBefore: 100 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureFresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, _ := m.GetCertificate(nil)

	obt.err = errors.New("cloudflare unreachable")
	if err := m.EnsureFresh(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	second, _ := m.GetCertificate(nil)
	if first != second {
		t.Error("a failed renewal must not disturb the certificate already in service")
	}
}

func TestEnsureFreshFirstObtainFailureLeavesNoCertificate(t *testing.T) {
	m := newTestManager(t, &fakeObtainer{err: errors.New("no cloudflare token configured")})
	if err := m.EnsureFresh(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := m.GetCertificate(nil); err == nil {
		t.Fatal("expected GetCertificate to still report no certificate")
	}
}

func TestEnsureFreshPersistsAcrossLoadCached(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	obt := &fakeObtainer{hostname: "shepherd.example.com", validFor: 90 * 24 * time.Hour}
	m1, err := New(Options{Hostname: "shepherd.example.com", Dir: dir, Obtainer: obt})
	if err != nil {
		t.Fatal(err)
	}
	if err := m1.EnsureFresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A fresh Manager over the same Dir, with an Obtainer that would fail if
	// ever called, must still end up with a certificate: LoadCached reads
	// what is already on disk, no network needed.
	m2, err := New(Options{Hostname: "shepherd.example.com", Dir: dir, Obtainer: &fakeObtainer{err: errors.New("must not be called")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m2.LoadCached(); err != nil {
		t.Fatalf("LoadCached: %v", err)
	}
	if _, err := m2.GetCertificate(nil); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
}

func TestLoadCachedMissingIsNotAnError(t *testing.T) {
	m := newTestManager(t, &fakeObtainer{})
	if err := m.LoadCached(); err != nil {
		t.Fatalf("LoadCached with nothing on disk: %v", err)
	}
	if _, err := m.GetCertificate(nil); err == nil {
		t.Fatal("expected no certificate to be loaded")
	}
}

func TestRunOnceObtainsAndReturns(t *testing.T) {
	obt := &fakeObtainer{hostname: "shepherd.example.com", validFor: 90 * 24 * time.Hour}
	m := newTestManager(t, obt)
	m.Run(context.Background(), 0) // every <= 0: once, like portscan.Scanner.Run
	if obt.callCount() != 1 {
		t.Errorf("Obtain calls = %d, want 1", obt.callCount())
	}
}

func TestRunReportsFailuresThroughOnError(t *testing.T) {
	obt := &fakeObtainer{err: errors.New("let's encrypt unreachable")}
	var reported error
	m, err := New(Options{Hostname: "shepherd.example.com", Dir: filepath.Join(t.TempDir(), "tls"), Obtainer: obt, OnError: func(e error) { reported = e }})
	if err != nil {
		t.Fatal(err)
	}
	m.Run(context.Background(), 0)
	if reported == nil {
		t.Fatal("expected OnError to be called")
	}
}

func TestRunCallsOnObtainedOnSuccess(t *testing.T) {
	obt := &fakeObtainer{hostname: "shepherd.example.com", validFor: 90 * 24 * time.Hour}
	var gotExpiry time.Time
	m, err := New(Options{Hostname: "shepherd.example.com", Dir: filepath.Join(t.TempDir(), "tls"), Obtainer: obt, OnObtained: func(t time.Time) { gotExpiry = t }})
	if err != nil {
		t.Fatal(err)
	}
	m.Run(context.Background(), 0)
	if gotExpiry.IsZero() {
		t.Fatal("expected OnObtained to be called with a non-zero expiry")
	}
}

func TestRunTicksUntilContextCancelled(t *testing.T) {
	// A certificate "valid" for only an hour is well inside the default
	// 30-day renewal threshold, so every tick renews it again; that is the
	// point of this test (that ticking actually happens and keeps calling
	// EnsureFresh), as opposed to the other Run tests which only check one
	// attempt.
	obt := &fakeObtainer{hostname: "shepherd.example.com", validFor: time.Hour}
	m := newTestManager(t, obt)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, 5*time.Millisecond); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
	if obt.callCount() < 2 {
		t.Errorf("Obtain calls = %d, want at least 2 ticks", obt.callCount())
	}
}

func TestKickChecksRightAwayInsteadOfWaitingForTheTick(t *testing.T) {
	obt := &fakeObtainer{err: errors.New("no token yet")}
	m := newTestManager(t, obt)
	m.Kick() // before Run: counted once, never blocks
	m.Kick()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, time.Hour); close(done) }() // the ticker never fires in this test
	waitCalls := func(n int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for obt.callCount() < n {
			if time.Now().After(deadline) {
				t.Fatalf("Obtain calls = %d, want %d", obt.callCount(), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitCalls(2) // the first check, then the queued kick
	m.Kick()
	waitCalls(3)
	cancel()
	m.Kick() // after cancellation: must not attempt again
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
