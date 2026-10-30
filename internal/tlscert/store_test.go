// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCert is newSelfSignedCert (testutil_test.go), failing the test
// on error instead of returning one, for callers that just want a cert.
func selfSignedCert(t *testing.T, hostname string, validFor time.Duration) tls.Certificate {
	t.Helper()
	cert, err := newSelfSignedCert(hostname, validFor)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSaveAndLoadCertificateRoundTrips(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	cert := selfSignedCert(t, "shepherd.example.com", 90*24*time.Hour)

	if err := SaveCertificate(dir, cert); err != nil {
		t.Fatalf("SaveCertificate: %v", err)
	}
	for _, name := range []string{certFileName, keyFileName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 0600", name, perm)
		}
	}

	loaded, err := LoadCertificate(dir)
	if err != nil {
		t.Fatalf("LoadCertificate: %v", err)
	}
	if loaded.Leaf == nil {
		t.Fatal("LoadCertificate did not set Leaf")
	}
	if !loaded.Leaf.NotAfter.Equal(cert.Leaf.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", loaded.Leaf.NotAfter, cert.Leaf.NotAfter)
	}
	if loaded.Leaf.Subject.CommonName != "shepherd.example.com" {
		t.Errorf("CommonName = %q", loaded.Leaf.Subject.CommonName)
	}
}

func TestLoadCertificateMissingIsNotExist(t *testing.T) {
	_, err := LoadCertificate(filepath.Join(t.TempDir(), "missing"))
	if !os.IsNotExist(err) {
		t.Fatalf("err = %v, want os.IsNotExist", err)
	}
}

func TestSaveCertificateRejectsUnsupportedKeyType(t *testing.T) {
	cert := selfSignedCert(t, "shepherd.example.com", time.Hour)
	cert.PrivateKey = "not a key"
	if err := SaveCertificate(filepath.Join(t.TempDir(), "tls"), cert); err == nil {
		t.Fatal("expected an error for a non-ECDSA private key")
	}
}
