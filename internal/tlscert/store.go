// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const (
	certFileName = "cert.pem"
	keyFileName  = "key.pem"
)

// SaveCertificate writes cert's full chain and private key to dir (created
// if needed) as cert.pem and key.pem, both mode 0600 like every other
// secret this project persists, atomically via a temp file and rename.
// cert.PrivateKey must be an *ecdsa.PrivateKey, the only key type Obtainer
// ever generates.
func SaveCertificate(dir string, cert tls.Certificate) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("saving certificate: unsupported private key type %T", cert.PrivateKey)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling certificate key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	var certPEM []byte
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	if err := writeFileAtomic(filepath.Join(dir, keyFileName), keyPEM); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, certFileName), certPEM); err != nil {
		return err
	}
	return nil
}

// LoadCertificate reads the certificate and key SaveCertificate wrote to
// dir and returns a tls.Certificate with Leaf already parsed and set.
func LoadCertificate(dir string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFileName))
	if err != nil {
		return tls.Certificate{}, err // callers check os.IsNotExist, as elsewhere in this project
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFileName))
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing saved certificate in %s: %w", dir, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing saved certificate's leaf in %s: %w", dir, err)
	}
	cert.Leaf = leaf
	return cert, nil
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("saving %s: %w", path, err)
	}
	return nil
}
