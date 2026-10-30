// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadOrCreateAccountKey returns the ACME account's private key at path,
// generating and saving a fresh ECDSA P-256 key (mode 0600, like every
// other secret this project persists) the first time it is called. The key
// identifies the ACME account itself, not any certificate; it is never sent
// anywhere except in the signed requests golang.org/x/crypto/acme makes.
func LoadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		return parseECKey(b)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating an ACME account key: %w", err)
	}
	if err := saveECKey(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

func parseECKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("not a PEM-encoded EC private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing EC private key: %w", err)
	}
	return key, nil
}

// saveECKey writes key to path (mode 0600), atomically via a temp file and
// rename, the same convention internal/portscan.Scanner.Save uses.
func saveECKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling ACME account key: %w", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("saving %s: %w", path, err)
	}
	return nil
}
