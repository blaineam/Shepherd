// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"
)

// MaxJWTLifetime is the longest VAPID token lifetime Shepherd will sign.
// RFC 8292 allows 24 hours and Apple rejects anything longer.
const MaxJWTLifetime = 24 * time.Hour

// DefaultJWTLifetime is used when a caller does not choose one.
const DefaultJWTLifetime = 12 * time.Hour

// ErrBadKey reports a malformed VAPID key pair.
var ErrBadKey = errors.New("webpush: invalid VAPID key")

// VAPIDKeys is the server's identity: the uncompressed P-256 public point
// (65 bytes) and the private scalar (32 bytes), both base64url without
// padding. Public is the browser's applicationServerKey.
type VAPIDKeys struct {
	Public  string `json:"public_key"`
	Private string `json:"private_key"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decodeB64 accepts base64url with or without padding.
func decodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
}

// GenerateVAPIDKeys creates a fresh key pair.
func GenerateVAPIDKeys() (VAPIDKeys, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return VAPIDKeys{}, err
	}
	return VAPIDKeys{Public: b64(k.PublicKey().Bytes()), Private: b64(k.Bytes())}, nil
}

// signingKey validates the pair and returns the ECDSA private key.
func (k VAPIDKeys) signingKey() (*ecdsa.PrivateKey, error) {
	d, err := decodeB64(k.Private)
	if err != nil || len(d) != 32 {
		return nil, fmt.Errorf("%w: private key", ErrBadKey)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, fmt.Errorf("%w: private key", ErrBadKey)
	}
	pub, err := decodeB64(k.Public)
	if err != nil || len(pub) != 65 {
		return nil, fmt.Errorf("%w: public key", ErrBadKey)
	}
	derived, err := priv.PublicKey.Bytes()
	if err != nil || b64(derived) != b64(pub) {
		return nil, fmt.Errorf("%w: public key does not match the private key", ErrBadKey)
	}
	return priv, nil
}

// Validate checks that both halves decode and belong together.
func (k VAPIDKeys) Validate() error {
	_, err := k.signingKey()
	return err
}

// jwtClaims is the RFC 8292 claim set.
type jwtClaims struct {
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Sub string `json:"sub"`
}

// JWT signs an ES256 token for the push service that owns endpoint. The
// audience is the endpoint's origin; the lifetime is clamped to
// MaxJWTLifetime. The signature is the raw r||s pair that JOSE requires, not
// DER.
func (k VAPIDKeys) JWT(endpoint, subject string, now time.Time, lifetime time.Duration) (string, error) {
	priv, err := k.signingKey()
	if err != nil {
		return "", err
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("webpush: bad endpoint %q", endpoint)
	}
	if lifetime <= 0 {
		lifetime = DefaultJWTLifetime
	}
	if lifetime > MaxJWTLifetime {
		lifetime = MaxJWTLifetime
	}
	header := b64([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, _ := json.Marshal(jwtClaims{Aud: u.Scheme + "://" + u.Host, Exp: now.Add(lifetime).Unix(), Sub: subject})
	signed := header + "." + b64(claims)
	sum := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signed + "." + b64(sig), nil
}

// Authorization returns the RFC 8292 header value: "vapid t=<jwt>, k=<key>".
func (k VAPIDKeys) Authorization(endpoint, subject string, now time.Time, lifetime time.Duration) (string, error) {
	jwt, err := k.JWT(endpoint, subject, now, lifetime)
	if err != nil {
		return "", err
	}
	return "vapid t=" + jwt + ", k=" + k.Public, nil
}

// VerifyJWT checks a token against a base64url public key and returns its
// audience, subject and expiry. It exists for tests and diagnostics; push
// services do the real verification.
func VerifyJWT(publicKey, token string) (aud, sub string, exp time.Time, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", time.Time{}, errors.New("webpush: token is not three parts")
	}
	raw, err := decodeB64(publicKey)
	if err != nil {
		return "", "", time.Time{}, ErrBadKey
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return "", "", time.Time{}, ErrBadKey
	}
	sig, err := decodeB64(parts[2])
	if err != nil || len(sig) != 64 {
		return "", "", time.Time{}, errors.New("webpush: signature is not raw r||s")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return "", "", time.Time{}, errors.New("webpush: signature does not verify")
	}
	hdr, err := decodeB64(parts[0])
	if err != nil {
		return "", "", time.Time{}, errors.New("webpush: bad header")
	}
	var h struct{ Typ, Alg string }
	if json.Unmarshal(hdr, &h) != nil || h.Alg != "ES256" {
		return "", "", time.Time{}, errors.New("webpush: header is not ES256")
	}
	body, err := decodeB64(parts[1])
	if err != nil {
		return "", "", time.Time{}, errors.New("webpush: bad claims")
	}
	var c jwtClaims
	if err := json.Unmarshal(body, &c); err != nil {
		return "", "", time.Time{}, errors.New("webpush: bad claims")
	}
	return c.Aud, c.Sub, time.Unix(c.Exp, 0), nil
}

// SaveVAPIDKeys writes the pair as JSON, mode 0600, atomically.
func SaveVAPIDKeys(path string, k VAPIDKeys) error {
	if err := k.Validate(); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(k, "", " ") // two strings: cannot fail
	return writeFileAtomic(path, data)
}

// LoadVAPIDKeys reads and validates a stored pair. A missing file returns an
// error satisfying errors.Is(err, os.ErrNotExist).
func LoadVAPIDKeys(path string) (VAPIDKeys, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return VAPIDKeys{}, err
	}
	var k VAPIDKeys
	if err := json.Unmarshal(data, &k); err != nil {
		return VAPIDKeys{}, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if err := k.Validate(); err != nil {
		return VAPIDKeys{}, err
	}
	return k, nil
}

// LoadOrCreateVAPIDKeys returns the stored pair, generating and saving one on
// first use. Changing the pair invalidates every existing subscription (the
// browsers subscribed against the old public key), so create it once and keep
// it.
func LoadOrCreateVAPIDKeys(path string) (VAPIDKeys, bool, error) {
	k, err := LoadVAPIDKeys(path)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return VAPIDKeys{}, false, err
	}
	k, err = GenerateVAPIDKeys()
	if err != nil {
		return VAPIDKeys{}, false, err
	}
	if err := SaveVAPIDKeys(path, k); err != nil {
		return VAPIDKeys{}, false, err
	}
	return k, true, nil
}
