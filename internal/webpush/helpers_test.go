// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// device is a fake browser: it owns the user-agent key pair and auth secret
// and can decrypt what the server sends.
type device struct {
	priv *ecdh.PrivateKey
	auth []byte
}

func newDevice(t testing.TB) *device {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 16)
	rand.Read(a)
	return &device{priv: k, auth: a}
}

func (d *device) p256dh() string  { return b64(d.priv.PublicKey().Bytes()) }
func (d *device) authB64() string { return b64(d.auth) }

func (d *device) browserSub(endpoint string) BrowserSubscription {
	var s BrowserSubscription
	s.Endpoint = endpoint
	s.Keys.P256dh, s.Keys.Auth = d.p256dh(), d.authB64()
	return s
}

// decrypt is the receiving side of RFC 8291, written separately from
// Encrypt so a mistake in one cannot hide in both.
func (d *device) decrypt(t testing.TB, body []byte) []byte {
	t.Helper()
	salt := body[:16]
	if rs := binary.BigEndian.Uint32(body[16:20]); rs != 4096 {
		t.Fatalf("record size %d", rs)
	}
	idlen := int(body[20])
	asPub := body[21 : 21+idlen]
	ct := body[21+idlen:]
	as, err := ecdh.P256().NewPublicKey(asPub)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := d.priv.ECDH(as)
	if err != nil {
		t.Fatal(err)
	}
	info := append(append([]byte("WebPush: info\x00"), d.priv.PublicKey().Bytes()...), asPub...)
	ikm, _ := hkdf.Key(sha256.New, secret, d.auth, string(info), 32)
	cek, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	blk, _ := aes.NewCipher(cek)
	g, _ := cipher.NewGCM(blk)
	plain, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain[len(plain)-1] != 2 {
		t.Fatalf("missing final-record delimiter")
	}
	return plain[:len(plain)-1]
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// signRaw signs signed with k's private key the way JWT does (raw r||s).
func signRaw(t testing.TB, k VAPIDKeys, signed string) string {
	t.Helper()
	priv, err := k.signingKey()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return b64(sig)
}
