// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	recordSize = 4096
	// headerLen is salt(16) + record size(4) + key length(1) + our public
	// key(65): the aes128gcm coding header of RFC 8188 with the RFC 8291
	// key ID.
	headerLen = 16 + 4 + 1 + 65
	gcmTag    = 16
	// MaxPayload is the largest plaintext that fits one 4096-byte push
	// message: 4096 minus the header, the padding delimiter and the GCM tag.
	MaxPayload = recordSize - headerLen - 1 - gcmTag
)

// Errors from Encrypt.
var (
	ErrPayloadTooLarge = errors.New("webpush: payload too large")
	ErrBadSubscription = errors.New("webpush: invalid subscription keys")
)

// ParseKeys decodes and validates a subscription's p256dh and auth values.
func ParseKeys(p256dh, auth string) (uaPublic, authSecret []byte, err error) {
	uaPublic, err = decodeB64(p256dh)
	if err != nil || len(uaPublic) != 65 || uaPublic[0] != 4 {
		return nil, nil, fmt.Errorf("%w: p256dh", ErrBadSubscription)
	}
	if _, err := ecdh.P256().NewPublicKey(uaPublic); err != nil {
		return nil, nil, fmt.Errorf("%w: p256dh is not a P-256 point", ErrBadSubscription)
	}
	authSecret, err = decodeB64(auth)
	if err != nil || len(authSecret) != 16 {
		return nil, nil, fmt.Errorf("%w: auth", ErrBadSubscription)
	}
	return uaPublic, authSecret, nil
}

// Encrypt encrypts payload for one subscription (RFC 8291, aes128gcm) with a
// fresh ephemeral key and salt, and returns the complete request body.
func Encrypt(payload []byte, p256dh, auth string) ([]byte, error) {
	// crypto/rand does not fail on supported platforms (it aborts the
	// process instead), so these errors are not reachable.
	as, _ := ecdh.P256().GenerateKey(rand.Reader)
	salt := make([]byte, 16)
	rand.Read(salt)
	return encryptWith(payload, p256dh, auth, as, salt)
}

// encryptWith is Encrypt with the ephemeral key and salt supplied, so the
// RFC 8291 Appendix A test vector can be reproduced.
func encryptWith(payload []byte, p256dh, auth string, as *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, fmt.Errorf("%w: %d bytes, max %d", ErrPayloadTooLarge, len(payload), MaxPayload)
	}
	uaBytes, authSecret, err := ParseKeys(p256dh, auth)
	if err != nil {
		return nil, err
	}
	// Everything below is infallible once the keys validated: the curve is
	// P-256 on both sides and the HKDF output lengths are fixed and small.
	ua, _ := ecdh.P256().NewPublicKey(uaBytes)
	secret, _ := as.ECDH(ua)
	asPub := as.PublicKey().Bytes()

	// RFC 8291 section 3.4: IKM = HKDF(auth, ecdh, "WebPush: info" 0 ua as, 32).
	keyInfo := append(append([]byte("WebPush: info\x00"), uaBytes...), asPub...)
	ikm, _ := hkdf.Key(sha256.New, secret, authSecret, string(keyInfo), 32)
	// RFC 8188 section 2.2/2.3: CEK and nonce from the salt.
	cek, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	// A single, final record: payload || 0x02.
	plain := append(append([]byte(nil), payload...), 0x02)
	out := make([]byte, headerLen, headerLen+len(plain)+gcmTag)
	copy(out, salt)
	binary.BigEndian.PutUint32(out[16:20], recordSize)
	out[20] = byte(len(asPub))
	copy(out[21:], asPub)
	return gcm.Seal(out, nonce, plain, nil), nil
}
