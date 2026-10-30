// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"strings"
	"testing"
)

// The RFC 8291 Appendix A test vector ("When I grow up, I want to be a
// watermelon"). The expected body is the RFC's own byte string.
const (
	rfcPlaintext = "When I grow up, I want to be a watermelon"
	rfcASPrivate = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	rfcUAPrivate = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	rfcUAPublic  = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rfcSalt      = "DGv6ra1nlYgDCS1FRnbzlw"
	rfcAuth      = "BTBZMqHH6r4Tts7J_aSIgg"
	rfcBody      = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
)

func TestEncryptMatchesRFC8291AppendixA(t *testing.T) {
	asBytes, err := decodeB64(rfcASPrivate)
	if err != nil {
		t.Fatal(err)
	}
	as, err := ecdh.P256().NewPrivateKey(asBytes)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := decodeB64(rfcSalt)
	got, err := encryptWith([]byte(rfcPlaintext), rfcUAPublic, rfcAuth, as, salt)
	if err != nil {
		t.Fatal(err)
	}
	if b64(got) != rfcBody {
		t.Fatalf("body differs from the RFC 8291 vector:\n got %s\nwant %s", b64(got), rfcBody)
	}
	// And the independent receiver reads the vector's body back.
	uaBytes, _ := decodeB64(rfcUAPrivate)
	ua, err := ecdh.P256().NewPrivateKey(uaBytes)
	if err != nil {
		t.Fatal(err)
	}
	authSecret, _ := decodeB64(rfcAuth)
	d := &device{priv: ua, auth: authSecret}
	want, _ := decodeB64(rfcBody)
	if p := d.decrypt(t, want); string(p) != rfcPlaintext {
		t.Fatalf("decrypted %q", p)
	}
}

func TestEncryptFreshMessagesRoundTrip(t *testing.T) {
	d := newDevice(t)
	payload := []byte(`{"title":"hi","body":"there"}`)
	a, err := Encrypt(payload, d.p256dh(), d.authB64())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(payload, d.p256dh(), d.authB64())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two messages must differ (fresh key and salt each time)")
	}
	for _, body := range [][]byte{a, b} {
		if got := d.decrypt(t, body); !bytes.Equal(got, payload) {
			t.Fatalf("got %q", got)
		}
	}
	if len(a) != headerLen+len(payload)+1+gcmTag {
		t.Fatalf("unexpected length %d", len(a))
	}
}

func TestEncryptLimits(t *testing.T) {
	d := newDevice(t)
	max := bytes.Repeat([]byte("x"), MaxPayload)
	body, err := Encrypt(max, d.p256dh(), d.authB64())
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 4096 {
		t.Fatalf("a maximum payload must fill exactly 4096 bytes, got %d", len(body))
	}
	if _, err := Encrypt(append(max, 'x'), d.p256dh(), d.authB64()); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestEncryptRejectsBadKeys(t *testing.T) {
	d := newDevice(t)
	notPoint := b64(append([]byte{4}, bytes.Repeat([]byte{1}, 64)...))
	cases := map[string][2]string{
		"short p256dh":   {"AAAA", d.authB64()},
		"not base64":     {"%%%", d.authB64()},
		"not on curve":   {notPoint, d.authB64()},
		"short auth":     {d.p256dh(), "AAAA"},
		"auth not b64":   {d.p256dh(), "***"},
		"compressed key": {b64(append([]byte{2}, d.priv.PublicKey().Bytes()[1:33]...)), d.authB64()},
	}
	for name, c := range cases {
		if _, err := Encrypt([]byte("x"), c[0], c[1]); !errors.Is(err, ErrBadSubscription) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Padded base64url is accepted, as some clients send it.
	if _, err := Encrypt([]byte("x"), d.p256dh()+"=", d.authB64()+"=="); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ErrBadSubscription.Error(), "keys") {
		t.Fatal("message")
	}
}
