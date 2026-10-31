// SPDX-License-Identifier: AGPL-3.0-or-later

// Package passkeystest is a software WebAuthn authenticator for tests. It is
// how go-webauthn tests itself (see its es256k_e2e_test.go): build the exact
// bytes a browser and authenticator would send, sign them with a real ES256
// key, and hand them to the server. It answers the JSON options the portal
// sends to a browser with the JSON a browser would post back, so a test can
// drive a full ceremony through the real HTTP API.
//
// What it cannot do is stand in for a real browser or a real authenticator:
// it only produces "none" attestation, it signs whatever it is asked to, and
// it knows nothing of platform passkey sync, hybrid (phone) transport,
// hardware-key PINs or browser quirks. Passing tests with it proves the
// server verifies well-formed and tampered ceremonies correctly; it does not
// prove any particular browser or authenticator works. docs/PASSKEYS.md
// lists what still needs a human with a real device.
//
// Nothing outside _test.go files imports this package.
package passkeystest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// Authenticator is one software credential holder. Its exported fields are
// knobs a test turns to produce a specific (often deliberately wrong)
// response.
type Authenticator struct {
	// Origin goes into clientDataJSON: what the browser says the page was.
	Origin string
	// RPID is hashed into authenticator data. Empty means "use the rp id
	// from the options", which is what a real authenticator does.
	RPID string
	// UserVerified sets the UV flag (a biometric or device PIN was used).
	UserVerified bool
	// BackupEligible/BackedUp set the BE/BS flags (a synced passkey).
	BackupEligible, BackedUp bool
	// SignCount is the counter reported by the next ceremony; it is
	// incremented after every login when Increment is true.
	SignCount uint32
	Increment bool
	// Type overrides clientData's ceremony type when non-empty.
	Type string
	// Challenge overrides the challenge echoed in clientData when non-empty.
	Challenge string
	// UserHandle overrides the user handle returned at login when non-nil.
	UserHandle []byte

	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
}

// New returns an authenticator for pages at origin, with user verification
// on and a counter that increments, like a typical hardware key.
func New(origin string) *Authenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &Authenticator{Origin: origin, UserVerified: true, Increment: true, key: key, credID: id}
}

// CredentialID is the credential id this authenticator registers.
func (a *Authenticator) CredentialID() []byte { return a.credID }

// Clone returns a second authenticator holding the same private key and
// credential (a cloned hardware key), with its own counter.
func (a *Authenticator) Clone() *Authenticator {
	c := *a
	return &c
}

// Impostor returns an authenticator presenting this one's credential id and
// user handle but signing with a different private key: what an attacker
// who learned the (public) credential id could at most produce.
func (a *Authenticator) Impostor() *Authenticator {
	c := *a
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	c.key = key
	return &c
}

type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		RPID string `json:"rpId"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

func parseOptions(b []byte) (options, error) {
	var o options
	if err := json.Unmarshal(b, &o); err != nil {
		return o, fmt.Errorf("passkeystest: options: %w", err)
	}
	if o.PublicKey.Challenge == "" {
		return o, fmt.Errorf("passkeystest: options carry no challenge")
	}
	return o, nil
}

var b64 = base64.RawURLEncoding

// Register answers creation options (the JSON the portal sent the browser)
// with the registration response a browser would post back.
func (a *Authenticator) Register(optionsJSON []byte) ([]byte, error) {
	o, err := parseOptions(optionsJSON)
	if err != nil {
		return nil, err
	}
	uh, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return nil, fmt.Errorf("passkeystest: user id: %w", err)
	}
	a.userHandle = uh
	clientData := a.clientData("webauthn.create", o.PublicKey.Challenge)
	authData := a.authData(a.rpID(o.PublicKey.RP.ID), 0x40, a.attestedCredentialData())
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		return nil, err
	}
	id := b64.EncodeToString(a.credID)
	return json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal", "hybrid"},
		},
		"clientExtensionResults": map[string]any{"credProps": map[string]any{"rk": true}},
	})
}

// Login answers request options with the assertion a browser would post
// back, signed by this authenticator's key.
func (a *Authenticator) Login(optionsJSON []byte) ([]byte, error) {
	o, err := parseOptions(optionsJSON)
	if err != nil {
		return nil, err
	}
	clientData := a.clientData("webauthn.get", o.PublicKey.Challenge)
	authData := a.authData(a.rpID(o.PublicKey.RPID), 0, nil)
	sig, err := a.sign(authData, clientData)
	if err != nil {
		return nil, err
	}
	if a.Increment {
		a.SignCount++
	}
	uh := a.userHandle
	if a.UserHandle != nil {
		uh = a.UserHandle
	}
	id := b64.EncodeToString(a.credID)
	return json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(uh),
		},
		"clientExtensionResults": map[string]any{},
	})
}

func (a *Authenticator) rpID(fromOptions string) string {
	if a.RPID != "" {
		return a.RPID
	}
	return fromOptions
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	if a.Type != "" {
		typ = a.Type
	}
	if a.Challenge != "" {
		challenge = a.Challenge
	}
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

// authData builds authenticator data: rpIdHash, flags, counter, then any
// attested credential data. extra carries the AT flag when it applies.
func (a *Authenticator) authData(rpID string, extra byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	flags := byte(0x01) | extra // UP
	if a.UserVerified {
		flags |= 0x04
	}
	if a.BackupEligible {
		flags |= 0x08
	}
	if a.BackedUp {
		flags |= 0x10
	}
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.SignCount)
	return append(out, attested...)
}

func (a *Authenticator) attestedCredentialData() []byte {
	out := make([]byte, 16) // a zero AAGUID, as "none" attestation reports
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
	out = append(out, a.credID...)
	point, _ := a.key.PublicKey.Bytes() // uncompressed: 0x04 || X || Y; cannot fail for a generated P-256 key
	pub, _ := webauthncbor.Marshal(map[int64]any{
		1:  int64(2),  // kty: EC2
		3:  int64(-7), // alg: ES256
		-1: int64(1),  // crv: P-256
		-2: point[1:33],
		-3: point[33:65],
	})
	return append(out, pub...)
}

func (a *Authenticator) sign(authData, clientData []byte) ([]byte, error) {
	ch := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), ch[:]...))
	return ecdsa.SignASN1(rand.Reader, a.key, digest[:])
}
