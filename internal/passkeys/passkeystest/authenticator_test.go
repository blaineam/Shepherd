// SPDX-License-Identifier: AGPL-3.0-or-later

package passkeystest

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

const opts = `{"publicKey":{"challenge":"Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2U","rp":{"id":"shepherd.example.com","name":"Shepherd"},"rpId":"shepherd.example.com","user":{"id":"dXNlcg"}}}`

// The responses must parse with the library's own parsers, carry the
// expected flags and RP ID hash, and echo the challenge and origin: the
// rest of the suite relies on this helper producing what a browser would.
func TestResponsesAreWhatABrowserWouldSend(t *testing.T) {
	a := New("https://shepherd.example.com:8443")
	reg, err := a.Register([]byte(opts))
	if err != nil {
		t.Fatal(err)
	}
	pr, err := protocol.ParseCredentialCreationResponseBytes(reg)
	if err != nil {
		t.Fatalf("registration does not parse: %v", err)
	}
	ad := pr.Response.AttestationObject.AuthData
	h := sha256.Sum256([]byte("shepherd.example.com"))
	if !bytes.Equal(ad.RPIDHash, h[:]) || !ad.Flags.UserPresent() || !ad.Flags.UserVerified() || !ad.Flags.HasAttestedCredentialData() {
		t.Errorf("registration auth data = %+v", ad)
	}
	if !bytes.Equal(ad.AttData.CredentialID, a.CredentialID()) || pr.Response.AttestationObject.Format != "none" {
		t.Errorf("credential id or format wrong: %q", pr.Response.AttestationObject.Format)
	}
	if pr.Response.CollectedClientData.Origin != "https://shepherd.example.com:8443" || pr.Response.CollectedClientData.Type != "webauthn.create" {
		t.Errorf("client data = %+v", pr.Response.CollectedClientData)
	}

	a.BackupEligible, a.BackedUp = true, true
	login, err := a.Login([]byte(opts))
	if err != nil {
		t.Fatal(err)
	}
	pa, err := protocol.ParseCredentialRequestResponseBytes(login)
	if err != nil {
		t.Fatalf("assertion does not parse: %v", err)
	}
	if !bytes.Equal(pa.Response.UserHandle, []byte("user")) || pa.Response.CollectedClientData.Type != "webauthn.get" {
		t.Errorf("assertion = %+v", pa.Response)
	}
	if f := pa.Response.AuthenticatorData.Flags; !f.HasBackupEligible() || !f.HasBackupState() {
		t.Errorf("backup flags not set: %v", f)
	}
	if a.SignCount != 1 {
		t.Errorf("the counter should advance after a login, got %d", a.SignCount)
	}
}

func TestKnobsAndClones(t *testing.T) {
	a := New("https://shepherd.example.com")
	a.Type, a.Challenge, a.RPID, a.UserHandle, a.UserVerified = "webauthn.other", "Zm9v", "other.example.com", []byte("x"), false
	b, err := a.Login([]byte(opts))
	if err != nil {
		t.Fatal(err)
	}
	pa, err := protocol.ParseCredentialRequestResponseBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("other.example.com"))
	cd := pa.Response.CollectedClientData
	if cd.Type != "webauthn.other" || cd.Challenge != "Zm9v" || !bytes.Equal(pa.Response.AuthenticatorData.RPIDHash, h[:]) || !bytes.Equal(pa.Response.UserHandle, []byte("x")) || pa.Response.AuthenticatorData.Flags.UserVerified() {
		t.Errorf("knobs ignored: %+v", pa.Response)
	}
	c := a.Clone()
	if !bytes.Equal(c.CredentialID(), a.CredentialID()) || c.key != a.key {
		t.Error("a clone holds the same credential and key")
	}
	i := a.Impostor()
	if !bytes.Equal(i.CredentialID(), a.CredentialID()) || i.key == a.key {
		t.Error("an impostor holds the same credential id but another key")
	}
}

func TestBadOptions(t *testing.T) {
	a := New("https://shepherd.example.com")
	for _, o := range []string{"{not json", `{"publicKey":{}}`} {
		if _, err := a.Register([]byte(o)); err == nil {
			t.Errorf("Register(%q) should fail", o)
		}
		if _, err := a.Login([]byte(o)); err == nil {
			t.Errorf("Login(%q) should fail", o)
		}
	}
	if _, err := a.Register([]byte(`{"publicKey":{"challenge":"abc","user":{"id":"!!"}}}`)); err == nil {
		t.Error("a user id that is not base64url should fail")
	}
}
