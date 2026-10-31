// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	"shepherd/internal/passkeys/passkeystest"
)

var updatePasskeyFixture = flag.Bool("update-passkey-fixture", false, "regenerate web/test/fixtures/passkeys.json from a real ceremony")

const passkeyFixture = "web/test/fixtures/passkeys.json"

type passkeyFixtureFile struct {
	Creation     json.RawMessage `json:"creation"`
	Registration json.RawMessage `json:"registration"`
	Request      json.RawMessage `json:"request"`
	Assertion    json.RawMessage `json:"assertion"`
}

// The frontend's passkeys.js is tested (test/passkeys.test.js) against a
// fixture of exactly what this server sends and accepts: options from the
// real begin endpoints, and the responses a browser posts back (from the
// software authenticator). This test keeps that fixture honest: it must
// parse with go-webauthn's own parsers, so a JS change that still matches
// the fixture byte for byte still produces bodies the server can read.
// Regenerate with: go test ./internal/portal -run PasskeyWebFixture -update-passkey-fixture
func TestPasskeyWebFixtureMatchesTheServer(t *testing.T) {
	if *updatePasskeyFixture {
		p := passkeyHarness(t, nil)
		c := p.browserUnlocked()
		a := passkeystest.New(pkOrigin)
		var f passkeyFixtureFile
		f.Creation = readAll(t, p.send(c, "POST", "/api/passkeys/register/begin", `{"name":"fixture"}`))
		reg, err := a.Register(f.Creation)
		if err != nil {
			t.Fatal(err)
		}
		f.Registration = reg
		if res := p.send(c, "POST", "/api/passkeys/register/finish", string(reg)); res.StatusCode != 200 {
			t.Fatalf("finish = %d", res.StatusCode)
		}
		f.Request = readAll(t, p.send(c, "POST", "/api/login/passkey/begin", ""))
		if f.Assertion, err = a.Login(f.Request); err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(f, "", "  ")
		if err := os.WriteFile(passkeyFixture, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(passkeyFixture)
	if err != nil {
		t.Fatal(err)
	}
	var f passkeyFixtureFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ParseCredentialCreationResponseBytes(f.Registration); err != nil {
		t.Errorf("the fixture's registration no longer parses: %v", err)
	}
	if _, err := protocol.ParseCredentialRequestResponseBytes(f.Assertion); err != nil {
		t.Errorf("the fixture's assertion no longer parses: %v", err)
	}
	var creation protocol.CredentialCreation
	if err := json.Unmarshal(f.Creation, &creation); err != nil || len(creation.Response.Challenge) == 0 || creation.Response.RelyingParty.ID != pkHost {
		t.Errorf("the fixture's creation options = %+v, %v", creation.Response, err)
	}
	var request protocol.CredentialAssertion
	if err := json.Unmarshal(f.Request, &request); err != nil || len(request.Response.AllowedCredentials) != 1 {
		t.Errorf("the fixture's request options = %+v, %v", request.Response, err)
	}
}
