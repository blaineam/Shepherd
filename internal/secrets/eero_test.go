// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const eeroToken = "eero-session-token-0123"

func TestEeroSessionIsStoredKeptAndForgotten(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s := openAt(t, path)
	if _, ok := s.Eero(); ok {
		t.Fatal("a fresh store holds no eero session")
	}

	got, err := s.SetEero(Eero{Token: "  " + eeroToken + "  ", NetworkID: " net-1 ", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != eeroToken || got.NetworkID != "net-1" || got.Source != SourcePortal {
		t.Fatalf("saved %+v, want it trimmed and marked portal-owned", got)
	}

	// It survives a reload, which is the point: no new code each restart.
	again, ok := openAt(t, path).Eero()
	if !ok || again.Token != eeroToken || !again.Enabled || again.NetworkID != "net-1" {
		t.Fatalf("after reload = %+v, %v", again, ok)
	}

	// The switch moves without disturbing the token.
	if ok, err := s.SetEeroEnabled(false); err != nil || !ok {
		t.Fatalf("SetEeroEnabled = %v, %v", ok, err)
	}
	e, _ := s.Eero()
	if e.Enabled || e.Token != eeroToken {
		t.Fatalf("after switching off = %+v, want the token kept", e)
	}

	// So does the chosen network.
	if ok, err := s.SetEeroNetwork(" net-2 "); err != nil || !ok {
		t.Fatalf("SetEeroNetwork = %v, %v", ok, err)
	}
	if e, _ := s.Eero(); e.NetworkID != "net-2" || e.Token != eeroToken {
		t.Fatalf("after choosing a network = %+v", e)
	}

	if err := s.ClearEero(); err != nil {
		t.Fatal(err)
	}
	if e, ok := s.Eero(); ok || e.Configured() {
		t.Fatalf("after clearing = %+v, %v", e, ok)
	}
	// Clearing is remembered, so a reload does not resurrect it.
	if _, ok := openAt(t, path).Eero(); ok {
		t.Fatal("a cleared session came back after a reload")
	}
}

func TestEeroSettersDoNothingWithoutAStoredSession(t *testing.T) {
	s := openAt(t, "")
	if ok, err := s.SetEeroEnabled(true); ok || err != nil {
		t.Fatalf("SetEeroEnabled on an empty store = %v, %v", ok, err)
	}
	if ok, err := s.SetEeroNetwork("net-1"); ok || err != nil {
		t.Fatalf("SetEeroNetwork on an empty store = %v, %v", ok, err)
	}
}

func TestEeroRefusesValuesItCouldNotStoreSafely(t *testing.T) {
	s := openAt(t, "")
	for name, e := range map[string]Eero{
		"no token":           {NetworkID: "n"},
		"blank token":        {Token: "   ", NetworkID: "n"},
		"control character":  {Token: "abc\ndef"},
		"space in the token": {Token: "abc def"},
		"absurd length":      {Token: strings.Repeat("x", maxLen+1)},
		"bad network":        {Token: eeroToken, NetworkID: "net\n1"},
	} {
		if _, err := s.SetEero(e); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// And a network id that could not be stored leaves the session alone.
	if _, err := s.SetEero(Eero{Token: eeroToken, NetworkID: "n"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetEeroNetwork("bad\nid"); ok || !errors.Is(err, ErrInvalid) {
		t.Fatalf("SetEeroNetwork = %v, %v", ok, err)
	}
	if e, _ := s.Eero(); e.NetworkID != "n" {
		t.Fatalf("a refused network id changed the stored one: %+v", e)
	}
}

func TestEeroNeverFormatsItsToken(t *testing.T) {
	var unset Eero
	if !strings.Contains(unset.String(), "not set") {
		t.Fatalf("unset = %q", unset.String())
	}
	e := Eero{Token: eeroToken, NetworkID: "net-1", Enabled: true, Meta: Meta{Source: SourcePortal}}
	for _, s := range []string{e.String(), e.GoString()} {
		if strings.Contains(s, eeroToken) {
			t.Fatalf("the token leaked into %q", s)
		}
		if !strings.Contains(s, "net-1") {
			t.Fatalf("%q should still say which network", s)
		}
	}
}

func TestAStoredSessionThatIsNotValidRefusesToLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(`{"version":1,"eero":{"token":"has a space","network_id":"n"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted an unusable stored session")
	}
}

func TestEeroTokenStoreIsTheClientsViewOfTheStore(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), FileName))
	ts := EeroTokenStore{S: s}

	tok, err := ts.Load()
	if err != nil || tok != "" {
		t.Fatalf("Load on an empty store = %q, %v", tok, err)
	}
	if err := ts.Save(eeroToken); err != nil {
		t.Fatal(err)
	}
	if tok, _ := ts.Load(); tok != eeroToken {
		t.Fatalf("Load = %q", tok)
	}
	// Saving again keeps the network and the switch already chosen.
	if _, err := s.SetEeroNetwork("net-9"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetEeroEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := ts.Save("a-newer-token"); err != nil {
		t.Fatal(err)
	}
	e, _ := s.Eero()
	if e.Token != "a-newer-token" || e.NetworkID != "net-9" || !e.Enabled {
		t.Fatalf("after re-saving the token = %+v", e)
	}
	if err := ts.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Eero(); ok {
		t.Fatal("Delete left a session behind")
	}
}

// The portal records the network and the switch together: two writes
// could leave a network chosen with the reader off if the second failed.
func TestSetEeroConnectionRecordsBothInOneWrite(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), FileName))
	if ok, err := s.SetEeroConnection("net-1", true); ok || err != nil {
		t.Fatalf("with nothing stored = %v, %v", ok, err)
	}
	if _, err := s.SetEero(Eero{Token: eeroToken}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetEeroConnection(" net-7 ", true); !ok || err != nil {
		t.Fatalf("= %v, %v", ok, err)
	}
	e, _ := s.Eero()
	if e.NetworkID != "net-7" || !e.Enabled || e.Token != eeroToken {
		t.Fatalf("stored = %+v", e)
	}
	if ok, err := s.SetEeroConnection("bad\nid", true); ok || !errors.Is(err, ErrInvalid) {
		t.Fatalf("a bad network id = %v, %v", ok, err)
	}
	if e, _ := s.Eero(); e.NetworkID != "net-7" {
		t.Fatalf("a refused write changed the stored network: %+v", e)
	}
}
