// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"testing"

	"shepherd/internal/secrets"
)

const testNtfyToken = "tk-ntfy-portal-test"

func TestNtfyStartsEmptyWithAUsableDefaultTopic(t *testing.T) {
	h := newHarness(t)
	h.withSecrets()
	got := h.ok("GET", "/api/alarms/ntfy", "", 200)
	if got["configured"] != false || got["enabled"] != false {
		t.Errorf("empty = %+v", got)
	}
	if got["topic"] != defaultNtfyTopic {
		t.Errorf("topic = %v, want the default so the form is never blank", got["topic"])
	}
	if _, has := got["source"]; has {
		t.Error("nothing saved yet: no source")
	}
}

func TestNtfySaveIsCheckedByPublishingWriteOnlyAndApplied(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	body := `{"server":"https://ntfy.example.com","topic":"shepherd-abc","token":"` + testNtfyToken + `"}`
	got := h.ok("PUT", "/api/alarms/ntfy", body, 200)
	if got["configured"] != true || got["enabled"] != true || got["has_token"] != true {
		t.Errorf("saved = %+v", got)
	}
	if got["source"] != secrets.SourcePortal {
		t.Errorf("source = %v", got["source"])
	}
	// The check is a real publish, so the owner sees it arrive.
	sent := rig.ntfy()
	if len(sent) != 1 || sent[0].Token != testNtfyToken {
		t.Errorf("the server should have been checked by publishing once, got %+v", sent)
	}
	// The running process is told, so no restart is needed.
	if changed := rig.changes(); len(changed) != 1 || changed[0] != SecretNtfy {
		t.Errorf("changes = %v", changed)
	}
	n, ok := store.Ntfy()
	if !ok || n.Token != testNtfyToken || !n.Enabled {
		t.Errorf("stored = %s", n)
	}
	_, raw := h.call("GET", "/api/alarms/ntfy", "")
	noSecretIn(t, raw, testNtfyToken)
}

func TestNtfyRefusedByTheServerStoresNothing(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	rig.set(func(r *secretsRig) { r.ntfyErr = errors.New("ntfy answered 403 forbidden") })
	h.expect("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"t","token":"x"}`, 422)
	if _, ok := store.Ntfy(); ok {
		t.Error("a refused server must not be stored")
	}
	if changed := rig.changes(); len(changed) != 0 {
		t.Errorf("nothing changed, so nothing should have been applied: %v", changed)
	}
}

func TestNtfyRejectsWhatThePublisherCouldNotUse(t *testing.T) {
	h := newHarness(t)
	h.withSecrets()
	for _, body := range []string{
		`{"server":"","topic":"t"}`,
		`{"server":"ntfy.example.com","topic":"t"}`,             // no scheme
		`{"server":"https://ntfy.example.com","topic":"a b"}`,   // a topic ntfy would refuse
		`{"server":"https://ntfy.example.com","topic":""}`,      // becomes the default, which is valid
		`{"server":"https://u:p@ntfy.example.com","topic":"t"}`, // credentials in the URL // leakcheck:allow fixture: credentials-in-URL test value
		`{"server":"https://ntfy.example.com","topic":"t","token":"x","username":"u","password":"p"}`,
	} {
		code, out := h.call("PUT", "/api/alarms/ntfy", body)
		if body == `{"server":"https://ntfy.example.com","topic":""}` {
			if code != 200 {
				t.Errorf("an empty topic should take the default: %d %s", code, out)
			}
			continue
		}
		if code != 400 {
			t.Errorf("%s = %d, want 400: %s", body, code, out)
		}
	}
}

func TestNtfyKeepsAStoredTokenForTheSameServerOnly(t *testing.T) {
	h := newHarness(t)
	store, _ := h.withSecrets()
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"t","token":"`+testNtfyToken+`"}`, 200)

	// Same server, blank token: the stored one is kept, so the owner does
	// not have to find it again to change the topic.
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"other"}`, 200)
	n, _ := store.Ntfy()
	if n.Token != testNtfyToken || n.Topic != "other" {
		t.Errorf("after a topic change = %s (token kept: %v)", n, n.Token == testNtfyToken)
	}

	// A different server with a blank token must not inherit it: that
	// would send the owner's token somewhere they never entered it.
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.net","topic":"t"}`, 200)
	n, _ = store.Ntfy()
	if n.Token != "" {
		t.Error("a stored token must not follow the owner to another server")
	}

	// And it can be removed deliberately.
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.net","topic":"t","token":"`+testNtfyToken+`"}`, 200)
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.net","topic":"t","clear_token":true}`, 200)
	if n, _ := store.Ntfy(); n.Token != "" {
		t.Error("clear_token should have removed it")
	}
}

func TestNtfySwitchingToAUsernameDropsTheStoredToken(t *testing.T) {
	// Keeping both would fail validation with a message about setting both
	// at once, which is not what the owner did.
	h := newHarness(t)
	store, _ := h.withSecrets()
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"t","token":"`+testNtfyToken+`"}`, 200)
	got := h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"t","username":"u","password":"pw"}`, 200)
	if got["has_token"] != false || got["username"] != "u" {
		t.Errorf("after switching to a username = %+v", got)
	}
	if n, _ := store.Ntfy(); n.Token != "" || n.Password != "pw" {
		t.Errorf("stored = %s", n)
	}
}

func TestNtfySwitchStopsDeliveryAndKeepsTheServer(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"t","token":"`+testNtfyToken+`"}`, 200)
	got := h.ok("PATCH", "/api/alarms/ntfy", `{"enabled":false}`, 200)
	if got["enabled"] != false || got["configured"] != true {
		t.Errorf("switched off = %+v", got)
	}
	n, _ := store.Ntfy()
	if n.Token != testNtfyToken {
		t.Error("switching off must not forget the credentials")
	}
	if got := h.ok("PATCH", "/api/alarms/ntfy", `{"enabled":true}`, 200); got["enabled"] != true {
		t.Errorf("switched on = %+v", got)
	}
	// Both switches reach the running process.
	if changed := rig.changes(); len(changed) != 3 {
		t.Errorf("changes = %v, want the save and both switches", changed)
	}
}

func TestNtfySwitchNeedsAServerFirst(t *testing.T) {
	h := newHarness(t)
	h.withSecrets()
	h.expect("PATCH", "/api/alarms/ntfy", `{"enabled":true}`, 400)
}

func TestNtfyTestSendsEvenWhileDeliveryIsOff(t *testing.T) {
	// Proving the server works before letting alarms go to it is the whole
	// point of the test button.
	h := newHarness(t)
	_, rig := h.withSecrets()
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"t","enabled":false}`, 200)
	before := len(rig.ntfy())
	if got := h.ok("POST", "/api/alarms/ntfy/test", "", 200); got["sent"] != true {
		t.Errorf("test = %+v", got)
	}
	if len(rig.ntfy()) != before+1 {
		t.Error("the test should have published once")
	}
	rig.set(func(r *secretsRig) { r.ntfyErr = errors.New("ntfy answered 401 unauthorized") })
	h.expect("POST", "/api/alarms/ntfy/test", "", 422)
}

func TestNtfyTestNeedsAStoredServerAndAPublisher(t *testing.T) {
	h := newHarness(t)
	store, _ := h.withSecrets()
	h.expect("POST", "/api/alarms/ntfy/test", "", 400)
	if _, err := store.SetNtfy(secrets.Ntfy{Server: "https://ntfy.example.com", Topic: "t"}); err != nil {
		t.Fatal(err)
	}
	h.srv.VerifyNtfy = nil
	h.expect("POST", "/api/alarms/ntfy/test", "", 404)
}

func TestNtfyCanBeForgotten(t *testing.T) {
	h := newHarness(t)
	store, rig := h.withSecrets()
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"t","token":"`+testNtfyToken+`"}`, 200)
	got := h.ok("DELETE", "/api/alarms/ntfy", "", 200)
	if got["configured"] != false || got["enabled"] != false {
		t.Errorf("forgotten = %+v", got)
	}
	if _, ok := store.Ntfy(); ok {
		t.Error("the server should be gone")
	}
	// Still managed by the portal, so shepherd.toml's copy is not imported
	// again at the next start.
	if !store.NtfyManaged() {
		t.Error("clearing is a decision the store has to remember")
	}
	if changed := rig.changes(); changed[len(changed)-1] != SecretNtfy {
		t.Errorf("changes = %v", changed)
	}
}

func TestPushDocumentFollowsTheStoredNtfyServer(t *testing.T) {
	h := newHarness(t)
	h.withSecrets()
	h.ok("PUT", "/api/alarms/ntfy", `{"server":"https://ntfy.example.com","topic":"shepherd-x"}`, 200)
	n := h.ok("GET", "/api/alarms/push", "", 200)["ntfy"].(map[string]any)
	if n["enabled"] != true || n["server"] != "https://ntfy.example.com" || n["topic"] != "shepherd-x" {
		t.Errorf("ntfy status = %v", n)
	}
	if len(n) != 3 {
		t.Errorf("the status must carry nothing else, got %v", n)
	}
}

func TestNtfyAvailabilityFollowsTheAlarmEngine(t *testing.T) {
	h := newHarness(t)
	h.withSecrets()
	// The harness wires an alarm engine; without one nothing is delivered
	// whatever is stored, and the screen has to say so.
	if got := h.ok("GET", "/api/alarms/ntfy", "", 200); got["available"] != true {
		t.Errorf("available = %+v", got)
	}
	h.srv.Alarms = nil
	if got := h.ok("GET", "/api/alarms/ntfy", "", 200); got["available"] != false {
		t.Errorf("available with no alarm engine = %+v", got)
	}
}
