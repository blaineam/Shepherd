// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"strings"
	"testing"

	"shepherd/internal/accountability"
)

// withAccountability wires a real, in-memory accountability engine into an
// existing harness, the way cmd/shepherd's startAccountability would once an
// SMTP relay is configured. The FakeSender never touches the network; no
// digest ever fires within a test's lifetime, so Options.Dir is left unset
// (nothing to persist).
func (h *harness) withAccountability() *accountability.Engine {
	h.t.Helper()
	eng, err := accountability.New(accountability.Options{Sender: &accountability.FakeSender{}, From: "shepherd@example.com"})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { eng.Close() })
	h.srv.Accountability = eng
	return eng
}

func TestAccountabilityNotConfiguredAnswers404(t *testing.T) {
	h := newHarness(t)
	h.expect("GET", "/api/accountability/contacts", "", 404)
	h.expect("POST", "/api/accountability/contacts", `{"name":"Jordan","email":"jordan@example.net"}`, 404)
	h.expect("DELETE", "/api/accountability/contacts/x", "", 404)
	h.expect("GET", "/api/accountability/subscriptions", "", 404)
	h.expect("POST", "/api/accountability/subscriptions", `{}`, 404)
	h.expect("DELETE", "/api/accountability/subscriptions/x", "", 404)
}

func TestAccountabilityContactsCRUD(t *testing.T) {
	h := newHarness(t)
	h.withAccountability()

	c := h.ok("POST", "/api/accountability/contacts", `{"name":"Jordan","email":"jordan@example.net"}`, 200)
	id, _ := c["id"].(string)
	if id == "" || c["name"] != "Jordan" || c["email"] != "jordan@example.net" {
		t.Fatalf("created contact = %+v", c)
	}

	list := h.ok("GET", "/api/accountability/contacts", "", 200)
	contacts, _ := list["contacts"].([]any)
	if len(contacts) != 1 {
		t.Fatalf("contacts = %+v", list)
	}

	h.expect("POST", "/api/accountability/contacts", `{"name":"Nobody","email":"not-an-address"}`, 400)
	h.expect("DELETE", "/api/accountability/contacts/nope", "", 404)
	h.expect("DELETE", "/api/accountability/contacts/"+id, "", 200)

	list = h.ok("GET", "/api/accountability/contacts", "", 200)
	if contacts, _ := list["contacts"].([]any); len(contacts) != 0 {
		t.Errorf("contacts after delete = %+v", list)
	}
}

func TestAccountabilitySubscriptionsCRUD(t *testing.T) {
	h := newHarness(t)
	h.withAccountability()
	deviceID := h.addDevice("02:00:5e:00:00:03", "203.0.113.20", "")
	group, err := h.reg.CreateGroup("Family Devices", "")
	if err != nil {
		t.Fatal(err)
	}

	c := h.ok("POST", "/api/accountability/contacts", `{"name":"Avery","email":"avery@example.net"}`, 200)
	contactID := c["id"].(string)

	// Network scope is deliberately not accepted here, unlike /api/policy/*.
	h.expect("POST", "/api/accountability/subscriptions", `{"contact_id":"`+contactID+`","scope":{"kind":"network"},"items":["ads"]}`, 400)
	// An unknown device is a 404, not a silently-accepted scope.
	h.expect("POST", "/api/accountability/subscriptions", `{"contact_id":"`+contactID+`","scope":{"kind":"device","id":"nope"},"items":["ads"]}`, 404)
	// No items at all.
	h.expect("POST", "/api/accountability/subscriptions", `{"contact_id":"`+contactID+`","scope":{"kind":"device","id":"`+deviceID+`"},"items":[]}`, 400)
	// An item that is neither a catalog entry nor the wildcard.
	h.expect("POST", "/api/accountability/subscriptions", `{"contact_id":"`+contactID+`","scope":{"kind":"device","id":"`+deviceID+`"},"items":["not-a-real-item"]}`, 404)
	// A negative digest interval.
	h.expect("POST", "/api/accountability/subscriptions", `{"contact_id":"`+contactID+`","scope":{"kind":"device","id":"`+deviceID+`"},"items":["ads"],"digest_interval_seconds":-1}`, 400)

	sub := h.ok("POST", "/api/accountability/subscriptions", `{"contact_id":"`+contactID+`","scope":{"kind":"device","id":"`+deviceID+`"},"items":["ads"]}`, 200)
	subID, _ := sub["id"].(string)
	if subID == "" || sub["detail"] != "summary" || sub["mode"] != "digest" || sub["trigger"] != "any" {
		t.Fatalf("defaults were not applied: %+v", sub)
	}
	scope, _ := sub["scope"].(map[string]any)
	if scope["kind"] != "device" || scope["id"] != deviceID {
		t.Errorf("scope = %+v", scope)
	}

	// A group scope with the wildcard item and explicit detail/mode/trigger.
	groupSub := h.ok("POST", "/api/accountability/subscriptions", `{"contact_id":"`+contactID+`","scope":{"kind":"group","id":"`+group.ID+`"},"items":["*"],"detail":"detailed","mode":"immediate","trigger":"blocked_only","digest_interval_seconds":3600}`, 200)
	if groupSub["detail"] != "detailed" || groupSub["mode"] != "immediate" || groupSub["trigger"] != "blocked_only" || groupSub["digest_interval_seconds"] != float64(3600) {
		t.Errorf("explicit fields were not honored: %+v", groupSub)
	}

	list := h.ok("GET", "/api/accountability/subscriptions", "", 200)
	all, _ := list["subscriptions"].([]any)
	if len(all) != 2 {
		t.Fatalf("subscriptions = %+v", list)
	}
	filtered := h.ok("GET", "/api/accountability/subscriptions?contact_id="+contactID, "", 200)
	if mine, _ := filtered["subscriptions"].([]any); len(mine) != 2 {
		t.Errorf("filtered subscriptions = %+v", filtered)
	}

	h.expect("DELETE", "/api/accountability/subscriptions/nope", "", 404)
	h.expect("DELETE", "/api/accountability/subscriptions/"+subID, "", 200)
	list = h.ok("GET", "/api/accountability/subscriptions", "", 200)
	if left, _ := list["subscriptions"].([]any); len(left) != 1 {
		t.Errorf("subscriptions after delete = %+v", list)
	}

	// Removing the contact cascades to its remaining subscription.
	h.expect("DELETE", "/api/accountability/contacts/"+contactID, "", 200)
	list = h.ok("GET", "/api/accountability/subscriptions", "", 200)
	if left, _ := list["subscriptions"].([]any); len(left) != 0 {
		t.Errorf("subscriptions after the contact is removed = %+v", list)
	}
}

func TestAccountabilitySubscriptionUnknownContact(t *testing.T) {
	h := newHarness(t)
	h.withAccountability()
	deviceID := h.addDevice("02:00:5e:00:00:04", "203.0.113.21", "")
	_, body := h.call("POST", "/api/accountability/subscriptions", `{"contact_id":"nope","scope":{"kind":"device","id":"`+deviceID+`"},"items":["ads"]}`)
	if !strings.Contains(body, "not found") {
		t.Errorf("body = %q, want a not-found error", body)
	}
}
