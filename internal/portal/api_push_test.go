// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"shepherd/internal/alarms"
	"shepherd/internal/webpush"
)

// fakePush is a PushService over a real webpush.Store with a fixed key:
// cmd/shepherd's own service is tested there; what matters here is that
// the API drives it faithfully and never leaks an endpoint or a key.
type fakePush struct{ store *webpush.Store }

func newFakePush() *fakePush {
	return &fakePush{store: webpush.NewStore(webpush.StoreOptions{NodeID: "test"})}
}
func (f *fakePush) PublicKey() string            { return "BPUBLICKEY" }
func (f *fakePush) Devices() []webpush.Device    { return f.store.List() }
func (f *fakePush) Rename(id, name string) error { return f.store.Rename(id, name) }
func (f *fakePush) Remove(id string) error       { return f.store.Remove(id) }
func (f *fakePush) Subscribe(sub webpush.BrowserSubscription, name, ua string) (webpush.Device, error) {
	return f.store.Add(sub, name, ua)
}

var _ PushService = (*fakePush)(nil)

// brokenPush fails every mutation with an error that is not "not found".
type brokenPush struct{ fakePush }

func (b *brokenPush) Remove(string) error { return errors.New("disk full") }

func TestPushReportsOtherFailuresAsBadRequests(t *testing.T) {
	h := newHarness(t)
	h.srv.Push = &brokenPush{*newFakePush()}
	h.expect("DELETE", "/api/alarms/push/x", "", 400)
}

// testP256dh is a real P-256 public point, generated per run, since the
// store refuses a key that is not one.
var testP256dh = func() string {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}()

var subJSON = `{"subscription":{"endpoint":"https://push.example.net/send/abcdef","keys":{"p256dh":"` + testP256dh + `","auth":"tBHItJI5svbpez7KI4CCXg"}},"name":"  Phone  "}`

func TestPushReportsOffWithoutAService(t *testing.T) {
	h := newHarness(t)
	out := h.ok("GET", "/api/alarms/push", "", 200)
	if out["enabled"] != false || len(out["devices"].([]any)) != 0 {
		t.Fatalf("status = %v", out)
	}
	if _, has := out["public_key"]; has {
		t.Fatal("no key when off")
	}
	h.expect("POST", "/api/alarms/push/subscribe", subJSON, 404)
	h.expect("PATCH", "/api/alarms/push/x", `{"name":"a"}`, 404)
	h.expect("DELETE", "/api/alarms/push/x", "", 404)
}

func TestPushSubscribeRenameRemoveAndTest(t *testing.T) {
	h := newHarness(t)
	h.srv.Push = newFakePush()

	out := h.ok("GET", "/api/alarms/push", "", 200)
	if out["enabled"] != true || out["public_key"] != "BPUBLICKEY" {
		t.Fatalf("status = %v", out)
	}
	d := h.ok("POST", "/api/alarms/push/subscribe", subJSON, 200)
	id, _ := d["id"].(string)
	if id == "" || d["name"] != "Phone" || d["service"] != "push.example.net" {
		t.Fatalf("subscribed = %v", d)
	}
	for _, k := range []string{"endpoint", "p256dh", "auth", "keys"} {
		if _, leaked := d[k]; leaked {
			t.Fatalf("the device JSON leaks %q", k)
		}
	}
	list := h.ok("GET", "/api/alarms/push", "", 200)["devices"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["id"] != id {
		t.Fatalf("devices = %v", list)
	}
	// Subscribing the same endpoint again updates rather than duplicates.
	h.ok("POST", "/api/alarms/push/subscribe", strings.Replace(subJSON, "Phone", "Same phone", 1), 200)
	if n := len(h.ok("GET", "/api/alarms/push", "", 200)["devices"].([]any)); n != 1 {
		t.Fatalf("devices after re-subscribe = %d, want 1", n)
	}
	h.ok("PATCH", "/api/alarms/push/"+id, `{"name":"Tablet"}`, 200)
	if got := h.ok("GET", "/api/alarms/push", "", 200)["devices"].([]any)[0].(map[string]any)["name"]; got != "Tablet" {
		t.Fatalf("renamed = %v", got)
	}
	h.expect("PATCH", "/api/alarms/push/"+id, `{"name":""}`, 400)
	h.expect("PATCH", "/api/alarms/push/nope", `{"name":"x"}`, 404)
	h.expect("POST", "/api/alarms/push/subscribe", `{"subscription":{"endpoint":""}}`, 400)
	h.expect("POST", "/api/alarms/push/subscribe", `{"subscription":{"endpoint":"http://plain.example/x","keys":{"p256dh":"a","auth":"b"}}}`, 400)
	h.expect("POST", "/api/alarms/push/subscribe", `not json`, 400)

	// The test alarm is raised through the engine, bypassing mutes.
	res := h.ok("POST", "/api/alarms/push/test", "", 200)
	if res["alarm_id"] == "" {
		t.Fatalf("test = %v", res)
	}
	page := h.alarms.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeTest}}})
	if page.Total != 1 || !strings.Contains(page.Alarms[0].Title, "Test notification") {
		t.Fatalf("test alarms = %+v", page)
	}

	h.ok("DELETE", "/api/alarms/push/"+id, "", 200)
	h.expect("DELETE", "/api/alarms/push/"+id, "", 404)
	if n := len(h.ok("GET", "/api/alarms/push", "", 200)["devices"].([]any)); n != 0 {
		t.Fatalf("devices after remove = %d", n)
	}
}

func TestPushStatusReportsNtfyWithoutCredentials(t *testing.T) {
	h := newHarness(t)
	h.srv.Ntfy = NtfyStatus{Enabled: true, Server: "https://ntfy.example.com", Topic: "shepherd-x"}
	n := h.ok("GET", "/api/alarms/push", "", 200)["ntfy"].(map[string]any)
	if n["enabled"] != true || n["server"] != "https://ntfy.example.com" || n["topic"] != "shepherd-x" || len(n) != 3 {
		t.Fatalf("ntfy = %v", n)
	}
	h.srv.Push = newFakePush()
	if n := h.ok("GET", "/api/alarms/push", "", 200)["ntfy"].(map[string]any); n["enabled"] != true {
		t.Fatalf("ntfy with push on = %v", n)
	}
}
