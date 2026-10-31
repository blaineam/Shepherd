// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeCloudflare is a minimal in-memory stand-in for the three Cloudflare
// API v4 endpoints CloudflareProvider uses: zone lookup, record create and
// record delete. It never touches the network itself (httptest.Server binds
// to loopback only), and records every request it receives so tests can
// assert on exactly what was sent.
type fakeCloudflare struct {
	zones      map[string]string // zone name -> zone id
	wantToken  string
	records    map[string]map[string]string // zoneID -> recordID -> content
	nextRecord int
	requests   []string // "METHOD path" for assertions
}

func newFakeCloudflare(t *testing.T, zones map[string]string) *httptest.Server {
	t.Helper()
	fc := &fakeCloudflare{zones: zones, wantToken: "test-token-1234", records: map[string]map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fc.requests = append(fc.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if got := r.Header.Get("Authorization"); got != "Bearer "+fc.wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 9109, "message": "invalid token"}}})
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			name := r.URL.Query().Get("name")
			var result []map[string]string
			if id, ok := fc.zones[name]; ok {
				result = []map[string]string{{"id": id}}
			} else if name == "" {
				for _, id := range fc.zones { // no filter: every zone the token can see
					result = append(result, map[string]string{"id": id})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dns_records") && strings.HasPrefix(r.URL.Path, "/zones/"):
			var body struct {
				Type, Name, Content string
				TTL                 int
			}
			json.NewDecoder(r.Body).Decode(&body)
			zoneID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/zones/"), "/dns_records")
			if _, ok := fc.records[zoneID]; !ok {
				fc.records[zoneID] = map[string]string{}
			}
			fc.nextRecord++
			id := "rec" + itoa(fc.nextRecord)
			fc.records[zoneID][id] = body.Content
			json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": map[string]string{"id": id}})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/dns_records/"):
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/zones/"), "/dns_records/")
			zoneID, recID := parts[0], parts[1]
			if recs, ok := fc.records[zoneID]; ok {
				delete(recs, recID)
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": map[string]string{"id": recID}})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 404, "message": "not found"}}})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestCloudflarePresentAndCleanUp(t *testing.T) {
	srv := newFakeCloudflare(t, map[string]string{"fort.example.com": "zone-abc"})
	p := &CloudflareProvider{APIToken: "test-token-1234", BaseURL: srv.URL}

	recordID, err := p.Present(context.Background(), "_acme-challenge.shepherd.fort.example.com", "the-digest-value")
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if recordID == "" {
		t.Fatal("Present returned an empty record id")
	}

	if err := p.CleanUp(context.Background(), "_acme-challenge.shepherd.fort.example.com", recordID); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
}

func TestCloudflareFindsZoneByWalkingLabelsOutward(t *testing.T) {
	// Only the apex, two labels up from the hostname, is a real zone; the
	// provider must not stop at "shepherd.fort.example.com" or
	// "fort.example.com" and must not need either configured separately.
	srv := newFakeCloudflare(t, map[string]string{"example.com": "zone-apex"})
	p := &CloudflareProvider{APIToken: "test-token-1234", BaseURL: srv.URL}

	if _, err := p.Present(context.Background(), "_acme-challenge.shepherd.fort.example.com", "v"); err != nil {
		t.Fatalf("Present: %v", err)
	}
}

func TestCloudflareNoZoneFound(t *testing.T) {
	srv := newFakeCloudflare(t, map[string]string{})
	p := &CloudflareProvider{APIToken: "test-token-1234", BaseURL: srv.URL}

	if _, err := p.Present(context.Background(), "_acme-challenge.shepherd.fort.example.com", "v"); err == nil {
		t.Fatal("expected an error when no zone matches")
	}
}

func TestCloudflareBadToken(t *testing.T) {
	srv := newFakeCloudflare(t, map[string]string{"fort.example.com": "zone-abc"})
	p := &CloudflareProvider{APIToken: "wrong-token", BaseURL: srv.URL}

	if _, err := p.Present(context.Background(), "_acme-challenge.shepherd.fort.example.com", "v"); err == nil {
		t.Fatal("expected an error for a bad token")
	}
}

func TestCloudflareProviderDefaults(t *testing.T) {
	p := &CloudflareProvider{}
	if got := p.baseURL(); got != CloudflareBaseURL {
		t.Errorf("baseURL() = %q, want %q", got, CloudflareBaseURL)
	}
	if got := p.client(); got != http.DefaultClient {
		t.Error("client() must default to http.DefaultClient")
	}
}

func TestCloudflareDecodingErrorFromBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)
	p := &CloudflareProvider{APIToken: "t", BaseURL: srv.URL}
	if _, err := p.Present(context.Background(), "_acme-challenge.shepherd.fort.example.com", "v"); err == nil {
		t.Fatal("expected a decoding error from a non-JSON response")
	}
}

func TestCloudflareCleanUpAPIError(t *testing.T) {
	srv := newFakeCloudflare(t, map[string]string{"fort.example.com": "zone-abc"})
	p := &CloudflareProvider{APIToken: "test-token-1234", BaseURL: srv.URL}
	// Deleting an id that was never created still succeeds against the fake
	// (Cloudflare's own API is idempotent about this), so instead force a
	// zone lookup failure path by cleaning up against an fqdn with no zone.
	if err := p.CleanUp(context.Background(), "_acme-challenge.nowhere.invalid", "rec1"); err == nil {
		t.Fatal("expected an error when the zone cannot be found")
	}
}

func TestCloudflareVerifyChecksEveryNameWithReadOnlyCalls(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Query().Get("name"))
		var result []map[string]string
		if r.URL.Query().Get("name") == "example.com" {
			result = []map[string]string{{"id": "zone-apex"}}
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	t.Cleanup(srv.Close)
	p := &CloudflareProvider{APIToken: "test-token-1234", BaseURL: srv.URL}
	if err := p.Verify(context.Background(), "*.example.com", "shepherd.fort.example.com.", "example.com"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := []string{
		"GET example.com",                                                          // *.example.com: the wildcard's challenge lives at the base
		"GET shepherd.fort.example.com", "GET fort.example.com", "GET example.com", // walked outward
		"GET example.com",
	}
	if strings.Join(requests, ",") != strings.Join(want, ",") {
		t.Errorf("requests = %q, want %q (zone lookups only, never a write)", requests, want)
	}
}

func TestCloudflareVerifyWithoutNamesNeedsSomeZone(t *testing.T) {
	srv := newFakeCloudflare(t, map[string]string{"example.com": "zone-apex"})
	if err := (&CloudflareProvider{APIToken: "test-token-1234", BaseURL: srv.URL}).Verify(context.Background()); err != nil {
		t.Errorf("a token that sees a zone: %v", err)
	}
	empty := newFakeCloudflare(t, map[string]string{})
	if err := (&CloudflareProvider{APIToken: "test-token-1234", BaseURL: empty.URL}).Verify(context.Background()); err == nil || !strings.Contains(err.Error(), "zone") {
		t.Errorf("a token that sees no zone must fail and say why: %v", err)
	}
	if err := (&CloudflareProvider{APIToken: "wrong", BaseURL: srv.URL}).Verify(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("a rejected token must fail with Cloudflare's reason: %v", err)
	}
}

func TestCloudflareVerifyFailures(t *testing.T) {
	srv := newFakeCloudflare(t, map[string]string{"example.com": "zone-apex"})
	p := &CloudflareProvider{APIToken: "wrong", BaseURL: srv.URL}
	if err := p.Verify(context.Background(), "example.com"); err == nil {
		t.Error("a rejected token must fail")
	}
	p.APIToken = "test-token-1234"
	if err := p.Verify(context.Background(), "*.example.net"); err == nil || !strings.Contains(err.Error(), "example.net") {
		t.Errorf("a name in a zone the token cannot see must fail and name it: %v", err)
	}
	if err := p.Verify(context.Background(), "", " "); err != nil {
		t.Errorf("blank names are skipped, falling back to any zone: %v", err)
	}
	down := &CloudflareProvider{APIToken: "t", BaseURL: "http://127.0.0.1:1"}
	if err := down.Verify(context.Background()); err == nil {
		t.Error("an unreachable API must fail")
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) }))
	t.Cleanup(garbage.Close)
	if err := (&CloudflareProvider{APIToken: "t", BaseURL: garbage.URL}).Verify(context.Background()); err == nil {
		t.Error("an undecodable answer must fail")
	}
}
