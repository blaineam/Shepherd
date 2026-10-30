// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"shepherd/internal/ntfy"
	"shepherd/internal/webpush"
)

func TestWebPushPusherEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var hdrs []http.Header
	statusFor := map[string]int{"/ok": 201, "/gone": 410, "/slow": 503}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		hdrs = append(hdrs, r.Header.Clone())
		mu.Unlock()
		w.WriteHeader(statusFor[r.URL.Path])
	}))
	defer srv.Close()
	keys, _ := webpush.GenerateVAPIDKeys()
	sender, err := webpush.NewSender(keys, "mailto:ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	sender.Client, sender.Validate = srv.Client(), webpush.AllowAnyEndpoint
	store := webpush.NewStore(webpush.StoreOptions{Validate: webpush.AllowAnyEndpoint})
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	auth := make([]byte, 16)
	rand.Read(auth)
	for _, p := range []string{"/ok", "/gone", "/slow"} {
		var sub webpush.BrowserSubscription
		sub.Endpoint = srv.URL + p
		sub.Keys.P256dh = base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
		sub.Keys.Auth = base64.RawURLEncoding.EncodeToString(auth)
		if _, err := store.Add(sub, p, ""); err != nil {
			t.Fatal(err)
		}
	}
	pusher := NewWebPushPusher(&webpush.Broadcaster{Store: store, Sender: sender})
	rep, err := pusher.Push(context.Background(), Notification{ID: "a1", Title: "New device", Body: "b", URL: "/alarms/a1", Tag: "k", Severity: SeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Subscribed != 3 || rep.Delivered != 1 || rep.Gone != 1 || rep.Failed != 1 || !strings.Contains(rep.Err, "503") {
		t.Fatalf("report = %+v", rep)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, h := range hdrs {
		if h.Get("Urgency") != "high" || h.Get("TTL") != "86400" || h.Get("Topic") != webpush.TopicFor("k") {
			t.Fatalf("headers: %v", h)
		}
	}
	if store.Count() != 2 {
		t.Fatal("the gone subscription was not retired")
	}
}

func TestPushUrgencyAndTTLMapping(t *testing.T) {
	cases := []struct {
		n       Notification
		urgency webpush.Urgency
		ttl     time.Duration
	}{
		{Notification{Severity: SeverityCritical}, webpush.UrgencyHigh, 24 * time.Hour},
		{Notification{Severity: SeverityHigh}, webpush.UrgencyHigh, 24 * time.Hour},
		{Notification{Severity: SeverityMedium}, webpush.UrgencyNormal, 6 * time.Hour},
		{Notification{Severity: SeverityLow}, webpush.UrgencyLow, 6 * time.Hour},
		{Notification{Severity: SeverityInfo}, webpush.UrgencyVeryLow, 6 * time.Hour},
		{Notification{Severity: SeverityCritical, Digest: true}, webpush.UrgencyLow, 24 * time.Hour},
	}
	for _, c := range cases {
		if urgencyFor(c.n) != c.urgency || ttlFor(c.n) != c.ttl {
			t.Errorf("%+v: %v %v", c.n, urgencyFor(c.n), ttlFor(c.n))
		}
	}
}

func TestNtfyAdapter(t *testing.T) {
	var mu sync.Mutex
	var last http.Header
	var body string
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		last, body = r.Header.Clone(), string(b)
		st := status
		mu.Unlock()
		w.WriteHeader(st)
		io.WriteString(w, `{"id":"x"}`)
	}))
	defer srv.Close()
	a := NewNtfyPublisher(&ntfy.Client{Server: srv.URL, Token: "tk_example"}, "shepherd")
	n := Notification{Title: "Upstream down", Body: "all pools", Severity: SeverityCritical, Click: "https://shepherd.example.com/alarms/a1"}
	if err := a.Publish(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if last.Get("Priority") != "5" || last.Get("Tags") != "rotating_light,skull" || last.Get("Click") != n.Click || last.Get("Authorization") != "Bearer tk_example" || body != "all pools" {
		t.Fatalf("request: %v %q", last, body)
	}
	mu.Unlock()
	n.Digest = true
	n.Click = ""
	a.Publish(context.Background(), n)
	mu.Lock()
	if last.Get("Priority") != "2" || last.Get("Click") != "" {
		t.Fatalf("digest request: %v", last)
	}
	// Retryable failures stay retryable; permanent ones are marked.
	status = 503
	mu.Unlock()
	if err := a.Publish(context.Background(), n); err == nil || IsPermanent(err) || !ntfy.IsRetryable(err) {
		t.Fatalf("503: %v", err)
	}
	mu.Lock()
	status = 401
	mu.Unlock()
	if err := a.Publish(context.Background(), n); err == nil || !IsPermanent(err) {
		t.Fatalf("401: %v", err)
	}
	var ne *ntfy.Error
	if err := a.Publish(context.Background(), n); !errors.As(err, &ne) || ne.Kind != ntfy.KindAuth {
		t.Fatalf("cause lost: %v", err)
	}
	// Local validation failures are permanent as well.
	bad := NewNtfyPublisher(&ntfy.Client{Server: srv.URL}, "bad topic!")
	if err := bad.Publish(context.Background(), n); !IsPermanent(err) {
		t.Fatalf("bad topic: %v", err)
	}
}
