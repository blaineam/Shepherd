// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type pushServer struct {
	*httptest.Server
	last atomic.Pointer[recorded]
}

type recorded struct {
	hdr  http.Header
	body []byte
	path string
}

func newPushServer(t *testing.T, status int, extra func(http.ResponseWriter)) *pushServer {
	t.Helper()
	ps := &pushServer{}
	ps.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ps.last.Store(&recorded{hdr: r.Header.Clone(), body: b, path: r.URL.Path})
		if extra != nil {
			extra(w)
		}
		w.WriteHeader(status)
		io.WriteString(w, "reply")
	}))
	t.Cleanup(ps.Close)
	return ps
}

func testSender(t *testing.T, ps *pushServer) (*Sender, VAPIDKeys) {
	t.Helper()
	keys, _ := GenerateVAPIDKeys()
	s, err := NewSender(keys, "mailto:ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.Client = ps.Client()
	s.Validate = AllowAnyEndpoint
	s.Now = newClock().Now
	return s, keys
}

func TestSendHeadersAndEncryption(t *testing.T) {
	ps := newPushServer(t, 201, nil)
	s, keys := testSender(t, ps)
	d := newDevice(t)
	sub := Subscription{Endpoint: ps.URL + "/send/abc", P256dh: d.p256dh(), Auth: d.authB64()}
	res := s.Send(context.Background(), sub, []byte(`{"title":"x"}`), Options{TTL: 90 * time.Minute, Urgency: UrgencyHigh, Topic: "alarm|key"})
	if !res.OK() || res.Status != 201 || res.Outcome.String() != "ok" || res.Err != nil {
		t.Fatalf("res = %+v", res)
	}
	got := ps.last.Load()
	h := got.hdr
	if h.Get("Content-Encoding") != "aes128gcm" || h.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("encoding headers: %v", h)
	}
	if h.Get("TTL") != "5400" || h.Get("Urgency") != "high" {
		t.Fatalf("ttl/urgency: %v", h)
	}
	if h.Get("Topic") != TopicFor("alarm|key") || len(h.Get("Topic")) != 22 {
		t.Fatalf("topic = %q", h.Get("Topic"))
	}
	auth := h.Get("Authorization")
	if !strings.HasPrefix(auth, "vapid t=") || !strings.HasSuffix(auth, ", k="+keys.Public) {
		t.Fatalf("authorization = %q", auth)
	}
	jwt := strings.TrimSuffix(strings.TrimPrefix(auth, "vapid t="), ", k="+keys.Public)
	aud, sub2, exp, err := VerifyJWT(keys.Public, jwt)
	if err != nil || aud != ps.URL || sub2 != "mailto:ops@example.com" {
		t.Fatalf("jwt: %q %q %v", aud, sub2, err)
	}
	if exp.Sub(s.Now()) > 24*time.Hour {
		t.Fatal("jwt lives too long")
	}
	if plain := d.decrypt(t, got.body); string(plain) != `{"title":"x"}` {
		t.Fatalf("plaintext = %q", plain)
	}
}

func TestSendDefaults(t *testing.T) {
	ps := newPushServer(t, 200, nil)
	s, _ := testSender(t, ps)
	d := newDevice(t)
	res := s.Send(context.Background(), Subscription{Endpoint: ps.URL, P256dh: d.p256dh(), Auth: d.authB64()}, []byte("x"), Options{})
	if !res.OK() {
		t.Fatalf("res = %+v", res)
	}
	h := ps.last.Load().hdr
	if h.Get("TTL") != strconv.Itoa(86400) || h.Get("Urgency") != "normal" || h.Get("Topic") != "" {
		t.Fatalf("defaults: %v", h)
	}
}

func TestSendClassifiesOutcomes(t *testing.T) {
	cases := []struct {
		status int
		want   Outcome
		str    string
	}{
		{200, OutcomeOK, "ok"}, {201, OutcomeOK, "ok"}, {202, OutcomeOK, "ok"},
		{404, OutcomeGone, "gone"}, {410, OutcomeGone, "gone"},
		{413, OutcomeTooLarge, "too-large"},
		{429, OutcomeTransient, "transient"}, {500, OutcomeTransient, "transient"}, {503, OutcomeTransient, "transient"},
		{400, OutcomeRejected, "rejected"}, {401, OutcomeRejected, "rejected"}, {403, OutcomeRejected, "rejected"},
		{302, OutcomeRejected, "rejected"},
	}
	d := newDevice(t)
	for _, c := range cases {
		ps := newPushServer(t, c.status, func(w http.ResponseWriter) {
			if c.status == 302 {
				w.Header().Set("Location", "https://push.example.com/elsewhere")
			}
		})
		s, _ := testSender(t, ps)
		res := s.Send(context.Background(), Subscription{Endpoint: ps.URL, P256dh: d.p256dh(), Auth: d.authB64()}, []byte("x"), Options{})
		if res.Outcome != c.want || res.Outcome.String() != c.str || res.Status != c.status {
			t.Errorf("%d: %+v", c.status, res)
		}
		if c.want != OutcomeOK && res.Err == nil {
			t.Errorf("%d: no error", c.status)
		}
		if res.Body != "reply" {
			t.Errorf("%d: body %q", c.status, res.Body)
		}
	}
	if Outcome(99).String() != "unknown" || OutcomeInvalid.String() != "invalid" {
		t.Fatal("Outcome.String")
	}
}

func TestSendRetryAfter(t *testing.T) {
	d := newDevice(t)
	now := newClock().Now()
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"120", 120 * time.Second},
		{now.Add(90 * time.Second).UTC().Format(http.TimeFormat), 90 * time.Second},
		{now.Add(-time.Hour).UTC().Format(http.TimeFormat), 0},
		{now.Add(72 * time.Hour).UTC().Format(http.TimeFormat), 24 * time.Hour},
		{"999999999", 24 * time.Hour},
		{"-5", 0},
		{"soon", 0},
		{"", 0},
	}
	for _, c := range cases {
		ps := newPushServer(t, 429, func(w http.ResponseWriter) {
			if c.header != "" {
				w.Header().Set("Retry-After", c.header)
			}
		})
		s, _ := testSender(t, ps)
		res := s.Send(context.Background(), Subscription{Endpoint: ps.URL, P256dh: d.p256dh(), Auth: d.authB64()}, []byte("x"), Options{})
		if res.Outcome != OutcomeTransient || res.RetryAfter != c.want {
			t.Errorf("Retry-After %q: %+v want %v", c.header, res, c.want)
		}
	}
}

func TestSendInvalidInputsNeverReachTheNetwork(t *testing.T) {
	ps := newPushServer(t, 201, nil)
	s, _ := testSender(t, ps)
	d := newDevice(t)
	good := Subscription{Endpoint: ps.URL, P256dh: d.p256dh(), Auth: d.authB64()}

	bad := good
	bad.P256dh = "AAAA"
	if res := s.Send(context.Background(), bad, []byte("x"), Options{}); res.Outcome != OutcomeInvalid || res.Err == nil {
		t.Fatalf("bad keys: %+v", res)
	}
	big := make([]byte, MaxPayload+1)
	if res := s.Send(context.Background(), good, big, Options{}); res.Outcome != OutcomeTooLarge {
		t.Fatalf("too large: %+v", res)
	}
	s.Validate = ValidateEndpoint // the production validator refuses a loopback endpoint
	if res := s.Send(context.Background(), good, []byte("x"), Options{}); res.Outcome != OutcomeInvalid {
		t.Fatalf("ssrf: %+v", res)
	}
	s.Validate = AllowAnyEndpoint
	if res := s.Send(context.Background(), Subscription{Endpoint: "https://bad host/x\x7f", P256dh: good.P256dh, Auth: good.Auth}, []byte("x"), Options{}); res.Outcome != OutcomeInvalid {
		t.Fatalf("bad url: %+v", res)
	}
	if res := s.Send(context.Background(), Subscription{Endpoint: "nonsense", P256dh: good.P256dh, Auth: good.Auth}, []byte("x"), Options{}); res.Outcome != OutcomeInvalid {
		t.Fatalf("no scheme: %+v", res)
	}
	s.keys = VAPIDKeys{}
	if res := s.Send(context.Background(), good, []byte("x"), Options{}); res.Outcome != OutcomeInvalid {
		t.Fatalf("bad vapid: %+v", res)
	}
	if ps.last.Load() != nil {
		t.Fatal("an invalid send reached the server")
	}
}

func TestSendNetworkErrorsAreTransient(t *testing.T) {
	ps := newPushServer(t, 201, nil)
	s, _ := testSender(t, ps)
	d := newDevice(t)
	sub := Subscription{Endpoint: ps.URL, P256dh: d.p256dh(), Auth: d.authB64()}
	ps.Close()
	res := s.Send(context.Background(), sub, []byte("x"), Options{})
	if res.Outcome != OutcomeTransient || res.Err == nil || res.Status != 0 {
		t.Fatalf("res = %+v", res)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res := s.Send(ctx, sub, []byte("x"), Options{}); res.Outcome != OutcomeTransient {
		t.Fatalf("cancelled: %+v", res)
	}
}

func TestNewSenderValidation(t *testing.T) {
	keys, _ := GenerateVAPIDKeys()
	if _, err := NewSender(VAPIDKeys{}, "mailto:ops@example.com"); err == nil {
		t.Error("bad keys accepted")
	}
	for _, sub := range []string{"", "ops@example.com", "http://example.com"} {
		if _, err := NewSender(keys, sub); err == nil {
			t.Errorf("subject %q accepted", sub)
		}
	}
	if s, err := NewSender(keys, "https://portal.example.com"); err != nil || s.Client == nil || s.Validate == nil {
		t.Fatalf("%v", err)
	}
}

func TestTopicFor(t *testing.T) {
	a, b := TopicFor("k1"), TopicFor("k2")
	if a == b || a != TopicFor("k1") || len(a) != 22 || strings.ContainsAny(a, "+/= |") {
		t.Fatalf("%q %q", a, b)
	}
}
