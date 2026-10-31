// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSMTPConfigValidate(t *testing.T) {
	base := SMTPConfig{Host: "mail.example.com", Port: 587, From: "shepherd@example.com", TLS: TLSStartTLS}
	if err := base.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil", err)
	}
	cases := []struct {
		name string
		mod  func(SMTPConfig) SMTPConfig
	}{
		{"no host", func(c SMTPConfig) SMTPConfig { c.Host = ""; return c }},
		{"bad port", func(c SMTPConfig) SMTPConfig { c.Port = 0; return c }},
		{"port too big", func(c SMTPConfig) SMTPConfig { c.Port = 99999; return c }},
		{"no from", func(c SMTPConfig) SMTPConfig { c.From = ""; return c }},
		{"bad tls mode", func(c SMTPConfig) SMTPConfig { c.TLS = "funky"; return c }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.mod(base).validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("validate() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestNewSMTPSenderRejectsBadConfig(t *testing.T) {
	if _, err := NewSMTPSender(SMTPConfig{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewSMTPSender() = %v, want ErrInvalid", err)
	}
}

func testMessage() Message {
	return Message{From: "shepherd@example.com", To: "jordan@example.com", Subject: "A check-in", Body: "Hi Jordan,\n\nhello.\n"}
}

func TestSMTPSenderSendOK(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.offerStartTLS = true
	srv.start()
	sender, err := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), Username: "shepherd", Password: "app-password",
		From: "shepherd@example.com", TLS: TLSStartTLS, InsecureSkipVerify: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	res := sender.Send(context.Background(), testMessage())
	if !res.OK() {
		t.Fatalf("Send() = %+v, want OK", res)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.received) != 1 {
		t.Fatalf("server received %d messages, want 1", len(srv.received))
	}
	if !strings.Contains(srv.received[0], "Subject: A check-in") {
		t.Errorf("received body missing subject header:\n%s", srv.received[0])
	}
	if !strings.Contains(srv.received[0], "hello.") {
		t.Errorf("received body missing message text:\n%s", srv.received[0])
	}
}

func TestSMTPSenderImplicitTLS(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.implicitTLS = true
	srv.start()
	sender, err := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), From: "shepherd@example.com",
		TLS: TLSImplicit, InsecureSkipVerify: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	res := sender.Send(context.Background(), testMessage())
	if !res.OK() {
		t.Fatalf("Send() = %+v, want OK", res)
	}
}

func TestSMTPSenderNoTLS(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.start()
	sender, err := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), From: "shepherd@example.com", TLS: TLSNone, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	res := sender.Send(context.Background(), testMessage())
	if !res.OK() {
		t.Fatalf("Send() = %+v, want OK", res)
	}
}

func TestSMTPSenderAuthFailed(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.offerStartTLS = true
	srv.authFail = true
	srv.start()
	sender, _ := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), Username: "shepherd", Password: "wrong",
		From: "shepherd@example.com", TLS: TLSStartTLS, InsecureSkipVerify: true, Timeout: 5 * time.Second,
	})
	res := sender.Send(context.Background(), testMessage())
	if res.Outcome != OutcomeAuthFailed {
		t.Fatalf("Outcome = %v, want OutcomeAuthFailed (err: %v)", res.Outcome, res.Err)
	}
}

func TestSMTPSenderRecipientRejected(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.rcptFail = true
	srv.start()
	sender, _ := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), From: "shepherd@example.com", TLS: TLSNone, Timeout: 5 * time.Second,
	})
	res := sender.Send(context.Background(), testMessage())
	if res.Outcome != OutcomeRecipientRejected {
		t.Fatalf("Outcome = %v, want OutcomeRecipientRejected (err: %v)", res.Outcome, res.Err)
	}
}

func TestSMTPSenderMailFromTransient(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.mailFail = true
	srv.start()
	sender, _ := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), From: "shepherd@example.com", TLS: TLSNone, Timeout: 5 * time.Second,
	})
	res := sender.Send(context.Background(), testMessage())
	if res.Outcome != OutcomeTransient {
		t.Fatalf("Outcome = %v, want OutcomeTransient (err: %v)", res.Outcome, res.Err)
	}
}

func TestSMTPSenderDataTransient(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.dataFail = true
	srv.start()
	sender, _ := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), From: "shepherd@example.com", TLS: TLSNone, Timeout: 5 * time.Second,
	})
	res := sender.Send(context.Background(), testMessage())
	if res.Outcome != OutcomeTransient {
		t.Fatalf("Outcome = %v, want OutcomeTransient (err: %v)", res.Outcome, res.Err)
	}
}

func TestSMTPSenderConnectionFailed(t *testing.T) {
	// Nothing is listening on this loopback port.
	sender, _ := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: 1, From: "shepherd@example.com", TLS: TLSNone, Timeout: time.Second,
	})
	res := sender.Send(context.Background(), testMessage())
	if res.Outcome != OutcomeConnectionFailed {
		t.Fatalf("Outcome = %v, want OutcomeConnectionFailed (err: %v)", res.Outcome, res.Err)
	}
}

func TestSMTPSenderStartTLSNotOffered(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.offerStartTLS = false
	srv.start()
	sender, _ := NewSMTPSender(SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), From: "shepherd@example.com",
		TLS: TLSStartTLS, InsecureSkipVerify: true, Timeout: 5 * time.Second,
	})
	res := sender.Send(context.Background(), testMessage())
	if res.Outcome != OutcomeConnectionFailed {
		t.Fatalf("Outcome = %v, want OutcomeConnectionFailed (err: %v)", res.Outcome, res.Err)
	}
}

func TestSMTPSenderEmptyRecipientIsInvalid(t *testing.T) {
	sender, _ := NewSMTPSender(SMTPConfig{Host: "127.0.0.1", Port: 25, From: "shepherd@example.com", TLS: TLSNone})
	msg := testMessage()
	msg.To = ""
	res := sender.Send(context.Background(), msg)
	if res.Outcome != OutcomeInvalid {
		t.Fatalf("Outcome = %v, want OutcomeInvalid", res.Outcome)
	}
}

func TestSMTPSenderContextDeadlineExceeded(t *testing.T) {
	sender, _ := NewSMTPSender(SMTPConfig{Host: "127.0.0.1", Port: 25, From: "shepherd@example.com", TLS: TLSNone, Timeout: time.Minute})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	res := sender.Send(ctx, testMessage())
	if res.Outcome != OutcomeTransient {
		t.Fatalf("Outcome = %v, want OutcomeTransient", res.Outcome)
	}
}

func TestEncodeMessageSanitizesHeaderInjection(t *testing.T) {
	msg := Message{From: "a@example.com", To: "b@example.com", Subject: "Hi\r\nBcc: evil@example.com", Body: "line1\nline2\n"}
	out := encodeMessage("a@example.com", msg)
	for _, line := range strings.Split(out, "\r\n") {
		if strings.HasPrefix(line, "Bcc:") {
			t.Fatalf("header injection succeeded: %q", out)
		}
	}
	if !strings.Contains(out, "line1\r\n") || !strings.Contains(out, "line2\r\n") {
		t.Errorf("body lines not CRLF-terminated:\n%q", out)
	}
}

func TestFakeSender(t *testing.T) {
	f := &FakeSender{
		Results: []Result{{Outcome: OutcomeOK}, {Outcome: OutcomeTransient}},
		Default: Result{Outcome: OutcomeInvalid},
	}
	r1 := f.Send(context.Background(), testMessage())
	r2 := f.Send(context.Background(), testMessage())
	r3 := f.Send(context.Background(), testMessage())
	if r1.Outcome != OutcomeOK || r2.Outcome != OutcomeTransient || r3.Outcome != OutcomeInvalid {
		t.Fatalf("got %v, %v, %v", r1.Outcome, r2.Outcome, r3.Outcome)
	}
	if len(f.Sent()) != 3 {
		t.Fatalf("Sent = %d, want 3", len(f.Sent()))
	}
}

func TestOutcomeString(t *testing.T) {
	cases := map[Outcome]string{
		OutcomeOK: "ok", OutcomeAuthFailed: "auth-failed", OutcomeConnectionFailed: "connection-failed",
		OutcomeRecipientRejected: "recipient-rejected", OutcomeTransient: "transient", OutcomeInvalid: "invalid",
		Outcome(99): "unknown",
	}
	for o, want := range cases {
		if got := o.String(); got != want {
			t.Errorf("Outcome(%d).String() = %q, want %q", o, got, want)
		}
	}
}

func verifySender(t *testing.T, srv *fakeSMTP, mod func(*SMTPConfig)) *SMTPSender {
	t.Helper()
	cfg := SMTPConfig{
		Host: "127.0.0.1", Port: srv.port(), Username: "shepherd", Password: "app-password",
		From: "shepherd@example.com", TLS: TLSStartTLS, InsecureSkipVerify: true, Timeout: 5 * time.Second,
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := NewSMTPSender(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSMTPSenderVerifyAuthenticatesWithoutSendingMail(t *testing.T) {
	srv := newFakeSMTP(t)
	srv.offerStartTLS = true
	srv.start()
	res := verifySender(t, srv, nil).Verify(context.Background())
	if !res.OK() {
		t.Fatalf("Verify() = %+v, want OK", res)
	}
	cmds := strings.Join(srv.commandsSeen(), " ")
	for _, want := range []string{"STARTTLS", "AUTH", "QUIT"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("Verify never sent %s (saw %s)", want, cmds)
		}
	}
	for _, never := range []string{"MAIL", "RCPT", "DATA"} {
		if strings.Contains(cmds, never) {
			t.Errorf("Verify sent %s: a check must never send mail (saw %s)", never, cmds)
		}
	}
	srv.mu.Lock()
	queued := len(srv.received)
	srv.mu.Unlock()
	if queued != 0 {
		t.Error("Verify queued a message")
	}
}

func TestSMTPSenderVerifyClassifiesFailures(t *testing.T) {
	authFail := newFakeSMTP(t)
	authFail.offerStartTLS = true
	authFail.authFail = true
	authFail.start()
	if res := verifySender(t, authFail, nil).Verify(context.Background()); res.Outcome != OutcomeAuthFailed {
		t.Errorf("wrong password: %v", res.Outcome)
	}

	noStartTLS := newFakeSMTP(t)
	noStartTLS.start()
	if res := verifySender(t, noStartTLS, nil).Verify(context.Background()); res.Outcome != OutcomeConnectionFailed {
		t.Errorf("no STARTTLS offered: %v", res.Outcome)
	}

	implicit := newFakeSMTP(t)
	implicit.implicitTLS = true
	implicit.start()
	if res := verifySender(t, implicit, func(c *SMTPConfig) { c.TLS = TLSImplicit }).Verify(context.Background()); !res.OK() {
		t.Errorf("implicit TLS: %+v", res)
	}

	plain := newFakeSMTP(t)
	plain.start()
	if res := verifySender(t, plain, func(c *SMTPConfig) { c.TLS, c.Username, c.Password = TLSNone, "", "" }).Verify(context.Background()); !res.OK() {
		t.Errorf("unauthenticated local relay: %+v", res)
	}

	ln := newFakeSMTP(t) // never started, then closed: nothing answers
	port := ln.port()
	ln.ln.Close()
	if res := verifySender(t, ln, func(c *SMTPConfig) { c.Port = port }).Verify(context.Background()); res.Outcome != OutcomeConnectionFailed {
		t.Errorf("nothing listening: %v", res.Outcome)
	}
}

func TestRelaySenderSwapsTheRelayLive(t *testing.T) {
	var r RelaySender
	if r.Configured() {
		t.Error("a zero RelaySender has no relay")
	}
	res := r.Send(context.Background(), testMessage())
	if res.Outcome != OutcomeInvalid || !errors.Is(res.Err, ErrNoRelay) {
		t.Errorf("send with no relay = %+v, want OutcomeInvalid/ErrNoRelay", res)
	}

	srv := newFakeSMTP(t)
	srv.offerStartTLS = true
	srv.start()
	r.Set(verifySender(t, srv, func(c *SMTPConfig) { c.From = "relay@example.com" }))
	if !r.Configured() {
		t.Error("Set must configure the relay")
	}
	if res := r.Send(context.Background(), testMessage()); !res.OK() {
		t.Fatalf("send through the relay = %+v", res)
	}
	srv.mu.Lock()
	got := srv.received[0]
	srv.mu.Unlock()
	if !strings.Contains(got, "From: relay@example.com") {
		t.Errorf("the relay's own From must be used, got:\n%s", got)
	}
	r.Set(nil)
	if r.Configured() {
		t.Error("Set(nil) must remove the relay")
	}
	if res := r.Send(context.Background(), testMessage()); res.Outcome != OutcomeInvalid {
		t.Errorf("after removal = %+v", res)
	}
}
