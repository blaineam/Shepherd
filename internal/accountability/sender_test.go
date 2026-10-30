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
