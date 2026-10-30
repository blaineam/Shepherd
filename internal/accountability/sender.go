// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// Message is one email ready to send. Body is plain text; see template.go
// for how it is produced.
type Message struct {
	From    string
	To      string
	Subject string
	Body    string
}

// Outcome classifies what happened when a Sender tried to deliver a
// Message, in the same spirit as internal/webpush's Outcome and
// internal/ntfy's Error.Kind: callers should be able to tell "this will
// never work until the configuration changes" from "try again later"
// without parsing an error string.
type Outcome int

// Outcomes of one send attempt.
const (
	// OutcomeOK: the message was accepted by the remote server for
	// delivery. SMTP acceptance is not delivery; see
	// docs/ACCOUNTABILITY.md's honest limits.
	OutcomeOK Outcome = iota
	// OutcomeAuthFailed: the SMTP server rejected the configured
	// credentials. Retrying without changing the password will not help.
	OutcomeAuthFailed
	// OutcomeConnectionFailed: could not reach the server, or could not
	// negotiate STARTTLS with it.
	OutcomeConnectionFailed
	// OutcomeRecipientRejected: the server accepted the connection and
	// credentials but refused the recipient address (for example, no
	// such mailbox).
	OutcomeRecipientRejected
	// OutcomeTransient: a temporary failure (for example a 4xx during
	// DATA, or the server closing mid-transaction). Worth trying again
	// later; this package does not retry on its own.
	OutcomeTransient
	// OutcomeInvalid: the message or configuration itself is unusable
	// (for example an empty recipient), so nothing was sent.
	OutcomeInvalid
)

// String names the outcome for logs.
func (o Outcome) String() string {
	switch o {
	case OutcomeOK:
		return "ok"
	case OutcomeAuthFailed:
		return "auth-failed"
	case OutcomeConnectionFailed:
		return "connection-failed"
	case OutcomeRecipientRejected:
		return "recipient-rejected"
	case OutcomeTransient:
		return "transient"
	case OutcomeInvalid:
		return "invalid"
	}
	return "unknown"
}

// Result is the classified answer to one send.
type Result struct {
	Outcome Outcome
	Err     error
}

// OK reports whether the message was accepted.
func (r Result) OK() bool { return r.Outcome == OutcomeOK }

// Sender delivers one email. A fake implementation is used throughout this
// package's own tests; SMTPSender is the real one.
type Sender interface {
	Send(ctx context.Context, msg Message) Result
}

// FakeSender is a Sender for tests: it records every call and returns
// scripted results. It is safe for concurrent use, since an Engine's
// background digest loop calls Send from its own goroutine.
type FakeSender struct {
	// Results, if non-empty, are returned in order (one per call); past
	// the end, or when empty, Default is returned.
	Results []Result
	Default Result

	mu    sync.Mutex
	sent  []Message
	calls int
}

// Send records msg and returns the next scripted result.
func (f *FakeSender) Send(_ context.Context, msg Message) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, msg)
	defer func() { f.calls++ }()
	if f.calls < len(f.Results) {
		return f.Results[f.calls]
	}
	return f.Default
}

// Sent returns every message passed to Send so far, in order.
func (f *FakeSender) Sent() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Message(nil), f.sent...)
}

// TLSMode is how an SMTPSender secures its connection.
type TLSMode string

// TLS modes.
const (
	// TLSStartTLS connects in plain text and upgrades with STARTTLS
	// before authenticating (the common port-587 convention).
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit connects already inside TLS (the common port-465
	// convention).
	TLSImplicit TLSMode = "tls"
	// TLSNone never encrypts. Only useful against a local, trusted relay;
	// see docs/ACCOUNTABILITY.md.
	TLSNone TLSMode = "none"
)

// SMTPConfig is the configuration shape this package needs from Shepherd's
// own config file (internal/config does not define this section; see
// docs/ACCOUNTABILITY.md).
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	// Password is a real secret. See docs/ACCOUNTABILITY.md for the
	// at-rest gap this leaves today.
	Password string
	From     string
	TLS      TLSMode
	// Timeout bounds the whole exchange; default 15s.
	Timeout time.Duration
	// InsecureSkipVerify disables certificate verification. Never set
	// this outside a test against a loopback fake server.
	InsecureSkipVerify bool
}

func (c SMTPConfig) validate() error {
	if c.Host == "" {
		return fmt.Errorf("%w: smtp host is required", ErrInvalid)
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("%w: smtp port %d is invalid", ErrInvalid, c.Port)
	}
	if c.From == "" {
		return fmt.Errorf("%w: smtp from address is required", ErrInvalid)
	}
	switch c.TLS {
	case TLSStartTLS, TLSImplicit, TLSNone:
	default:
		return fmt.Errorf("%w: smtp tls mode %q", ErrInvalid, c.TLS)
	}
	return nil
}

// SMTPSender sends mail through a user-supplied SMTP server using only the
// standard library (net/smtp), matching Shepherd's free, keyless,
// bring-your-own-credentials convention: no paid transactional-email API.
type SMTPSender struct {
	cfg SMTPConfig
	// dial opens the initial connection; overridden in tests to reach a
	// loopback fake server. Default net.Dial via DialTimeout.
	dial func(network, addr string, timeout time.Duration) (net.Conn, error)
}

// NewSMTPSender returns a Sender for cfg. It does not connect until Send is
// called.
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &SMTPSender{cfg: cfg, dial: func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, addr, timeout)
	}}, nil
}

// Send delivers msg, classifying the outcome by which step of the SMTP
// exchange failed.
func (s *SMTPSender) Send(ctx context.Context, msg Message) Result {
	if msg.To == "" {
		return Result{Outcome: OutcomeInvalid, Err: errors.New("accountability: message has no recipient")}
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	deadline := time.Now().Add(s.cfg.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return Result{Outcome: OutcomeTransient, Err: context.DeadlineExceeded}
	}

	var conn net.Conn
	var err error
	if s.cfg.TLS == TLSImplicit {
		d := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(d, "tcp", addr, s.tlsConfig())
	} else {
		conn, err = s.dial("tcp", addr, timeout)
	}
	if err != nil {
		return Result{Outcome: OutcomeConnectionFailed, Err: fmt.Errorf("accountability: connect: %w", err)}
	}
	_ = conn.SetDeadline(deadline)
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return Result{Outcome: OutcomeConnectionFailed, Err: fmt.Errorf("accountability: smtp handshake: %w", err)}
	}
	defer client.Close()

	if s.cfg.TLS == TLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return Result{Outcome: OutcomeConnectionFailed, Err: errors.New("accountability: server does not offer STARTTLS")}
		}
		if err := client.StartTLS(s.tlsConfig()); err != nil {
			return Result{Outcome: OutcomeConnectionFailed, Err: fmt.Errorf("accountability: starttls: %w", err)}
		}
	}

	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return Result{Outcome: OutcomeAuthFailed, Err: fmt.Errorf("accountability: auth: %w", err)}
		}
	}

	from := s.cfg.From
	if err := client.Mail(from); err != nil {
		return Result{Outcome: OutcomeTransient, Err: fmt.Errorf("accountability: mail from: %w", err)}
	}
	if err := client.Rcpt(msg.To); err != nil {
		return Result{Outcome: OutcomeRecipientRejected, Err: fmt.Errorf("accountability: rcpt to: %w", err)}
	}
	wc, err := client.Data()
	if err != nil {
		return Result{Outcome: OutcomeTransient, Err: fmt.Errorf("accountability: data: %w", err)}
	}
	if _, err := wc.Write([]byte(encodeMessage(from, msg))); err != nil {
		wc.Close()
		return Result{Outcome: OutcomeTransient, Err: fmt.Errorf("accountability: write body: %w", err)}
	}
	if err := wc.Close(); err != nil {
		return Result{Outcome: OutcomeTransient, Err: fmt.Errorf("accountability: finish body: %w", err)}
	}
	_ = client.Quit()
	return Result{Outcome: OutcomeOK}
}

func (s *SMTPSender) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: s.cfg.Host, InsecureSkipVerify: s.cfg.InsecureSkipVerify} //nolint:gosec // opt-in test-only flag
}

// encodeMessage renders a minimal RFC 5322 message: headers and a plain-text
// body, CRLF throughout.
func encodeMessage(from string, msg Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", msg.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitizeHeader(msg.Subject))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	for _, line := range strings.Split(msg.Body, "\n") {
		b.WriteString(strings.TrimRight(line, "\r"))
		b.WriteString("\r\n")
	}
	return b.String()
}

// sanitizeHeader strips CR/LF so a subject built from any input cannot
// inject extra headers.
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", " ")
}
