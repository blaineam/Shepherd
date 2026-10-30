// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Urgency is the RFC 8030 Urgency header value.
type Urgency string

// Urgency values. Push services may delay low urgency messages for devices
// that are asleep; very-low and low are for digests and housekeeping.
const (
	UrgencyVeryLow Urgency = "very-low"
	UrgencyLow     Urgency = "low"
	UrgencyNormal  Urgency = "normal"
	UrgencyHigh    Urgency = "high"
)

// Outcome classifies what a push service answered.
type Outcome int

// Outcomes of one send.
const (
	// OutcomeOK: the push service accepted the message (200, 201 or 202).
	OutcomeOK Outcome = iota
	// OutcomeGone: 404 or 410. The subscription is dead and must be retired.
	OutcomeGone
	// OutcomeRejected: another 4xx or an unexpected status. Not retried
	// blindly: a 401/403 usually means the VAPID key changed.
	OutcomeRejected
	// OutcomeTransient: 429, 5xx or a network error. Retry later, honoring
	// Result.RetryAfter.
	OutcomeTransient
	// OutcomeTooLarge: the payload exceeds the 4096-byte limit (locally or
	// by a 413).
	OutcomeTooLarge
	// OutcomeInvalid: nothing was sent; the endpoint or keys are unusable.
	OutcomeInvalid
)

func (o Outcome) String() string {
	switch o {
	case OutcomeOK:
		return "ok"
	case OutcomeGone:
		return "gone"
	case OutcomeRejected:
		return "rejected"
	case OutcomeTransient:
		return "transient"
	case OutcomeTooLarge:
		return "too-large"
	case OutcomeInvalid:
		return "invalid"
	}
	return "unknown"
}

// Options are the per-message RFC 8030 parameters.
type Options struct {
	// TTL is how long the push service may hold the message for an offline
	// device. Zero means DefaultTTL. A TTL of zero seconds is not useful for
	// alarms, so it cannot be requested.
	TTL time.Duration
	// Urgency; empty means normal.
	Urgency Urgency
	// Topic lets a newer message replace an undelivered older one with the
	// same topic. It is passed through TopicFor, so any string is safe.
	Topic string
}

// DefaultTTL is the message lifetime when none is given.
const DefaultTTL = 24 * time.Hour

// Result is the classified answer to one send.
type Result struct {
	Outcome    Outcome
	Status     int           // HTTP status, 0 when nothing was answered
	RetryAfter time.Duration // from Retry-After, 0 when absent
	Body       string        // up to 512 bytes of the response, for logs
	Err        error
}

// OK reports whether the message was accepted.
func (r Result) OK() bool { return r.Outcome == OutcomeOK }

// Subscription is the information needed to push to one browser.
type Subscription struct {
	Endpoint string
	P256dh   string
	Auth     string
}

// Sender posts encrypted, VAPID-signed messages. The zero value is not
// usable; build one with NewSender.
type Sender struct {
	keys    VAPIDKeys
	subject string
	// Client performs the POST. NewSender installs NewHTTPClient.
	Client *http.Client
	// Validate vets an endpoint before any request. NewSender installs
	// ValidateEndpoint; tests inject AllowAnyEndpoint to reach loopback.
	Validate func(endpoint string) error
	// Now is the clock for the VAPID token.
	Now func() time.Time
	// JWTLifetime defaults to DefaultJWTLifetime and is capped at 24 hours.
	JWTLifetime time.Duration
}

// NewSender builds a Sender. subject is the RFC 8292 contact: a mailto: or
// https: URL that the push service can use to reach the operator.
func NewSender(keys VAPIDKeys, subject string) (*Sender, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(subject, "mailto:") && !strings.HasPrefix(subject, "https://") {
		return nil, errors.New("webpush: subject must be a mailto: or https: URL")
	}
	return &Sender{keys: keys, subject: subject, Client: NewHTTPClient(), Validate: ValidateEndpoint, Now: time.Now}, nil
}

// TopicFor turns any string (an alarm's dedupe key, say) into a valid RFC
// 8030 topic: 22 base64url characters of a SHA-256 digest (the limit is 32).
func TopicFor(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64(sum[:])[:22]
}

// Send encrypts payload for sub and delivers it. It never panics and never
// retries; the caller decides what to do with the classified Result.
func (s *Sender) Send(ctx context.Context, sub Subscription, payload []byte, o Options) Result {
	if err := s.Validate(sub.Endpoint); err != nil {
		return Result{Outcome: OutcomeInvalid, Err: err}
	}
	body, err := Encrypt(payload, sub.P256dh, sub.Auth)
	if err != nil {
		if errors.Is(err, ErrPayloadTooLarge) {
			return Result{Outcome: OutcomeTooLarge, Err: err}
		}
		return Result{Outcome: OutcomeInvalid, Err: err}
	}
	auth, err := s.keys.Authorization(sub.Endpoint, s.subject, s.Now(), s.JWTLifetime)
	if err != nil {
		return Result{Outcome: OutcomeInvalid, Err: err}
	}
	ttl := o.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{Outcome: OutcomeInvalid, Err: err}
	}
	h := req.Header
	h.Set("Authorization", auth)
	h.Set("Content-Encoding", "aes128gcm")
	h.Set("Content-Type", "application/octet-stream")
	h.Set("TTL", strconv.FormatInt(int64(ttl/time.Second), 10))
	urg := o.Urgency
	if urg == "" {
		urg = UrgencyNormal
	}
	h.Set("Urgency", string(urg))
	if o.Topic != "" {
		h.Set("Topic", TopicFor(o.Topic))
	}
	// A push service answers directly: never follow a redirect, whatever
	// client was injected, so a hostile endpoint cannot bounce the request.
	client := *s.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return Result{Outcome: OutcomeTransient, Err: err}
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	r := Result{Status: resp.StatusCode, Body: strings.TrimSpace(string(snippet)), RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), s.Now())}
	switch {
	case resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 202:
		r.Outcome = OutcomeOK
	case resp.StatusCode == 404 || resp.StatusCode == 410:
		r.Outcome = OutcomeGone
		r.Err = fmt.Errorf("push service answered %d: subscription is gone", resp.StatusCode)
	case resp.StatusCode == 413:
		r.Outcome = OutcomeTooLarge
		r.Err = errors.New("push service answered 413: payload too large")
	case resp.StatusCode == 429 || resp.StatusCode >= 500:
		r.Outcome = OutcomeTransient
		r.Err = fmt.Errorf("push service answered %d", resp.StatusCode)
	default:
		r.Outcome = OutcomeRejected
		r.Err = fmt.Errorf("push service answered %d", resp.StatusCode)
	}
	return r
}

// parseRetryAfter reads delta-seconds or an HTTP date. Absent or invalid
// values give 0; the result is capped at 24 hours.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 {
			return 0
		}
		if n > 86400 {
			n = 86400
		}
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
		if d < 0 {
			return 0
		}
		if d > 24*time.Hour {
			d = 24 * time.Hour
		}
	}
	return d
}
