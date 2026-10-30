// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"context"
	"errors"
	"time"

	"shepherd/internal/ntfy"
	"shepherd/internal/webpush"
)

// WebPushPusher adapts a webpush.Broadcaster to the Router's Pusher.
type WebPushPusher struct {
	Broadcaster *webpush.Broadcaster
}

// NewWebPushPusher wraps a broadcaster.
func NewWebPushPusher(b *webpush.Broadcaster) *WebPushPusher { return &WebPushPusher{Broadcaster: b} }

// urgencyFor maps a severity to the RFC 8030 Urgency: critical and high wake
// the device, medium is normal, the rest may be delayed by the push service.
func urgencyFor(n Notification) webpush.Urgency {
	if n.Digest {
		return webpush.UrgencyLow
	}
	switch n.Severity {
	case SeverityCritical, SeverityHigh:
		return webpush.UrgencyHigh
	case SeverityMedium:
		return webpush.UrgencyNormal
	case SeverityLow:
		return webpush.UrgencyLow
	}
	return webpush.UrgencyVeryLow
}

func ttlFor(n Notification) time.Duration {
	if n.Severity.AtLeast(SeverityHigh) {
		return 24 * time.Hour
	}
	return 6 * time.Hour
}

// Push sends the notification's small JSON payload to every subscription.
func (p *WebPushPusher) Push(ctx context.Context, n Notification) (PushReport, error) {
	rep := p.Broadcaster.Broadcast(ctx, n.PushPayload(), webpush.Options{
		TTL: ttlFor(n), Urgency: urgencyFor(n), Topic: n.Tag,
	})
	out := PushReport{Subscribed: rep.Subscribed, Delivered: rep.Delivered, Gone: rep.Gone, Failed: rep.Failed}
	for _, r := range rep.Results {
		if r.Err != "" && r.Outcome != webpush.OutcomeGone {
			out.Err = r.Err
			break
		}
	}
	return out, nil
}

// NtfyAdapter adapts an ntfy.Client and topic to the Router's NtfyPublisher.
type NtfyAdapter struct {
	Client *ntfy.Client
	Topic  string
}

// NewNtfyPublisher wraps a client and topic.
func NewNtfyPublisher(c *ntfy.Client, topic string) *NtfyAdapter {
	return &NtfyAdapter{Client: c, Topic: topic}
}

// Publish sends the notification with a severity-mapped priority and tags and
// Click set to the portal URL. Errors that retrying cannot fix (bad
// credentials, a bad topic, an oversized message) are marked Permanent.
func (a *NtfyAdapter) Publish(ctx context.Context, n Notification) error {
	m := ntfy.Message{Topic: a.Topic, Title: n.Title, Body: n.Body, Priority: ntfy.PriorityFor(string(n.Severity)),
		Tags: ntfy.TagsFor(string(n.Severity)), Click: n.Click}
	if n.Digest {
		m.Priority = ntfy.PriorityLow
	}
	_, err := a.Client.Publish(ctx, m)
	if err == nil {
		return nil
	}
	var ne *ntfy.Error
	if errors.As(err, &ne) && !ne.Retryable() {
		return Permanent(err)
	}
	return err
}
