// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"shepherd/internal/accountability"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
)

// accessQueueSize bounds how many access events can be queued for the
// accountability engine before new ones are dropped. See startAccountability
// for why this exists at all.
const accessQueueSize = 256

// startAccountability wires the DNS engine's OnAccess hook to an
// accountability.Engine (docs/ACCOUNTABILITY.md), resolving each access's
// device and groups from the device registry. It is gated by
// cfg.Accountability.Enabled and by an SMTP relay actually being configured:
// the feature defaults on, but the library itself starts with zero contacts
// and zero subscriptions, and there is no default mail relay, so until both
// a subscription exists (set up in the portal) and an SMTP host is
// configured here, this returns (nil, nil) — not wired, not an error.
func startAccountability(ctx context.Context, cfg config.Config, engine *dnsengine.Engine, reg *devices.Registry) (*accountability.Engine, error) {
	ac := cfg.Accountability
	if !ac.Enabled || ac.SMTP.Host == "" {
		return nil, nil
	}
	password, err := smtpPassword(ac.SMTP)
	if err != nil {
		return nil, fmt.Errorf("accountability: %w", err)
	}
	tlsMode := accountability.TLSMode(ac.SMTP.TLS)
	if tlsMode == "" {
		tlsMode = accountability.TLSStartTLS
	}
	sender, err := accountability.NewSMTPSender(accountability.SMTPConfig{
		Host: ac.SMTP.Host, Port: ac.SMTP.Port, Username: ac.SMTP.Username,
		Password: password, From: ac.SMTP.From, TLS: tlsMode,
	})
	if err != nil {
		return nil, fmt.Errorf("accountability: %w", err)
	}
	eng, err := accountability.New(accountability.Options{
		Dir: filepath.Join(cfg.DataDir, "accountability"), Sender: sender, From: ac.SMTP.From,
	})
	if err != nil {
		return nil, fmt.Errorf("accountability: %w", err)
	}

	// Engine.Record can write its pending digest to disk (fsync and rename)
	// on every call that matches a subscription. ServeDNS calls OnAccess
	// synchronously on the hot DNS path, so Record itself must never run
	// there: a worker goroutine drains a small queue instead, and a full
	// queue drops the event rather than blocking a DNS response (the same
	// "never hold up the query for this" choice ClientSeen and Observe make
	// elsewhere in dnsengine).
	events := make(chan accountability.AccessEvent, accessQueueSize)
	go func() {
		for {
			select {
			case ev := <-events:
				eng.Record(ev)
			case <-ctx.Done():
				return
			}
		}
	}()
	engine.OnAccess = func(info dnsengine.AccessInfo) {
		deviceID, groupIDs := reg.ScopesFor(info.ClientIP)
		for _, item := range info.Items {
			ev := accountability.AccessEvent{
				Time: info.Time, ClientID: deviceID, GroupIDs: groupIDs,
				Item: item, Domain: info.Domain, Action: info.Action,
			}
			select {
			case events <- ev:
			default: // queue full: drop rather than block the DNS response
			}
		}
	}
	return eng, nil
}

// smtpPassword resolves the SMTP password: PasswordFile, when set, is read
// fresh (and trimmed) on every startup; config.Validate already rejects
// setting both it and Password, so there is never a "which one wins"
// question. See docs/ACCOUNTABILITY.md's "SMTP secret handling" section.
func smtpPassword(smtp config.AccountabilitySMTP) (string, error) {
	if smtp.PasswordFile == "" {
		return smtp.Password, nil
	}
	b, err := os.ReadFile(smtp.PasswordFile)
	if err != nil {
		return "", fmt.Errorf("reading accountability.smtp.password_file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
