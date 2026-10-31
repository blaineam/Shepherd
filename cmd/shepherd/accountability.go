// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"shepherd/internal/accountability"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/secrets"
)

// accessQueueSize bounds how many access events can be queued for the
// accountability engine before new ones are dropped. See startAccountability
// for why this exists at all.
const accessQueueSize = 256

// startAccountability wires the DNS engine's OnAccess hook to an
// accountability.Engine (docs/ACCOUNTABILITY.md), resolving each access's
// device and groups from the device registry. Gated only by
// cfg.Accountability.Enabled (on by default): the engine is built whether or
// not a mail relay is set up, so contacts and subscriptions can always be
// managed in the portal, and the relay itself comes from the portal-managed
// secrets store through a RelaySender that a relay saved later is swapped
// into live (cmd/shepherd/secrets.go's secretsChanged) — no restart.
//
// Being enabled still costs nothing until a relay exists: the OnAccess hook
// is installed for the life of the process, but OnAccessWanted keeps the DNS
// engine from even looking up a query's items while no relay is set, and no
// access is ever queued, recorded or persisted without one. Returns nil
// values when the feature is disabled in shepherd.toml.
func startAccountability(ctx context.Context, cfg config.Config, engine *dnsengine.Engine, reg *devices.Registry, sec *secrets.Store) (*accountability.Engine, *accountability.RelaySender, error) {
	if !cfg.Accountability.Enabled {
		return nil, nil, nil
	}
	relay := &accountability.RelaySender{}
	if err := applySMTP(relay, sec); err != nil {
		log.Print(err) // the engine still starts; a fixed relay saved in the portal takes over
	}
	eng, err := accountability.New(accountability.Options{
		Dir: filepath.Join(cfg.DataDir, "accountability"), Sender: relay,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("accountability: %w", err)
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
	engine.OnAccessWanted = relay.Configured
	engine.OnAccess = func(info dnsengine.AccessInfo) {
		if !relay.Configured() {
			return // never accumulate what could not be sent (OnAccessWanted already skips this in ServeDNS)
		}
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
	return eng, relay, nil
}

// smtpPassword resolves the SMTP password in [accountability.smtp], only
// ever to import it once into the portal-managed relay (openSecrets):
// PasswordFile, when set, wins; config.Validate already rejects setting
// both it and Password. See docs/ACCOUNTABILITY.md.
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
