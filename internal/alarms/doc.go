// SPDX-License-Identifier: AGPL-3.0-or-later

// Package alarms is Shepherd's alarm system: one engine that every feature
// raises alarms through, and a router that delivers them.
//
// The engine records alarms (Engine.Raise), folds repeats into one alarm with
// a count (dedupe), collapses bursts into a bundle (storm control), applies
// mute rules, snoozes, quiet hours and learning mode, and offers batch
// management (acknowledge, resolve, mute, delete over IDs or a filter, with
// undo) plus listing, paging and badge counts. Every record carries an HLC
// stamp, writer node and tombstone flag, like the device registry, so the
// dataset can be replicated by last-writer-wins (see docs/DESIGN.md, "Mesh
// dataset sync"). Alarms, rules, preferences and the delivery log persist as
// atomic 0600 JSON files behind a Codec.
//
// The Router (NewRouter) consumes the engine's change stream and delivers
// newly raised, non-muted alarms to Web Push and ntfy by per-channel minimum
// severity and per-type switches: immediately for high and above, in a digest
// for the rest, with retries and backoff, and with a per-channel delivery log.
// It talks to the outside world only through the small interfaces Pusher and
// NtfyPublisher and the Clock, so tests never touch a network. NewWebPushPusher
// and NewNtfyPublisher adapt internal/webpush and internal/ntfy.
//
// Typical wiring:
//
//	eng, _ := alarms.New(alarms.Options{Dir: stateDir, Node: nodeID})
//	rt := alarms.NewRouter(alarms.RouterOptions{Prefs: eng, Pusher: push, Ntfy: ntfy})
//	eng.Subscribe(rt.Handle)
//	go rt.Run(ctx)
//	// anywhere in Shepherd:
//	eng.Raise(alarms.Event{Type: alarms.TypeNewDevice, DeviceID: id, Title: "New device: " + name})
//
// Raise never blocks the caller (it queues to a worker and counts drops when
// the queue is full), so it is safe on the DNS hot path.
package alarms
