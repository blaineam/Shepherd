// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webpush sends Web Push notifications using only the Go standard
// library.
//
//   - RFC 8030: the push protocol (an HTTPS POST to the subscription endpoint
//     with TTL, Urgency and Topic headers).
//   - RFC 8291: message encryption (ECDH on P-256, HKDF-SHA-256, AES-128-GCM)
//     using the aes128gcm content coding of RFC 8188.
//   - RFC 8292: VAPID, an ES256 JWT that identifies the sending server. The
//     audience is the push service origin and the expiry is never more than
//     24 hours ahead, because Apple's push service rejects longer lifetimes.
//
// It works with Apple (home-screen web apps on iOS 16.4 and later), Mozilla
// and Google push services.
//
// The pieces:
//
//   - VAPIDKeys, GenerateVAPIDKeys and LoadOrCreateVAPIDKeys: the server key
//     pair, generated once and stored (JSON, mode 0600, atomic).
//   - Encrypt: RFC 8291 encryption of one payload for one subscription.
//   - Sender: encrypts, signs and POSTs one message, and classifies the
//     outcome (ok, gone, rejected, transient, too large, invalid).
//   - Store: the subscriptions, one per browser, with a stable short device
//     ID, rename, remove, last-ok and last-error bookkeeping, tombstones and
//     atomic JSON persistence behind a Codec (same shape as internal/devices,
//     so encryption can be plugged in later).
//   - Broadcaster: sends one payload to every subscription in a Store and
//     retires the ones the push service reports gone.
//   - ValidateEndpoint: a subscription endpoint is attacker-influenced input,
//     so it must be https, on port 443 and not point at a private, loopback
//     or link-local host. NewHTTPClient repeats that check at dial time so a
//     hostname that resolves to an internal address cannot be used either.
//
// Nothing here talks to a push service unless the caller sends a message.
package webpush
