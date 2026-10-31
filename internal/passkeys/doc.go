// SPDX-License-Identifier: AGPL-3.0-or-later

// Package passkeys lets the portal unlock with a passkey (WebAuthn): Face ID,
// Touch ID, Windows Hello, a phone, or a hardware security key. It is
// additive to the token and the PIN, never a replacement for them
// (docs/PASSKEYS.md).
//
// The WebAuthn protocol itself (challenge generation, client data and origin
// checks, attestation and COSE key parsing, signature verification, the
// signature counter) is github.com/go-webauthn/webauthn, not code in this
// package. What lives here is the part that is specific to Shepherd:
//
//   - RelyingParty derives the one relying-party ID and the exact origins a
//     browser may report from [tls]'s hostname and listen address, and says
//     whether a request reached the portal at that address over HTTPS, so a
//     ceremony that cannot work is refused before it starts.
//   - Store persists the registered passkeys (public keys only: a passkey's
//     private key never leaves its authenticator) in a 0600 JSON file, wiped
//     when the portal token rotates, the same as PINs and trusted browsers.
//   - Service runs the registration and login ceremonies for the single
//     owner, holding each ceremony's challenge in memory, single use and
//     short lived.
package passkeys
