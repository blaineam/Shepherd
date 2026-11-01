// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

// ReleasePublicKeyB64 is the base64 Ed25519 public key releases are
// signed with (cmd/shepherd-sign, docs/UPDATE.md). Empty until the
// maintainer generates the key pair and commits the public half; while it
// is empty, Shepherd still reports updates but refuses to apply one, since
// it could not verify it.
var ReleasePublicKeyB64 = ""

// ReleasePublicKey decodes ReleasePublicKeyB64, or returns nil when none
// is built in or it is malformed.
func ReleasePublicKey() ed25519.PublicKey {
	if ReleasePublicKeyB64 == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(ReleasePublicKeyB64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}
