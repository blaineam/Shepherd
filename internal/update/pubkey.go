// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

// ReleasePublicKeyB64 is the base64 Ed25519 public key releases are
// signed with (cmd/shepherd-sign, docs/UPDATE.md). The private half is the
// SHEPHERD_SIGNING_KEY repository secret, held only by the maintainer, and
// both workflows sign dist/SHA256SUMS with it.
//
// This is the public half, so it is meant to be here: a Shepherd built from
// this commit verifies every release against it before applying an update,
// and refuses one it cannot verify. Replacing the pair invalidates nothing
// already installed, but binaries built before the change will refuse
// releases signed with the new key, which is the point of signing them.
var ReleasePublicKeyB64 = "i1UBvJCjZn73vs7x9PhYaSjFyn8muhPPksiu8revQbw="

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
