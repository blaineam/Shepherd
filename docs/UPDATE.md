# Self-update

Shepherd checks for a newer release once a day, says so, and can replace its own binary with it,
verified, keeping the previous one and putting it back on its own if the new one does not stay up.
`internal/update` is the mechanism; `cmd/shepherd/update.go` wires it; the Overview screen's
**Software** card is where it shows. It is deliberately quiet: one small HTTPS request a day, and
nothing downloaded until someone asks.

## What happens

1. **Check.** Every `check_hours` (24 by default) Shepherd asks GitHub's releases API for the
   latest release on its channel: `stable` is the release marked latest; `beta` also considers the
   rolling beta. Versions compare as semantic versions, so `0.1.1-beta.12` is newer than
   `0.1.1-beta.9` and older than `0.1.1`. A development build (`dev`, or any build without a
   version) sees every release as newer and never applies one.
2. **Say so.** A newer release raises a `self-update` alarm (low severity, keyed by the release tag
   so it is raised once) with a link to the release page, and the Software card shows it.
3. **Apply**, only when asked, from the card or `POST /api/update/apply`:
   - download `SHA256SUMS` and `SHA256SUMS.sig` from the release, and verify the signature against
     the Ed25519 public key built into this binary. An unsigned release, or a binary with no key
     built in, is refused here, before anything larger is fetched;
   - download the archive for this platform (`shepherd_<version>_<os>_<arch>.tar.gz`) and check
     its SHA-256 against the signed sums;
   - write the new binary beside the running one, rename the running one to `shepherd.prev`, and
     rename the new one into place, so there is a complete binary at the path at every moment;
   - record the swap in `<data_dir>/update.json`, answer the request, and a second later re-execute
     into the new binary with the same arguments and environment, which a supervisor sees as the
     same process carrying on.
4. **Confirm or roll back.** The new binary counts each start in `update.json`. After it has been
   up for two minutes it records itself confirmed. If it reaches three starts without ever being
   confirmed (it crashes on start, or keeps dying within two minutes), the next start renames
   `shepherd.prev` back into place and re-executes into it. `shepherd -rollback` does the same by
   hand for a binary that runs but misbehaves. A different version starting (a manual install)
   clears the record.

## Where it cannot update itself

The card says why instead of trying:

- **A read-only container.** The usual Docker deployment copies the binary into an image with a
  read-only filesystem; the directory cannot take a new file. Rebuild the container with the
  release instead.
- **No signing key built in.** `update.ReleasePublicKeyB64` in `internal/update/pubkey.go` is empty
  until the maintainer generates the key pair (below). Checks and alarms still work.
- **Windows.** A running executable cannot be replaced in place there yet; the release is linked
  for a manual install.
- **A development build.**

## Signing releases

Releases are signed once, by CI, with a key only the maintainer holds:

```
go run ./cmd/shepherd-sign -generate -out release.key
```

prints the public key and writes the private one to `release.key` (mode 0600). Put the private
key's contents in the `SHEPHERD_SIGNING_KEY` repository secret and never commit it; put the public
key in `update.ReleasePublicKeyB64` and commit that. From then on both workflows run
`scripts/sign-release`, which writes `dist/SHA256SUMS.sig` next to the sums, and every Shepherd built
from that commit on verifies releases against the key. Replacing the key invalidates nothing already
installed, but older binaries will refuse releases signed with the new one, which is the point.

`shepherd-sign -verify dist/SHA256SUMS -pub <key>` checks a signature by hand.

## Retention

The data directory's size, by top-level part, is on the Software card so growth is visible. The
stores that can grow each cap themselves: encrypted history by age and size
([HISTORY.md](HISTORY.md)), bandwidth history at 8 MiB of daily points ([TRAFFIC.md](TRAFFIC.md)),
network health at 8 MiB ([NETHEALTH.md](NETHEALTH.md)). A single budget across all of them, and a
settings screen for the alarm digest, are still open.

## Configuration

```toml
[update]
enabled = true
channel = "stable"    # or "beta"
check_hours = 24      # at least 1; a check downloads nothing
```

## API

| Endpoint | Does |
|---|---|
| `GET /api/update` | `enabled`, and `status`: `current`, `channel`, `latest` (tag, name, page URL, published), `available`, `can_apply` with a `reason` when not, `applying`, `applied`, `last_checked`, `last_error`, the `state` from `update.json`, and `data_dir_bytes` with `data_dir_parts` |
| `POST /api/update/check` | checks now and returns the status |
| `POST /api/update/apply` | applies the latest release and restarts; 409 with the reason when it cannot |
