# Releasing

Shepherd uses [Semantic Versioning](https://semver.org/) and keeps a
[Keep a Changelog](https://keepachangelog.com/) changelog. Releases are built by GitHub Actions on
public runners, so anyone can verify them.

## Rolling beta

Every push to `main` runs the **Beta** workflow:

1. Tests, the coverage floor and the leak guard must pass.
2. The version is the next planned release from `VERSION` plus `-beta.<run number>`, for example `0.1.0-beta.17`. Prerelease numbers compare numerically, so `beta.10` is newer than `beta.9`.
3. Static binaries for Linux, macOS and Windows (amd64 and arm64 where applicable) are built with `SHA256SUMS`.
4. A GitHub prerelease is published, and **every older beta and its tag are deleted**. Only the newest beta exists.

Pushes are serialized, so a burst of commits builds only the latest.

### When a push gets no beta

A beta is only useful if it is **newer than the newest stable release**. SemVer orders
`1.1.1-beta.113` *before* `1.1.1`, so such a beta is not merely pointless: everyone already on the
release stops being offered anything, because the newest thing on their channel is older than what
they run. `scripts/beta-guard` therefore declines two kinds of commit, and the Beta workflow skips
the build rather than failing:

- **The release commit**, and any commit where `VERSION` has not been bumped back afterwards. A
  `## [X.Y.Z]` section in `CHANGELOG.md` for the current `VERSION` means that version is released,
  not in development. This is what left the beta channel dead for a day after 1.0.0 shipped with
  `VERSION` still at `1.0.0`.
- **A `VERSION` no newer than the newest published stable release**, whatever the changelog says.
  Pushing a release commit and its tag together starts both workflows on the same commit, and the
  Release workflow deletes the betas it can see: a beta published seconds after that cleanup
  survives it. That is how `1.1.1-beta.113` came to sit above `1.1.1` on the Releases page.

`scripts/test-beta-guard` covers both, and CI runs it.

## Stable release

1. Move the `## [Unreleased]` entries in `CHANGELOG.md` under a new `## [X.Y.Z] - YYYY-MM-DD` heading and start a fresh empty Unreleased section.
2. Set `VERSION` to `X.Y.Z`.
3. Commit, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The Beta workflow runs on
   that push too and publishes nothing, by design (see above).

The **Release** workflow checks that the tag, `VERSION` and a changelog section agree, builds, publishes
the release with the changelog section as notes, marks it latest, and removes any remaining beta.

After a stable release, bump `VERSION` to the next planned version, in its own "Back to
development: X.Y.Z" commit. That commit is what starts the next rolling beta; until it lands there
is no beta, which the guard says in the skipped run's log.

## Choosing the version

- **Patch** (0.1.1): fixes only.
- **Minor** (0.2.0): new features. Before 1.0.0, breaking changes also go here and are listed under Changed or Removed.
- **Major** (1.0.0): the first stable promise of compatibility for the configuration file and API.

## Signing, and self-update

Both workflows sign `dist/SHA256SUMS` with the Ed25519 key in the `SHEPHERD_SIGNING_KEY`
repository secret (`scripts/sign-release`, `cmd/shepherd-sign`), producing `SHA256SUMS.sig` next to
it. A running Shepherd verifies that signature against the public key built into it before it
applies an update, and refuses an unsigned release. Without the secret the build is published
unsigned and self-update only reports it. See [UPDATE.md](UPDATE.md) for generating the key pair
once and where each half goes.
