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

## Stable release

1. Move the `## [Unreleased]` entries in `CHANGELOG.md` under a new `## [X.Y.Z] - YYYY-MM-DD` heading and start a fresh empty Unreleased section.
2. Set `VERSION` to `X.Y.Z`.
3. Commit, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.

The **Release** workflow checks that the tag, `VERSION` and a changelog section agree, builds, publishes
the release with the changelog section as notes, marks it latest, and removes any remaining beta.

After a stable release, bump `VERSION` to the next planned version.

## Choosing the version

- **Patch** (0.1.1): fixes only.
- **Minor** (0.2.0): new features. Before 1.0.0, breaking changes also go here and are listed under Changed or Removed.
- **Major** (1.0.0): the first stable promise of compatibility for the configuration file and API.

## Coming in Wave 5

Signed releases and signed self-update with rollback, so a Shepherd can update itself safely.
