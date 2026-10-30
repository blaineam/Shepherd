# Contributing to Shepherd

Shepherd is built in public, for networks that belong to real people. Two rules shape
everything: **tests come first**, and **a real network's details never reach the repository**.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Set up

```bash
git clone https://github.com/blaineam/shepherd && cd shepherd
make hooks     # installs the pre-commit leak guard and docs check
make check     # everything CI runs: format, vet, tests with -race, coverage floor, leak guard
```

You need Go 1.24 or newer. Nothing else: no CGO, no Docker.

## Test-driven development

1. Write a failing test that describes the behavior. Run it and watch it fail for the right reason.
2. Write the smallest change that makes it pass.
3. Refactor with the tests green.

Every bug fix starts with a test that reproduces the bug. Coverage is enforced by `.coverage-floor`
and only goes up: `scripts/coverage --ratchet` raises the floor when coverage has grown. A change that
lowers coverage below the floor fails CI. See [docs/TESTING.md](docs/TESTING.md) for patterns
(fake upstreams, fake response writers, no real network).

## Never publish a real network

Tests, docs and examples use reserved values only: `192.0.2.x`, `198.51.100.x`, `203.0.113.x`,
`2001:db8::/32`, `02:00:...` MAC addresses, `example.com`, `example.ts.net`. `scripts/leakcheck` blocks
private and public addresses, MACs, tailnet names, keys, personal paths and emails, in files and in
commit messages. Put your own identifiers (domains, device names) in the git-ignored
`.leakcheck.local`. Never paste real logs into issues. See [docs/PUBLIC-DEV.md](docs/PUBLIC-DEV.md).

## Documentation travels with code

A change to Go source, the example config or the compose testbed must include a change to
`CHANGELOG.md` (and `docs/`, `README.md` or `site/` when behavior or setup changes).
`scripts/doccheck` enforces it locally and in CI. Describe user-visible changes under
`## [Unreleased]` in [Keep a Changelog](https://keepachangelog.com/) style.

## Versioning and releases

Shepherd follows [Semantic Versioning](https://semver.org/). Every push to `main` produces one rolling
beta; stable releases are tagged `vX.Y.Z`. See [docs/RELEASING.md](docs/RELEASING.md).

## Pull requests

Keep changes small and focused. Sign off your commits (`git commit -s`) to certify the
[Developer Certificate of Origin](https://developercertificate.org/). Contributions are licensed
under AGPL-3.0-or-later. Maintainers may later ask for a contributor license agreement if the project
ever needs to dual-license.

Security issues go through [SECURITY.md](SECURITY.md), not public issues.
