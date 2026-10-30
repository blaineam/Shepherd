# Testing

Shepherd is developed test-first, and coverage only goes up.

## The loop

1. Write a failing test. Run `go test ./internal/dnsengine -run TestName` and watch it fail for the right reason.
2. Write the smallest change that passes.
3. Refactor with everything green.
4. `make check` before committing (CI runs the same).

Every bug fix begins with a test that reproduces it. The outage that shaped the upstream prober
(an encrypted upstream that connected and never answered) is now `TestPoolFailsOverFromDeadUpstream`
and the probe tests.

## The coverage floor

`.coverage-floor` holds the minimum total statement coverage. `scripts/coverage` fails below it and
`scripts/coverage --ratchet` raises it when coverage has grown. Commit the new floor. Lowering it
needs a reason in the commit message.

## Patterns that keep tests fast and reliable

- **No real network.** Fake upstream resolvers listen on `127.0.0.1:0` (`fakeUpstream`, `bigUpstream`).
  Use reserved names and `192.0.2.x` addresses only. The leak guard rejects anything else.
- **Fake response writer.** `fakeWriter` implements `dns.ResponseWriter` so handler tests choose UDP or
  TCP and read replies without sockets.
- **Ephemeral ports.** `freeUDPAndTCPPort` and `freePort` avoid clashes between parallel runs.
- **Real binary tests.** `cmd/shepherd` tests start `run` with a temp config, query it over real
  sockets, then cancel the context and require a clean stop.
- **Race detector always on.** Everything runs with `-race`.
- **Property-style tests** for anything that must converge, such as the mesh dataset sync planned
  for Wave 4: generate operations, apply them in different orders on two replicas, require equal state.

## What the leak guard tests

`scripts/test-leakcheck` creates a throwaway repository and proves each detector (private and public
IPs, Tailscale addresses, MACs, IPv6, tailnet names, keys, paths, emails, private identifiers)
catches what it claims and lets documentation values through.

## Planned

Portal front-end tests (pure functions first), end-to-end tests that drive the portal in a browser,
fuzzing for the DNS and list parsers, and mutation testing on the filter.
