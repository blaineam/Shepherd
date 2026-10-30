# Building a network tool in public

Shepherd is developed in the open on a real home network. That network's addresses, devices, names
and traffic must never reach the repository, and development must stay fast. These are the guards.

## Defense in depth

| Layer | What it does |
|---|---|
| **Data lives outside the repo** | State (portal token, rules, cached lists) is stored in `data_dir`, which defaults to a git-ignored `data/` and in practice points outside the checkout. The query log is memory only. |
| **`.gitignore` denies runtime files** | `.env`, `shepherd.toml`, `data/`, `rules.json`, `portal-token`, captures and databases can never be staged by accident. |
| **`scripts/leakcheck`** | Scans every staged line and every commit message for private and public IPs, Tailscale addresses, MACs, IPv6 ULA/link-local/global addresses, tailnet names, keys, personal paths and emails. |
| **`.leakcheck.local`** | Your own identifiers (domains, device and family names). Git-ignored, so the public repo never lists them. Matching is case-insensitive and also covers commit messages. |
| **Pre-commit and commit-msg hooks** | `make hooks` installs them. Commits fail in under a second. `LEAKCHECK_SKIP=1` exists for the rare false positive and prints a warning. |
| **CI** | Runs the leak guard on the whole tree and its own self-test on every push, and blocks beta builds if it fails. |
| **GitHub push protection** | Secret scanning for public repositories catches known token formats as a final net. |
| **Commit identity** | Commits use GitHub's private noreply address, not a personal email. |

## Reserved values for examples and tests

`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `02:00:...` MACs, `example.com`,
`example.ts.net`. Well-known public resolvers (1.1.1.1, 9.9.9.10 and similar) are allowed. Everything
else needs a `leakcheck:allow` marker and a reason.

## Iterating quickly

- The guards run on the diff only, so they stay fast.
- Test against fakes (`127.0.0.1:0` upstreams and a fake response writer), never your live network.
- Try changes on real hardware by building a beta locally (`make build`) and running it beside your
  production resolver on another port. The config for that lives in your git-ignored `shepherd.toml`.
- Keep screenshots and recordings synthetic: use the demo data mode (planned) or redact before sharing.

## If something leaks

1. Rotate any key or token immediately.
2. Remove it from history before anyone clones: GitHub's own guidance on removing sensitive data
   applies, and the repository is small enough that rewriting history is practical early on.
3. Add the pattern to `.leakcheck.local` (or to `scripts/leakcheck` if it is generic) with a test in
   `scripts/test-leakcheck`.
