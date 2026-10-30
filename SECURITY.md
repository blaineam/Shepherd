# Security policy

Shepherd sees which devices on a network talk to which domains, so its security matters
more than most hobby projects. Thank you for taking it seriously.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: **Security tab, "Report a vulnerability"**.
Do not open a public issue for anything exploitable. You will get an acknowledgement within a few
days. While the project is pre-1.0, only the latest beta and the latest stable release are supported.

## Never include real network data

When you report anything, do not paste real query logs, IP or MAC addresses, tailnet names, tokens
or configuration. Redact them or replace them with documentation values (`192.0.2.x`,
`example.com`). If you already did, tell us and we will remove it.

## What Shepherd promises

- **No telemetry.** Shepherd does not phone home. The only outbound connections are your configured
  DNS upstreams and blocklist downloads.
- **Query history stays in memory** and is never written to disk by the DNS engine.
- **The portal requires a token**, uses strict same-site cookies, requires a custom header on every
  state-changing request and serves a strict content security policy.
- **Blocklist updates are guarded**, so a broken or hostile list cannot take over the filter.

## In scope

The DNS engine, the portal and its API, configuration handling, the release pipeline and the
leak guard. Out of scope: vulnerabilities in third-party software Shepherd talks to (report those
upstream) and issues that need physical access to the machine running Shepherd.
