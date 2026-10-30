# Wave 2: the Shepherd core

One native binary: an embedded DNS filtering resolver and the web portal. No Docker needed.

## Build and run

```bash
make build                          # bin/shepherd, static, no CGO
cp shepherd.example.toml shepherd.toml
# edit shepherd.toml: set dns.listen to your LAN address and portal.listen
bin/shepherd -config shepherd.toml
```

Open the portal at the address you configured. Sign in with the token from `data/portal-token`
(or `bin/shepherd -config shepherd.toml -print-token`).

Cross-compile for another machine from anywhere:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o shepherd-linux ./cmd/shepherd
```

## Try it beside your current resolver

Run Shepherd on a spare port (for example `dns.listen = ["192.0.2.10:5300"]`) while your existing
resolver keeps serving the network, then compare:

```bash
dig +short @192.0.2.10 -p 5300 example.com
dig @192.0.2.10 -p 5300 mask.icloud.com      # NXDOMAIN when the Private Relay policy is on
```

Nothing changes on your network until you point your router's DNS at Shepherd.

## What to verify (report back)

- [ ] DNS answers over IPv4 and IPv6, over UDP and TCP.
- [ ] Ads and trackers from your blocklist are blocked; a blocked domain returns `0.0.0.0` / `::`.
- [ ] Kill your first upstream (or block its IP): lookups keep working, and the portal shows it unhealthy.
- [ ] Per-device attribution: the portal shows each device's own address, not your router's.
- [ ] With the Private Relay policy on, an iPhone or Mac reports the relay is unavailable on this network, and the attempts show in the query list.
- [ ] Thread, Matter and AirPlay devices behave normally.
- [ ] Restart: lists load from cache immediately, and rules and policy switches persist.

## Apple iCloud Private Relay

The policy is **on by default** (opt out with `block_private_relay = false` or the portal switch). It answers NXDOMAIN for `mask.icloud.com`, `mask-h2.icloud.com` and `mask-api.icloud.com`.
Apple documents NXDOMAIN or an empty answer for those names as the way for a network to signal it
does not allow the relay. Some reports say devices that use their own DNS, or already hold relay
addresses, can still connect. Fully enforcing this needs Watch mode (Wave 6), which can also block
the QUIC traffic and outside DNS the relay uses.

## Run it as a supervised service

Shepherd is one static binary, so any service manager works. Where none is available (a NAS without
root, for example), `deploy/docker/` packages the same binary under Docker's restart policy. Docker is
only the supervisor: read-only filesystem, all capabilities dropped except binding port 53, state in
one mounted directory.

```bash
cd deploy/docker
cp /path/to/shepherd .                     # a release binary, or `make build` output
cp ../../shepherd.example.toml shepherd.toml   # set data_dir = "/data" and your addresses
mkdir data && docker compose up -d --build
```

## Cutting over from another resolver

If your router already hands out this machine's address for DNS (it usually does when another
resolver such as AdGuard or Pi-hole is running there), the router needs no change. Swap what answers
on port 53:

1. Run Shepherd on a spare port first and check it (`dig`, the portal, a restart).
2. Stop the old resolver, point Shepherd's `dns.listen` at port 53, restart it.
3. Verify within seconds from another machine. If anything is wrong, stop Shepherd and start the old resolver again.

Keep the old resolver installed (stopped) for a while. A stopped container with a restart policy of
`unless-stopped` stays stopped across reboots, so only Shepherd comes back.

## Not in this wave

Persistent query history and replay, device identity and groups, alarms, the mesh, and the globe HUD
are scheduled in [ROADMAP.md](ROADMAP.md).
