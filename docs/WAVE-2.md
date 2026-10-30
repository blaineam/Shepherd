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

The policy answers NXDOMAIN for `mask.icloud.com`, `mask-h2.icloud.com` and `mask-api.icloud.com`.
Apple documents NXDOMAIN or an empty answer for those names as the way for a network to signal it
does not allow the relay. Some reports say devices that use their own DNS, or already hold relay
addresses, can still connect. Fully enforcing this needs Watch mode (Wave 6), which can also block
the QUIC traffic and outside DNS the relay uses.

## Not in this wave

Persistent query history and replay, device identity and groups, alarms, the mesh, and the globe HUD
are scheduled in [ROADMAP.md](ROADMAP.md).
