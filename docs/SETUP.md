# First-run setup

Start Shepherd. With no configuration file, it brings up a setup page and prints the addresses to
open:

```
setup: no configuration yet, so Shepherd is waiting for you to finish setting it up.
setup: open one of these in a browser (the token is what proves it is you):
setup:   http://127.0.0.1:8787/?token=…
setup:   http://192.0.2.10:8787/?token=…
```

Open one of them from any machine on the network, answer five questions, press **Finish**. Shepherd
writes `shepherd.toml`, shuts the setup page down and carries straight on with what you chose —
same process, no restart, no editing TOML by hand.

`shepherd setup` runs the same flow deliberately, for an install that already has a configuration
file. `-config /etc/shepherd/shepherd.toml` writes somewhere else, and `-port` moves the setup page.

Run it on the host that will serve DNS, since the addresses it offers are that host's own. In the
container deployment ([`deploy/docker/`](../deploy/docker/)) that means running Shepherd with the
volume mounted and opening the address it prints, the same as anywhere else.

## Why it works this way

The setup page is **not** the portal. The portal needs a data directory, a policy store, a DNS
engine and a token, none of which exists on a first run, and its own default puts it on `127.0.0.1`
— unreachable from the laptop of whoever is installing Shepherd on a NAS or a Pi. So setup brings up
its own listener on **every** address this host has, and the one-time token in the printed URL is
what keeps the rest of the network out: the console is the one place that proves you are the person
who started the process. The page keeps that token in memory and sends it as a header, and drops it
from the address bar as soon as it has read it — deliberately not a cookie, since setup is plain
HTTP (there is no certificate yet) and this host and port become the portal once setup is done. The
listener stops the moment setup finishes.

If the preferred port is already taken, setup moves to a free one and says so rather than refusing
to start. That matters on a NAS: binding the wildcard can succeed while another process still owns
loopback, so a page that "came up" would be answering somebody else's service.

A setup page that cannot come up at all is logged, not fatal — Shepherd then starts on its defaults
(loopback only), and `shepherd setup` can be run later.

## What it asks

1. **Where Shepherd keeps its state** (`data_dir`) — stated, not asked. It is `data` beside the
   configuration file, created and checked while the page loads, so a directory that cannot be
   written is reported there rather than as a startup error after you have walked away. Nothing the
   page sends can change it: a path typed into a web page is both a question nobody can answer
   better than Shepherd and a path this process would then create and write to on a stranger's
   say-so. Move it later by editing `data_dir` if you really want it elsewhere. This is the
   directory to back up.

2. **Which addresses answer DNS** (`dns.listen`). Every address this host has, listed with its
   interface, all ticked by default. This is the question the page exists for: a device asks one
   specific address, so a host serving only its Wi-Fi address while the router hands out the wired
   one is a network with no DNS, and nothing in the configuration looks wrong. Loopback is not in the
   list because Shepherd adds `127.0.0.1` and `[::1]` itself; link-local addresses are left out
   because nothing can be pointed at one. The port is checked as you change it, and something already
   holding it is explained rather than refused — the holder is usually the resolver being replaced.

3. **Which resolvers to ask** (`dns.upstreams`). Presets that say what each resolver does and does
   not block, because this choice decides who sees every name the network looks up, or your own list
   typed in. **Test these resolvers** probes each one from this host — the same check the portal
   makes before it will add one — twice before calling one a failure, since public resolvers drop the
   odd uncached query.

4. **Where the portal listens** (`portal.listen`). Loopback by default, with the `ssh -L` line
   written into the file as a comment. A LAN address is offered, and what it means — the sign-in page
   reachable from anywhere on the network, the token still gating everything behind it — is said
   plainly.

5. **Whether to read per-device bandwidth from your router** ([TRAFFIC.md](TRAFFIC.md)). Optional and
   skipped by default: filtered DNS, devices, alarms and the rest work without it. A UniFi controller
   is collected here and verified by reading it once, so a password typo surfaces now instead of days
   later as an empty Bandwidth screen; its credentials go into `<data_dir>/secrets.json` (0600),
   never into `shepherd.toml`. eero signs in from the portal's Bandwidth screen instead, because it
   needs a code eero emails while you wait.

Everything else keeps its default and is deliberately left out of the file, so a default that
improves in a later version improves for your install too.
[`shepherd.example.toml`](../shepherd.example.toml) documents the full set if you would rather take
one over.

## What it does not do

It does not check the host. `scripts/shepherd-doctor` is the read-only preflight — which ports are
held, whether IPv6 works, link speeds, Thread border routers, the container runtime — and it changes
nothing. Setup is the other half: it asks what only you can answer and writes the file.

It writes nothing but the configuration file (plus the data directory, and `secrets.json` if you
connect a router). It installs no service and changes no system setting. An existing
`shepherd.toml` is kept as `shepherd.toml.bak`, because it may hold settings this page never asked
about.

## After it finishes

The page ends with the three things to check, in this order:

1. Query Shepherd from this host **and from another one**: `dig @<address> example.com`. A listener
   that works locally and not from the network is the failure this is looking for.
2. Open the portal and sign in with the token (`shepherd -print-token`, or
   `<data_dir>/portal-token`).
3. Only then hand the address out as the network's DNS server.

[WAVE-2.md](WAVE-2.md) walks through that last step. The built-in self-test ([DNS-QA.md](DNS-QA.md))
also warns on the Upstreams screen when this host has a LAN address with no DNS listener, which is
the same failure caught from the inside.

## Re-running it

Safe. The questions are asked again from scratch (it does not read your current file), the old file
is kept as `.bak`, and your data directory — rules, devices, history, policy — is untouched. What the
portal owns stays owned by the portal: `upstreams.json` keeps winning over `dns.upstreams` once you
have edited the list there.
