# First-run setup

Start Shepherd. With no configuration file, it brings up a setup page and prints the addresses to
open:

```
setup: no configuration yet, so Shepherd is waiting for you to finish setting it up.
setup: open one of these in a browser (the token is what proves it is you):
setup:   http://127.0.0.1:8787/?token=…
setup:   http://192.0.2.10:8787/?token=…
```

Open one of them from any machine on the network and answer what it asks. Press **Finish** and
Shepherd writes `shepherd.toml` and starts on it — same process, no restart, no editing TOML by
hand. The page then stays with you for the part that can only happen once it is running: it proves
DNS is filtering, hands over the portal token, and tells you what to change on your router. Closing
it is the last step, and it is yours to take.

Setup listens on port 8788, not the portal's 8787: it is still serving while Shepherd starts, so the
two cannot share a port (and it says so if you try to give the portal 8788).

`shepherd setup` runs the same flow deliberately, for an install that already has a configuration
file. Nothing starts after that subcommand, so the second half has nothing to show and says so.
`-config /etc/shepherd/shepherd.toml` writes somewhere else, and `-port` moves the setup page.

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

3. **Which resolvers to ask** (`dns.upstreams`) — measured, not guessed. Setup asks every candidate
   the same uncached question several times from this host and shows what came back, then
   recommends one. What it prefers, in order: encrypted (DoT) **and** filtering known-malicious
   names upstream; then reliability, because a resolver that lost any probe here is a device that
   waits and then falls back to something else; then the median latency of the probes that
   answered. An encrypted filtering resolver that is slower than 250ms from here loses to a quick
   plain one — that preference is not worth paying for on every uncached lookup. The numbers are on
   the page, so the recommendation can be checked rather than taken on faith, and you can pick any
   of them or type your own.

4. **What to block for the whole network.** A handful of categories from the shipped catalog
   ([POLICY.md](POLICY.md)) on top of the recommended blocklists Shepherd already starts with:
   malware and phishing, and ads and trackers, are ticked; adult, gambling, piracy, drugs and dating
   are offered. They are switched on in the running policy once Shepherd is up, so they are the same
   object the portal's Blocking screen edits afterwards — not a copy in the configuration file.
   Everything finer (per device, per group, schedules, the rest of the catalog) is the portal's job.

5. **Where the portal listens** (`portal.listen`). Loopback by default, with the `ssh -L` line
   written into the file as a comment. A LAN address is offered, and what it means — the sign-in page
   reachable from anywhere on the network, the token still gating everything behind it — is said
   plainly.

## What it does once Shepherd is running

**It proves DNS is filtering.** The page asks Shepherd's own listeners, over UDP and TCP, for a name
that must resolve and a name that must be blocked, and shows the result per address. That is the
self-test from [DNS-QA.md](DNS-QA.md) run on demand, not a second implementation, so setup cannot
call something working that the portal will call broken an hour later. "Run `dig` from another
machine" is advice most people will not take; this is the same check, taken for them.

**It hands over the portal token**, concealed, with Show and Copy, and asks you to say you have kept
it before it moves on. There is no password reset: that token is the way in. It is also in
`<data_dir>/portal-token` and from `shepherd -print-token`, and the page says plainly that it is
being shown over plain HTTP on your network — setup has no certificate and cannot have one, so if
that is not acceptable on your network, read it from the file instead.

**It tells you how to point the network at Shepherd**: the DNS server to hand out in your router's
DHCP settings (with the port, when it is not 53), the alternative of moving one device first, and a
reminder to give the Shepherd host a fixed address, since every device would otherwise be pointed at
nothing the day its address moves. Shepherd does not change your router for you: the APIs it speaks
to eero and UniFi are the read-only ones it uses for per-device bandwidth, and those vendors do not
publish a supported way to set a network's DNS server. Saying so is better than a button that works
on one firmware and silently does nothing on the next.

**It connects a router for bandwidth, if you want it.** UniFi is collected here and verified by
reading the controller once, so a password typo surfaces now instead of days later as an empty
Bandwidth screen; its credentials go into `<data_dir>/secrets.json` (0600), never into
`shepherd.toml`. eero signs in from the portal's Bandwidth screen instead, because it needs a code
eero emails while you wait.

**Then you close it.** The setup listener stops; Shepherd keeps running. A passkey or a PIN, so the
token is not what you type every time, is on the portal's Locking screen
([PASSKEYS.md](PASSKEYS.md), [LOCKING.md](LOCKING.md)).

## What it does not do

It does not check the host. `scripts/shepherd-doctor` is the read-only preflight — which ports are
held, whether IPv6 works, link speeds, Thread border routers, the container runtime — and it changes
nothing. Setup is the other half: it asks what only you can answer and writes the file.

It writes nothing but the configuration file (plus the data directory, the policy it was told to
set, and `secrets.json` if you connect a router). It installs no service, changes no system setting,
and touches nothing on your router. An existing
`shepherd.toml` is kept as `shepherd.toml.bak`, because it may hold settings this page never asked
about.

## Re-running it

Safe. The questions are asked again from scratch (it does not read your current file), the old file
is kept as `.bak`, and your data directory — rules, devices, history, policy — is untouched. What the
portal owns stays owned by the portal: `upstreams.json` keeps winning over `dns.upstreams` once you
have edited the list there.
