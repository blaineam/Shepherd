# Shepherd on a Firewalla box

A Firewalla Gold or Purple is an ordinary Linux machine, and Shepherd is one static binary, so
Shepherd can run on the box itself. There it is a **dashboard over the box**: Firewalla keeps doing
DNS, DHCP and filtering, and Shepherd shows and controls it, keeps the bandwidth history, syncs
device names, and can serve your reverse-proxy names. This is not something Firewalla supports;
read [what can go wrong](#what-can-go-wrong) first.

## Install

On the box, over SSH as the `pi` user:

```sh
curl -fsSL https://raw.githubusercontent.com/blaineam/shepherd/main/scripts/firewalla-install -o firewalla-install
less firewalla-install     # read it first; it uses sudo
bash firewalla-install
```

It prints the portal's address (`http://<the box's LAN address>:8787`) and where the sign-in token
is. Open **Router**, and under **Connections** choose **Use this box**
([BACKENDS.md](BACKENDS.md#firewalla-on-the-box)). There is nothing to type: Shepherd reads the API
the box serves on its own loopback address.

| | |
|---|---|
| `bash firewalla-install` | the newest release, betas included; run again to upgrade |
| `bash firewalla-install v1.3.0` | a release you name |
| `bash firewalla-install --tailscale` | also install Tailscale beside it (below) |
| `bash firewalla-install --remove` | stop everything and delete it |

What it puts on the box, and nothing else:

- `/data/shepherd/`: the binary, `shepherd.toml`, the data directory and the log. `/data` is the
  partition Firewalla keeps across firmware updates.
- `~/.firewalla/config/post_main.d/start_shepherd.sh`: Firewalla's own hook for starting things
  after boot. It starts Shepherd only if it is not already running.
- With `--tailscale`, `/data/tailscale/`.

No package is installed and no Firewalla file is changed. Shepherd runs as `pi`, not root; the one
privilege it is given is binding port 443, for the reverse proxy.

## What is switched off, and why

The config it writes is **dashboard mode** (`dns.enabled = false`) with everything that would be
wrong on a router turned off:

| Off | Because |
|---|---|
| DNS | the box's own resolver owns port 53 |
| Decoy ports, port scan, vulnerability scan | they would open ports on, or scan from, your router |
| ARP monitor, mDNS listener | the box already tracks devices, and Shepherd reads them from it |
| DNS self-test | there is no Shepherd DNS to test |
| Self-update | the installer is how it is upgraded here |

Devices, requests, alarms, rules and bandwidth all come from the box. History is kept encrypted on disk
(14 days, at most 1 GB) so the History screen and the map's replay survive a restart. To keep more,
raise `retention_days` and `max_mb` under `[history]` in `/data/shepherd/shepherd.toml` and restart;
a busy household's traffic, blocked attempts included, runs to a few tens of megabytes a day.

## Tailscale and the reverse proxy

`--tailscale` installs Tailscale's static binaries and runs `tailscaled` as `pi` in **userspace
networking** mode, so it adds no route and no firewall rule to your router. Join your tailnet with
the command the installer prints.

With that, Shepherd's reverse proxy ([REVERSEPROXY.md](REVERSEPROXY.md)) on the box can serve your
names to your tailnet: point your wildcard DNS record at the box's tailnet address and list each
service by its LAN address. The box's firewall already drops new connections from the internet
side, so port 443 is reachable from your LAN and your tailnet only.

**Exit node.** The same Tailscale can offer the box as an exit node, so a phone or laptop away from
home sends its traffic out through your home connection:

```sh
/data/tailscale/tailscale --socket=/data/tailscale/tailscaled.sock set --advertise-exit-node=true
```

**Subnet router.** To reach the devices on your LAN by their own addresses from anywhere on your
tailnet, advertise the LAN's range as well (yours may differ):

```sh
/data/tailscale/tailscale --socket=/data/tailscale/tailscaled.sock set --advertise-routes=192.0.2.0/24 --advertise-exit-node=true
```

Then approve both for the machine in Tailscale's admin console. If another machine already
advertises the same range, Tailscale keeps using that one until it goes offline or you switch its
route off there. In userspace mode this still adds
nothing to the router's firewall or routes. Two things follow from that: it is slower than a
kernel VPN, and the traffic leaves as the box's own, so Firewalla's per-device rules and its device
list do not see the remote device behind it.

One consequence of userspace mode: a visitor arriving over Tailscale reaches Shepherd from the
box's loopback address, so **the services behind the proxy cannot tell a tailnet visitor from any
other**. `X-Forwarded-For` carries `127.0.0.1` for them. A service that trusts tailnet addresses
(to skip a password, say) will not see one. Do not work around this by exposing such a service to
the whole LAN: anything on the LAN could then claim a tailnet address in that header.

A service behind the proxy that checks where requests come from (Home Assistant's
`trusted_proxies`, for one) has to be told about the box's LAN address.

## Moving an existing Shepherd onto the box

Install, then stop Shepherd on the box and **wait for it to exit** (it writes its data as it
stops), copy across what you want to keep, and start it again with the hook:

| File in the data directory | Carries |
|---|---|
| `devices.json` | devices, your names for them, groups |
| `settings.json`, `locking.json`, `passkeys.json` | portal settings, PIN and trusted browsers, passkeys |
| `portal-token` | the sign-in token, so it stays the same |
| `alarms/` | alarm history, mute rules, notification subscriptions |
| `reverseproxy.json`, `reverseproxy/`, `tls/` | proxy hosts and the certificates already issued |

Then edit each proxy host's target from `127.0.0.1` to the old machine's LAN address, add `[tls]`
and `[reverseproxy]` to `/data/shepherd/shepherd.toml` as they were, and change your DNS record
last. Leave `secrets.json`, the DNS history and the blocklists behind: the box does not serve DNS.

## What can go wrong

- **Firewalla does not support this.** The local API is not published and a firmware update can
  change it; see [BACKENDS.md](BACKENDS.md#firewalla-on-the-box) for exactly which calls are made.
  If it changes, the dashboard stops reading until Shepherd is updated. Your network is not
  affected: Shepherd is not in the path of any traffic.
- **It is your router.** Shepherd used about 240 MB of memory and almost no processor time on a
  Gold Pro with 80 devices. On a smaller box, watch the box's own health.
- **Replacing the binary by hand** loses its permission to bind port 443. The boot hook grants it
  again; run the hook (or the installer) rather than copying a binary over.
- **A reboot** runs the hook through Firewalla's `post_main.d`. That path was installed and run by
  hand here, and is what Firewalla documents for this, but it has not been watched through a real
  reboot or a firmware update.

`bash firewalla-install --remove` takes all of it off.
