# Devices

Shepherd keeps a registry of the devices on your network so the portal, the log and the policy can say
"Kitchen tablet" instead of `192.0.2.14`. You can search it, edit it, and put devices in groups; a group or a device is
what you point a [policy](POLICY.md) at.

## How a device is found

Everything is passive. Shepherd listens; it never scans, spoofs or announces anything.

| Source | What it learns | Config |
|---|---|---|
| **DNS clients** | an address that sends a query is a device (reported at most once a minute per address) | `devices.dns` |
| **Neighbor table** | the MAC address behind each IP, from the operating system's ARP and neighbor tables, every 30 s | `devices.neighbors` |
| **mDNS** | the names devices announce about themselves (`kitchen-tablet`, model hints, services) | `devices.mdns` |
| **Reverse DNS** | the name your router gave a newly seen address (a PTR lookup to one resolver) | `devices.reverse_dns` |
| **MAC vendor** | the manufacturer, from a table of the IEEE's public assignments built into the binary | always |

A device is keyed by MAC when known, otherwise by IP, and merges when a MAC is learned later. Phones that rotate a private
(randomized) address are folded into the device that already holds the IP or the announced name instead of multiplying.
Addresses are tracked as they change: a device keeps its identity, its groups and its name when DHCP gives it a new address.

Turn everything off with `devices.enabled = false`, or any one source off by name. The registry is saved to
`<data_dir>/devices.json` (mode 0600) every minute when something changed and on shutdown; it holds MAC addresses, names and
groups. Encrypting this file like the query history is planned; the code has a single place for it.

### What is the neighbor table?

On Linux Shepherd reads `/proc/net/arp` and runs `ip -6 neigh show`; on macOS it runs `arp -an`. These only list machines this host has
talked to recently, so the table is a hint, not an inventory. DNS clients fill the rest.

## Names, and the order they are chosen

A device's display name is the first that exists:

1. **Alias**: the name you gave it.
2. **mDNS or DHCP hostname**: what the device calls itself.
3. **Reverse DNS**: what your router calls it.
4. **Vendor and type**, for example "Acme tablet".
5. **The IP address**.

Rename a device (set an alias) and every query log line, including those already in the history, keeps the name it had when it was
recorded; new lines use the new name. Clear the alias to go back to the learned name.

Reverse DNS asks the **default gateway** (Linux: from `/proc/net/route`) unless you set `devices.reverse_dns_server`. Elsewhere,
set it or the names from PTR records are skipped. Lookups are rate limited, cached for hours, and go to that one server only, never to the
internet.

The device **type** (phone, tablet, laptop, tv, speaker, camera, printer, game console, smart-home hub, router) is a guess from the
vendor, name and announced services, with the reason shown. Set it yourself to keep it.

## Search

The search box takes free text and filters. A `-` in front negates a term; quote values with spaces.

| Term | Matches |
|---|---|
| `kitchen` | name, alias, hostname, IP, MAC, vendor, type, tags, group names, notes |
| `group:kids` | members of a group whose name contains it; `group:none` for devices in no group |
| `vendor:apple` | vendor contains |
| `type:camera` | device type |
| `ip:192.0.2.` | a current or past address that starts with it |
| `name:tv` | the display name, alias, mDNS, host or reverse DNS name contains it |
| `mac:02:00:5e` | MAC prefix |
| `seen:1h` | seen within the last hour (`m`, `h`, `d`) |
| `excluded:true` | opted out of protection |
| `unnamed:true` | no real name known yet |
| `tag:guest` | a tag |
| `-group:kids` | not in the group |

Order by most recently seen (`sort=recent`) or name; results are paged (`offset`, `limit`, at most 500).

## Groups and bulk edit

A group has a name, a color and members. A device can be in several. Select any number of devices (from a search, for instance
`unnamed:true`) and in one step: add them to or remove them from a group, set or clear **excluded**, add or remove tags, or delete them.
A deleted device comes back as a new one if it is seen again. Deleting a group takes its devices out of it and forgets the policy set for
it; deleting a device forgets the policy set for it.

You can also **merge** devices that Shepherd wrongly kept apart (a phone seen on Wi-Fi and on a VPN): the target keeps the addresses,
names, groups and tags of the sources, which are removed along with their device-level policy.

## Quarantine

A newly discovered device lands in the reserved **Quarantine** group automatically, so nothing new on your network gets the run of it
before you have looked at it. Assigning a device to *any other* group releases it from quarantine in the same step; moving it back in
later is still allowed. To release a device without putting it anywhere else, remove it from quarantine directly (the same bulk "remove
from group" action, pointed at Quarantine).

Quarantine is a group like any other for policy purposes: set its rules on the Blocking screen (scope: **A group** → Quarantine) the same
way you would for any group, so a sensible default (block known trackers and malware, say) applies to everything new the moment it is
seen. You can rename or recolor the group; it cannot be deleted, because new devices need somewhere to land.

Turn off automatic assignment with `devices.quarantine_new_devices = false` in the configuration (the group itself still exists, so you
can set up its policy ahead of time); the default is on, matching the rest of Shepherd's protect-by-default convention.

**What quarantine does not do.** Shepherd enforces quarantine's rules the same way it enforces any group's: through DNS, and, once Watch
mode is trialed and enabled, through steering a device's own outbound traffic. Neither of those stops a quarantined device from talking
directly to another device on your LAN — that traffic never goes through DNS, and one-sided Watch mode only sees a device's traffic
*toward the gateway*, not toward its neighbors. Real LAN isolation needs your router: a guest network (which eero and most consumer mesh
routers support, as an isolated SSID and subnet) is the practical way to keep a new or untrusted device off the rest of your network
today. True peer isolation enforced by Shepherd itself would need spoofing a device's view of every other LAN peer, not just the
gateway — a materially bigger and riskier step than the ARP interception already planned, and not scheduled; see the roadmap's research
items.

## Excluded

**Excluded** means the device has opted out of protection. Today that means its DNS queries are answered with no blocking at all (the log
says `excluded`), but it is still named and logged. When Watch mode arrives (planned), excluded also means the device is never steered
through Shepherd.

## What needs Watch mode

Today's registry needs no special placement, only that devices use Shepherd for DNS or show up in the neighbor table. Watch mode (planned)
adds ARP-based steering and with it: seeing devices that never ask Shepherd for DNS, per-device bandwidth, pause, and the exact moment a
new device joins. Until then a device that does not use Shepherd for DNS and is not in the neighbor table is not seen.

## API

Under the portal token, `X-Shepherd: 1` on every change.

| Endpoint | Does |
|---|---|
| `GET /api/devices?q=&sort=&offset=&limit=` | search; returns `{devices, total, offset, limit}` |
| `GET /api/devices/{id}`, `PATCH`, `DELETE` | read, edit (`alias`, `notes`, `type`, `excluded`, `tags`), forget |
| `POST /api/devices/bulk` | `{ids, op, group_id?, excluded?, add_tags?, remove_tags?}`, `op` is `assign_group`, `remove_group`, `set_excluded`, `set_tags` or `delete`; returns `{changed, missing}` |
| `POST /api/devices/merge` | `{target, sources}` |
| `GET/POST /api/groups`, `PATCH/DELETE /api/groups/{id}` | list, create, rename or recolor, delete |

Names are plain text and are rendered as text, never HTML. An unknown id is a 404, a duplicate group name a 409, bad input a 400.

## Modes: Protected, Wandering, Excluded

Every device is in one of three modes, set from the Devices screen (or `PATCH /api/devices/{id}`, or in bulk):

| Mode | Filtering | Watched and logged | Use it for |
|---|---|---|---|
| **Protected** (default) | Everything that applies: blocklists, app and category blocks, rules, policies | Yes | Normal devices |
| **Wandering** | **None at all.** Not even the Private Relay policy | **Yes, every request**, flagged as wandering | A device that misbehaves under filtering, a device you want to study, or a guest you want to see but not restrict |
| **Excluded** | None | Yes (DNS), but the device is left alone | Infrastructure that must never be touched (routers, mesh nodes, Thread border routers) and, later, devices that must never be steered by Watch mode |

Like a sheep wandering off while the shepherd keeps watch, a wandering device talks freely and nothing it does goes unseen.

- **A timer is optional.** Choose 15 minutes, 1 hour, 4 hours, 24 hours (up to 30 days) or until you turn it off. A timed device returns to Protected by itself, and the DNS engine honours the end time on the very next query, not on a sweep.
- **Shadow results.** For every request from a wandering device, Shepherd still works out what filtering *would* have blocked and records it as `shadow` (for example `hagezi-pro (network)` or `instagram (group Kids)`). You can see exactly what the device would have been denied, which also makes wandering mode a way to find false positives without breaking anything.
- **Visible everywhere.** Wandering queries carry `wandering: true` and the reason `wandering` in the live stream, the in-memory view and the encrypted history, so they are easy to filter and replay. The HUD marks them distinctly.
- **If both are set**, Wandering wins, so the shadow is still recorded.
- **Search:** `wandering:true` finds the devices currently wandering.
- **In Watch mode** (later) a wandering device is steered through Shepherd and its flows and bytes are recorded in full, with no blocking of any kind (no geo rules, no automatic blocks).
