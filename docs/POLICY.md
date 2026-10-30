# Blocking policy

Shepherd decides what to block from one policy, kept in `<data_dir>/policy.json`. You change it in the
portal (or the API below); you never edit that file by hand while Shepherd runs.

Three ideas, and that is all there is:

1. **The catalog** is what can be blocked: lists, apps and categories.
2. **Scopes** say who it applies to: the whole **network**, a **group** of devices, or one **device**.
3. **Precedence** decides what happens when scopes disagree.

## The catalog

The catalog ships inside the binary (95 entries) and is the same on every install. Entries come in three kinds:

| Kind | What it is | Examples |
|---|---|---|
| **list** | A general blocklist you download from its publisher. | HaGeZi Pro (ads, trackers, malware), Block List Project porn, a threat intelligence feed |
| **app** | One app or service, or a suite of several. | Instagram, Discord, YouTube, Steam, the whole Meta family |
| **category** | A switch for everything in a group. | Social, Streaming, Gaming, Adult, Gambling, Messaging and Calls, Malware and Phishing |

Switching a category or a suite switches everything it includes. A switch on one app beats the switch on the
category that contains it (block Social but keep Reddit: turn Social on, Reddit off). Each entry shows its
license, homepage, approximate size and whether it is recommended.

Only the lists that are switched on somewhere are downloaded. Nothing is fetched for an item that is off
everywhere, and a fetched list is checked before it is used: an empty list, one that blocks a protected domain
(your bank, your OS vendor) or one that changes size drastically is rejected and the last good copy stays.

### Recommended items and first run

Protection is opt-out. On a **new install** the recommended entries (a general ads, trackers and malware list and a
threat feed) are on at network scope, and so is the Apple Private Relay switch. You can turn any of them off.

### Upgrading an install that predates the policy store

The first start of a version with the policy store reads what you had and writes `policy.json`:

- your `rules.json` allow rules, block rules and policy switches become the **network scope's** rules and switches;
- each `[[lists]]` entry becomes the catalog entry that has the same URL (so the default list becomes "HaGeZi Pro"), or a
  **custom list** when no entry matches;
- nothing else is switched on. An install that already existed keeps exactly the blocking it had; add more from the catalog.

`rules.json` and `[[lists]]` are read **only this once**. After `policy.json` exists, both are ignored (`rules.json` is
left in place as a backup) and the portal is the one place you change things.

`no_default_lists = true`, or defining your own `[[lists]]`, means a new install starts with the recommended items off.

## Scopes

| Scope | Applies to | Use it for |
|---|---|---|
| **network** | every device | ads, malware, the baseline |
| **group** | every device in the group, for example "Kids" | a bedtime-free, age-appropriate set |
| **device** | one device | the one console, the one TV |

A device that is in several groups gets the blocks of all of them. A client Shepherd has not identified gets the network
scope only.

Each scope holds the same three things: **items** (catalog or custom entries switched on or off), **rules** (your own allow and
block domains) and **switches** (built-in policies such as Private Relay).

## Precedence

- **Blocks add up.** A name is blocked if any scope that applies to the device blocks it: the network, any of its groups, or the device.
- **An allow at a more specific scope overrides a block from a less specific one.** A device's allow beats its group's and the network's
  blocks; a group's allow beats the network's. An allow does not reach the other way: a network-wide allow does not unblock something
  a group blocks.
- **Opting out works the same way.** Switching an item **off** at a group or device removes that item for it and cancels a switch-on at
  a less specific scope. Removing the setting (not off, just unset) makes it follow the scope above again.
- **Rules at the same scope:** adding a block for a domain removes its allow at that scope and the reverse.
- A domain matches its subdomains: blocking `example.com` blocks `www.example.com`.

### Examples

*Block an app for one group.* Create the group "Kids", put the children's devices in it (see [DEVICES.md](DEVICES.md)), then in the policy
switch **Discord** on at scope *group: kids*. Their devices lose Discord; everyone else keeps it.

*Block a whole category for everyone except one device.* Switch **Gaming** on at *network*, then switch **Steam** off at *device: studio-pc*
(or add an allow rule). The studio PC is the only machine that can use Steam.

*Everything social for the evening, but not for the grown-ups.* Switch **Social** on at *group: kids*; do nothing at the network.

*Let one site through for one device.* Add an **allow** rule for the domain at *device: living-room-tv*. It beats any block from the network
or the TV's groups.

*A blocklist of your own.* Add a custom list from a URL or paste domains (hosts, one-per-line or adblock `||domain^` form, up to 1 MiB).
It is enabled on the network and can then be switched on or off per group or device like any catalog entry.

## Country blocking

Blocking a country is **not** one of this policy's rules. It is a separate, additive check that runs after
this policy has already allowed a query, using the same network/group/device scopes but its own store and
its own API — see [GEOBLOCK.md](GEOBLOCK.md).

## Excluded devices

A device marked **excluded** has opted out of protection: its queries are answered without any blocking (the log shows reason
`excluded`), and it is still named and still appears in the log. Use it for a machine that must never be filtered, such as a work laptop on a
managed profile. In Watch mode (planned) excluded will also mean the device's traffic is never steered through Shepherd.

## API

All under the portal token, with `X-Shepherd: 1` on every change; bodies are JSON.

| Endpoint | Does |
|---|---|
| `GET /api/catalog` | every entry and the category names |
| `GET /api/policy` | each scope's items, rules and switches, the custom lists, list health, the switch descriptions |
| `POST /api/policy/items` | `{scope, item, enabled}`: `true` or `false` set it, `null` removes the setting from that scope |
| `POST /api/policy/rules`, `DELETE /api/policy/rules?scope_kind=&scope_id=&kind=&domain=` | add or remove an allow or block rule |
| `POST /api/policy/switches` | `{scope, name, enabled}` for built-in policies |
| `POST /api/policy/custom-lists`, `DELETE /api/policy/custom-lists/{id}` | a list of your own (`url` or `inline`) |
| `POST /api/policy/refresh` | fetch lists now (`{item}` for one) |

A scope is `{"kind": "network"|"group"|"device", "id": ""}`. An unknown group, device, item or switch is a 404; bad input a 400; a body over
the limit a 413. The older `/api/rules`, `/api/policies` and `/api/lists/refresh` keep working and act on the network scope.
`GET /api/policy` reports an item you switched **off** at a scope as `false`, and one you never set as absent.
