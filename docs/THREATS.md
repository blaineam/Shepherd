# Threat feeds

Which device reached for something on a threat-intelligence list, blocked or not. `internal/threats`
matches every recorded DNS query's name and answer against curated feeds of malware distribution
hosts, botnet command-and-control addresses and hijacked network ranges, and raises a `threat-match`
alarm naming the device. The portal's Alarms screen has a **Threat feeds** tab with each feed's
state and the recent matches.

This is the cheap kind of threat detection, on purpose. Nothing inspects packets and nothing runs a
model: a match is a few hash-set lookups per query, and the feeds are a few hundred kilobytes each,
refreshed every six hours, the same kind of download the blocklists already make. It costs the
network nothing and the host almost nothing.

## Why it is not a blocklist

The blocklists in [POLICY.md](POLICY.md) already block most of what these feeds list, and a blocked
query never reaches a device. What the blocklists cannot say is *who tried*. A laptop that keeps
looking up a malware distribution host, or a TV whose app resolves a name sitting in a botnet
controller's range, is a device worth looking at whether or not the lookup was blocked. So this
feature checks the query after the engine has decided what to do with it, and reports the device,
the name, what matched, which feed, and whether the query was allowed, cached or blocked.

## The feeds

Built in, chosen for being plain text, permissively licensed, fetched without a key and maintained
by people whose job it is:

| Feed | Lists | Kind |
|---|---|---|
| HaGeZi Threat Intelligence Feeds, mini edition | names tied to malware, phishing, scams and botnets | names |
| SSL Blacklist (abuse.ch) | botnet command-and-control servers behind known bad certificates | addresses |
| Feodo Tracker (abuse.ch) | botnet command-and-control servers | addresses |
| Spamhaus DROP | hijacked and criminal-controlled networks | address prefixes |

The address feeds are a few kilobytes each; the name feed is a few megabytes, held in memory as a
set, which is the one place a broad list earns its size. abuse.ch's URLhaus and ThreatFox host
files were built in until 2026-11-01, when abuse.ch put its downloads behind an Auth-Key and the
old addresses began answering HTTP 410; Shepherd fetches feeds without credentials, so they are out
until a keyed fetch exists.

Each is downloaded in its own format: hosts-file lines (`127.0.0.1 name`), bare names, bare
addresses, CIDR prefixes with trailing comments. Lines that do not parse are skipped, not fatal. A
download that fails or comes back empty keeps the previous copy and records the error, which the
Threat feeds tab shows. Each feed is capped at 16 MiB. Feeds are cached under `<data_dir>/threats/`
so a restart matches from the moment it starts, before its first refresh.

## Matching

- A name matches an entry exactly or as a child of it: a feed naming `bad.example.com` catches
  `x.bad.example.com`, never `example.com`.
- An answer address matches an entry exactly or by prefix, with IPv4-mapped addresses unmapped
  first. Prefixes are checked longest first.
- The same client reaching the same indicator is reported once an hour, and the alarm engine's own
  dedupe folds anything that gets past that into the open alarm, so a beacon is one alarm with a
  rising count rather than one per query.
- Nothing is blocked by a match. The blocklists block; this names the device.

## Alarms

`threat-match`, critical by default, attributed to the registry's device for the query's client
address when it knows one, keyed by device and indicator. Evidence carries the name looked up, the
indicator matched, the feed, what the engine did with the query, and the client address. The server
log gets one line per match too.

## Configuration

```toml
[threats]
enabled = true          # on by default
interval_hours = 6      # how often the feeds are re-downloaded; at least 1
```

## API

| Endpoint | Does |
|---|---|
| `GET /api/threats` | `enabled`, `loaded` (indicators in all), `feeds` (each with `count`, `bytes`, `updated`, `error`) and `matches` (the last 200, newest first) |
| `POST /api/threats/refresh` | re-downloads every feed now and returns their state |

## What it does not do

No per-destination byte counts from Watch mode are checked against the address feeds yet; only DNS
answers are, so a device that reaches a listed address without a lookup is not seen. No feed can be
added from the configuration yet; the four built in are the set. No local model of what is normal
for a device, by decision: this project stays light on the host it runs on.
