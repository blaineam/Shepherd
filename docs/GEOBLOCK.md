# Country blocking (geo-block)

A Firewalla-style feature: block DNS answers whose address resolves to a country you choose, per scope
(network, a group or a device), the same three scopes as everything else in [POLICY.md](POLICY.md).

## How it works, and why it is not a policy rule

Country blocking is deliberately **not** a rule inside the Filter's policy engine (`internal/dnsengine`'s
`CheckFor`, the allow/block/scope precedence described in POLICY.md). It is an **additive check that runs
after** a query has already been allowed or answered from the cache: `Engine.CountryBlock`, a hook field on
`dnsengine.Engine` set once at startup (`cmd/shepherd/geoblock.go`'s `startGeoBlock`), following the exact
shape Apple Private Relay's own block check and `internal/classify`'s `Observe` hook use to reach into the
engine from the outside. Concretely, inside `ServeDNS`'s `finishAllowed`:

1. The engine resolves the query normally (cache or upstream) and geolocates the answer's addresses with
   the same `geo.Locator` the globe HUD uses (`Engine.Geo`, `destsOf`) — no second database, no second
   lookup.
2. `CountryBlock(clientIP, dests)` is given those destinations. If any one's `Dest.Country` is in the
   blocked set for that client's scopes, the query is turned into a blocked one: the answer is replaced with
   the engine's existing sinkhole response (the same `block_mode` — `null` or `nxdomain` — every other block
   uses), `Entry.Action` becomes `"blocked"`, `Entry.Reason` becomes `"geo"`, and `Entry.GeoCountry` carries
   the matched code.
3. Otherwise the query is left alone exactly as it would have been.

This keeps `Filter.CheckFor` and the scheduled-access/allowlist rule-evaluation path untouched: geo-block
state lives in its own file and its own store (`GeoBlockStore`, `<data_dir>/geoblock.json`), never inside
`policy.json` or `PolicyData`.

## Where the state lives

`internal/dnsengine/geoblock.go`'s `GeoBlockStore` owns a per-scope list of ISO 3166-1 alpha-2 country codes
(network, and sparse maps keyed by group and device ID), persisted atomically to `<data_dir>/geoblock.json`
(mode 0600) the same way `PolicyStore` persists `policy.json` — but it is a separate file, opened and edited
independently, with no shared code path. A code is validated only for shape (two uppercase letters); Shepherd
ships no canonical list of assigned codes here, so a well-formed but unassigned code is accepted and simply
never matches a resolved country.

**Blocks union across scopes**, the same rule POLICY.md describes for everything else: a country is blocked
for a client if the network, any of its groups, or the device itself lists it. There is no allow mechanism
and none is needed — a country not listed is never blocked, so there is nothing to override.

## The `[map]` dependency

Country blocking only works when `[map]` is enabled and its GeoIP database has loaded (`cfg.Map.Enabled`,
the same `geo.Locator` the globe HUD uses — see [the map config](../shepherd.example.toml)). When the map is
off, or it is on but the database has not finished loading yet, `CountryBlock` **never blocks and never
errors**: queries are answered exactly as if the feature did not exist. This is checked on every query (the
hook simply finds no destinations to compare, since `Engine.Geo` is nil until the map is enabled and ready),
and if a scope actually has countries configured while this is the case, Shepherd logs it **once**, not per
query:

```
geo-block: countries are configured but [map] is disabled or the GeoIP database has not loaded yet; country blocking is inactive until then
```

An install that never configures any blocked country never sees this log line and never pays for the check.

## API

Under the portal token, with `X-Shepherd: 1` on the change; the scope addressing matches every other scoped
endpoint (`{"kind": "network"|"group"|"device", "id": ""}`).

| Endpoint | Does |
|---|---|
| `GET /api/geoblock` | `{"network": [...], "groups": {id: [...]}, "devices": {id: [...]}}` — a scope with nothing blocked is simply absent from `groups`/`devices` |
| `POST /api/geoblock` | `{scope, countries}` replaces the whole list at that scope; an empty list clears it |

An unknown group or device is a 404; an invalid country code (not two letters) or scope kind a 400. Deleting
a group or device also deletes its geo-block scope, the same way it already forgets that group's or device's
policy settings.

## Portal UI

The Blocking screen's existing scope picker (Whole network / A group / One device) gained a **Countries**
tab: a filterable, checkbox-style list of common ISO country names and codes (`internal/portal/web/js/countries.js`,
reference data for the picker only — the server accepts any two-letter code, with or without a row in this
list). A country blocked at a broader scope shows as locked and inherited at a narrower one, exactly like a
policy switch.

## Visibility

A geo-blocked query is identifiable in the live stream and history the same way every other blocked query
is: `action: "blocked"`, with its own reason, `reason: "geo"`, and `geo_country` carrying the ISO code that
matched. The destinations it would have reached (`dests`, the same field the globe HUD already shows for
allowed and cached queries) are kept on the entry, so the inspector can show exactly where the query resolved
to before it was blocked.

## Honest limitation

Like every other DNS-based check in Shepherd, this only ever sees the IP address(es) in **Shepherd's own DNS
answer**. A device that bypasses Shepherd's resolver entirely — its own hard-coded resolver, encrypted DNS to
somewhere else, or a VPN — is invisible to it, exactly the same caveat the rest of the DNS-based filtering
(blocklists, Private Relay, device classification) already carries. This blocks **lookups that resolve into**
a country, not all traffic to it: a connection reached by an address Shepherd never saw resolved (a
hard-coded IP, a previously cached answer from before the block was set) is not caught. It is also no
stronger than the GeoIP database's own accuracy, which is coarse (city-level, sometimes wrong) by nature.
