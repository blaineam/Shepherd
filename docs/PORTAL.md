# The portal

Open the portal at the address in `portal.listen` and sign in with the token (`shepherd -print-token`,
or the file `portal-token` in the data directory).

## HUD

- **The globe.** Drag to rotate, scroll or pinch to zoom, it slowly auto-rotates until you touch it. Each arc runs from home to a place a device talked to. Repeated lookups to the same place merge into one **lane** that gets thicker and brighter (on a log scale) the more traffic it carries, so a heavy flow stands out from a one-off lookup.
- **Colors.** Teal is allowed, blue is cached, red is blocked, amber is an error. A blocked query has no destination, so it pulses a red shield ring at home.
- **What thickness means.** In Guard mode (DNS only) it is the number of lookups merged into the lane. When Watch mode supplies byte counts it becomes bytes. The legend always says which one you are looking at.
- **Control.** Click an arc, a destination or a row in the live feed to open the inspector: device, domain, place, count and, for a blocked query, a "Blocked by" row naming what matched (a catalog/custom list id, "custom rule", "allowlist", a geo block or a policy name — `dnsengine.Entry.Reason`). Block or allow the domain with one click and undo it. A one-click "block this country" control *on the globe itself* still needs Watch mode (true enforcement beyond DNS) and is shown disabled until then. Blocking a country by scope (network, group or device) today, DNS-answer based and working now in Guard mode, is on the Blocking screen's Countries tab — see [GEOBLOCK.md](GEOBLOCK.md).
- **Filters.** By device, by action, and by domain search.
- **Legend.** Colors, lane thickness scale and map attribution. Always visible on desktop; on a phone it starts hidden behind a small "i" button so it does not permanently take over the screen.
- **Home.** Found automatically from your network's public address. Choose **Set home** and click the globe to choose your own, which always wins; the automatic location is only city-level and can be wrong.
- **Replay.** The timeline at the bottom switches between **LIVE** and any retained period. Pause, and play at 1x, 10x, 60x or 300x. With encrypted history enabled, replay reaches as far back as you keep history; otherwise it covers what is in memory.
- **Details.** The earlier dashboard (live table, upstream and list health, rules, the Private Relay switch, top devices) is one tab away. It also states plainly that Watch mode is a planned feature not yet available in this build (see the roadmap's step 11) — everything shown is from DNS-only Guard mode, so the portal never leaves that silently ambiguous.

It needs WebGL for the globe and falls back to the Details view without it. It respects reduced motion (no auto-rotate, calmer pulses).

## Mobile

Below 760-900px (breakpoints vary slightly by screen) every management screen with a wide multi-column
table — Devices, Alarms, Vulnerabilities, History, the device drawer's Ports/Vulnerabilities panels —
reflows into stacked cards instead of scrolling sideways; Upstreams and Blocking were already narrow
enough to need no change. The top nav collapses behind a hamburger button into a vertical dropdown once
its tabs no longer fit in one row (desktop keeps the plain horizontal tab bar). The viewport pins
`user-scalable=no` (a deliberate tradeoff, commented in `index.html`) and every text input is kept at an
effective 16px so iOS Safari never force-zooms the page on focus. The Devices screen also surfaces a
"Needs attention" panel above the main list — wandering, excluded and newly quarantined devices pulled to
the top instead of mixed alphabetically into (for a real network) dozens of otherwise-identical rows.

## Demo mode

`/?demo=1` shows a realistic synthetic stream generated in the browser, with no API calls, for screenshots and
trying the interface. Options: `rate=N` events per second (default 5), `demo=bytes` to see byte-weighted lanes,
`rotate=0` to stop the auto-rotate, `nogl=1` to test the fallback, `debug=1` to expose `window.__hud` for measuring.

The portal is also locked behind demo data by default until you sign in with the token or a PIN, and relocks itself
after you are idle. See [LOCKING.md](LOCKING.md).

## How it gets data

Live entries come from `GET /api/stream` (Server-Sent Events, resuming from the last event) and fall back to polling
`/api/queries`. Replay and search use `GET /api/history`. Settings and home use `/api/settings`. Everything goes
through the same token and CSRF protections as the rest of the API, and every value from the network is rendered
as text, never HTML.

## Management API

The portal's management screens use these endpoints (all behind the token; every change needs the `X-Shepherd: 1` header; bodies are JSON and size limited):
devices, groups, bulk edit and merge in [DEVICES.md](DEVICES.md); the catalog, scopes, rules, switches and custom lists in [POLICY.md](POLICY.md); per-scope
country blocking in [GEOBLOCK.md](GEOBLOCK.md); the upstream list, presets and bootstrap in [UPSTREAMS.md](UPSTREAMS.md); alarms in [ALARMS.md](ALARMS.md); and
vulnerability findings and manual scans in [VULNSCAN.md](VULNSCAN.md). `GET /api/status` also reports
`device_count`, `group_count`, `catalog_count`, `custom_list_count` and `network_item_count`. Query entries carry `device` and `device_id` when the device is known.
A blocked History row also offers a one-click "Allow" action (the same `POST /api/rules` the HUD inspector's own block/allow buttons use), an explicit
per-domain override — narrower and safer than disabling whatever list or rule matched.

## Developing the front end

The pure logic (geometry, lane weighting, replay clock, demo generator, data sources) lives in small modules under
`internal/portal/web/js/` with unit tests in `internal/portal/web/test/`. Run them with `node --test internal/portal/web/test/`.
The globe library and land outlines are vendored in `internal/portal/web/vendor/` (see `VENDOR.md` there), so the portal
never loads anything from the internet.
