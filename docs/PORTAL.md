# The portal

Open the portal at the address in `portal.listen` and sign in with the token (`shepherd -print-token`,
or the file `portal-token` in the data directory).

## Layout

The portal is a dashboard with a side menu. On a desktop the menu is always visible on the left,
grouped into **Monitor** (Map, History, Alarms, Vulnerabilities, Network health, Bandwidth), **Protect**
(Devices, Blocking) and **Settings** (Upstream DNS, DHCP, Reverse proxy, Accountability, Locking, System). The portal opens on the Map.
Monitor also holds **Bandwidth** ([TRAFFIC.md](TRAFFIC.md)): live and historical bytes per device, group and network.
Settings holds **DHCP** ([DHCP.md](DHCP.md)): what DHCP mode is doing and what is stopping it, the addressing it
would hand out, the current leases with the gateway each was actually given, address reservations you can add,
edit and remove, and a plainly worded account of what turning it on will do. It is off by default and the screen
says so; every part of it works with the mode off, which is the point -- the whole arrangement is meant to be
reviewed before it is switched on.
The top bar carries the connection state (live, demo, replay or offline), the clock, the demo-data switch
and the Lock button. Below about 1024px the side menu slides in from the left behind a labelled **Menu**
button in the top bar; picking a screen, tapping outside the menu or pressing Escape closes it.

Every screen uses the full width of the window, and the window's own scroll bar is the one you scroll
with: the long lists (Devices, Alarms, Vulnerabilities) run to the right edge of the window on purpose so
their scroll bar sits at the edge of the screen rather than inside a box. Screens are linked by hash
(`#devices`, `#blocking`, ...), so a screen can be bookmarked; the Map is the default.

## HUD

- **The globe.** Drag to rotate, scroll or pinch to zoom, it slowly auto-rotates until you touch it. Each arc runs from home to a place a device talked to. Repeated lookups to the same place merge into one **lane** that gets thicker and brighter (on a log scale) the more traffic it carries, so a heavy flow stands out from a one-off lookup.
- **Colors.** Teal is allowed, blue is cached, red is blocked, amber is an error. A blocked query has no destination, so it pulses a red shield ring at home.
- **What thickness means.** In Guard mode (DNS only) it is the number of lookups merged into the lane. When Watch mode supplies byte counts it becomes bytes. The legend always says which one you are looking at.
- **Control.** Click an arc, a destination or a row in the live feed to open the inspector: device, domain, place, count and, for a blocked query, a "Blocked by" row naming what matched (a catalog/custom list id, "custom rule", "allowlist", a geo block or a policy name — `dnsengine.Entry.Reason`). Block or allow the domain with one click and undo it. A one-click "block this country" control *on the globe itself* still needs Watch mode (true enforcement beyond DNS) and is shown disabled until then. Blocking a country by scope (network, group or device) today, DNS-answer based and working now in Guard mode, is on the Blocking screen's Countries tab — see [GEOBLOCK.md](GEOBLOCK.md).
- **Filters.** By device, by action, and by domain search.
- **Legend.** Colors, lane thickness scale and map attribution. Always visible on desktop; on a phone it starts hidden behind a "Legend" button so it does not permanently take over the screen.
- **Home.** Found automatically from your network's public address. Choose **Set home** and click the globe to choose your own, which always wins; the automatic location is only city-level and can be wrong.
- **Replay.** The timeline at the bottom switches between **LIVE** and any retained period. Pause, and play at 1x, 10x, 60x or 300x. With encrypted history enabled, replay reaches as far back as you keep history; otherwise it covers what is in memory.
- **System.** Software updates, blocklist health (with the reason a list was rejected), your own allow and block rules and the Private Relay switch. The query totals, live table and top lists the old Overview repeated are on the Map, History and Bandwidth screens. Without WebGL or canvas the HUD falls back to Bandwidth. Watch mode's controls are the last section of Bandwidth.

Without WebGL (Safari in Lockdown Mode, for one) the globe is replaced by a flat 2D map drawn on a canvas: the same dot-matrix land, home-to-destination arcs, comets, pulses, day/night shading, drag-to-pan and scroll or pinch to zoom, with click, hover and Set home working the same way. Only if canvas is also missing does the HUD fall back to Bandwidth. It respects reduced motion (no auto-rotate, calmer pulses).

## Mobile

Below 760-900px (breakpoints vary slightly by screen) every management screen with a wide multi-column
table — Devices, Alarms, Vulnerabilities, History, the device drawer's Ports/Vulnerabilities panels —
reflows into stacked cards instead of scrolling sideways; Upstreams and Blocking were already narrow
enough to need no change. The side menu becomes a slide-in sheet behind the Menu button (see Layout
above). The viewport pins
`user-scalable=no` (a deliberate tradeoff, commented in `index.html`) and every text input is kept at an
effective 16px so iOS Safari never force-zooms the page on focus. The Devices screen also surfaces a
"Needs attention" panel above the main list — wandering, excluded and newly quarantined devices pulled to
the top instead of mixed alphabetically into (for a real network) dozens of otherwise-identical rows.

## Demo mode

`/?demo=1` shows a realistic synthetic stream generated in the browser, with no API calls, for screenshots and
trying the interface. Options: `rate=N` events per second (default 5), `demo=bytes` to see byte-weighted lanes,
`rotate=0` to stop the auto-rotate, `nogl=1` to force the 2D map, `debug=1` to expose `window.__hud` for measuring.

The portal is also locked behind demo data by default until you sign in with the token, a PIN or (at the portal's own
HTTPS address) a passkey, and relocks itself after you are idle. See [LOCKING.md](LOCKING.md) and [PASSKEYS.md](PASSKEYS.md).

## How it gets data

Live entries come from `GET /api/stream` (Server-Sent Events, resuming from the last event) and fall back to polling
`/api/queries`. Replay and search use `GET /api/history`. Settings and home use `/api/settings`. Everything goes
through the same token and CSRF protections as the rest of the API, and every value from the network is rendered
as text, never HTML.

## Management API

The portal's management screens use these endpoints (all behind the token; every change needs the `X-Shepherd: 1` header; bodies are JSON and size limited):
devices, groups, bulk edit and merge in [DEVICES.md](DEVICES.md); the catalog, scopes, rules, switches and custom lists in [POLICY.md](POLICY.md); per-scope
country blocking in [GEOBLOCK.md](GEOBLOCK.md); the upstream list, presets and bootstrap in [UPSTREAMS.md](UPSTREAMS.md); alarms in [ALARMS.md](ALARMS.md); and
vulnerability findings and manual scans in [VULNSCAN.md](VULNSCAN.md); and proxied hosts and the shared DNS provider token (the Proxy tab) in [REVERSEPROXY.md](REVERSEPROXY.md); and the accountability mail relay in [ACCOUNTABILITY.md](ACCOUNTABILITY.md). Secrets are write-only: no endpoint ever returns a saved token or password. `GET /api/status` also reports
`device_count`, `group_count`, `catalog_count`, `custom_list_count` and `network_item_count`. Query entries carry `device` and `device_id` when the device is known.
A blocked History row also offers a one-click "Allow" action (the same `POST /api/rules` the HUD inspector's own block/allow buttons use), an explicit
per-domain override — narrower and safer than disabling whatever list or rule matched.

## Developing the front end

The pure logic (geometry, lane weighting, replay clock, demo generator, data sources) lives in small modules under
`internal/portal/web/js/` with unit tests in `internal/portal/web/test/`. Run them with `node --test internal/portal/web/test/`.
The globe library and land outlines are vendored in `internal/portal/web/vendor/` (see `VENDOR.md` there), so the portal
never loads anything from the internet.

## The public demo, and why its imports carry a hash

`site/demo/` is this same front end, generated by `scripts/sync-site-demo` and served at
<https://wemiller.com/apps/shepherd/demo/>. CI runs `scripts/sync-site-demo --check`, so the two cannot drift.

The generated copy is verbatim except for `index.html`, which turns demo mode on, and the `.js` files, whose relative
imports are rewritten to carry a content hash: `import { el } from './dom.js?v=1a2b3c4d'`. That is
`cmd/stamp-demo-modules`, run from `sync-site-demo`.

It is there because the CDN in front of the marketing site serves `.js` with a year-long `max-age` while `index.html`
expires in minutes, and the portfolio repo's own cache buster can only stamp URLs it can see in HTML attributes and CSS
`url()`. That covers `app.js` and `style.css`. It cannot see the modules under `js/`, because `app.js` imports them —
so a returning visitor could be served a fresh `app.js` together with modules cached a year earlier. A first visit
always looked correct, which is what made the fault easy to misread.

The hash is taken bottom-up over the import graph: a file is hashed after its own imports have been rewritten, so a
change in a leaf changes the URL of everything that reaches it, and `app.js`'s own bytes change with it. Hashing each
import against its target's *original* bytes would not be enough — the browser would keep serving a cached importer
still pointing at the old leaf URL. Because the hashes are of content and nothing else, regenerating an unchanged demo
produces identical bytes, which is what lets `--check` run on every commit.

Two limits worth knowing. The graph has to be acyclic for a transitive hash to have an answer at all, and
`stamp-demo-modules` fails loudly rather than guessing if a cycle ever appears. And it stamps module imports only: the
world outline that the globe pulls in with `fetch('vendor/land-110m.json')` is not an import and is not stamped. That
file is fixed Natural Earth data and is not expected to change, but if it ever does, returning visitors are the thing
to check.
