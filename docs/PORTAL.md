# The portal

Open the portal at the address in `portal.listen` and sign in with the token (`shepherd -print-token`,
or the file `portal-token` in the data directory).

## HUD

- **The globe.** Drag to rotate, scroll or pinch to zoom, it slowly auto-rotates until you touch it. Each arc runs from home to a place a device talked to. Repeated lookups to the same place merge into one **lane** that gets thicker and brighter (on a log scale) the more traffic it carries, so a heavy flow stands out from a one-off lookup.
- **Colors.** Teal is allowed, blue is cached, red is blocked, amber is an error. A blocked query has no destination, so it pulses a red shield ring at home.
- **What thickness means.** In Guard mode (DNS only) it is the number of lookups merged into the lane. When Watch mode supplies byte counts it becomes bytes. The legend always says which one you are looking at.
- **Control.** Click an arc, a destination or a row in the live feed to open the inspector: device, domain, place, count. Block or allow the domain with one click and undo it. Blocking a whole country needs Watch mode and is shown disabled until then.
- **Filters.** By device, by action, and by domain search.
- **Home.** Found automatically from your network's public address. Choose **Set home** and click the globe to choose your own, which always wins; the automatic location is only city-level and can be wrong.
- **Replay.** The timeline at the bottom switches between **LIVE** and any retained period. Pause, and play at 1x, 10x, 60x or 300x. With encrypted history enabled, replay reaches as far back as you keep history; otherwise it covers what is in memory.
- **Details.** The earlier dashboard (live table, upstream and list health, rules, the Private Relay switch, top devices) is one tab away.

It needs WebGL for the globe and falls back to the Details view without it. It respects reduced motion (no auto-rotate, calmer pulses).

## Demo mode

`/?demo=1` shows a realistic synthetic stream generated in the browser, with no API calls, for screenshots and
trying the interface. Options: `rate=N` events per second (default 5), `demo=bytes` to see byte-weighted lanes,
`rotate=0` to stop the auto-rotate, `nogl=1` to test the fallback, `debug=1` to expose `window.__hud` for measuring.

## How it gets data

Live entries come from `GET /api/stream` (Server-Sent Events, resuming from the last event) and fall back to polling
`/api/queries`. Replay and search use `GET /api/history`. Settings and home use `/api/settings`. Everything goes
through the same token and CSRF protections as the rest of the API, and every value from the network is rendered
as text, never HTML.

## Developing the front end

The pure logic (geometry, lane weighting, replay clock, demo generator, data sources) lives in small modules under
`internal/portal/web/js/` with unit tests in `internal/portal/web/test/`. Run them with `node --test internal/portal/web/test/`.
The globe library and land outlines are vendored in `internal/portal/web/vendor/` (see `VENDOR.md` there), so the portal
never loads anything from the internet.
