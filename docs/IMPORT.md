# Importing device names and groups

Shepherd can bring in the names and groups you already built somewhere else, once, so you do not
rebuild them by hand. It also learns real MAC addresses this way.

There are two importers, both in `internal/importers`:

- **CSV**, for any router or spreadsheet. Export Shepherd's own devices, or write a file in the same shape.
- **eero**, optional and one-time, for people whose router is an eero. It reads the device names and the
  profiles ("Kids", "Adults"...) from eero's cloud and turns them into Shepherd aliases and groups.

Shepherd stays router-agnostic. Nothing in the core depends on eero. If you do not use eero you never
touch that code.

## Read this first: the eero importer is unofficial and unverified

- eero publishes **no official export and no official API** for this. The importer talks to the
  undocumented cloud API that the eero app itself uses, the way well-known open-source clients do. eero
  can change or close it at any time, and may rate limit or block it.
- It is an unofficial integration. Use it at your own discretion and read eero's terms for your account.
- **It has not been verified against a live eero account.** It was written and tested only against
  fixtures that reproduce the response shapes public clients document, served by a fake server on
  loopback. The parser tolerates missing, extra and renamed fields, but a real response may still
  differ in ways nobody here has seen.
- Accounts that sign in with a third party instead of an email address or phone number cannot use the
  login endpoint this importer uses.
- Your safety net is the **preview**. Nothing is changed until you have read the preview and confirmed.
  If the preview looks wrong, stop; you lose nothing. The CSV importer is the dependable fallback.

## What is imported and how it maps

Everything is first turned into one neutral **Plan**, whatever the source. A plan lists devices (MAC,
IPs, display name, hostname, vendor, connection type, groups, tags, notes, a paused hint) and groups
(name, optional color), plus warnings.

| From eero | Becomes in Shepherd |
|---|---|
| Device nickname | The device's alias (the name you see) |
| Device hostname | Hostname evidence |
| Manufacturer | Vendor evidence |
| MAC address | The device's identity (the real MAC) |
| IPs | Current addresses |
| Connection type and the eero node it uses | A note, "Imported from eero: wireless via Living Room" |
| Device type | A hint to the type guesser (never forced) |
| Profile | A group with the profile's name |
| A device in a profile | Membership of that group |
| Guest flag | The tag `guest` |
| Paused | A hint in the preview only. Shepherd does not pause anything on import. |
| The eero routers and nodes themselves | **Infrastructure:** type router, and **excluded** from protection and traffic steering, so a future Watch mode never steers them |

Anything uncertain becomes a **warning**, never a guess. For example: a device listed in two profiles
joins no group and says so; a device made by eero that is not in eero's list of its own routers is not
marked as infrastructure; a profile entry that cannot be identified is left out.

### Rules that apply to every import

- **Your names win.** An alias you already set is kept. The preview lists it as a conflict. Only
  "overwrite names" replaces it.
- **Nothing is ever deleted.** Not devices, not groups, not memberships, not tags.
- **Idempotent.** Applying the same import twice changes nothing the second time.
- **Matching.** A device is matched by MAC first, then by IP (an IP-only device learns its MAC). An
  address held by a device with different hardware is **not** moved; the preview says so.
- **Existing evidence wins.** A device that already has a hostname keeps it. A device that already
  holds an IPv4 address keeps it; an imported address is never allowed to displace a live one.
- **Notes, types, tags.** Notes and a type you set are kept (listed as conflicts when they differ).
  Tags are only added. Exclusion is only ever turned on.
- **Randomized (private) MACs.** Phones and laptops rotate these. They are handed to the registry as
  evidence, and the registry folds a rotated address into the device that already holds the IP or
  hostname instead of making a duplicate. The preview warns how many such devices the import has, because
  they can reappear under a new address later.
- **Devices with no MAC** are accepted if they have an IP. A device with neither is skipped with a warning.
- **Untrusted text.** Names come from a third party. Control characters and invisible or direction-
  changing characters are removed, whitespace is collapsed, text is trimmed and capped (alias 100 bytes,
  hostname 100, vendor 64, group name 64, tag 32, notes 500). Limits: 5000 devices, 200 groups per import;
  a larger file is refused outright.
- **New-device events.** Created devices go through the registry's normal path, so anything listening
  for new devices sees them once.

## Privacy model of the eero importer

- The login happens **on your own machine**, in your Shepherd. Your email address or phone number and
  the verification code go **only to eero's servers**, over TLS with normal certificate verification.
  They are never sent anywhere else.
- They are **never logged, never stored and never put in an error message**. If eero's error text
  happens to echo one, it is replaced with `[redacted]` before it reaches you.
- The session token is held **in memory only** and is **discarded after the import**
  (`Client.Discard`). It is stored only if the caller explicitly supplies a `TokenStore`; the default is
  none.
- Requests have timeouts, the response size is capped (8 MiB), requests are spaced out (one every
  500 ms), and `429`/`Retry-After` is honoured. A redirect to another host is refused. The address must
  be `https`; a plain `http` address is accepted only by the test constructor and only on loopback.
- Shepherd does not need and does not ask for your eero password, and nothing about the import is sent
  to any Shepherd server (there is none).

## Step by step, in the portal

Open the **Devices** screen and click **Import**. A modal walks through either source; nothing is ever
changed before you review a preview and click Apply.

### eero

1. **Pick "eero"** in the import modal. The modal repeats the caveats above.
2. **Enter the login.** Type the email address or phone number of your eero account. eero sends a
   verification code. (`POST /api/import/eero/start`, which calls `Client.StartLogin`.)
3. **Enter the code.** (`POST /api/import/eero/verify`, `Client.Verify`) A wrong code, an expired code
   or a rate limit is explained in plain words, and you can try again or start over. On success the
   response lists the account's networks (`Client.Networks`); with exactly one, the import moves on by
   itself.
4. **Pick the network** if the account has more than one.
5. **Review the preview.** (`POST /api/import/eero/preview`) Shepherd reads the devices, profiles and
   eero nodes for that network (`Client.Snapshot`), maps them (`MapEero`) and shows the diff
   (`PreviewWith`): devices it would create, devices matched by MAC or IP, names it would set, groups it
   would create, memberships it would add, conflicts it would leave alone, and warnings. Nothing has
   changed yet. An "overwrite names" checkbox controls whether the preview (and the apply that follows)
   is allowed to replace a name you already set.
6. **Confirm.** (`POST /api/import/eero/apply`, `Apply`) The eero session token is discarded
   (`Client.Discard`) the moment this call returns, whether or not it succeeded. Closing the modal, or
   clicking "Start over", discards it too (`POST /api/import/eero/cancel`) — as does simply walking away:
   an untouched session expires and is discarded after 15 minutes.

### CSV

1. **Pick "CSV file"** and choose a file. It is read in the browser and sent as text; nothing is
   uploaded as a file attachment.
2. **Review the preview.** (`POST /api/import/csv/preview`) Parse errors are per row (`row_errors`) and
   never stop the import; the rest of the file is still shown.
3. **Confirm.** (`POST /api/import/csv/apply`)

### The eero import session

The multi-step eero flow needs somewhere to hold the in-progress login between requests, without ever
writing eero's token to disk. The portal keeps it **server-side, in memory only**, under a random
`session_id` the browser holds instead of the token itself:

- `start` creates the session (and makes the *importers.Client, holding eero's session token once
  `verify` succeeds). It is never written to configuration, to `devices.json`, or to any log.
- `verify`, `preview` and `apply` all take the same `session_id`.
- The session (and the token inside it) is discarded by `apply`, by `cancel`, or automatically 15
  minutes after it was last used.
- Every portal endpoint still requires the normal token auth and `X-Shepherd` CSRF header
  (see docs/PORTAL.md); the `session_id` only threads one import flow's steps together, it is not a
  second authentication scheme.

## API reference

All endpoints are `POST`, JSON in and out, under the usual portal auth (bearer token or cookie, plus the
`X-Shepherd` header). A report (the shape `Preview`/`Apply` return) is rendered as:

```json
{
  "dry_run": true, "source": "eero (Home)", "changed": true,
  "created": 1, "matched_by_mac": 0, "matched_by_ip": 0, "updated": 0,
  "named": 1, "renamed": 0, "skipped": 0, "unchanged": 0,
  "groups_created": 1, "memberships_added": 1, "tags_added": 0,
  "marked_excluded": 0, "notes_set": 0, "types_set": 0,
  "lines": ["create device \"Kids Tablet\" (02:00:5e:00:00:11)", "create group \"Kids\""],
  "conflicts": [],
  "warnings": []
}
```

The CSV endpoints add `"row_errors": ["line 4: ..."]` (omitted when there are none).

| Endpoint | Body | Response |
|---|---|---|
| `POST /api/import/eero/start` | `{"login": "owner@example.com"}` | `{"session_id": "..."}` |
| `POST /api/import/eero/verify` | `{"session_id": "...", "code": "123456"}` | `{"session_id": "...", "networks": [{"id": "1001", "name": "Home"}]}` |
| `POST /api/import/eero/preview` | `{"session_id": "...", "network_id": "1001", "overwrite_names": false}` | a report, `dry_run: true` |
| `POST /api/import/eero/apply` | `{"session_id": "..."}` | a report, `dry_run: false` |
| `POST /api/import/eero/cancel` | `{"session_id": "..."}` | `{"ok": true}` |
| `POST /api/import/csv/preview` | `{"csv": "mac,name\n...", "overwrite_names": false}` | a report (+ `row_errors`), `dry_run: true` |
| `POST /api/import/csv/apply` | `{"csv": "mac,name\n...", "overwrite_names": false}` | a report (+ `row_errors`), `dry_run: false` |

A bad login, a bad or expired code, an unknown network, an unparseable CSV, or an import session that
has expired or was never started all answer `4xx` with a plain-text error body; a rate limit from eero
answers `429`.

## CSV format

`ExportCSV` writes, and `ImportCSV` reads, this shape:

```
mac,ip,name,vendor,type,groups,tags,excluded,notes
02:00:5e:00:00:21,192.0.2.21,Kids Tablet,ExampleCo,tablet,Kids,child,,Charges in the hall
00:00:5e:00:00:22,192.0.2.22,Living Room TV,ExampleCo,tv,Living Room;Media,,,
00:00:5e:00:00:23,192.0.2.1,Hall eero,eero,router/infrastructure,,,yes,Do not steer
```

- `groups`, `tags`, and multiple IPs are separated by `;`. Groups are written by **name**.
- `type` is the type you set yourself (`tv`, `camera`, `printer`, ...). `excluded` is `yes` or empty.
- Export writes your aliases, not guessed names, so re-importing never turns a guess into a name.
- **Tolerated on import:** a UTF-8 BOM; `,` `;` or tab delimiters (detected from the first line);
  quoted fields with embedded delimiters, quotes and newlines; Windows line endings; blank lines;
  extra columns (ignored) and reordered columns.
- **Columns are found by header name.** Accepted aliases (case, spaces and punctuation ignored):
  - mac: `MAC`, `MAC Address`, `HW Addr`, `Hardware Address`, `Physical Address`, `Client MAC`
  - ip: `IP`, `IP Address`, `IPv4`, `Address`, `Last IP`
  - name: `Name`, `Nickname`, `Alias`, `Device Name`, `Display Name`, `Label`, `Friendly Name`
  - hostname: `Hostname`, `Host`, `DNS Name`
  - vendor: `Vendor`, `Manufacturer`, `Brand`, `Make`
  - type: `Type`, `Device Type`, `Category`
  - groups: `Group`, `Groups`, `Profile`, `Profiles`
  - tags: `Tag`, `Tags`, `Labels`
  - excluded: `Excluded`, `Exclude`, `Ignore`
  - notes: `Note`, `Notes`, `Comment`, `Comments`, `Description`

  A file needs a header row with a MAC or an IP column.
- **Errors are per row and never stop the import.** A bad MAC, a bad IP, a row with neither, an unknown
  type, an unreadable `excluded` value, a malformed quote: that row (or that field) is reported with its
  line number as a warning in the preview, and the rest imports. A file with several MAC addresses in one
  cell imports the first and says so. A file over 8 MiB, or empty, or with no usable header, is refused.
- **Spreadsheet safety.** On export, a text field that starts with `=`, `+`, `-` or `@` (or a tab or
  carriage return) gets a leading apostrophe so a spreadsheet will not run it as a formula. Import removes
  that apostrophe again, so an export round-trips.

## Using it from Go

```go
plan, rowErrs, err := importers.ImportCSV(file)      // or importers.MapEero(snapshot)
report, err := importers.Preview(plan, registry)     // changes nothing
fmt.Print(report)                                    // the human-readable diff
report, err = importers.Apply(plan, registry, importers.Options{OverwriteNames: false})
```

The eero client is `importers.NewClient(importers.ClientOptions{})` (production host, https only).
Pass a `TokenStore` in `ClientOptions` only if you decide to keep the token. Tests use
`NewTestClient` with a loopback address.

## Not built yet

- Periodic re-sync. The importers are one-time by design; running one again is safe (idempotent) but
  nothing schedules it.
- Refreshing an expired eero session; an expired session just asks you to sign in again.
- Importing eero's schedules, blocked apps or content filters. Only names, groups and identity evidence.
- Other routers' native formats. CSV covers them for now.

## Sources for the eero API shapes

Endpoint paths and response shapes come from reading public open-source code and documentation:

- `343max/eero-client` (Python): base URL, `POST login`, `POST login/verify`, the `s` session cookie,
  `GET account`, `GET networks/{id}/devices`, `GET networks/{id}/eeros`, the `meta`/`data` envelope and
  its `meta.code`/`meta.error` error shape. Its README notes that the API was reverse-engineered, that
  responses carry URLs to related resources, and that only email or phone logins are supported.
- The public Home Assistant eero integration by `schmittx` (`home-assistant-eero`): the same login and
  verify flow with the `s` cookie, the `error.session.*` errors, the device fields (`nickname`,
  `hostname`, `manufacturer`, `mac`, `ip`, `connection_type`, `device_type`, `wireless`, `paused`,
  `is_guest`, `source.location`), the profile fields (`name`, `paused`, `devices`) and the eero node
  fields (`mac_address`, `location`, `model`, `gateway`).

Pagination (a next link or a cursor) is handled defensively in several shapes because the public clients
did not need it; that part in particular is a best guess.
