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

## Step by step (as it will appear in the portal)

The portal screens are not built yet (see below). The flow they will drive:

1. **Choose** "Import from eero" (or "Import from a CSV file"). The page repeats the caveats above.
2. **Enter the login.** Type the email address or phone number of your eero account. eero sends a code.
   (`Client.StartLogin`)
3. **Enter the code.** (`Client.Verify`) A wrong code, an expired code or a rate limit is explained in
   plain words, and you can try again or start over.
4. **Pick the network** if the account has more than one. (`Client.Networks`)
5. **Review the preview.** Shepherd reads the devices, profiles and eero nodes
   (`Client.Snapshot`), maps them (`MapEero`) and shows the diff (`Preview`): devices it would create,
   devices matched by MAC or IP, names it would set, groups it would create, memberships it would add,
   conflicts it would leave alone, and warnings. Nothing has changed yet.
6. **Confirm.** (`Apply`, optionally with "overwrite names") The session token is discarded
   (`Client.Discard`) whether or not you confirm.

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

- The portal screens and API endpoints for both importers (this package is the engine behind them).
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
