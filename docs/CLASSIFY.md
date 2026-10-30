# Automatic device classification

Shepherd guesses what each device is (camera, TV, phone, printer...) from evidence it already
has, and says why. This page is the reference for that feature. It is built in pieces; the
sections below say what exists today.

## The ASN database

An autonomous system (AS) is a network, and its number (ASN) and holder name say who runs the
network an address lives on: "Netflix Streaming Services Inc.", "Roku Inc.". Shepherd looks up the
addresses in DNS answers to learn which networks a device talks to.

- **Source:** the free monthly DB-IP "IP to ASN Lite" database, published as
  `<base>/dbip-asn-lite-YYYY-MM.mmdb.gz` (`https://download.db-ip.com/free` by default).
- **Licence and credit:** CC BY 4.0. The portal must show the attribution string
  `IP to ASN data by DB-IP.com (CC BY 4.0)` (`geo.ASNAttribution`, also in `ASNManager.Status()`).
- **How it is kept fresh** (`geo.ASNManager`, the same guarantees as the map database): it loads
  the file on disk, refreshes it when older than 35 days, tries this month's file and falls back to
  last month's when the new one is not published yet, and only trusts a download whose database
  type mentions ASN and that opens as a valid database. A failed, truncated, wrong-kind or
  corrupt download never replaces a working database, and the temporary file is removed.
- **Privacy:** only the database is downloaded. Every lookup happens locally; no address is sent
  anywhere.
- **API:** `geo.ASNLocator` (`Open`, `Ready`, `Lookup(net.IP)`, `LookupAddr(netip.Addr)`) returns
  `geo.ASN{Number, Org}`. The city database and the ASN database are kept side by side, in
  `<data dir>/geo/`, by the same shared downloader.

## Registry changes

The device registry gained what this feature needs, all additive:

- **New device types:** `streaming box`, `smart plug/sensor`, `doorbell`, `thermostat`,
  `e-reader`, `wearable`, `NAS/server`.
- **A guess is not a choice.** `Device.TypeAuto` marks a type chosen by the classifier and
  `Device.TypeConfidence` records how sure it was. `Registry.SetGuessedType` writes a guess and does
  nothing for a device whose type the user set (`TypeUser`). `Registry.ClearGuessedType` withdraws
  a guess. `SetType` (the user) always wins, clears the guess and survives every later guess.
