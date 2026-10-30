# internal/devices data

`oui_data.gz` is the embedded MAC-prefix to vendor table used by `LookupVendor`.

- **Source:** the IEEE Registration Authority MA-L ("OUI") public registry,
  <https://standards-oui.ieee.org/oui/oui.txt>.
- **Fetched:** 2026-10-30, once, during development (not at build or run time).
- **License:** the registry is published by the IEEE for public lookup. It is
  factual assignment data (a 24-bit prefix and an organization name); it is not
  redistributed under an open-source license, so treat the IEEE terms at
  <https://standards.ieee.org/products-programs/regauth/> as governing. Only
  prefixes and normalized vendor names are embedded, no addresses or contacts.
- **Content:** 39,877 prefixes, about 19,700 distinct vendors, 340 KB gzipped.
  Format: gzip of sorted `PREFIX<TAB>vendor` lines (six upper-case hex digits).
- **Normalization:** legal suffixes (Inc, Ltd, Co., GmbH, Corp, ...) are
  stripped and ALL-CAPS names are title-cased (`NormalizeVendor`). Placeholder
  entries ("Private", and blocks the IEEE sub-assigns as MA-M/MA-S to many
  small organizations) are dropped, so those prefixes resolve to no vendor
  rather than a wrong one.
- **Randomized MACs:** addresses with the locally-administered bit set carry no
  manufacturer information and always resolve to no vendor.

Regenerate (download `oui.txt` with a `curl` User-Agent; the IEEE site rejects
some browsers' default agents):

    go run ./internal/devices/internal/gen -in oui.txt -out internal/devices/oui_data.gz

Then update the date and counts above.
