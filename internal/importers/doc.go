// SPDX-License-Identifier: AGPL-3.0-or-later

// Package importers brings device names and groups into Shepherd's device
// registry from outside sources, once, so nobody has to rebuild them by hand.
//
// Every source (a CSV file, an optional one-time eero import) is turned into
// the same neutral Plan. Preview shows what applying a Plan would do without
// changing anything; Apply performs it through the registry's own API
// (Observe for identity evidence, Rename, CreateGroup, BulkAssignGroup).
//
// Apply never deletes anything, never overwrites a name the user already set
// (unless Options.OverwriteNames), and is idempotent. Everything inside a Plan
// is treated as untrusted third-party text and sanitized.
package importers
