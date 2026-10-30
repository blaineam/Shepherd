# Encrypted history

Shepherd can remember past queries so you can trace a problem afterwards: which device looked up what,
when, and what happened. The default is **memory only**: recent queries are kept in RAM and nothing is
written to disk. Turn on persistence in `shepherd.toml`:

```toml
[history]
mode = "encrypted"
retention_days = 30      # 0 keeps everything
max_mb = 2048            # 0 means no size cap
key_source = "file"      # or "passphrase"
key_file = ""            # default <data_dir>/history/history.key
```

## How it is protected

- History is written as immutable segments. Each segment has its own key derived from a master key with HKDF, every frame is sealed with AES-256-GCM, and each frame is bound to its position in its segment, so frames cannot be altered, dropped or reordered unnoticed.
- File names are random and the index (which segment covers which time range) is encrypted too, so the files reveal almost nothing, not even when the network was busy.
- A frame that fails authentication is skipped and counted, never trusted. A truncated final frame (a crash mid-write) is ignored and earlier data stays readable.
- Files and directories are private to the owning user. Old segments are deleted by age and by total size.
- If the key does not match existing data, Shepherd refuses to start rather than replacing your history.

## Where the key lives

| `key_source` | Behavior | Protects against |
|---|---|---|
| `file` (default) | A random key in `key_file`. Put it on a different volume or a removable drive. | Someone reading the data files, or a backup of them, without the key file. It does **not** protect against someone who takes the whole disk **and** finds the key file next to the data. |
| `passphrase` | The key is derived from a passphrase with Argon2id and never stored. After a restart the history is locked until you unlock it in the portal (or set `SHEPHERD_HISTORY_PASSPHRASE` for unattended starts). While locked, DNS keeps working and new entries wait in memory, then are written after unlock. | Theft of the whole disk. The cost is an unlock after each restart. |

## Searching

The portal's history view and `GET /api/history` take a time range, a device, an action, and a domain
search, and return the newest matches. The globe's replay uses the same data. After a restart the live
view is repopulated from the last entries.

## Not covered yet

Syncing history between Shepherds (planned, opt-in per node), encryption of the allow and block rule
files, and exporting a slice of history for sharing.
