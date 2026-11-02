# Packaging: roadmap step 24

The bar is that a person who has never heard of DNS can protect their home network without opening a
terminal or a text editor. Everything here is judged against that sentence, and a platform is not
"supported" until its install path meets it. **Nothing below is built yet** except what the status
column says; this is the plan and the order.

## The promise

1. **Install** with the platform's own way of installing things: double-click, a store, one pasted
   line, or one command the platform's users already know.
2. **Answer a few questions in a browser.** The portal opens on first run and walks the owner through
   setup. No `shepherd.toml` is ever edited by hand.
3. **It keeps itself running**: starts at boot, restarts after a crash, updates itself (step 22) and
   tidies its own data (retention, also step 22).

## What the first-run wizard decides

The portal shows the wizard until it has been completed, then never again (it stays reachable from
Settings). It writes the configuration; the file remains the source of truth for anyone who wants it.

| Step | Question | Default |
|---|---|---|
| 1 | Where to store data | the platform's standard application-data location, shown, not asked unless changed |
| 2 | Which upstream resolver (Cloudflare, Quad9, Google, the router's own, or custom) | the one that tested fastest from this machine, with its test result shown |
| 3 | Which lists to start with | the "Recommended" catalog bundle, each item switchable |
| 4 | A PIN for the portal (step 19) | required, with a reminder that it is the only lock |
| 5 | How devices will use Shepherd | the one thing no installer can do for you; see below |
| 6 | Notifications (push or ntfy) | skipped unless chosen |

Step 5 is the hardest part of the whole promise, so it gets its own screen. Shepherd only protects a
device once the device asks it for DNS. The wizard shows the address to enter in the router's DHCP/DNS
setting, detects the router model where it can (UPnP, the vendor's own page) and links the matching
instructions, and offers a test that confirms a phone on the network is really using it. Until that
test passes the Overview says plainly that nothing is protected yet.

## Targets

One column per kind of owner, not per CPU. Every row cross-compiles with no CGO today; what is missing
is the installer, not the binary.

| Target | Who it is for | Installer | Starts at boot as | Status |
|---|---|---|---|---|
| **Raspberry Pi** (3 and newer, arm64) | the "I bought a Pi for this" owner | a flashable image: Shepherd preinstalled, first boot prints the portal address on the screen and over mDNS (`shepherd.local`) | systemd | planned |
| **Debian, Ubuntu, Raspberry Pi OS** | spare PCs, mini PCs, VMs | `.deb` from the release page and an apt repository; one command `sudo apt install shepherd` | systemd | planned |
| **Fedora, RHEL, openSUSE** | the same, on RPM distributions | `.rpm` | systemd | planned |
| **Any Linux** | everyone else | a one-line script that fetches the signed release, verifies the checksum and signature, installs the service, and prints the portal address | systemd, OpenRC | planned |
| **macOS** | a Mac mini or laptop someone already owns | signed and notarized `.pkg`, and a Homebrew formula | launchd | planned |
| **Windows** | a spare gaming PC | signed `.msi`, plus `winget` | a Windows service | planned |
| **Docker and Compose** | people who already run containers | the published image, with a Compose file that needs no editing | the container runtime | image and compose exist; not yet published to a registry |
| **NAS** (Synology, QNAP, UGOS, Unraid, TrueNAS) | the NAS owner | each platform's own app format where one exists, otherwise the Compose file with that platform's UI instructions | the platform | planned; one NAS runs it today |
| **Home Assistant** | the Home Assistant owner | an add-on | the Supervisor | considered; decide after the Linux path is solid |

Not on the list on purpose: running on the router itself (routers rarely have the headroom, and the
dual-NIC gateway profile in [GATEWAY.md](GATEWAY.md) is its own project) and mobile phones.

## Constraints that shape the installers

- **Port 53 is usually taken.** `systemd-resolved` holds it on desktop Ubuntu, and Windows and macOS
  have their own resolvers. The installer must detect this and handle it (a documented, reversible
  drop-in for `systemd-resolved`) instead of letting Shepherd fail to bind and tell the owner to
  investigate. This is the single most common first-run failure and is treated as part of install.
- **Privileges.** DNS on port 53 and Watch mode need privileges the installer grants once, narrowly
  (a capability on Linux, a service account elsewhere), never "run as root".
- **Watch mode is not part of the baseline install.** It stays opt-in ([WATCH.md](WATCH.md)); the
  installer neither enables it nor mentions it before the owner has a working DNS setup.
- **Signing.** `.pkg` and `.msi` need developer certificates. Until those exist the release says
  "unsigned" in plain words rather than shipping something the OS will warn about without explanation.
- **Updates reuse step 22.** Packages that a system package manager owns update through it; the
  self-updater yields there ([UPDATE.md](UPDATE.md)) so the two never fight over the binary.
- **Uninstall is part of install.** Each path ships a documented removal that restores the owner's
  DNS settings exactly as they were, because a protection tool that leaves the network broken when
  removed is worse than none.

## Order of work

1. **First-run wizard in the portal.** Platform-independent and unlocks every target, so it goes first.
   Includes the "is a device really using me" test.
2. **Port 53 detection and the `systemd-resolved` fix**, with tests against the fake platform layer.
3. **Linux: `.deb` and the one-line script**, built in the release workflow next to the binaries and
   signed with the same key; the NAS in use here is the first real install through it.
4. **Docker image published**, Compose file that needs no editing.
5. **Raspberry Pi image**, built in CI from the `.deb`.
6. **macOS `.pkg` and Windows `.msi`**, once the signing certificates exist.
7. **NAS app formats and the Home Assistant add-on**, as demand shows which are worth carrying.

Each step ships when it works on a real machine of that kind, is described in the CHANGELOG, and has
its removal path tested. Roadmap step 24 turns "done" only when the table above has no "planned" in
the rows the maintainer chose to support.
