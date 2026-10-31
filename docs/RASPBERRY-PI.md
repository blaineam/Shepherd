# Running Shepherd on a Raspberry Pi (or similar cheap hardware)

Shepherd is one static Go binary. It already cross-compiles to `linux/arm64` — the same build CI
checks on every push — so a Raspberry Pi 3 or newer, or any similar low-power ARM64 board you
already own, is a real, supported place to run it. You do not need a NAS or a beefy mini PC to get
real value out of Shepherd.

## What's genuinely light, and what isn't

Most of what Shepherd does today is cheap: answering DNS queries against an in-memory blocklist,
learning devices passively (DNS, mDNS, the neighbor table), the catalog/policy engine, and the
portal itself are all lightweight enough that a Pi 3 or 4 handles a typical home network's query
volume without strain. This is the baseline everyone gets, and it costs the network nothing —
DNS-only protection and the passive ARP monitor never add a hop to anyone's traffic.

Watch mode ([WATCH.md](WATCH.md), mechanism in [INTERCEPT.md](INTERCEPT.md)) is the one piece that is
genuinely not free: it is a software relay, not a hardware switch. On a 12-core x86_64 NAS it relays
a gigabit device's upload at full speed with no perceivable slowdown (WATCH.md has the measurements),
and the in-kernel XDP relay it prefers does the work before a packet ever reaches the kernel's network
stack. A Pi has a fraction of those cores and, on most models, a USB-attached network interface whose
driver has no XDP support at all — so expect the userspace relay, and expect it to be the limit on how
much steered traffic the Pi can carry. None of this is measured on a Pi.

Watch mode is on by default, so **if you are running on a Pi and want to be careful, turn it off**
(`[watch] enabled = false`) or steer a few devices deliberately by switching the rest to "Never
watch" in the portal. DNS filtering and the passive ARP monitor cost the Pi nothing either way, and
the kill switch on the Watch screen stops all steering at once if it does not go well.

## Setup

1. **Get a binary.** Either grab the newest beta from
   [Releases](https://github.com/blaineam/shepherd/releases) if an `arm64` build is published there,
   or cross-compile it yourself from any machine with Go installed:

   ```bash
   git clone https://github.com/blaineam/shepherd && cd shepherd
   GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o shepherd-arm64 ./cmd/shepherd
   ```

2. **Copy it to the Pi** (over `scp`, a USB stick, whatever's easiest) and make it executable:

   ```bash
   scp shepherd-arm64 pi@raspberrypi.local:~/shepherd  # leakcheck:allow Raspberry Pi OS's own default user/hostname
   ssh pi@raspberrypi.local chmod +x ~/shepherd         # leakcheck:allow same default user/hostname
   ```

3. **Configure and run it**, same as any other machine — see the main
   [Wave 2 guide](WAVE-2.md) for the config file and the "try it beside your current resolver"
   approach (strongly recommended before you point your router at it):

   ```bash
   cp shepherd.example.toml shepherd.toml
   # edit shepherd.toml: dns.listen and portal.listen to the Pi's LAN address
   ./shepherd -config shepherd.toml
   ```

4. **Keep it running** across reboots with a systemd unit:

   ```ini
   # /etc/systemd/system/shepherd.service
   [Unit]
   Description=Shepherd
   After=network-online.target
   Wants=network-online.target

   [Service]
   ExecStart=/home/pi/shepherd -config /home/pi/shepherd.toml  # leakcheck:allow Raspberry Pi OS's own default home dir
   Restart=on-failure
   User=pi
   AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

   [Install]
   WantedBy=multi-user.target
   ```

   `CAP_BPF` belongs in that list too if you want Watch mode's in-kernel relay (`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_BPF`).
   The two ambient capabilities are only needed if you ever turn on the passive ARP monitor or
   Watch mode (both need `CAP_NET_RAW`; Watch mode's GRO handling also needs `CAP_NET_ADMIN`) —
   leave them off if you only want DNS-level protection, which needs neither.

   ```bash
   sudo systemctl enable --now shepherd
   ```

## Honest expectations

No formal installer or setup wizard exists yet (see the roadmap's "Packaging" step) — this is a
binary-and-a-config-file setup today, not a one-click app. If that changes, this page will too.
