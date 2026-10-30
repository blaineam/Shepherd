# Wave 1: setup and test checklist

Goal: network-wide DNS filtering, Tailscale remote access, uptime monitoring. Nothing here
puts Shepherd in the data path, and nothing touches IPv6 routing.

## 1. Preflight

```bash
./scripts/shepherd-doctor
```

Fix any FAIL. Read each WARN. On Linux hosts, if it reports `net.ipv4.ip_forward=0`, enable
forwarding for Tailscale subnet routing before continuing.

## 2. Start the stack

```bash
cp .env.example .env     # set HOST_IP, LAN_ROUTES, TS_HOSTNAME (and TS_AUTHKEY for a new node)
docker compose up -d
docker compose ps
```

Already running Tailscale in another container? Follow
[MIGRATING-TAILSCALE.md](MIGRATING-TAILSCALE.md) before starting the `tailscale` service.

## 3. AdGuard Home first-run

1. Open `http://<NAS-IP>:3002`.
2. For DNS, choose your LAN interface (for example `eth0`), **not** "All interfaces". NAS system DNS often owns `127.0.0.1:53`, which blocks a wildcard bind. A LAN interface still covers IPv4 and IPv6.
3. Leave the admin UI port at 3002 and create the admin account.
4. Under Filters, add a blocklist or two (for example Hagezi Pro). Automatic list management arrives in Wave 2.

## 4. Point the router at Shepherd

1. In your router, **reserve a fixed IP** for the NAS.
2. Set the router's custom DNS to the NAS's IPv4 address (and its IPv6 address, if your router has an IPv6 DNS field).
3. Do **not** change any other router setting.

Rollback: set the router's DNS back to automatic.

## 5. Tailscale

1. A new node needs its subnet routes and exit node approved in the admin console. A migrated node keeps its existing approvals.
2. Under DNS, add the NAS's tailnet IP as a nameserver and enable "Override DNS servers".

## 6. Uptime Kuma

Open `http://<NAS-IP>:3001`, create the admin account, and add monitors (router, internet,
a few sites).

## 7. Test checklist (report back)

- [ ] Ads and trackers are blocked on a phone and a laptop on Wi-Fi.
- [ ] **Per-device attribution:** in the AdGuard query log, do queries show each device's own IP, or the router's IP for everyone? (This decides whether Wave 3 can rely on DNS for per-device views.)
- [ ] Thread and Matter devices still work normally (lights, locks, sensors).
- [ ] IPv6 still works: `curl -6 https://ifconfig.co` on a LAN client.
- [ ] Remote over Tailscale: reach a LAN device by its LAN IP, and use the NAS as an exit node.
- [ ] A 5 Gbps speed test from the wired workstation is unaffected.
- [ ] `docker compose ps` shows all services healthy after a NAS reboot.
