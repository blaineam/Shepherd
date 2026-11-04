# IPv6 and Thread rules

IPv6 is mandatory in Shepherd, not optional. Thread border routers (Apple TV, HomePod, many
mesh routers, smart displays) bridge the Thread mesh onto your LAN over IPv6, and Matter
discovers devices with mDNS. Break either and smart-home devices quietly stop working.

## Hard rules

These hold for the Guard, Watch and **DHCP** profiles. Gateway mode ([GATEWAY.md](GATEWAY.md)) has to
rescope rules 1 and 5, because a router advertises itself and is the default gateway; that rescope is
recorded there rather than quietly taken here. **DHCP mode keeps every one of them**, which is a real
advantage of it: Shepherd sends no Router Advertisements and no DHCPv6, the router stays the IPv6
router, and the Thread and Matter risk is therefore almost entirely absent. The cost is stated in
[DHCP.md](DHCP.md): a routed device's IPv6 traffic does not pass through Shepherd and is not measured.


1. **Never run a Router Advertisement or DHCPv6 server on the LAN.** Routers and Thread border
   routers advertise default routes and Thread-mesh routes via RAs. A second source breaks them.
2. **Never filter or rewrite ICMPv6 neighbor discovery, RAs, or mDNS** (UDP 5353, `ff02::fb`).
3. **Never strip AAAA records to filter content.** Blocking decides by name, never by address
   family, and a blocked name is blocked for A and AAAA alike. Withholding AAAA answers on a
   network that has no IPv6 route to the internet at all is a separate thing, done only while that
   is true of the network, and is described under "Withholding AAAA answers" below.
4. **DNS listens on IPv4 and IPv6.** Otherwise clients that learn the NAS as an IPv6 DNS server fail.
5. **Never change a client's IPv6 default gateway.** Any future in-path mode is IPv4 only
   unless a separately reviewed IPv6 design lands. Until then IPv6 is passed through untouched
   and covered by DNS filtering and Tailscale.
6. **Never spoof NDP broadly.** Watch mode's IPv6 steering is the one reviewed exception, and it
   is deliberately the narrowest possible one: unsolicited **unicast** Neighbor Advertisements
   sent only to a device explicitly being steered, never to a multicast group, never an RA, and
   **never** to a smart-home hub, Thread border router or Matter device — a refusal no portal
   switch can override. It is off by default and engages only on a network with a global IPv6
   route. See [IPV6-WATCH.md](IPV6-WATCH.md) for the design and [WATCH.md](WATCH.md) for the
   operator's view. Everything else in this list stands unchanged; rule 1 especially.
7. **Forwarding trap:** on a Linux host, enabling `net.ipv6.conf.all.forwarding=1` (needed to
   advertise IPv6 subnet routes over Tailscale) makes the kernel stop accepting RAs unless
   `accept_ra` is `2` on the LAN interface. Without that, the NAS loses its IPv6 default route.
   `shepherd-doctor` checks for this.

## What this means for visibility

Without being the IPv6 gateway, Shepherd cannot see IPv6 flows from the LAN. That's an accepted
limit: DNS queries (both families) and Tailscale traffic remain fully visible. Passive
IPv6 observation and any in-path design are tracked on the roadmap as research items.

A design for how Watch mode *could* steer IPv6 without violating the hard rules above — unicast
Neighbor Advertisements only, never RAs — is worked out in [IPV6-WATCH.md](IPV6-WATCH.md). It is a
proposal awaiting a go/no-go decision, not a shipped feature; the rules on this page stand.

## Withholding AAAA answers

On a network whose devices have no IPv6 route to the internet -- only private `fd..` or
link-local addresses -- every AAAA answer is an address nothing can reach. Some devices try it
first and wait for it to fail; some report a network problem instead of trying IPv4. Shepherd can
answer AAAA queries with an empty answer (NODATA) and drop `ipv6hint` from HTTPS and SVCB records
while that is the case. This is not content filtering (rule 3): it hides addresses that do not
work, on a network where none of them do, and it stops as soon as IPv6 works.

Three positions, network-wide:

| Mode | What it does |
| --- | --- |
| `auto` (default) | Withhold only while outbound IPv6 is unreachable. A TCP connect to three public IPv6 resolvers every minute decides: one success turns answers back on at once, two failed rounds in a row turn them off. |
| `on` | Always withhold, even where IPv6 works. |
| `off` | Never withhold; answer as an ordinary resolver does. |

Set it in the portal, on **Upstreams -> IPv6 answers**. `dns.filter_aaaa` in `shepherd.toml` is
the value for a first run; a mode saved in the portal is kept in `<data_dir>/settings.json` and
wins over it from then on, with no restart. Filtered answers show in the query log as
`ipv6-filtered`.

### One device at a time

A device may need the opposite of whatever the network is doing, so each device has its own switch
on its card under **Devices -> IPv6 answers** (`PATCH /api/devices/{id}` with `aaaa`, and the
`set_aaaa` bulk operation; `aaaa:off` finds them again in the device search). It is **follow the
network** by default, and overrides the network-wide mode when it is not.

**Answer in full** is the escape hatch, and it exists because of a real device. A synthesized
NODATA carries an SOA so it can be cached (RFC 2308), but a client that does not cache it has
nothing to remember, and a client that then does not fall back to IPv4 simply asks again. A solar
inverter here asked for the same filtered `AAAA` about forty times a second, indefinitely. Nothing
on Shepherd's side can fix a device that will not take an answer: the fix is to give that one
device the real answer, and let it fail to connect over IPv6 the way it would without Shepherd.
The query log is where this is noticed -- one device, one name, a rate nothing else comes close to
-- and the switch is on that device's own card, which is where you end up looking.

**Withhold** is the other direction: one device that cannot cope with unreachable IPv6 addresses on
a network where everything else is fine with them.

Both are remembered across a merge of two device records, the way the Watch switch is: an explicit
**answer in full** survives, because it is the setting that keeps a device working.

### API

| Endpoint | What |
| --- | --- |
| `GET /api/dns/aaaa` | `{mode, from_config, config_mode, filtering, ipv6_usable, exceptions}`. `filtering` is what the network-wide setting is doing right now; `ipv6_usable` is the probe's own verdict, whatever the mode; `exceptions` lists the devices with a switch of their own |
| `PUT /api/dns/aaaa` | `{mode}` saves `"auto"`, `"on"` or `"off"`. An empty mode forgets the saved choice, so `dns.filter_aaaa` decides again |
| `PATCH /api/devices/{id}` | `{"aaaa": "auto"\|"on"\|"off"}` sets one device's switch |
| `POST /api/devices/bulk` | `{"op":"set_aaaa","aaaa":...}` sets it on many |
