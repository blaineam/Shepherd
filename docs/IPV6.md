# IPv6 and Thread rules

IPv6 is mandatory in Shepherd, not optional. Thread border routers (Apple TV, HomePod, many
mesh routers, smart displays) bridge the Thread mesh onto your LAN over IPv6, and Matter
discovers devices with mDNS. Break either and smart-home devices quietly stop working.

## Hard rules

1. **Never run a Router Advertisement or DHCPv6 server on the LAN.** Routers and Thread border
   routers advertise default routes and Thread-mesh routes via RAs. A second source breaks them.
2. **Never filter or rewrite ICMPv6 neighbor discovery, RAs, or mDNS** (UDP 5353, `ff02::fb`).
3. **Never strip AAAA records.** DNS filtering serves both address families normally.
4. **DNS listens on IPv4 and IPv6.** Otherwise clients that learn the NAS as an IPv6 DNS server fail.
5. **Never change a client's IPv6 default gateway.** Any future in-path mode is IPv4 only
   unless a separately reviewed IPv6 design lands. Until then IPv6 is passed through untouched
   and covered by DNS filtering and Tailscale.
6. **Never spoof NDP.** ARP interception (Watch mode) is IPv4 only. The IPv6 equivalent would
   disrupt neighbor discovery that Thread border routers rely on.
7. **Forwarding trap:** on a Linux host, enabling `net.ipv6.conf.all.forwarding=1` (needed to
   advertise IPv6 subnet routes over Tailscale) makes the kernel stop accepting RAs unless
   `accept_ra` is `2` on the LAN interface. Without that, the NAS loses its IPv6 default route.
   `shepherd-doctor` checks for this.

## What this means for visibility

Without being the IPv6 gateway, Shepherd cannot see IPv6 flows from the LAN. That's an accepted
limit: DNS queries (both families) and Tailscale traffic remain fully visible. Passive
IPv6 observation and any in-path design are tracked on the roadmap as research items.
