# Link watch

Shepherd watches the network address it serves DNS on, once a second, and tells you when it
goes away and for how long.

## Why

When the machine under Shepherd loses its network (a cable or switch hiccup, a DHCP renewal that
briefly drops the address, a second interface taking the route), every lookup in the house fails
at once and every upstream looks dead, because Shepherd cannot reach anything. The existing
checks cannot see a short drop: [network health](NETHEALTH.md) probes every couple of minutes
and needs several bad samples in a row, and an alarm cannot be delivered while the link is down.
A twelve-second drop used to leave a burst of failed lookups and no explanation.

## What it does

Every second it reads the state of the interface that holds each address in `dns.listen`
(loopback and wildcard addresses are skipped, they cannot lose a link). An address counts as lost
when:

- the interface lost its **carrier** (the cable or Wi-Fi link dropped);
- the interface was **taken down**; or
- the address **was removed** from every interface.

The moment that happens it logs `linkwatch: 192.0.2.10 lost: <cause>`. When the address is
usable again it logs how long it was gone and raises one `network-link-lost` alarm (high) with
the address, interface, cause, duration and start time. The alarm is raised on return, not on
loss, because it could not leave the machine while the link was down.

A link that flaps repeatedly merges into one alarm per address with a count, so a bad cable shows
up as "lost 14 times", not as 14 alarms.

## What it does not do

It reads the interface's own state; it does not probe the network beyond it. A router or ISP
outage with the link still up is what [network health](NETHEALTH.md) and the `upstream-down`
alarm are for. There is nothing to configure and nothing it blocks.

## Reading an alarm

| Cause | Usually means |
|---|---|
| `lost its link (no carrier)` | cable, switch port, or the far end of the link dropped |
| `was taken down` | something (the NAS's network manager, a driver reset) brought the interface down |
| `address was removed from every interface` | a DHCP lease change or network-manager reconfigure, often with two interfaces on one subnet |
