# Watch mode and IPv6: a design, not an implementation

This document resolves *how* Watch mode could steer one device's IPv6 traffic the same way
it already steers IPv4, without breaking the hard rule in [IPV6.md](IPV6.md) that keeps
Thread and Matter working. Nothing here is wired in. Read [INTERCEPT.md](INTERCEPT.md) first
for the IPv4 mechanism, its one-sided scope, its safety model, and the still-open throughput
story; this is the IPv6 counterpart to that document, and it leans on it throughout.

---

## The decision Blaine has to make

IPv6 Watch mode is buildable and can be made safe, but it is **not worth turning on today, and
the recommended shape is deliberately cautious.** The mechanism that fits Shepherd's existing
one-sided model is unsolicited *unicast* Neighbor Advertisements sent only to an explicitly
steered device — the exact IPv6 mirror of today's unicast ARP replies — never a Router
Advertisement and never anything sent to a multicast group, so no device Shepherd was not told
to steer can ever be touched. The real obstacle is not the mechanism; it is three things stacked
together: (1) your LAN has only ULA IPv6 (a private, non-globally-routable range) and no global
IPv6 route, so a steered
device sends essentially *zero* steerable IPv6 traffic — there is nothing off-link to relay, so
the feature would relay nothing while adding risk; (2) the IPv4 throughput ceiling (1.1 Gbps →
~0.3 Gbps while steered) is still not root-caused, and layering a second address family onto an
unexplained regression is how you get two bugs wearing one coat; and (3) the one failure mode
IPV6.md exists to prevent — disturbing a Thread border router or a Matter device — is
catastrophic and silent, so the bar for enabling this near your smart-home gear is high.
**My recommendation: build the Neighbor Advertisement frame builder and its tests as a pure,
unwired library addition now (it sharpens the design and costs nothing to leave dormant, exactly
as the IPv4 interceptor shipped), keep a hard master switch defaulting to off, auto-exclude every
smart-home/Thread/Matter device, and do not run a live trial until you both (a) have a global
IPv6 route to actually steer and (b) have root-caused the IPv4 throughput drop.** **Go/no-go,
two parts: first, do you want the dormant NA library + frame-builder spike landed now, or deferred
until the IPv4 throughput ceiling is understood? Second, when it does ship, should IPv4 and IPv6
be one user-facing "Watch this device" switch (with IPv6 as a silent add-on that only engages when
a global route exists) or two explicit switches the operator arms separately?**

---

## 1. Mechanism options

### (a) Unsolicited unicast Neighbor Advertisements — the recommended mechanism

The IPv4 story (INTERCEPT.md): a device reaches the internet through its default gateway, whose
IP→MAC mapping it caches in its ARP table; Shepherd sends that one device periodic unicast ARP
replies claiming the gateway's IP lives at Shepherd's MAC, so the device's *outbound* frames go
to Shepherd, which relays them to the real gateway. One-sided, unicast, per-device.

IPv6 has an exact structural analogue. A device reaches the IPv6 internet through a **default
router it learned from that router's Router Advertisement**, and the next hop for its default
route is the router's **link-local address** (the reserved link-local range). The device resolves that link-local
address to a MAC with Neighbor Discovery (ICMPv6 Neighbor Solicitation / Neighbor Advertisement,
types 135/136) and caches it in its **Neighbor Cache** — the IPv6 counterpart of the ARP table.

So the steering move is: send the steered device an **unsolicited Neighbor Advertisement
claiming the router's link-local address is at Shepherd's MAC.** Precisely:

| NA field | Value | Why |
|---|---|---|
| ICMPv6 type | 136 (Neighbor Advertisement) | |
| Target Address | the gateway's **link-local** address | the address the device's default route actually points at; **not** the router's ULA/global address |
| Target Link-Layer Address option (type 2) | **Shepherd's MAC** | what the device will cache as the router's MAC |
| **R** (Router) flag | **1** | the real node *is* a router; clearing R makes the device drop it from its Default Router List and lose IPv6 entirely — a blackhole, not a steer. R=1 is a correctness **and** safety requirement. |
| **S** (Solicited) flag | **0** | this is unsolicited |
| **O** (Override) flag | **1** | without Override, a stack that already has the real router cached **ignores** the new link-layer address (RFC 4861 §7.2.5). O=1 forces the overwrite. |
| IPv6 destination | the steered device's unicast address (its link-local always works) | **never** `ff02::1` (all-nodes) — unicast is the whole safety story |
| Ethernet destination | the steered device's unicast MAC | same |
| Hop Limit | **255** | NDP requires it; receivers reject NDP with hop limit ≠ 255, which is the standard on-link defense. Shepherd is on-link, so 255 is correct. |

**Who, how often, and the active half.** Sent only to the one explicitly steered device, every
`DefaultSpoofInterval` (2 s), mirroring the ARP Spoofer. One caveat NDP adds over ARP: an
unsolicited NA with O=1 updates an **existing** cache entry and sets it to **STALE** — it does
**not create** a new one (RFC 4861 §7.2.5: an unsolicited NA for an address with no cache entry
is silently discarded). A device with working IPv6 already has the router cached, so on a live
IPv6 LAN the entry exists; this is only a note that steering cannot *bootstrap* a device with no
IPv6 traffic. A STALE entry is still used for sending immediately, with revalidation happening in
parallel (DELAY → PROBE), so outbound traffic flows to Shepherd the moment the entry flips. The
robust version also **answers the device's unicast revalidation Neighbor Solicitation** (which it
unicasts to Shepherd's MAC when the STALE entry enters PROBE) with a solicited NA (S=1, O=1); the
minimal version relies on the 2 s unsolicited refresh out-pacing the PROBE timeout, and fails
*safe* if it loses the race (the entry is discarded and the device re-resolves the **real**
router via multicast). Recommend building the NS responder; it is a few lines on top of the
frame builder and removes the only flaky part.

**Corrective on unsteer and panic-stop — the exact messages.** Identical shape to the ARP
corrective (`Spoofer.sendCorrective`): a single unsolicited unicast NA restoring the truth,
sent best-effort and bounded, so the device recovers instantly instead of waiting out its cache.

```
claim      (while steered):  NA  target=gw-link-local  TLLA=SHEPHERD_MAC  R=1 S=0 O=1  → device unicast
corrective (on stop/panic):  NA  target=gw-link-local  TLLA=GATEWAY_MAC   R=1 S=0 O=1  → device unicast
```

PanicStop sends the corrective for every steered device and empties the set at once, exactly as
it does for IPv4 today; the IPv6 corrective rides the same best-effort, never-blocking path.

### (b) A Router Advertisement approach — ruled out, and why it stays ruled out

The "easier" way to redirect IPv6 is to have Shepherd send its own Router Advertisements. **This
is forbidden by [IPV6.md](IPV6.md) hard rule 1 and must stay forbidden.** A second RA source on
the LAN is not a per-device nudge — it is a broadcast to `ff02::1` that every node processes.
Thread border routers (your Apple TV/HomePod) advertise the Thread mesh's on-link prefix and
default route via RAs; a competing RA speaker corrupts the Default Router List and prefix list of
*every* device at once, and the failure is silent — smart-home devices just stop working. RAs
also cannot be made unicast-per-device in any way a stack will honor the way an NA can. Option
(b) is listed only to be explicitly rejected: **Shepherd never sends RAs, period.** Everything in
option (a) is designed precisely to get per-device redirection *without* an RA.

### (c) Do nothing for IPv6 — document the blind spot

The status quo, and the correct choice for a ULA-only LAN. Shepherd is not the IPv6 gateway, so
it sees no device IPv6 flows; DNS filtering (both families) and Tailscale visibility are
unaffected (IPV6.md, "What this means for visibility"). On your current LAN this is not even a
compromise: with no global IPv6 route, there is no off-link IPv6 traffic to steer in the first
place (see §2), so (a) and (c) relay the *same amount of traffic — none —* and (c) carries none
of the risk. The design below treats (c) as the default and (a) as something that only engages
when a global route exists.

---

## 2. What breaks, honestly

**SEND / secure Neighbor Discovery (RFC 3971).** Authenticates NDP with CGAs and signatures; a
device running SEND rejects Shepherd's spoofed NA. In practice no consumer gear implements SEND,
and the failure mode is *safe*: the device keeps the real router cached, steering silently does
nothing, nothing breaks. Not a concern beyond "steering may no-op for a hardened device."

**iOS / Android privacy addresses (RFC 8981) and MAC randomization.** These rotate the *device's
own* source addresses, and iOS/Android also present a per-network randomized ("private Wi-Fi")
MAC. Neither breaks steering: Shepherd poisons the cache entry for the **router's** address, which
is independent of the device's own addresses, and the Relay matches a device by **MAC**, which is
stable within one network (the IPv4 side relies on the same fact, and `arp.MAC` already carries
`IsLocallyAdministered` for the randomized-MAC signature). Privacy addresses are a non-issue for
the mechanism.

**How modern stacks treat unsolicited NAs.** RFC 4861 §7.2.5 is the whole ballgame. Override=1 is
mandatory or the overwrite is ignored; unsolicited NAs land the entry in STALE (used for sending,
revalidated lazily); and unsolicited NAs never *create* an entry. Linux additionally has
`accept_untracked_na`-style hardening and configs that drop unsolicited NAs outright; any such
hardening makes steering no-op, never breaks. The cache state machine (INCOMPLETE → REACHABLE →
STALE → DELAY → PROBE) matters only in that we keep re-STALE-ing the entry and should answer the
PROBE's unicast NS (above).

**The ULA-only LAN — this is the big one for you today.** Your LAN has only a ULA prefix (a
private, non-globally-routable range) and no global IPv6 route. ULA is not globally routable, so a
device has **no IPv6 default route to the
internet**; its only IPv6 traffic is on-link ULA delivery to peers, which does not transit the
router at all. There is therefore **nothing for Watch mode to steer** — the steerable set is
"IPv6 packets the device sends *to the router* for off-link destinations," and that set is empty.
IPv6 steering on this LAN relays nothing and provides zero visibility benefit, at nonzero risk.
**The design must detect this and refuse to arm IPv6 steering unless a global IPv6 default route
is present** (observable passively from RAs carrying a GUA prefix with a non-zero router
lifetime). On a ULA-only LAN, IPv6 steering is option (c), automatically.

**Multiple gateways / multiple link-local addresses.** A LAN can have more than one default
router (several RAs), and a mesh like your eero exposes a link-local per node. Steering one
router's link-local does not capture a device that routes via another. Shepherd must identify
*the* default router (RA with router lifetime > 0 advertising the default route) and claim that
link-local; if several exist, visibility is partial and the data would understate usage —
honestly worse than the IPv4 case, where there is normally one gateway. First cut: steer the
single observed primary and record in `Status()` when more than one default router was seen, so
partial capture is visible rather than silently misleading.

---

## 3. Thread / Matter safety: how this never touches them

The guarantee is a chain, each link of which is independently sufficient:

1. **Unicast-only, per-device, structurally.** Every NA Shepherd sends is addressed to one
   explicitly steered device's unicast IPv6 address and unicast MAC. A Thread border router or
   Matter device that is not the steered device **never receives a single Shepherd NDP frame.**
   This is the same property that makes one-sided ARP safe, carried over exactly. There is no
   broadcast, no multicast, no RA — the three things that could touch a bystander — anywhere in
   the design.

2. **Registry-enforced exclusion of smart-home devices.** The device registry already classifies
   Thread/Matter/HomeKit gear as `TypeSmartHome` from its mDNS service advertisements
   (`internal/devices/guess.go`): `_meshcop._udp` is a Thread border router, `_matter` /
   `_matterc` is Matter, `_hap` / `_homekit` is HomeKit, `_hue` is a Hue bridge. The existing
   `Excluder` interface (`controller.go`) already lets `Controller.Steer` reject a device the
   registry marks excluded. For IPv6, wire a **stricter v6 Excluder** that refuses, in addition
   to the operator's opt-outs, **any device that has ever advertised one of those services, any
   device typed `TypeSmartHome` or `TypeRouter`, and any device Shepherd has seen source a Router
   Advertisement.** This is enforced at the `Steer` call, not merely documented — the same place
   the gateway, Shepherd's own MAC, and the static `ExcludedMACs` list are rejected today.

3. **The mesh is untouched even in the worst case.** Thread runs over 802.15.4; a border router
   bridges it onto the LAN by *sending RAs* and doing NDP. Shepherd sends no RAs (rule 1 intact)
   and, because of (1) and (2), never sends NDP to a border router. Even an operator error that
   somehow steered a border router would only poison *that device's own* neighbor cache for the
   upstream router — it would not stop the BR from advertising the Thread prefix onto the LAN,
   because that is outbound RA traffic the BR originates, which this design never interferes with.
   The conservative stance is still "never steer them," via (2).

4. **A master kill switch, default off, that no per-device action can override.** A single global
   `IPv6SteeringEnabled` flag, defaulting to **off**, gates every v6 `Steer`. `PanicStop()`
   already empties the steered set and fires correctives for both families and needs no change.
   Add one behavior: if Shepherd ever detects a condition that should never occur — a v6 steer
   requested for a `TypeSmartHome` device, or (defense in depth) any NA it is about to send whose
   destination is multicast — it trips the master switch off and records it, rather than
   proceeding.

---

## 4. Relay changes: Go Relay, capture filter, XDP

All three surfaces today **positively match plain IPv4** (ethertype `0x0800`) and have agreement
tests proving they relay the same frames, plus a fuzz test proving IPv6 is never relayed. The
invariant to preserve, reworded for the new world, is: **"an IPv6 frame is relayed only if its
source-MAC device is explicitly IPv6-steered; by default no IPv6 is ever relayed."** Each surface
gains an IPv6 path guarded by a per-device family flag.

**Per-device family flag.** The steered-set value (`deviceState`, and the XDP `steered` map
value) gains a family bit: `SteerV4`, `SteerV6`, or both. `Relay.Lookup` returns it. A device
steered for v4 only has its IPv6 frames **passed through untouched**, and vice versa. This flag is
what makes the invariant provable: "v6 relayed ⇒ device is v6-steered" is a single check.

**Go `Relay.HandleFrame` (`relay.go`).** Today: after the `dst == ShepherdMAC` check, it requires
`etherType == etherTypeIPv4`, then `Lookup`, then the `ShepherdIPs` (destined-for-Shepherd) check.
Change: accept `etherTypeIPv6` (`0x86dd`) **as a second positive branch**, and for that branch
check the source MAC against a v6-steered lookup and the IPv6 destination against a new
`ShepherdIPs6` set (the host's own IPv6 addresses on the interface — link-local, ULA, and any
global). The IPv6 destination sits at a **fixed** offset (16 bytes at `ethHeaderLen + 24`; the
IPv6 base header has no options, unlike IPv4), so `destinedForShepherd` gets a straightforward
v6 sibling. The inner IP packet, **hop limit included, is left untouched** — this is a pure
Ethernet-layer relay, so unlike a real router it does **not** decrement the hop limit; stating
that explicitly because it is exactly the IPv6 counterpart of "no TTL decrement, no NAT." The rule
stays a positive allowlist (IPv4 **or** IPv6), never a denylist, so a VLAN-tagged `0x8100` frame
is still dropped rather than inspected.

**Classic-BPF capture filter (`capture_filter.go`).** Today it admits `dst == ShepherdMAC AND
ethertype == IPv4`. It is, by its own contract, a **cost optimization only, never a correctness
boundary** — `HandleFrame` re-checks everything. So it can safely admit
`dst == ShepherdMAC AND (ethertype == IPv4 OR ethertype == IPv6)` **while any device is
v6-steered**, and be rebuilt/reattached to the IPv4-only form when the last v6 device unsteers.
Admitting IPv6 when nothing is v6-steered would only cost a userspace discard, not a correctness
bug — so the fallback (always admit both) is acceptable if the reattach-on-transition is deemed
not worth it. **The IPv6 hard rule's enforcement does not rest on this filter** — it rests on
`HandleFrame` and XDP, which is why the fuzz test lives on `HandleFrame`.

**XDP program (`bpf/xdp_relay.c`).** Mirror the four rules for IPv6:
1. accept `ETH_P_IPV6` (`0x86dd`) as a second ethertype branch (rule 1 stays "first thing
   checked," now "IPv4 or IPv6, nothing else");
2. dst MAC is Shepherd's — unchanged;
3. source MAC is in `steered` **and** that entry's family bit includes v6 — the map value gains
   the family field;
4. destination IPv6 is not one of Shepherd's own — a new `local_ips6` map keyed on the 16-byte
   address (the existing `local_ips` is keyed on a 4-byte IPv4 address), populated by
   `xdp_linux.go` from the interface's own IPv6 addresses the same way it reads IPv4 today
   (`interfaceIPv4s` gets a v6 sibling).

   The IPv6 header is fixed-length to the destination field, so the bounds check is a single
   `(void *)(ip6 + 1) > data_end` against a 40-byte header struct. Rewrite both MACs, leave the
   packet (hop limit included) untouched, `XDP_TX`. The `dev_counters` and per-CPU `relay_stats`
   gain v6 counters (or the loader diffs by family); `last_seen_ns` feeds health exactly as for v4.

**How the tests evolve so the invariant stays provable.**
- The **fuzz test** (`FuzzRelayHandleFrame`) keeps its current assertion as the *default-off*
  case: with a `Lookup` that never reports v6-steered, **no `0x86dd` frame is ever relayed or
  sent**, under any input. Add a second fuzz target with a `Lookup` that reports v6-steered and
  assert the dual invariant: a `0x86dd` frame is relayed **iff** it passed dst-MAC, source-steered
  and not-for-Shepherd — never on a malformed/truncated frame, and still never for a v4-only
  device.
- The **agreement test** (XDP vs Go Relay over the same frames, `xdp_linux_test.go`) extends its
  corpus with IPv6 frames (steered, not-steered, for-Shepherd-itself, truncated) and asserts the
  two relays still make identical accept/rewrite decisions for every one.
- The **Spoofer frame-builder property test** gains an NA sibling: the new NA builder produces
  only a well-formed ICMPv6 Neighbor Advertisement with R=1, S=0, O=1, a type-2 TLLA option, a
  correct ICMPv6 checksum, and hop limit 255 — and **never** an RA (type 134) or any multicast
  destination, for any input. That last clause is the machine-checked form of "Shepherd never
  sends an RA."

---

## 5. Health verification and the one-switch-vs-two question

The IPv4 health loop (`checkHealth`) fails a device **open** — reverts it to the real gateway —
the moment no relayed traffic is observed within a grace window (`IdleGrace` 15 s once it has
relayed, `StartupGrace` 30 s before it ever has). That logic assumes "steered and healthy ⇒ some
traffic." IPv6 breaks that assumption: a device can have **zero** steerable IPv6 traffic for long
stretches — and on a ULA-only LAN, *forever* — while its IPv4 is perfectly healthy. If v4 and v6
were one health check requiring both to show traffic, a healthy device would flap constantly on
IPv6 silence.

**So health must be per-family.** Track `SteerV4` and `SteerV6` as independent steered states with
independent `lastVerified`/grace bookkeeping. Silence on v6 unsteers **only** v6 (sends only the
v6 corrective) and leaves v4 running, and vice versa. Critically, **v6 "silence" must not be
treated as unhealthy on a LAN where there is nothing to relay** — which is why v6 steering should
only *arm* when a global IPv6 route exists (§2). Where it does arm, v6 uses a much more lenient
model than v4: because legitimate IPv6 idle is normal, prefer "did the neighbor-cache flip take
(did we ever see one outbound v6 frame arrive at Shepherd's MAC)?" as the startup health signal,
and treat sustained post-flip silence as *idle*, not *failed*, unsteering only after a long grace
or on an explicit send error.

**One switch or two — my recommendation.** Internally, **two** independent states (above) are
non-negotiable for health to work. For the operator, I recommend **one user-facing "Watch this
device" switch** that always enables v4 (the proven path) and *additionally* enables v6 **only
when** the master `IPv6SteeringEnabled` flag is on **and** a global IPv6 route is present —
otherwise v6 stays dormant and the UI says so. This keeps the common case one click, never arms v6
where it would do nothing or add risk, and still lets an advanced operator see and control the two
families separately in `Status()`/history. The go/no-go asks you to confirm this versus two
explicit switches.

---

## 6. Rollout plan

Same shape as IPv4: **library-only first, then `cmd/intercept-trial`, then a single supervised
live run — never wired into `cmd/shepherd` or the portal without your explicit go-ahead**
(INTERCEPT.md, "This package is a library only").

1. **Land the NA frame builder + NS responder + tests, unwired.** A `NewNeighborAdvert(...)`
   builder beside `arp.NewReply`, with the property test from §4. This is the optional spike the
   task allows; it sharpens the checksum/flag details and costs nothing dormant. No `Controller`
   path constructs it yet.
2. **Extend the three relay surfaces and their agreement/fuzz tests** (§4), behind the per-device
   v6 family flag that nothing sets yet. At this point `go test -race ./internal/intercept` proves
   the full invariant with zero behavior change for anyone not v6-steering.
3. **`cmd/intercept-trial -ipv6`** (opt-in, default off), reusing the mandatory
   `-target-mac`/`-confirm` double-naming, the capped duration, and the Ctrl-C → `PanicStop`
   wiring. It refuses to start if no global IPv6 route is detected, and refuses any target the v6
   Excluder rejects.

**What to measure in a trial:**
- **Did the cache flip?** Does the device's outbound IPv6 start arriving at Shepherd's MAC —
  visible as a non-zero v6 `relayed` count in the extended `rate:` log line, and/or on the device
  via `ndp -an` / `ip -6 neigh` showing the router's link-local at Shepherd's MAC.
- **Throughput delta on IPv6**, measured the same way the IPv4 drop was — and compared against it,
  because the unexplained 1.1 → 0.3 Gbps IPv4 regression is the second-ranked risk below and must
  not be compounded blindly.
- **Relayed v6 pps/bytes vs examined**, reusing the `Stats()` counters with a v6 breakdown, to see
  whether the same "mostly `not_for_shepherd` bursts" pattern from the IPv4 investigation appears.
- **Smart-home liveness, the whole time.** With your HomeKit/Matter/Thread devices in view,
  confirm every one stays responsive for the entire trial and after the auto-revert. This is the
  acceptance gate, not an afterthought.

**The live test you would run on your iPhone** (only once you have a global IPv6 route — on
today's ULA-only LAN this is a no-op by design): steer the iPhone for v6 for a capped two
minutes, load an IPv6-only target (`test-ipv6.com`, `ipv6.google.com`), confirm its outbound
IPv6 destinations/SNI become visible in `Status()` and that a smart-home device (an Apple
TV/HomePod acting as a Thread BR) keeps working throughout, then let the trial auto-revert and
confirm the iPhone's neighbor cache returns to the real router's MAC within a second.

---

## Recommendation and ranked risks

**Recommendation.** Build option (a) as a dormant library addition now (frame builder + NS
responder + the three extended relay paths + tests), behind a master switch defaulting to off,
with every smart-home/Thread/Matter device hard-excluded, unicast-only, two internal family
states with per-family fail-open health, and a one-click operator switch that engages v6 only
where a global route exists. **Do not run a live trial until there is a global IPv6 route to steer
and the IPv4 throughput ceiling is root-caused.** Never ship option (b). On today's LAN, option
(c) is what actually runs, by design.

**Risks, worst first:**
1. **Collateral NDP disturbance of a Thread BR / Matter device → silent smart-home breakage.** The
   reason IPV6.md exists. Mitigated to structural impossibility by unicast-only + registry
   exclusion + no-RA + master switch; this is the risk the whole design is shaped around.
2. **Compounding the unexplained IPv4 throughput regression.** 1.1 → ~0.3 Gbps while steered is
   still not root-caused (INTERCEPT.md). Adding a second family before that is understood risks a
   second, entangled regression. Gate the live trial on the IPv4 fix.
3. **Multiple default routers → partial, misleading capture.** More likely on a mesh than the
   IPv4 single-gateway case; surface it in `Status()` rather than silently understating usage.
4. **Device hardening / SEND / ignore-unsolicited-NA → steering no-ops.** Fails safe (device keeps
   the real router); low harm, only disappointment.
5. **Doubled state-machine complexity** in the most safety-critical package in the repo. Mitigated
   by reusing every existing structure (Spoofer, Relay, Controller, Excluder, PanicStop) rather
   than adding a parallel one, and by the fuzz/agreement tests carrying the invariant.

See [IPV6.md](IPV6.md) for the standing hard rules this design is written to respect, and
[INTERCEPT.md](INTERCEPT.md) for the IPv4 mechanism it mirrors.
