// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"shepherd/internal/devices"
)

// Settings is the network DHCP mode hands out. It is read afresh for every
// packet, so a change in the portal takes effect on the next renewal rather
// than on the next restart.
type Settings struct {
	// Subnet is the LAN, which gives the netmask and bounds every address.
	Subnet netip.Prefix
	// ServerIP is Shepherd's own address on the LAN: the server identifier,
	// and what goes in option 3 for a routed device.
	ServerIP netip.Addr
	// Gateway is the router. It goes in option 3 for every device that is
	// not routed, which is what makes "not routed" mean "exactly as before".
	Gateway netip.Addr
	// DNS is what goes in option 6. Shepherd's own address is the point of
	// the whole project, but it is configurable because a household that
	// wants a fallback resolver in the list should be able to have one.
	DNS    []netip.Addr
	Domain string
	Pool   Pool
	// LeaseTime is short by default (docs/DHCP.md): a routed device that
	// should stop being routed stops at its next renewal, and that is the
	// mechanism the whole fail-open story rests on. The cost is that the
	// segment starts failing sooner after the host goes down.
	LeaseTime time.Duration
}

// DefaultLeaseTime is the lease time when none is configured. Ten minutes,
// which means renewal at about five: long enough not to be chatty, short
// enough that an unhealthy Shepherd stops routing the house within minutes
// without anybody doing anything.
const DefaultLeaseTime = 10 * time.Minute

// Valid reports whether these settings are usable, and says what is missing
// when they are not. Serving is gated on it.
func (s Settings) Valid() error {
	switch {
	case !s.Subnet.IsValid() || !s.Subnet.Addr().Is4():
		return fmt.Errorf("dhcp: no IPv4 LAN prefix configured")
	case !s.ServerIP.IsValid() || !s.ServerIP.Is4():
		return fmt.Errorf("dhcp: no IPv4 address for Shepherd on the LAN")
	case !s.Subnet.Contains(s.ServerIP):
		return fmt.Errorf("dhcp: Shepherd's address %s is not inside the LAN %s", s.ServerIP, s.Subnet)
	case !s.Gateway.IsValid() || !s.Gateway.Is4():
		return fmt.Errorf("dhcp: no IPv4 gateway configured; DHCP mode needs one to hand out to devices it does not route")
	case !s.Subnet.Contains(s.Gateway):
		return fmt.Errorf("dhcp: the gateway %s is not inside the LAN %s", s.Gateway, s.Subnet)
	case !s.Pool.Valid():
		return fmt.Errorf("dhcp: no usable address pool configured")
	case !s.Subnet.Contains(s.Pool.Start) || !s.Subnet.Contains(s.Pool.End):
		return fmt.Errorf("dhcp: the pool %s-%s is not inside the LAN %s", s.Pool.Start, s.Pool.End, s.Subnet)
	case s.Pool.Contains(s.ServerIP):
		return fmt.Errorf("dhcp: Shepherd's own address %s is inside the pool, so it could be handed to a device", s.ServerIP)
	case s.Pool.Contains(s.Gateway):
		return fmt.Errorf("dhcp: the gateway's address %s is inside the pool, so it could be handed to a device", s.Gateway)
	}
	return nil
}

func (s Settings) leaseTime() time.Duration {
	if s.LeaseTime <= 0 {
		return DefaultLeaseTime
	}
	return s.LeaseTime
}

// Action says what the handler decided, for logs, the portal and the tests.
type Action string

// What a handler can decide.
const (
	ActionOffer   Action = "offer"
	ActionAck     Action = "ack"
	ActionNak     Action = "nak"
	ActionObserve Action = "observe" // learned something, sent nothing
	ActionIgnore  Action = "ignore"
)

// Result is the handler's decision about one received packet.
type Result struct {
	Action Action
	// Reply is nil whenever nothing is to be sent, which is always the case
	// in observe mode.
	Reply *dhcpv4.DHCPv4
	// To is where the reply goes. Broadcast when the client has no usable
	// address yet; see replyTo.
	To netip.Addr
	// Lease is the lease this packet created or changed, for the caller to
	// log. Zero when nothing changed.
	Lease Lease
	// Routing is the decision that went into option 3, so the portal can
	// explain a device that is not going through Shepherd.
	Routing Decision
	// Why explains an ignore or a NAK in plain language.
	Why string
}

// Handler turns one received DHCP packet into a decision. It holds no socket
// and no goroutine: Server owns those, which is what lets every branch here
// be tested by calling a method.
type Handler struct {
	// Settings and Policy are functions so that both follow the portal
	// without the handler holding a lock over a config struct.
	Settings func() Settings
	Policy   func() RoutePolicy
	Leases   *Leases
	Alloc    *Allocator
	// Peers records other DHCP servers seen answering, which is the
	// interlock that stops Shepherd joining a race it cannot win cleanly.
	Peers *Peers
	// Sink receives the identity evidence in every client packet. This is
	// the part of DHCP mode that is useful in observe mode on its own.
	Sink devices.Sink
	Now  func() time.Time
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Handle decides what to do with one packet. from is the address it arrived
// from, which is how a reply from another DHCP server is told apart from a
// client's request.
//
// In ModeObserve it never returns a Reply. That is checked here and enforced
// again in Server, which does not even open a writable socket in that mode.
func (h *Handler) Handle(pkt *dhcpv4.DHCPv4, mode Mode, from netip.Addr) Result {
	if pkt == nil {
		return Result{Action: ActionIgnore, Why: "empty packet"}
	}
	set := h.settings()

	// A reply from some other server is the thing the interlock exists for.
	if pkt.OpCode == dhcpv4.OpcodeBootReply {
		return h.observeServer(pkt, from, set)
	}
	if pkt.OpCode != dhcpv4.OpcodeBootRequest {
		return Result{Action: ActionIgnore, Why: "not a BOOTP request or reply"}
	}

	mac := NormalizeMAC(pkt.ClientHWAddr.String())
	if mac == "" {
		return Result{Action: ActionIgnore, Why: "no usable client MAC address"}
	}

	// Every client packet is identity evidence whatever else happens to it,
	// and in observe mode it is the only thing that happens to it.
	h.observeClient(pkt, mac)

	if pkt.GatewayIPAddr != nil && !pkt.GatewayIPAddr.IsUnspecified() {
		// A relayed request means there is a second segment behind a relay
		// agent, which this design does not cover (docs/DHCP.md keeps to
		// one flat segment). Answering it with a lease from this segment's
		// pool would give a device an address it cannot use.
		return Result{Action: ActionIgnore, Why: "relayed request from " + pkt.GatewayIPAddr.String() + "; DHCP mode serves one flat segment only"}
	}

	if mode != ModeServe {
		return Result{Action: ActionObserve, Why: "observe mode: nothing is sent"}
	}
	if err := set.Valid(); err != nil {
		return Result{Action: ActionIgnore, Why: err.Error()}
	}

	switch pkt.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		return h.offer(pkt, mac, set)
	case dhcpv4.MessageTypeRequest:
		return h.request(pkt, mac, set)
	case dhcpv4.MessageTypeDecline:
		return h.decline(pkt, mac)
	case dhcpv4.MessageTypeRelease:
		return h.release(pkt, mac)
	case dhcpv4.MessageTypeInform:
		return h.inform(pkt, mac, set)
	default:
		return Result{Action: ActionIgnore, Why: "message type " + pkt.MessageType().String() + " is not served"}
	}
}

func (h *Handler) settings() Settings {
	if h.Settings == nil {
		return Settings{}
	}
	return h.Settings()
}

func (h *Handler) policy() RoutePolicy {
	if h.Policy == nil {
		return RoutePolicy{}
	}
	return h.Policy()
}

// observeServer records a BOOTREPLY that did not come from Shepherd. An
// OFFER or an ACK from another address means another DHCP server is
// answering on this segment, which Server treats as a reason to stop.
func (h *Handler) observeServer(pkt *dhcpv4.DHCPv4, from netip.Addr, set Settings) Result {
	server := from
	if sid := pkt.ServerIdentifier(); sid != nil {
		if a, ok := netip.AddrFromSlice(sid.To4()); ok && a.IsValid() && !a.IsUnspecified() {
			server = a
		}
	}
	if !server.IsValid() || server == set.ServerIP {
		return Result{Action: ActionIgnore, Why: "our own reply"}
	}
	mt := pkt.MessageType()
	if mt != dhcpv4.MessageTypeOffer && mt != dhcpv4.MessageTypeAck {
		return Result{Action: ActionIgnore, Why: "reply of type " + mt.String()}
	}
	now := h.now()
	if h.Peers != nil {
		h.Peers.Saw(server, now)
	}
	// An ACK from the other server is also a fact about the network: it is
	// the lease that device is actually holding, which is what makes the
	// portal's lease list useful before Shepherd serves anything.
	var l Lease
	if mt == dhcpv4.MessageTypeAck {
		mac := NormalizeMAC(pkt.ClientHWAddr.String())
		ip, _ := netip.AddrFromSlice(pkt.YourIPAddr.To4())
		if mac != "" && ip.IsValid() && !ip.IsUnspecified() {
			router, _ := netip.AddrFromSlice(firstIP(pkt.Router()))
			l = Lease{
				MAC: mac, IP: ip, Hostname: strings.TrimSpace(pkt.HostName()),
				Router: router, Origin: OriginObserved, Allocated: now, Renewed: now,
				Expires: now.Add(pkt.IPAddressLeaseTime(DefaultLeaseTime)),
			}
			if h.Leases != nil {
				h.Leases.Put(l)
			}
		}
	}
	return Result{Action: ActionObserve, Lease: l, Why: "another DHCP server answered from " + server.String()}
}

func firstIP(ips []net.IP) []byte {
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	return nil
}

// observeClient feeds the registry everything a client packet says about
// itself. This runs in every mode, including observe, and it is what makes
// devices.SourceDHCP real.
func (h *Handler) observeClient(pkt *dhcpv4.DHCPv4, mac string) {
	if h.Sink == nil {
		return
	}
	o := devices.Observation{Source: devices.SourceDHCP, MAC: mac, Time: h.now()}
	if host := strings.TrimSpace(pkt.HostName()); host != "" {
		o.Hostname = host
	}
	if ip, ok := netip.AddrFromSlice(pkt.ClientIPAddr.To4()); ok && ip.IsValid() && !ip.IsUnspecified() {
		o.IP = ip.String()
	}
	if vc := strings.TrimSpace(pkt.ClassIdentifier()); vc != "" {
		// The vendor class is a self-reported string ("MSFT 5.0",
		// "android-dhcp-14", a printer's model). It is a hint, not a
		// vendor name, so it goes in Hints where the classifier can weigh
		// it rather than in VendorHint where it would become a label.
		o.Hints = append(o.Hints, vc)
	}
	if fp := fingerprint(pkt); fp != "" {
		o.Hints = append(o.Hints, "dhcp-fingerprint:"+fp)
	}
	h.Sink.Observe(o)
}

// fingerprint is the parameter request list (option 55) as a comma-separated
// list of option numbers. It is the closest thing DHCP has to a device
// signature: the set and order of options a client asks for is characteristic
// of its operating system, and it costs nothing to record.
func fingerprint(pkt *dhcpv4.DHCPv4) string {
	codes := pkt.ParameterRequestList()
	if len(codes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, strconv.Itoa(int(c.Code())))
	}
	return strings.Join(parts, ",")
}

func clientID(pkt *dhcpv4.DHCPv4) string {
	b := pkt.GetOneOption(dhcpv4.OptionClientIdentifier)
	if len(b) == 0 {
		return ""
	}
	// Client identifiers are opaque. The common form is a one-byte type
	// followed by a MAC, and the rest is anything at all, so this is
	// recorded as hex rather than interpreted.
	var sb strings.Builder
	const hex = "0123456789abcdef"
	for _, c := range b {
		sb.WriteByte(hex[c>>4])
		sb.WriteByte(hex[c&0xf])
	}
	return sb.String()
}

// compose builds the lease record and the common reply options for one
// client, and is where the routing decision actually becomes option 3.
func (h *Handler) compose(pkt *dhcpv4.DHCPv4, mac string, ip netip.Addr, reserved bool, set Settings) (Lease, Decision, []dhcpv4.Modifier) {
	now := h.now()
	dec := h.policy().Decide(mac, ip)
	router := set.Gateway
	if dec.Routed {
		router = set.ServerIP
	}
	host := strings.TrimSpace(pkt.HostName())
	if h.Alloc != nil {
		if r, ok := h.Alloc.reservation(mac); ok && r.Hostname != "" {
			host = r.Hostname
		}
	}
	lease := Lease{
		MAC: mac, ClientID: clientID(pkt), IP: ip, Hostname: host,
		VendorClass: strings.TrimSpace(pkt.ClassIdentifier()), Fingerprint: fingerprint(pkt),
		Router: router, Reserved: reserved, Origin: OriginShepherd,
		Allocated: now, Renewed: now, Expires: now.Add(set.leaseTime()),
	}
	if prev, ok := h.Leases.Get(mac); ok && prev.Origin == OriginShepherd && prev.IP == ip {
		lease.Allocated = prev.Allocated
		lease.DeviceID = prev.DeviceID
	}

	mods := []dhcpv4.Modifier{
		dhcpv4.WithServerIP(set.ServerIP.AsSlice()),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(set.ServerIP.AsSlice())),
		dhcpv4.WithNetmask(net.CIDRMask(set.Subnet.Bits(), 32)),
		dhcpv4.WithOption(dhcpv4.OptRouter(router.AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(set.leaseTime())),
		dhcpv4.WithOption(dhcpv4.OptBroadcastAddress(broadcastOf(set.Subnet).AsSlice())),
	}
	// Renewal and rebinding times are sent explicitly rather than left to
	// the client's own halves-and-eighths defaults, because the whole
	// fail-open story depends on knowing when a device will ask again.
	mods = append(mods,
		dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(set.leaseTime()/2)),
		dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(set.leaseTime()*7/8)),
	)
	if dns := ipSlice(set.DNS); len(dns) > 0 {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDNS(dns...)))
	}
	if set.Domain != "" {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDomainName(set.Domain)))
	}
	if host != "" {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptHostName(host)))
	}
	return lease, dec, mods
}

func ipSlice(addrs []netip.Addr) []net.IP {
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if a.Is4() {
			out = append(out, a.AsSlice())
		}
	}
	return out
}

func (h *Handler) offer(pkt *dhcpv4.DHCPv4, mac string, set Settings) Result {
	requested, _ := netip.AddrFromSlice(pkt.RequestedIPAddress().To4())
	ip, reserved, err := h.Alloc.Allocate(mac, requested)
	if err != nil {
		// Saying nothing is right here: the client retries, and by the
		// time it does a lease may have expired. A NAK would only tell it
		// to start over, which is what it is already doing.
		return Result{Action: ActionIgnore, Why: err.Error()}
	}
	_, dec, mods := h.compose(pkt, mac, ip, reserved, set)
	reply, err := dhcpv4.NewReplyFromRequest(pkt, append([]dhcpv4.Modifier{
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithYourIP(ip.AsSlice()),
	}, mods...)...)
	if err != nil {
		return Result{Action: ActionIgnore, Why: "building the offer: " + err.Error()}
	}
	// An offer is not a lease. Nothing is stored until the client asks for
	// the address in a REQUEST, because storing it here would let one
	// device's DISCOVER sweep reserve the whole pool.
	return Result{Action: ActionOffer, Reply: reply, To: replyTo(pkt), Routing: dec}
}

func (h *Handler) request(pkt *dhcpv4.DHCPv4, mac string, set Settings) Result {
	// A REQUEST naming a different server identifier is the client telling
	// us it chose someone else. The right response is silence, and the
	// right side effect is to forget any offer-shaped state for it.
	if sid := pkt.ServerIdentifier(); sid != nil {
		if a, ok := netip.AddrFromSlice(sid.To4()); ok && a.IsValid() && !a.IsUnspecified() && a != set.ServerIP {
			if h.Peers != nil {
				h.Peers.Saw(a, h.now())
			}
			return Result{Action: ActionIgnore, Why: "the client chose the server at " + a.String()}
		}
	}

	want, _ := netip.AddrFromSlice(pkt.RequestedIPAddress().To4())
	if !want.IsValid() || want.IsUnspecified() {
		// Renewing clients put the address in ciaddr rather than
		// option 50.
		want, _ = netip.AddrFromSlice(pkt.ClientIPAddr.To4())
	}
	if !want.IsValid() || want.IsUnspecified() {
		return h.nak(pkt, set, "the request names no address")
	}
	ip, reserved, err := h.Alloc.Allocate(mac, want)
	if err != nil {
		return h.nak(pkt, set, err.Error())
	}
	if ip != want {
		// The client asked for something it cannot have: it is on the
		// wrong segment, the address is reserved for somebody else, or
		// the pool has moved. A NAK is correct and makes it start again.
		return h.nak(pkt, set, "the address "+want.String()+" is not available; "+ip.String()+" is")
	}
	lease, dec, mods := h.compose(pkt, mac, ip, reserved, set)
	reply, err := dhcpv4.NewReplyFromRequest(pkt, append([]dhcpv4.Modifier{
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(ip.AsSlice()),
	}, mods...)...)
	if err != nil {
		return Result{Action: ActionIgnore, Why: "building the acknowledgement: " + err.Error()}
	}
	h.Leases.Put(lease)
	return Result{Action: ActionAck, Reply: reply, To: replyTo(pkt), Lease: lease, Routing: dec}
}

func (h *Handler) nak(pkt *dhcpv4.DHCPv4, set Settings, why string) Result {
	reply, err := dhcpv4.NewReplyFromRequest(pkt,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(set.ServerIP.AsSlice())),
		dhcpv4.WithOption(dhcpv4.OptMessage(why)),
	)
	if err != nil {
		return Result{Action: ActionIgnore, Why: "building the refusal: " + err.Error()}
	}
	// RFC 2131: a NAK always goes to the broadcast address, because the
	// address the client thinks it has is exactly what is being refused.
	return Result{Action: ActionNak, Reply: reply, To: netip.AddrFrom4([4]byte{255, 255, 255, 255}), Why: why}
}

func (h *Handler) decline(pkt *dhcpv4.DHCPv4, mac string) Result {
	ip, _ := netip.AddrFromSlice(pkt.RequestedIPAddress().To4())
	if !ip.IsValid() {
		ip, _ = netip.AddrFromSlice(pkt.ClientIPAddr.To4())
	}
	if !ip.IsValid() || ip.IsUnspecified() {
		return Result{Action: ActionIgnore, Why: "a decline naming no address"}
	}
	// The client found the address already in use by something Shepherd
	// cannot see — a statically configured device, most likely. Remembering
	// it is the only way not to offer it again immediately.
	h.Leases.Decline(mac, ip)
	return Result{Action: ActionObserve, Why: "the client declined " + ip.String() + "; it will not be offered again"}
}

func (h *Handler) release(pkt *dhcpv4.DHCPv4, mac string) Result {
	l, ok := h.Leases.Get(mac)
	if !ok {
		return Result{Action: ActionIgnore, Why: "a release for a device with no lease"}
	}
	h.Leases.Delete(mac)
	return Result{Action: ActionObserve, Lease: l, Why: "released " + l.IP.String()}
}

func (h *Handler) inform(pkt *dhcpv4.DHCPv4, mac string, set Settings) Result {
	ip, _ := netip.AddrFromSlice(pkt.ClientIPAddr.To4())
	if !ip.IsValid() || ip.IsUnspecified() {
		return Result{Action: ActionIgnore, Why: "an inform from no address"}
	}
	// INFORM asks for configuration without a lease, so no lease is stored
	// and no address is allocated — but the routing decision still has to
	// be made, because option 3 is the whole point of the answer.
	_, dec, mods := h.compose(pkt, mac, ip, false, set)
	// A lease time in an INFORM reply is a protocol error: there is no
	// lease.
	reply, err := dhcpv4.NewReplyFromRequest(pkt, append([]dhcpv4.Modifier{
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
	}, mods...)...)
	if err != nil {
		return Result{Action: ActionIgnore, Why: "building the inform reply: " + err.Error()}
	}
	reply.DeleteOption(dhcpv4.OptionIPAddressLeaseTime)
	reply.DeleteOption(dhcpv4.OptionRenewTimeValue)
	reply.DeleteOption(dhcpv4.OptionRebindingTimeValue)
	return Result{Action: ActionAck, Reply: reply, To: ip, Routing: dec}
}

// replyTo picks the destination for a reply, following RFC 2131 section 4.1
// as far as a UDP socket allows.
//
// The limit worth naming: when a client has no address yet and has *not* set
// the broadcast flag, the RFC says to unicast to the offered address and the
// client's MAC. A UDP socket cannot do that — the kernel would ARP for an
// address the client has not accepted yet, get no answer, and drop the
// reply — so Shepherd broadcasts instead. Broadcasting to a client that
// asked for unicast is harmless; it reads the reply either way. Doing it
// properly needs a raw frame socket, which is a worthwhile change and not
// this one.
func replyTo(pkt *dhcpv4.DHCPv4) netip.Addr {
	if ip, ok := netip.AddrFromSlice(pkt.ClientIPAddr.To4()); ok && ip.IsValid() && !ip.IsUnspecified() {
		return ip
	}
	return netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
