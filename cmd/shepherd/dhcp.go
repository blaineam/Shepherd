// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/arp"
	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dhcp"
)

// hostNetwork is what starting DHCP mode needs to know about this machine:
// which interface faces the LAN, what the router's address is, and what
// addresses and prefixes this host holds. It is an interface so that the
// wiring below is exercised on every platform without a Linux /proc or a
// real NIC — the same arrangement watchPlatform has.
type hostNetwork interface {
	// DefaultRoute names the interface the default route leaves through
	// and the gateway it points at.
	DefaultRoute() (iface string, gateway netip.Addr, err error)
	// Addrs returns one interface's IPv4 addresses and prefixes.
	Addrs(iface string) (addrs []netip.Addr, nets []netip.Prefix, err error)
	// LocalAddrs returns every MAC and every IPv4 address on this host,
	// across all of its interfaces. All of them, because on a host whose
	// interfaces share a segment the other ones look exactly like LAN
	// devices, and handing one of them Shepherd's own address as its
	// gateway makes Shepherd NAT its own traffic to itself.
	LocalAddrs() (macs []string, ips []netip.Addr, err error)
}

// realHostNetwork reads the kernel: internal/arp's /proc routing table and
// the standard library's interface list.
type realHostNetwork struct{}

func (realHostNetwork) DefaultRoute() (string, netip.Addr, error) {
	r, err := arp.DefaultRoute(os.ReadFile)
	if err != nil {
		return "", netip.Addr{}, err
	}
	return r.Iface, r.Gateway, nil
}

func (realHostNetwork) Addrs(name string) ([]netip.Addr, []netip.Prefix, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %q: %w", name, err)
	}
	list, err := ifc.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("addresses of %q: %w", name, err)
	}
	var addrs []netip.Addr
	var nets []netip.Prefix
	for _, a := range list {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok || !ip.Unmap().Is4() {
			continue
		}
		ip = ip.Unmap()
		ones, _ := ipn.Mask.Size()
		addrs = append(addrs, ip)
		nets = append(nets, netip.PrefixFrom(ip, ones))
	}
	return addrs, nets, nil
}

func (realHostNetwork) LocalAddrs() ([]string, []netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	var macs []string
	var ips []netip.Addr
	for _, ifc := range ifaces {
		if m := dhcp.NormalizeMAC(ifc.HardwareAddr.String()); m != "" {
			macs = append(macs, m)
		}
		list, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range list {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
					ips = append(ips, ip.Unmap())
				}
			}
		}
	}
	return macs, ips, nil
}

// dhcpHost is a test seam over realHostNetwork.
var dhcpHost = func() hostNetwork { return realHostNetwork{} }

// startDHCP builds DHCP mode (internal/dhcp, docs/DHCP.md) and runs it until
// ctx is cancelled. It returns nil when the mode is off, which is the
// default.
//
// Like startWatch and startARP it never fails Shepherd's startup. A host
// that cannot run it — not Linux, no nft, no usable interface, a DHCP block
// that does not describe this network — gets a logged reason and a server
// that reports itself blocked in the portal, with DNS filtering and
// everything else untouched. That is the right trade here for the same
// reason it is there: DHCP mode is the one feature whose failure must not
// take the rest of Shepherd with it.
func startDHCP(ctx context.Context, cfg config.Config, reg *devices.Registry, alarmEngine *alarms.Engine) (*dhcp.Server, error) {
	mode, ok := dhcp.ParseMode(cfg.DHCP.Mode)
	if !ok {
		return nil, fmt.Errorf("dhcp.mode %q is not one of \"off\", \"observe\" or \"serve\"", cfg.DHCP.Mode)
	}

	statePath := filepath.Join(cfg.DataDir, "dhcp.json")
	state, err := dhcp.OpenState(statePath, time.Now)
	if err != nil {
		// Reservations are the one piece of DHCP state nothing re-sends,
		// so an unreadable file is refused rather than started over. It
		// still must not stop Shepherd: the mode reports the reason and
		// everything else runs.
		log.Printf("dhcp: %v; DHCP mode will not start, and nothing else is affected", err)
		return nil, nil
	}

	// The addressing is worked out for every mode, including off. With the
	// mode off nothing is served, but the portal still needs it: a
	// reservation has to be refused when it lands inside the dynamic pool,
	// and that check is the whole reason the screen is usable before the
	// mode is ever switched on.
	host := dhcpHost()
	iface := cfg.DHCP.Interface
	gateway, _ := netip.ParseAddr(cfg.DHCP.Gateway)
	var addrs []netip.Addr
	var nets []netip.Prefix
	var macs []string
	var ips []netip.Addr

	if iface == "" || !gateway.IsValid() {
		routeIface, routeGW, err := host.DefaultRoute()
		switch {
		case err != nil && mode != dhcp.ModeOff:
			log.Printf("dhcp: cannot work out the LAN interface and gateway (%v); DHCP mode will not start", err)
			return nil, nil
		case err != nil:
			// Off: the file's own values are all there is, and that is
			// enough for the screen.
			log.Printf("dhcp: cannot work out the LAN interface and gateway (%v); with the mode off this only means the DHCP screen shows less", err)
		default:
			if iface == "" {
				iface = routeIface
			}
			if !gateway.IsValid() {
				gateway = routeGW
			}
		}
	}

	if iface != "" {
		var err error
		addrs, nets, err = host.Addrs(iface)
		if err != nil {
			if mode != dhcp.ModeOff {
				log.Printf("dhcp: %v; DHCP mode will not start", err)
				return nil, nil
			}
			log.Printf("dhcp: %v; with the mode off this only means the DHCP screen shows less", err)
		}
	}

	settings, err := dhcpSettings(cfg.DHCP, gateway, addrs, nets)
	if err != nil && mode != dhcp.ModeOff {
		// A mode that is switched on but cannot describe the network is a
		// configuration mistake, and the portal is where it should be read
		// rather than the log alone. The server is built anyway so the
		// status carries the reason.
		log.Printf("dhcp: %v; DHCP mode will not serve until this is fixed", err)
	}

	if mode == dhcp.ModeOff {
		// No socket, no kernel configuration, no routing: only the stored
		// reservations and the addressing they are checked against.
		srv := &dhcp.Server{
			Mode: func() dhcp.Mode { return dhcp.ModeOff }, State: state,
			Store: dhcp.NewLeases(), Peers: dhcp.NewPeers(),
			Settings: func() dhcp.Settings { return settings },
			// Observed even with the mode off: choosing a range is
			// something to work through before anything is served, and
			// the whole point of the check is to say what has to change
			// on the router first.
			Observe: func() dhcp.Observed { return observeNetwork(host, iface, reg) },
			Log:     log.Default(),
		}
		if err := srv.Prepare(); err != nil {
			log.Printf("dhcp: %v", err)
		}
		log.Print("dhcp: DHCP mode is off (dhcp.mode = \"off\"); Shepherd serves no leases and routes nothing")
		return srv, nil
	}

	macs, ips, err = host.LocalAddrs()
	if err != nil {
		log.Printf("dhcp: cannot list this host's own addresses (%v); DHCP mode will not start, because it could otherwise route Shepherd through itself", err)
		return nil, nil
	}

	nat := &dhcp.Reconciler{LAN: iface, NFT: cfg.DHCP.NFT}
	srv := &dhcp.Server{
		Mode:          func() dhcp.Mode { return mode },
		Settings:      func() dhcp.Settings { return settings },
		Route:         func() bool { return cfg.DHCP.Route },
		RouteConsoles: func() bool { return cfg.DHCP.RouteConsoles },
		Own:           func() dhcp.Own { return dhcp.Own{MACs: macs, IPs: ips, Gateway: gateway} },
		Lookup:        func(mac string) (devices.Device, bool) { return reg.FindByMAC(mac) },
		Observe:       func() dhcp.Observed { return observeNetwork(host, iface, reg) },
		Store:         dhcp.NewLeases(),
		State:         state,
		Peers:         dhcp.NewPeers(),
		Sink:          reg,
		NAT:           nat,
		Open:          dhcp.UDPOpener{Log: log.Default()}.Open,
		Iface:         iface,
		LeasePath:     filepath.Join(cfg.DataDir, "dhcp-leases.json"),
		Settle:        time.Duration(cfg.DHCP.SettleSeconds) * time.Second,
		Log:           log.Default(),
		Alarm:         dhcpAlarm(alarmEngine),
	}

	log.Printf("dhcp: DHCP mode is %q on %s: LAN %s, Shepherd %s, gateway %s, pool %s-%s, leases %s, routing %v",
		mode, iface, settings.Subnet, settings.ServerIP, settings.Gateway,
		settings.Pool.Start, settings.Pool.End, settings.LeaseTime, cfg.DHCP.Route)

	go func() {
		if err := srv.Run(ctx); err != nil {
			log.Printf("dhcp: stopped: %v", err)
		}
	}()
	return srv, nil
}

// observeNetwork is the network as Shepherd can see it now, for the
// collision check behind the portal's range picker: this host's own
// addresses, the gateway, and every address the device registry knows is in
// use. The registry is the right source because it already learns addresses
// from DNS queries, the neighbour table, mDNS and -- once this mode is
// watching -- from DHCP itself, which between them is a far better picture
// of "what is actually on this network" than anything this package could
// gather on its own.
func observeNetwork(host hostNetwork, iface string, reg *devices.Registry) dhcp.Observed {
	o := dhcp.Observed{}
	if addrs, nets, err := host.Addrs(iface); err == nil {
		o.HostAddrs, o.HostNets = addrs, nets
	}
	if _, gw, err := host.DefaultRoute(); err == nil {
		o.Gateway = gw
	}
	if reg == nil {
		return o
	}
	for _, d := range reg.List() {
		mac := ""
		if len(d.MACs) > 0 {
			mac = d.MACs[0]
		}
		for _, raw := range d.IPs {
			ip, err := netip.ParseAddr(raw)
			if err != nil || !ip.Is4() {
				continue
			}
			o.Holders = append(o.Holders, dhcp.Holder{IP: ip, MAC: mac, Name: d.DisplayName()})
		}
	}
	return o
}

// dhcpSettings turns the configuration block plus what the interface says
// into the settings the server hands out. Anything the file leaves empty is
// taken from the interface, which is what makes a minimal [dhcp] block work.
func dhcpSettings(c config.DHCP, gateway netip.Addr, addrs []netip.Addr, nets []netip.Prefix) (dhcp.Settings, error) {
	s := dhcp.Settings{Gateway: gateway, Domain: c.Domain}
	if c.LeaseSeconds > 0 {
		s.LeaseTime = time.Duration(c.LeaseSeconds) * time.Second
	} else {
		s.LeaseTime = dhcp.DefaultLeaseTime
	}

	if c.ServerIP != "" {
		s.ServerIP, _ = netip.ParseAddr(c.ServerIP)
	} else if len(addrs) > 0 {
		s.ServerIP = addrs[0]
	}
	if c.Subnet != "" {
		s.Subnet, _ = netip.ParsePrefix(c.Subnet)
	} else {
		for _, n := range nets {
			if n.Contains(s.ServerIP) {
				s.Subnet = n.Masked()
				break
			}
		}
	}
	if c.PoolStart != "" {
		s.Pool.Start, _ = netip.ParseAddr(c.PoolStart)
		s.Pool.End, _ = netip.ParseAddr(c.PoolEnd)
	}
	for _, v := range c.DNS {
		if a, err := netip.ParseAddr(v); err == nil {
			s.DNS = append(s.DNS, a)
		}
	}
	if len(s.DNS) == 0 && s.ServerIP.IsValid() {
		// Handing out Shepherd as the resolver is the point of the whole
		// project, so it is the default rather than something to
		// remember to configure.
		s.DNS = []netip.Addr{s.ServerIP}
	}
	return s, s.Valid()
}

// dhcpAlarm maps the server's three conditions onto alarm types. It returns
// nil when the alarm engine is off, which the server handles.
func dhcpAlarm(e *alarms.Engine) func(severity, title, detail string) {
	if e == nil {
		return nil
	}
	return func(severity, title, detail string) {
		typ := alarms.TypeDHCPNATFailed
		switch {
		case strings.Contains(title, "DHCP server"):
			typ = alarms.TypeDHCPRogueServer
		case strings.Contains(title, "lease file"):
			typ = alarms.TypeDHCPLeaseReset
		}
		e.Raise(alarms.Event{
			Type: typ, Severity: alarms.Severity(severity), Title: title, Body: detail,
			Source: "dhcp", Key: typ + "|",
		})
	}
}
