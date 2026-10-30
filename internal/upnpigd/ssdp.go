// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// ssdpMulticastAddr is the standard SSDP multicast group and port every
// UPnP device on a LAN listens on, the same on every network everywhere,
// not a detail of this one.
const ssdpMulticastAddr = "239.255.255.250:1900" // leakcheck:allow — standard SSDP address, not private

// searchTargets are the IGD device-type URNs this client searches for, in
// the order tried: version 2 first, since a router that advertises both
// should be asked with its newer control surface, then version 1, which is
// what most deployed home routers still answer to.
var searchTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
}

// ssdpConn is the part of a UDP socket SSDP discovery needs: enough to
// send one multicast datagram per search target and read back whatever
// responses arrive before a deadline. Production uses a real UDP socket
// (see dialSSDP); tests inject a fake, the same way
// internal/devices.PacketConn and internal/portscan.DialFunc keep real
// sockets out of their own unit tests.
type ssdpConn interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetDeadline(t time.Time) error
	Close() error
}

// dialSSDP opens the real UDP socket production discovery sends from.
func dialSSDP() (ssdpConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// buildSearch renders one SSDP M-SEARCH request for searchTarget.
func buildSearch(searchTarget string, mx int) []byte {
	return []byte(fmt.Sprintf(
		"M-SEARCH * HTTP/1.1\r\n"+
			"HOST: %s\r\n"+
			"MAN: \"ssdp:discover\"\r\n"+
			"MX: %d\r\n"+
			"ST: %s\r\n\r\n",
		ssdpMulticastAddr, mx, searchTarget))
}

// parseLocation extracts the LOCATION header's value from a raw SSDP HTTP
// response (the M-SEARCH 200 OK reply). It is case-insensitive about the
// header name, as HTTP requires, and returns ok=false if there is none.
func parseLocation(raw string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		if strings.EqualFold(key, "LOCATION") {
			loc := strings.TrimSpace(line[idx+1:])
			if loc != "" {
				return loc, true
			}
		}
	}
	return "", false
}

// discoverLocation sends an M-SEARCH for every search target over conn,
// then reads responses until one carries a usable LOCATION header or
// deadline passes. It tries every target before giving up, since routers
// vary in which device-type URN they answer to.
func discoverLocation(conn ssdpConn, deadline time.Time) (string, error) {
	dst, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddr)
	if err != nil {
		return "", fmt.Errorf("upnpigd: resolving SSDP multicast address: %w", err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return "", fmt.Errorf("upnpigd: setting discovery deadline: %w", err)
	}
	for _, st := range searchTargets {
		if _, err := conn.WriteTo(buildSearch(st, 2), dst); err != nil {
			return "", fmt.Errorf("upnpigd: sending M-SEARCH: %w", err)
		}
	}
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return "", fmt.Errorf("upnpigd: no IGD answered discovery: %w", err)
		}
		if loc, ok := parseLocation(string(buf[:n])); ok {
			return loc, nil
		}
	}
}
