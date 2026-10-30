// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ProcNetRoute is the Linux routing table the helpers below parse.
const ProcNetRoute = "/proc/net/route"

// ErrNoDefaultRoute means the table has no usable default route.
var ErrNoDefaultRoute = errors.New("arp: no default route")

// Route is the default route chosen from /proc/net/route.
type Route struct {
	Iface   string
	Gateway netip.Addr
	Metric  int
}

const (
	rtfUp      = 0x1
	rtfGateway = 0x2
)

// ParseDefaultRoute picks the default route (destination 0.0.0.0/0, up,
// via a gateway) with the lowest metric from the text of /proc/net/route.
// Malformed lines are skipped.
func ParseDefaultRoute(data []byte) (Route, error) {
	var best Route
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[0] == "Iface" {
			continue
		}
		dest, e1 := strconv.ParseUint(f[1], 16, 32)
		gw, e2 := strconv.ParseUint(f[2], 16, 32)
		flags, e3 := strconv.ParseUint(f[3], 16, 32)
		metric, e4 := strconv.Atoi(f[6])
		mask, e5 := strconv.ParseUint(f[7], 16, 32)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
			continue
		}
		if dest != 0 || mask != 0 || flags&rtfUp == 0 || flags&rtfGateway == 0 || gw == 0 {
			continue
		}
		var raw [4]byte
		binary.LittleEndian.PutUint32(raw[:], uint32(gw))
		r := Route{Iface: f[0], Gateway: netip.AddrFrom4(raw), Metric: metric}
		if !found || r.Metric < best.Metric {
			best, found = r, true
		}
	}
	if !found {
		return Route{}, ErrNoDefaultRoute
	}
	return best, nil
}

// DefaultRoute reads and parses the routing table through readFile, which
// is injectable (os.ReadFile in production).
func DefaultRoute(readFile func(string) ([]byte, error)) (Route, error) {
	data, err := readFile(ProcNetRoute)
	if err != nil {
		return Route{}, fmt.Errorf("arp: read routing table: %w", err)
	}
	return ParseDefaultRoute(data)
}

// DefaultGatewayFunc returns a Config.GatewayFunc that learns the default
// gateway from the routing table via readFile.
func DefaultGatewayFunc(readFile func(string) ([]byte, error)) func() (netip.Addr, error) {
	return func() (netip.Addr, error) {
		r, err := DefaultRoute(readFile)
		return r.Gateway, err
	}
}
