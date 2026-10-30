// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DefaultGateway finds the IPv4 default gateway in the text of
// /proc/net/route (Linux). It returns false when there is none.
func DefaultGateway(route []byte) (string, bool) {
	lines := strings.Split(string(route), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x2 == 0 { // RTF_GATEWAY
			continue
		}
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || gw == 0 {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(gw)) // the kernel prints it in host order
		return netip.AddrFrom4(b).String(), true
	}
	return "", false
}

// ReadDefaultGateway reads path (normally /proc/net/route) and returns its
// default gateway.
func ReadDefaultGateway(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return DefaultGateway(b)
}

// PTRLookup returns a ReverseLookup that asks one DNS server (host or
// host:port; port 53 by default) for PTR records. It uses plain DNS to that
// one server only, never the system resolver, so a home router that knows its
// DHCP clients can name them.
func PTRLookup(server string) ReverseLookup {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(strings.Trim(server, "[]"), "53")
	}
	client := &dns.Client{Timeout: 3 * time.Second}
	return func(ctx context.Context, ip string) ([]string, error) {
		arpa, err := dns.ReverseAddr(ip)
		if err != nil {
			return nil, err
		}
		m := new(dns.Msg)
		m.SetQuestion(arpa, dns.TypePTR)
		resp, _, err := client.ExchangeContext(ctx, m, addr)
		if err != nil {
			return nil, err
		}
		if resp.Rcode != dns.RcodeSuccess {
			return nil, errors.New("rcode " + dns.RcodeToString[resp.Rcode])
		}
		var out []string
		for _, rr := range resp.Answer {
			if p, ok := rr.(*dns.PTR); ok {
				out = append(out, strings.TrimSuffix(p.Ptr, "."))
			}
		}
		return out, nil
	}
}
