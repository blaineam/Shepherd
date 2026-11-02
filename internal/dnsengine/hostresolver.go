package dnsengine

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
)

// HostResolver returns a resolver for Shepherd's own outbound HTTP fetches
// (update checks, blocklists, geo and vulnerability feeds) that asks the
// bootstrap servers instead of whatever /etc/resolv.conf names. Inside a host
// network container that file often points at 127.0.0.1 or ::1, which is not
// where Shepherd listens, so every lookup would time out. Each lookup attempt
// the Go resolver makes is sent to the next bootstrap server in turn, so one
// dead server costs a retry, not the lookup.
func HostResolver(servers func() []string) *net.Resolver {
	var n atomic.Uint64
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			list := servers()
			if len(list) == 0 {
				var d net.Dialer
				return d.DialContext(ctx, network, address)
			}
			addr := list[int(n.Add(1)-1)%len(list)]
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr = net.JoinHostPort(strings.Trim(addr, "[]"), "53")
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}
