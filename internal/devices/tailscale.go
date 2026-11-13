// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultTailscaleSocket is where tailscaled serves its local API on Linux.
const DefaultTailscaleSocket = "/var/run/tailscale/tailscaled.sock"

// tailscaleNode is the part of a tailscaled status entry Shepherd reads.
type tailscaleNode struct {
	HostName     string
	DNSName      string
	TailscaleIPs []string
	Online       bool
}

type tailscaleStatus struct {
	Self *tailscaleNode
	Peer map[string]*tailscaleNode
}

// TailscaleSource names tailnet devices. DNS queries that arrive over the
// tailnet come from the sender's own tailnet address, which no ARP table
// or DHCP lease explains; this asks the local tailscaled for the name behind
// each address and feeds it to a Sink as a SourceTailscale observation, so the
// query log and device list say "pixel-8" rather than an unnamed 100.x address.
// It only reads the local API; it never changes anything in the tailnet.
type TailscaleSource struct {
	Sink     Sink
	Socket   string        // unix socket of tailscaled; default DefaultTailscaleSocket
	Interval time.Duration // default 60s
	Now      func() time.Time
	OnError  func(error) // may be nil
	// Client overrides the HTTP client (tests); default dials Socket.
	Client *http.Client
	// BaseURL overrides the request URL's origin (tests).
	BaseURL string
}

func (t *TailscaleSource) client() *http.Client {
	if t.Client != nil {
		return t.Client
	}
	sock := t.Socket
	if sock == "" {
		sock = DefaultTailscaleSocket
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
	}
}

// Poll fetches the status once and observes every online node. It returns the
// number of nodes observed.
func (t *TailscaleSource) Poll(ctx context.Context) (int, error) {
	base := t.BaseURL
	if base == "" {
		base = "http://local-tailscaled.sock"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/localapi/v0/status?peers=true", nil)
	if err != nil {
		return 0, err
	}
	// tailscaled's local API insists on a Host of local-tailscaled.sock.
	req.Host = "local-tailscaled.sock"
	resp, err := t.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("tailscaled local API answered %s", resp.Status)
	}
	var st tailscaleStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&st); err != nil {
		return 0, fmt.Errorf("reading tailscaled status: %w", err)
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	at := now()
	n := 0
	observe := func(node *tailscaleNode) {
		if node == nil {
			return
		}
		name := node.HostName
		if name == "" {
			name, _, _ = strings.Cut(strings.TrimSuffix(node.DNSName, "."), ".")
		}
		if name == "" || len(node.TailscaleIPs) == 0 {
			return
		}
		for _, ip := range node.TailscaleIPs {
			t.Sink.Observe(Observation{Source: SourceTailscale, IP: ip, Hostname: name, Hints: []string{"tailscale"}, Time: at})
		}
		n++
	}
	observe(st.Self)
	for _, p := range st.Peer {
		// Offline nodes would otherwise become devices that never ask Shepherd anything.
		if p != nil && p.Online {
			observe(p)
		}
	}
	return n, nil
}

// Run polls until ctx ends. Errors (tailscaled not running, socket not
// mounted) go to OnError and the next poll tries again.
func (t *TailscaleSource) Run(ctx context.Context) error {
	every := t.Interval
	if every <= 0 {
		every = time.Minute
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if _, err := t.Poll(ctx); err != nil && ctx.Err() == nil && t.OnError != nil {
			t.OnError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
