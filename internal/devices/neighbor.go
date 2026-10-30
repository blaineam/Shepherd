// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Neighbor is one entry of the host's ARP or neighbor table: a MAC seen for
// an IP on the local segment.
type Neighbor struct {
	IP    string
	MAC   string // normalized
	Iface string
}

func newNeighbor(ip, mac, iface string) (Neighbor, bool) {
	a, ok := parseIP(ip)
	if !ok {
		return Neighbor{}, false
	}
	m, ok := NormalizeMAC(mac)
	if !ok {
		return Neighbor{}, false
	}
	return Neighbor{IP: a.String(), MAC: m, Iface: iface}, true
}

// ParseProcNetARP parses Linux /proc/net/arp. Incomplete entries (flags 0x0)
// and all-zero hardware addresses are skipped.
func ParseProcNetARP(data []byte) []Neighbor {
	var out []Neighbor
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 || f[2] == "0x0" {
			continue
		}
		if n, ok := newNeighbor(f[0], f[3], f[5]); ok {
			out = append(out, n)
		}
	}
	return out
}

// ParseArpAn parses macOS and BSD `arp -an` output, for example
// "? (192.0.2.1) at 2:0:5e:0:0:1 on en0 ifscope [ethernet]". macOS prints
// octets without leading zeros; incomplete entries are skipped.
func ParseArpAn(data []byte) []Neighbor {
	var out []Neighbor
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[2] != "at" {
			continue
		}
		ip := strings.Trim(f[1], "()")
		iface := ""
		if len(f) >= 6 && f[4] == "on" {
			iface = f[5]
		}
		if n, ok := newNeighbor(ip, f[3], iface); ok {
			out = append(out, n)
		}
	}
	return out
}

// ParseIPNeigh parses Linux `ip neigh` output (IPv4 and IPv6), for example
// "2001:db8::1 dev eth0 lladdr 02:00:5e:00:00:01 REACHABLE". Entries without
// a link-layer address are skipped. Reading the table is passive: Shepherd
// never sends or spoofs neighbor discovery (docs/IPV6.md).
func ParseIPNeigh(data []byte) []Neighbor {
	var out []Neighbor
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		var iface, mac string
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "dev":
				iface = f[i+1]
			case "lladdr":
				mac = f[i+1]
			}
		}
		if n, ok := newNeighbor(f[0], mac, iface); ok {
			out = append(out, n)
		}
	}
	return out
}

// NeighborSource reads a neighbor table. Implementations are small so that
// ARP interception can later provide a live one.
type NeighborSource interface {
	Neighbors(ctx context.Context) ([]Neighbor, error)
}

// FileNeighbors reads and parses a table file such as /proc/net/arp.
type FileNeighbors struct {
	Path     string
	Parse    func([]byte) []Neighbor
	ReadFile func(string) ([]byte, error) // default os.ReadFile
}

func (f FileNeighbors) Neighbors(context.Context) ([]Neighbor, error) {
	read := f.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	b, err := read(f.Path)
	if err != nil {
		return nil, err
	}
	return f.Parse(b), nil
}

// CommandNeighbors runs a command (for example `arp -an`) and parses its
// output.
type CommandNeighbors struct {
	Name  string
	Args  []string
	Parse func([]byte) []Neighbor
	Run   func(ctx context.Context, name string, args ...string) ([]byte, error) // default exec
}

func (c CommandNeighbors) Neighbors(ctx context.Context) ([]Neighbor, error) {
	run := c.Run
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		}
	}
	b, err := run(ctx, c.Name, c.Args...)
	if err != nil {
		return nil, err
	}
	return c.Parse(b), nil
}

// DefaultNeighborSources returns the passive neighbor sources for an
// operating system: /proc/net/arp and `ip neigh` on Linux, `arp -an` on
// macOS. Other systems get none.
func DefaultNeighborSources(goos string) []NeighborSource {
	switch goos {
	case "linux":
		return []NeighborSource{
			FileNeighbors{Path: "/proc/net/arp", Parse: ParseProcNetARP},
			CommandNeighbors{Name: "ip", Args: []string{"-6", "neigh", "show"}, Parse: ParseIPNeigh},
		}
	case "darwin":
		return []NeighborSource{CommandNeighbors{Name: "arp", Args: []string{"-an"}, Parse: ParseArpAn}}
	}
	return nil
}

// Poller periodically reads neighbor sources and feeds the registry.
type Poller struct {
	Sources  []NeighborSource
	Sink     Sink
	Interval time.Duration // default 30s
	Now      func() time.Time
	OnError  func(error)
}

// PollOnce reads every source once and returns how many neighbors it fed to
// the sink. Source errors are joined; the other sources still run.
func (p *Poller) PollOnce(ctx context.Context) (int, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	var errs []error
	n := 0
	for _, s := range p.Sources {
		ns, err := s.Neighbors(ctx)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, nb := range ns {
			p.Sink.Observe(Observation{Source: SourceNeighbor, MAC: nb.MAC, IP: nb.IP, Time: now()})
			n++
		}
	}
	return n, errors.Join(errs...)
}

// Run polls until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	iv := p.Interval
	if iv <= 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		if _, err := p.PollOnce(ctx); err != nil && p.OnError != nil {
			p.OnError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Discoverer is anything that runs in the background feeding observations:
// the neighbor Poller, the mDNS listener, and later the ARP interceptor.
type Discoverer interface {
	Run(ctx context.Context) error
}

var (
	_ Discoverer = (*Poller)(nil)
	_ Sink       = (*Registry)(nil)
)
