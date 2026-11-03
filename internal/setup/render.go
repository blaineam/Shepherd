// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Answers is everything setup decided: the page posts exactly this. It is
// deliberately small, because only the keys asked about are written, so a
// default that improves in a later version keeps improving for an install
// made today rather than being frozen into its file.
type Answers struct {
	DataDir    string   `json:"data_dir"`
	DNSListen  []string `json:"dns_listen"` // bare addresses; DNSPort is added when rendering
	DNSPort    int      `json:"dns_port"`
	Upstreams  []string `json:"upstreams"`
	PortalHost string   `json:"portal_host"`
	PortalPort int      `json:"portal_port"`
	// RouterConnected names the router connected in the optional step
	// ("unifi"), or is empty. Nothing about it goes into the file -- the
	// credentials live in the data directory's secrets.json -- so it is
	// only here to be mentioned in the written comments.
	RouterConnected string `json:"router_connected,omitempty"`
}

// validate is what the page cannot be trusted to have got right. The
// messages are written for whoever is looking at the page, since that is
// where they are shown.
func (a Answers) validate() error {
	if strings.TrimSpace(a.DataDir) == "" {
		return errors.New("choose a data directory")
	}
	if len(a.DNSListen) == 0 {
		return errors.New("choose at least one address to answer DNS on")
	}
	for _, ip := range a.DNSListen {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("%q is not an address this host can listen on", ip)
		}
	}
	if a.DNSPort < 1 || a.DNSPort > 65535 {
		return errors.New("the DNS port must be between 1 and 65535")
	}
	if len(a.Upstreams) == 0 {
		return errors.New("choose at least one upstream resolver")
	}
	if net.ParseIP(a.PortalHost) == nil {
		return fmt.Errorf("%q is not an address this host can serve the portal on", a.PortalHost)
	}
	if a.PortalPort < 1 || a.PortalPort > 65535 {
		return errors.New("the portal port must be between 1 and 65535")
	}
	return nil
}

// Preset is one offered upstream choice. Note says what the resolver does
// and does not do rather than selling it, because this choice decides who
// sees every name the network looks up.
type Preset struct {
	Name  string   `json:"name"`
	Note  string   `json:"note"`
	Addrs []string `json:"addrs"`
}

// Presets are the offered upstreams. Quad9's unfiltered pair is first
// because it is what config.Default() already uses: Shepherd's own lists are
// then the only filter, which keeps one answer in one place. The rest are
// here because they are the resolvers people actually name.
var Presets = []Preset{
	{"Quad9", "no blocking of its own, so Shepherd's lists are the only filter", []string{"9.9.9.10", "149.112.112.10"}},
	{"Quad9 with malware blocking", "a second filter, run by someone else", []string{"9.9.9.9", "149.112.112.112"}},
	{"Cloudflare", "fast and widely reachable", []string{"1.1.1.1", "1.0.0.1"}},
	{"Google", "fast and widely reachable", []string{"8.8.8.8", "8.8.4.4"}},
	{"Quad9 over TLS", "encrypted to the resolver (docs/UPSTREAMS.md)", []string{"tls://dns.quad9.net"}},
	{"Cloudflare over TLS", "encrypted to the resolver", []string{"tls://cloudflare-dns.com"}},
}

// listenAddrs is dns.listen: each chosen address with the chosen port.
func (a Answers) listenAddrs() []string {
	out := make([]string, 0, len(a.DNSListen))
	for _, ip := range a.DNSListen {
		out = append(out, net.JoinHostPort(ip, strconv.Itoa(a.DNSPort)))
	}
	return out
}

func (a Answers) firstListen() string {
	if len(a.DNSListen) == 0 {
		return "127.0.0.1"
	}
	return a.DNSListen[0]
}

// digHint is the arguments for the dig the wizard tells the owner to run. A
// non-standard port has to be named explicitly or dig quietly asks 53, which
// is the resolver Shepherd was put beside rather than Shepherd.
func (a Answers) digHint() string {
	if a.DNSPort == 53 || a.DNSPort == 0 {
		return "@" + a.firstListen()
	}
	return fmt.Sprintf("@%s -p %d", a.firstListen(), a.DNSPort)
}

// Render turns the answers into shepherd.toml. It writes comments, not a
// dump of values: the file is the thing the owner edits for years afterwards,
// and a bare list of addresses tells them nothing about why those addresses
// and not others. Every key here was explicitly asked about; everything else
// is left out on purpose so it keeps following Shepherd's own default.
func Render(a Answers) string {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	p("# Shepherd's configuration, written by \"shepherd setup\".")
	p("#")
	p("# Only what setup asked about is here. Every other setting keeps its")
	p("# default, which is what you want: a default that improves in a later")
	p("# version then improves for you too. shepherd.example.toml documents")
	p("# the full set, with the same comments, if you want to take one over.")
	p("#")
	p("# Protection is on out of the box: the recommended blocklists are")
	p("# enabled on first run and Apple Private Relay is blocked. Both are")
	p("# changed in the portal, not here (docs/POLICY.md).")
	p("#")
	p("# Re-running \"shepherd setup\" replaces this file and keeps a .bak.")
	p("")
	p("# Where Shepherd keeps its state: the portal token, your rules, the")
	p("# device registry, the cached blocklists and the secrets the portal")
	p("# manages. This is the directory to back up.")
	p("data_dir = %q", a.DataDir)
	p("")
	p("[dns]")
	p("# Every address that answers DNS, each served over UDP and TCP.")
	p("# All of this host's addresses were offered because a device asks one")
	p("# specific address: if your router hands out the wired address and")
	p("# Shepherd listens only on the Wi-Fi one, that device has no DNS at")
	p("# all and nothing here looks wrong. Add an address (a new interface, a")
	p("# Tailscale address) by putting it in this list.")
	p("#")
	p("# Shepherd also adds 127.0.0.1 and [::1] on this port by itself, so")
	p("# this host can always resolve even if an interface goes down; set")
	p("# listen_loopback = false to stop it.")
	p("listen = [%s]", quoteList(a.listenAddrs()))
	p("")
	p("# The resolvers Shepherd asks for whatever it does not block. Each one")
	p("# was tested from this host during setup. They see every name this")
	p("# network looks up; docs/UPSTREAMS.md covers DoT and DoH forms and how")
	p("# to change the list from the portal (after which upstreams.json in")
	p("# the data directory wins over this).")
	p("upstreams = [%s]", quoteList(a.Upstreams))
	p("")
	p("[portal]")
	p("# Shepherd's own interface. It shows demo data until you sign in with")
	p("# the token in <data_dir>/portal-token (or \"shepherd -print-token\"),")
	p("# and relocks when left idle.")
	if a.PortalHost == "127.0.0.1" {
		p("#")
		p("# This is loopback: the portal is reachable from this host only.")
		p("# From a laptop, forward it over SSH:")
		p("#   ssh -L %d:127.0.0.1:%d <this host>", a.PortalPort, a.PortalPort)
		p("# then open http://127.0.0.1:%d there.", a.PortalPort)
	} else {
		p("#")
		p("# This is a LAN address, so the sign-in page is reachable from")
		p("# anywhere on the network. The token still gates everything behind")
		p("# it; docs/TLS.md adds HTTPS and docs/PASSKEYS.md a passkey.")
	}
	p("listen = %q", joinHostPort(a.PortalHost, a.PortalPort))
	if a.RouterConnected != "" {
		p("")
		p("# A %s router was connected during setup for per-device bandwidth.", a.RouterConnected)
		p("# Nothing about it is configured here: the credentials are in")
		p("# <data_dir>/secrets.json (0600) and the connection is managed on")
		p("# the portal's Bandwidth screen (docs/TRAFFIC.md).")
	}
	return b.String()
}

func quoteList(items []string) string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		out = append(out, strconv.Quote(s))
	}
	return strings.Join(out, ", ")
}
