// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads Shepherd's single TOML configuration file.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"shepherd/internal/dnsengine"
	"shepherd/internal/ntfy"
	"shepherd/internal/reverseproxy"
	"shepherd/internal/vulnscan"
)

type Config struct {
	DataDir string `toml:"data_dir"`
	// NoDefaultLists opts out of the blocklists Shepherd enables on a fresh
	// install (the catalog's recommended items). Lists you define yourself are
	// always kept. It only matters the first time Shepherd runs in a data
	// directory: after that policy.json, edited in the portal, is the truth.
	NoDefaultLists bool           `toml:"no_default_lists"`
	DNS            DNS            `toml:"dns"`
	Lists          []List         `toml:"lists"`
	Portal         Portal         `toml:"portal"`
	Privacy        Privacy        `toml:"privacy"`
	History        History        `toml:"history"`
	Map            Map            `toml:"map"`
	Devices        Devices        `toml:"devices"`
	Classify       Classify       `toml:"classify"`
	ARP            ARP            `toml:"arp"`
	Alarms         Alarms         `toml:"alarms"`
	Accountability Accountability `toml:"accountability"`
	Portscan       Portscan       `toml:"portscan"`
	Vulnscan       Vulnscan       `toml:"vulnscan"`
	Threats        Threats        `toml:"threats"`
	Update         Update         `toml:"update"`
	Retention      Retention      `toml:"retention"`
	TLS            TLS            `toml:"tls"`
	Nethealth      Nethealth      `toml:"nethealth"`
	Selftest       Selftest       `toml:"selftest"`
	ReverseProxy   ReverseProxy   `toml:"reverseproxy"`
	Watch          Watch          `toml:"watch"`
}

// Watch controls Watch mode (docs/WATCH.md), which is opt-in and off by
// default: outbound-only by construction, with downloads estimated from TCP
// acknowledgements (docs/TRAFFIC.md), and bandwidth in both directions
// still needs Gateway mode (docs/GATEWAY.md).
//
// Watch mode: one-sided ARP steering of each
// eligible device's outbound IPv4 traffic through Shepherd, relayed to the
// real gateway in the kernel (XDP) or by a parallel userspace relay
// (internal/intercept). Enabled defaults true, per the protect-by-default
// decision in docs/DESIGN.md: every device is steered once it has been seen
// with a MAC and an IPv4 address, except the gateway, Shepherd's own
// interfaces, devices marked Excluded, network infrastructure (routers, mesh
// nodes, access points, hubs and bridges, Thread border routers, anything
// advertising Thread or Matter services) and any device whose own Watch
// switch is off. It needs Linux with CAP_NET_RAW plus CAP_NET_ADMIN and
// CAP_BPF; anywhere else, or without them, it logs why, reports itself
// unavailable in the portal and Shepherd starts normally. Watch mode is
// IPv4-only by the hard rule in docs/IPV6.md.
type Watch struct {
	Enabled bool `toml:"enabled"`
	// Interface names the NIC to steer on. Empty picks the interface the
	// default route leaves through, the same convention [arp] uses.
	Interface string `toml:"interface"`
	// Mode selects the relay: "auto" (XDP in the NIC driver, else XDP in
	// the kernel's generic path, else the userspace ParallelRelay), "xdp"
	// (XDP only; unavailable when it cannot load), "userspace" (never XDP)
	// or "off" (same as enabled = false).
	Mode string `toml:"mode"`
	// Workers is how many parallel capture-and-relay workers the userspace
	// relay runs; 0 means intercept.DefaultParallelism. Ignored under XDP.
	Workers int `toml:"workers"`
	// IPv6 additionally steers each eligible device's IPv6 traffic, by
	// unicast Neighbor Advertisements (docs/IPV6-WATCH.md). Off by
	// default, deliberately: it only earns its risk on a network with a
	// global IPv6 route, and even then it never touches a smart-home hub,
	// a Thread border router or a Matter device, whatever that device's
	// own Watch switch says. On a network without a global IPv6 route —
	// unique-local addresses only, which is the common case — it reports
	// itself idle and steers nothing rather than pretending. Shepherd
	// never sends Router Advertisements under any setting
	// (docs/IPV6.md hard rule 1).
	IPv6 bool `toml:"ipv6"`
	// SteerInfrastructure steers router/infrastructure and smart-home hub
	// devices too. Off by default: a mesh node or a Thread border router
	// is exactly the kind of device whose traffic must not be touched.
	SteerInfrastructure bool `toml:"steer_infrastructure"`
	// ActiveWindowSeconds is how recently a device must have been seen to be
	// steered at all; a device quiet longer than this is left alone until
	// it shows up again. Default 900 (15 minutes).
	ActiveWindowSeconds int `toml:"active_window_seconds"`
	// Health knobs passed straight through to intercept.ControllerConfig
	// (docs/INTERCEPT.md explains each); 0 keeps that package's default.
	HealthIntervalSeconds int `toml:"health_interval_seconds"`
	IdleGraceSeconds      int `toml:"idle_grace_seconds"`
	StartupGraceSeconds   int `toml:"startup_grace_seconds"`
	// AllowRoutingHost lets Watch mode run on a host that forwards IPv4
	// and has a second interface on the relay's own segment. On by
	// default since 2026-11-01: that shape was measured not to be the
	// loop's mechanism (a single-homed phone echoed too), the duplicate
	// brake in both relays drops any copy the segment hands back, and the
	// loop brake stays armed. Set false to refuse instead (docs/WATCH.md).
	AllowRoutingHost bool `toml:"allow_routing_host"`
	// Diagnostics logs a digest of what the in-kernel relay is carrying
	// (addresses, ports, TTL and IP ID of sampled frames, never payload)
	// every few seconds while traffic moves. Off by default.
	Diagnostics bool `toml:"diagnostics"`
}

// ARP controls the passive ARP monitor (docs/ARP.md): a read-only listener
// that learns real MAC addresses for the device registry and raises events
// about the ARP layer itself (a new MAC, an IP moving to a different MAC, a
// changed gateway MAC). It needs CAP_NET_RAW and is Linux-only; elsewhere, or
// without the capability, it logs a warning and Shepherd starts normally.
type ARP struct {
	Enabled bool `toml:"enabled"`
	// Interface names the NIC to listen on. Empty auto-detects it from the
	// default route, the same convention arp.Open("") already uses.
	Interface string `toml:"interface"`
}

// ListsAreDefault reports whether [[lists]] is exactly the built-in default,
// that is, the user defined no lists of their own.
func (c Config) ListsAreDefault() bool { return slices.Equal(c.Lists, Default().Lists) }

// Devices controls how Shepherd learns who is on the network. Every source is
// passive: nothing here transmits on the network except the optional reverse
// DNS lookups, which go to one server you control (your router).
type Devices struct {
	Enabled bool `toml:"enabled"` // false turns the whole registry off
	// DNS learns a device from the address its queries come from.
	DNS bool `toml:"dns"`
	// Neighbors reads the operating system's neighbor (ARP/NDP) table.
	Neighbors               bool `toml:"neighbors"`
	NeighborIntervalSeconds int  `toml:"neighbor_interval_seconds"`
	// MDNS listens passively for multicast DNS announcements.
	MDNS bool `toml:"mdns"`
	// ReverseDNS asks one resolver for the PTR name of each newly seen address.
	ReverseDNS bool `toml:"reverse_dns"`
	// ReverseDNSServer is that resolver, "ip" or "ip:port". Empty uses the
	// default gateway found in /proc/net/route (Linux only).
	ReverseDNSServer    string `toml:"reverse_dns_server"`
	SaveIntervalSeconds int    `toml:"save_interval_seconds"`
	// QuarantineNewDevices puts every newly discovered device into the
	// reserved Quarantine group until you move it somewhere else, so it never
	// silently gets the run of the network before you have looked at it.
	// Quarantine's own rules apply like any group's (see docs/DEVICES.md);
	// Shepherd cannot stop a quarantined device from reaching other devices
	// on the LAN directly (that needs your router's guest network or VLANs).
	QuarantineNewDevices bool `toml:"quarantine_new_devices"`
}

// Classify automatically guesses a device's type (phone, camera, TV, ...) from
// its DNS lookups, MAC vendor and, when the map's ASN database is available,
// the networks it talks to. A type you set yourself is never overwritten.
type Classify struct {
	Enabled         bool `toml:"enabled"`
	IntervalSeconds int  `toml:"interval_seconds"` // how often guesses are reconsidered
}

// Alarms controls Shepherd's alarm engine (docs/ALARMS.md): the engine itself
// (dedupe, mute rules, quiet hours, learning mode) always records alarms when
// enabled, and delivers them over Web Push (Push, on by default; a browser
// can only subscribe from the HTTPS portal) and ntfy (Ntfy, off until a
// server is named).
type Alarms struct {
	Enabled bool       `toml:"enabled"`
	Push    AlarmsPush `toml:"push"`
	Ntfy    AlarmsNtfy `toml:"ntfy"`
}

// AlarmsPush configures Web Push delivery (internal/webpush, docs/ALARMS.md).
// The VAPID key pair is generated once under <data_dir>/alarms and kept:
// browsers subscribe against its public half. Nothing here needs filling in.
type AlarmsPush struct {
	Enabled bool `toml:"enabled"`
	// Contact is the RFC 8292 contact a push service may use to reach the
	// operator: an email address or an https URL. Empty uses the portal's
	// own HTTPS address when [tls] is on, else Shepherd's project page.
	Contact string `toml:"contact"`
}

// AlarmsNtfy configures the ntfy delivery channel: a self-hosted or public
// ntfy server Shepherd publishes alarm notifications to. Off by default
// because it needs a server address only you can provide.
type AlarmsNtfy struct {
	Enabled bool `toml:"enabled"`
	// Server is the ntfy base URL, e.g. "https://ntfy.example.com".
	Server string `toml:"server"`
	// Topic is the ntfy topic to publish to.
	Topic string `toml:"topic"`
	// Token authenticates with a bearer token; it wins over Username and Password.
	Token string `toml:"token"`
	// Username and Password authenticate with basic auth when Token is empty.
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// Accountability controls accountability-partner email alerts
// (docs/ACCOUNTABILITY.md): emailing a trusted contact when a device accesses
// something they chose to watch. Enabled by default is safe: the library
// itself starts with no contacts and no subscriptions, and this section's
// SMTP.Host is empty by default too, so a fresh install sends no mail until
// both a subscription is added in the portal and an SMTP relay is set up
// (in the portal's Accountability tab; SMTP here is only a read-once seed
// for it).
type Accountability struct {
	Enabled bool               `toml:"enabled"`
	SMTP    AccountabilitySMTP `toml:"smtp"`
}

// AccountabilitySMTP is a read-once seed for the outgoing mail relay
// accountability alerts send through, which the portal manages
// (internal/secrets; docs/ACCOUNTABILITY.md): the first time Shepherd runs
// without a portal-managed relay, a relay set here (Host non-empty) is
// imported, password included, and from then on this section is ignored.
// The relay is one you already have (a Gmail or iCloud app password, a
// self-hosted Postfix), matching this project's free, keyless,
// bring-your-own-credentials convention. Password is the plaintext secret
// kept directly in shepherd.toml (protected only by that file's own 0600
// permissions, the same honest limit docs/DEVICES.md and docs/HISTORY.md
// already note for other secrets); PasswordFile instead points at a separate
// 0600 file holding just the password, so the secret need not live inside
// the configuration file people might paste into an issue or back up more
// widely. Setting both is a configuration error (Validate rejects it), so
// there is never an ambiguous "which one wins". See docs/ACCOUNTABILITY.md's
// "SMTP secret handling" section for the tradeoff this leaves.
type AccountabilitySMTP struct {
	Host         string `toml:"host"`
	Port         int    `toml:"port"`
	Username     string `toml:"username"`
	Password     string `toml:"password"`
	PasswordFile string `toml:"password_file"`
	From         string `toml:"from"`
	// TLS is "starttls" (default, port 587 convention), "tls" (implicit TLS,
	// port 465 convention) or "none" (only sane against a local, trusted relay).
	TLS string `toml:"tls"`
}

// Portscan schedules gentle TCP connect scans of every known device's common
// ports, to flag exposure the owner might not expect (an open Telnet port, an
// exposed SMB share...). Enabled defaults true: unlike most of Shepherd's
// passive, listen-only sources, this one actively opens connections to every
// known device, but it is engineered to be gentle enough (plain connect
// scans, a short port list, bounded concurrency) that withholding it by
// default would just mean most owners never learn about exposure they did
// not know they had, which defeats the point of the feature. See
// docs/PORTSCAN.md, including what it does not do (router port-forwarding
// discovery).
type Portscan struct {
	Enabled bool `toml:"enabled"`
	// IntervalSeconds is how often every known device is rescanned. Hours,
	// not seconds: scanning is cheap and gentle, but there is no reason to
	// repeat it constantly.
	IntervalSeconds int `toml:"interval_seconds"`
	// WANExposure deepens each open port with a best-effort read of
	// whether the router also forwards it from the internet, via the
	// router's own UPnP IGD port-mapping table (internal/upnpigd). See
	// docs/PORTSCAN.md's "WAN exposure" section for what this can and
	// cannot detect.
	WANExposure WANExposure `toml:"wan_exposure"`
}

// WANExposure controls internal/portscan's optional WAN-exposure check:
// for every port a scan finds open on the LAN, a best-effort read of
// whether the router's own UPnP IGD port-mapping table also forwards it
// from the internet. Enabled defaults true, for the same reasoning as
// Portscan.Enabled itself (docs/PORTSCAN.md's "Should this be on by
// default?" sections for both): the whole value of this feature is an
// owner learning about exposure they did not expect, and WAN-forwarded is
// strictly the more dangerous half of that picture. The extra LAN traffic
// this adds — one SSDP multicast discovery and, at most, a handful of SOAP
// calls per RefreshIntervalSeconds, never per scan — is no more active on
// the network than an owner's own UPnP-enabled game console or torrent
// client already is. It needs Portscan.Enabled: with no open-port data to
// deepen, there is nothing for it to check.
type WANExposure struct {
	Enabled bool `toml:"enabled"`
	// RefreshIntervalSeconds bounds how often the router's NAT table is
	// actually re-queried. A UPnP discovery-and-enumerate round trip is
	// much slower and more fragile than internal/portscan's own TCP
	// connect probes, so results are served from a cache in between,
	// however many ports or devices a scan cycle checks.
	RefreshIntervalSeconds int `toml:"refresh_interval_seconds"`
}

// Vulnscan schedules internal/vulnscan's deeper probe of every open port
// internal/portscan already found: a banner or minimal protocol exchange,
// matched against the built-in vulnerability signature table plus the
// signature feed Shepherd publishes from the NVD and CISA's Known
// Exploited Vulnerabilities catalog (docs/VULNSCAN.md). Enabled defaults true, for
// the same reason Portscan does (the whole value of the feature is the
// owner learning about exposure they did not expect), weighed again for
// this feature's own, slightly deeper probing in docs/VULNSCAN.md's "Should
// this be on by default?" section. It needs Portscan enabled: with no
// open-port data to deepen, cmd/shepherd logs a warning and does not start
// it (see cmd/shepherd/vulnscan.go).
type Vulnscan struct {
	Enabled bool `toml:"enabled"`
	// IntervalSeconds is how often every device with open ports is
	// reprobed. Daily by default: this is a deeper, slower probe than
	// Portscan's own connect scan.
	IntervalSeconds int `toml:"interval_seconds"`
	// FeedURL is where the signature feed is fetched from
	// (vulnscan.DefaultFeedURL by default; a "file://" URL pins a local
	// copy). Empty disables the feed entirely: only the built-in table is
	// used and Shepherd makes no request for it.
	FeedURL string `toml:"feed_url"`
	// FeedRefreshSeconds is how often the feed is re-fetched (6 hours by
	// default, minimum 300). The published feed itself is rebuilt daily, and
	// an unchanged one costs one conditional request.
	FeedRefreshSeconds int `toml:"feed_refresh_seconds"`
}

// Update controls the self-update checker (internal/update, docs/UPDATE.md):
// one request a day to GitHub's releases for a newer Shepherd, an alarm
// when there is one, and an "update now" on the Overview screen that
// downloads, verifies and swaps the binary in, keeping the previous one.
type Update struct {
	Enabled bool `toml:"enabled"`
	// Channel is "stable" (releases marked latest) or "beta" (the rolling
	// beta too).
	Channel string `toml:"channel"`
	// CheckHours is how often to look. Nothing is downloaded by a check.
	CheckHours int `toml:"check_hours"`
}

// Threats controls the threat-intelligence feeds (internal/threats,
// docs/THREATS.md): curated lists of malware hosts, botnet controllers and
// hijacked networks, matched against every DNS query's name and answer and
// raised as alarms. On by default: the feeds are a few hundred kilobytes
// refreshed every few hours, the same kind of download the blocklists
// already make, and a match costs a few map lookups.
type Threats struct {
	Enabled bool `toml:"enabled"`
	// IntervalHours is how often the feeds are re-downloaded.
	IntervalHours int `toml:"interval_hours"`
}

// TLS obtains and renews a real certificate for the portal's own hostname
// via the ACME protocol's DNS-01 challenge against Cloudflare DNS
// (docs/TLS.md) — the first, additive step of roadmap item 18 ("Access").
// It changes nothing about the existing plain-HTTP portal listener on
// portal.listen: enabling this only adds a second, HTTPS listener
// alongside it, on its own hostname and address. Off by default, and safe
// to leave off: both a scoped Cloudflare API token and a real DNS hostname
// that resolves to this machine are needed before it does anything, and
// withholding either just leaves the portal exactly as it is today.
type TLS struct {
	Enabled bool `toml:"enabled"`
	// Hostname is the certificate's subject, e.g. "shepherd.example.com".
	// It must already resolve (its DNS A/AAAA record can point anywhere
	// reachable, even a tailnet-only address, since DNS-01 only ever
	// touches a TXT record, never connects to the host itself) before
	// Let's Encrypt will issue for it.
	Hostname string `toml:"hostname"`
	// Listen is the address the HTTPS listener binds, separate from
	// portal.listen (which stays loopback-only by convention): e.g.
	// "0.0.0.0:8443", so it is reachable from wherever Hostname's DNS
	// record actually resolves to.
	Listen string `toml:"listen"`
	// Email is an optional contact Let's Encrypt can use for certificate
	// expiry notices. Never required.
	Email string `toml:"email"`
	// CloudflareAPIToken and CloudflareAPITokenFile are read-once seeds
	// for the DNS provider token the portal manages (internal/secrets,
	// shared with [reverseproxy]): the first time Shepherd runs without a
	// portal-managed token, whatever is set here is imported, and from
	// then on the portal's value is the one used and these are ignored
	// (cmd/shepherd/secrets.go, docs/TLS.md). Neither is required any
	// more; setting both is still a configuration error (Validate rejects
	// it), so an import is never an ambiguous "which one wins".
	CloudflareAPIToken     string `toml:"cloudflare_api_token"`
	CloudflareAPITokenFile string `toml:"cloudflare_api_token_file"`
}

// ReverseProxy terminates HTTPS for other self-hosted services and forwards
// each request by its Host header to the backend the portal configured for
// it (docs/REVERSEPROXY.md), with one wildcard certificate for "*.Domain"
// obtained the same way [tls] obtains the portal's own. Off by default: it
// opens a new listener and, once DNS points at it, carries real traffic for
// every proxied service, so it waits for the owner to ask. The hosts
// themselves are not configured here; they live in the portal.
type ReverseProxy struct {
	Enabled bool `toml:"enabled"`
	// Listen is where the HTTPS listener binds. ":8443" by default, never
	// 443: taking over the standard port from an existing reverse proxy is
	// a cutover the owner makes deliberately (docs/REVERSEPROXY.md).
	Listen string `toml:"listen"`
	// RedirectListen is where a plain-HTTP listener answers every request
	// with a 302 to the same host and path over https, so a bookmark or
	// hardcoded "http://" link to a proxied host still gets there instead
	// of just failing to connect once nothing else is listening on 80.
	// Empty (off) by default, the same reason Listen itself defaults to
	// ":8443" and never ":80"/":443": binding a port below 1024 needs a
	// capability (CAP_NET_BIND_SERVICE, or root) a default install does
	// not have, so a plain `go test` or an uncapable process must never
	// try it just because [reverseproxy] is enabled. Set it to ":80"
	// once the deployment already has that capability (the same
	// container that lets Listen bind ":443" already grants it).
	RedirectListen string `toml:"redirect_listen"`
	// Domain is the zone the wildcard certificate covers: "example.com"
	// (or "*.example.com", the same thing) gets "*.example.com", valid for
	// jellyfin.example.com but not for example.com itself or a.b.example.com.
	Domain string `toml:"domain"`
	// Email is an optional Let's Encrypt expiry-notice contact.
	Email string `toml:"email"`
	// CloudflareAPIToken and CloudflareAPITokenFile are read-once seeds
	// for the same shared, portal-managed DNS provider token [tls]'s seed
	// fields feed (never both set). When both sections hold different
	// tokens at import time, [tls]'s wins and the conflict is logged.
	CloudflareAPIToken     string `toml:"cloudflare_api_token"`
	CloudflareAPITokenFile string `toml:"cloudflare_api_token_file"`
}

// BaseDomain is Domain normalized: lowercase, without a "*." prefix or a
// trailing dot. Empty when Domain is unset.
func (r ReverseProxy) BaseDomain() string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Domain)), ".")
	return strings.TrimPrefix(d, "*.")
}

// Wildcard is the name the certificate is issued for, "*.<BaseDomain>", or
// empty when no domain is configured.
func (r ReverseProxy) Wildcard() string {
	if b := r.BaseDomain(); b != "" {
		return "*." + b
	}
	return ""
}

// Nethealth schedules internal/nethealth's periodic latency, jitter,
// packet-loss and reachability probes against the configured DNS
// upstreams plus a couple of well-known public resolvers, and its
// separate, much less frequent bufferbloat check (docs/NETHEALTH.md).
// Unlike Portscan and Vulnscan, both Enabled and BufferbloatEnabled
// default to false: Portscan/Vulnscan only ever contact devices this
// Shepherd has already discovered on its own LAN, so building a Config
// with Default() (as this project's own tests do throughout, to build a
// real server end to end) never reaches outside the test's own loopback
// fixtures. Nethealth's targets, by contrast, are inherently fixed public
// internet addresses (9.9.9.10, 1.1.1.1, 8.8.8.8) — there is no "this
// Shepherd's own devices" equivalent to scope them to. Defaulting this on
// would make every one of this project's many Default()-based tests
// silently dependent on real internet connectivity it never opted into,
// which is exactly the kind of hermetic-testing violation this project
// otherwise goes out of its way to avoid (see docs/NETHEALTH.md's "Should
// this be on by default?" section for the full reasoning, including why
// this is a genuinely different situation from Portscan/Vulnscan's own
// default-on choice, not an inconsistency).
type Nethealth struct {
	Enabled bool `toml:"enabled"`
	// IntervalSeconds is how often the latency/jitter/loss/reachability
	// probe runs. Minutes, not hours: each cycle is cheap, and the whole
	// point of this feature is a trend line dense enough to be useful.
	IntervalSeconds int `toml:"interval_seconds"`
	// BufferbloatEnabled turns on the separate, far less frequent
	// bufferbloat check, which actually generates load. Off by default.
	BufferbloatEnabled bool `toml:"bufferbloat_enabled"`
	// BufferbloatIntervalSeconds is how often the bufferbloat check runs,
	// when enabled.
	BufferbloatIntervalSeconds int `toml:"bufferbloat_interval_seconds"`
}

// Selftest is the built-in DNS self-test (internal/selftest, docs/DNS-QA.md):
// every interval it asks canary names of every address Shepherd listens on,
// over UDP and TCP, checks upstream error rates and latency, and warns about
// LAN addresses with no listener. On by default: it only ever talks to
// Shepherd's own listeners.
type Selftest struct {
	Enabled bool `toml:"enabled"`
	// IntervalSeconds is how often a round runs (minimum 10).
	IntervalSeconds int `toml:"interval_seconds"`
	// GoodName must resolve; BlockedName must be blocked. An empty
	// BlockedName uses a synthetic name the engine always blocks.
	GoodName    string `toml:"good_name"`
	BlockedName string `toml:"blocked_name"`
	// NotServed lists this host's LAN addresses that deliberately have no
	// DNS listener, so they are not warned about.
	NotServed []string `toml:"not_served"`
	// MaxErrorPercent flags an upstream whose error rate over WindowMinutes
	// is above it.
	MaxErrorPercent float64 `toml:"max_error_percent"`
	WindowMinutes   int     `toml:"window_minutes"`
	// AlarmCooldownMinutes is the least time between two alarms for the
	// same finding.
	AlarmCooldownMinutes int `toml:"alarm_cooldown_minutes"`
}

// History controls what is remembered after the fact. "memory" (the default)
// keeps recent queries in RAM only and writes nothing to disk. "encrypted"
// keeps a searchable, AES-256-GCM encrypted record on disk.
type History struct {
	Mode          string `toml:"mode"`           // "memory" or "encrypted"
	RetentionDays int    `toml:"retention_days"` // 0 keeps everything
	MaxMB         int    `toml:"max_mb"`         // 0 means no size cap
	KeySource     string `toml:"key_source"`     // "file" or "passphrase"
	KeyFile       string `toml:"key_file"`       // default <data_dir>/history/history.key
}

// Retention is the one budget for everything Shepherd keeps on disk
// (docs/UPDATE.md "Retention"). MaxMB 0, the default, leaves each store to
// its own cap (history.max_mb; 8 MiB each for bandwidth and network health
// history). A value caps the data directory as a whole: bandwidth and
// network health history each get up to 8 MiB, a share is reserved for the
// small files (devices, alarms, the threat-feed cache), and query history
// gets the rest, never more than history.max_mb when that is set too. The
// Overview's Software card shows how much of the budget is in use and a
// low-severity alarm says when the directory has grown past it anyway.
type Retention struct {
	MaxMB int `toml:"max_mb"`
}

// Map controls the globe's location data, a free GeoIP database downloaded
// once a month and used entirely on this machine.
type Map struct {
	Enabled bool `toml:"enabled"`
	// AutoHome places "home" on the globe from the network's public address (a
	// DNS "who am I" query to public resolvers). Choosing your own home in the
	// portal always wins, and then nothing is looked up.
	AutoHome bool `toml:"auto_home"`
	// DatabaseURL overrides where the GeoIP database is downloaded from, for a
	// local mirror or an offline install. Empty uses the default.
	DatabaseURL string `toml:"database_url"`
}

// Privacy holds initial policy switches. Protections are on by default; after
// first run the portal owns them, and each one can be switched off.
type Privacy struct {
	BlockPrivateRelay bool `toml:"block_private_relay"`
}

type DNS struct {
	// Listen holds host:port addresses; each is served over UDP and TCP.
	Listen []string `toml:"listen"`
	// Upstreams are resolvers: "9.9.9.10", "tcp://1.1.1.1", "tls://dns.quad9.net:853".
	Upstreams []string `toml:"upstreams"`
	// Bootstrap are plain resolvers (IP addresses) used only to look up the
	// hostnames of tls:// and https:// upstreams.
	Bootstrap []string `toml:"bootstrap"`
	// ListenLoopback also serves on 127.0.0.1 and [::1], on the same port
	// as the first address in Listen. On by default, and worth leaving on:
	// when Shepherd is the resolver its own host uses, a loopback listener
	// is the one address that cannot disappear with an interface. Without
	// it, a host pointed at Shepherd's LAN address loses name resolution
	// the moment that interface goes down — which on a real install took
	// sshd with it (it blocks on reverse lookups), so the machine could
	// not be reached to fix the interface. Pair it with 127.0.0.1 first in
	// the host's own resolver; a loopback listener nothing asks is no help.
	// A loopback address already in Listen is not added twice, and one that
	// cannot be bound (a system resolver often holds 127.0.0.1:53) is a
	// logged warning, not a startup failure.
	ListenLoopback *bool `toml:"listen_loopback"`
	// BlockMode is "null" (answer 0.0.0.0 / ::) or "nxdomain".
	BlockMode string `toml:"block_mode"`
	// FilterAAAA is "auto" (default), "on" or "off". Filtering answers AAAA
	// queries with an empty answer and removes IPv6 hints from HTTPS
	// records, which is right on a network with no IPv6 route to the
	// internet (devices hold only private or link-local IPv6 addresses),
	// where an unreachable address is worse than none. "auto" probes
	// outbound IPv6 and filters only while it is unreachable.
	FilterAAAA           string   `toml:"filter_aaaa"`
	ProbeIntervalSeconds int      `toml:"probe_interval_seconds"`
	CacheSize            int      `toml:"cache_size"`
	LogSize              int      `toml:"log_size"`
	ProtectedDomains     []string `toml:"protected_domains"`
}

type List struct {
	Name string `toml:"name"`
	// URL is an http(s):// URL or a file:// path.
	URL string `toml:"url"`
}

type Portal struct {
	Listen string `toml:"listen"`
	// IdleLockMinutes is how long the portal may sit idle before it relocks
	// to demo data and requires the token or a PIN again. 0 disables idle
	// locking. The portal's own settings screen can override this at
	// runtime; that override, once saved, wins over this value.
	IdleLockMinutes int `toml:"idle_lock_minutes"`
}

// defaultList is the blocklist a fresh install protects with.
var defaultList = List{
	Name: "hagezi-pro",
	URL:  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
}

// Default returns a configuration that protects out of the box: a blocklist is
// active and Apple Private Relay is blocked. Everything can be opted out of.
// Network addresses stay on loopback so it is safe to start on any machine.
func Default() Config {
	return Config{
		Lists:          []List{defaultList},
		Privacy:        Privacy{BlockPrivateRelay: true},
		History:        History{Mode: "memory", RetentionDays: 30, MaxMB: 2048, KeySource: "file"},
		Map:            Map{Enabled: true, AutoHome: true},
		Devices:        Devices{Enabled: true, DNS: true, Neighbors: true, NeighborIntervalSeconds: 30, MDNS: true, ReverseDNS: true, SaveIntervalSeconds: 60, QuarantineNewDevices: true},
		Classify:       Classify{Enabled: true, IntervalSeconds: 300},
		ARP:            ARP{Enabled: true},
		Alarms:         Alarms{Enabled: true, Push: AlarmsPush{Enabled: true}, Ntfy: AlarmsNtfy{Topic: "shepherd-alarms"}},
		Accountability: Accountability{Enabled: true, SMTP: AccountabilitySMTP{Port: 587, TLS: "starttls"}},
		Portscan:       Portscan{Enabled: true, IntervalSeconds: 6 * 3600, WANExposure: WANExposure{Enabled: true, RefreshIntervalSeconds: 600}},
		Vulnscan:       Vulnscan{Enabled: true, IntervalSeconds: 24 * 3600, FeedURL: vulnscan.DefaultFeedURL, FeedRefreshSeconds: 6 * 3600},
		Threats:        Threats{Enabled: true, IntervalHours: 6},
		Update:         Update{Enabled: true, Channel: "stable", CheckHours: 24},
		Nethealth:      Nethealth{Enabled: false, IntervalSeconds: 120, BufferbloatEnabled: false, BufferbloatIntervalSeconds: 3600},
		Selftest:       Selftest{Enabled: true, IntervalSeconds: 60, GoodName: "example.com", MaxErrorPercent: 5, WindowMinutes: 15, AlarmCooldownMinutes: 30},
		ReverseProxy:   ReverseProxy{Listen: ":8443"},
		// Watch mode is opt-in. It was on, under the protect-by-default
		// decision in docs/DESIGN.md, until 2026-11-01; it is kept off by
		// default because it is outbound-only and a device's already-open
		// connections can bypass it (docs/WATCH.md), not because it loops:
		// the loops that retired it that morning were uploads misread.
		Watch:   Watch{Enabled: false, Mode: "auto", ActiveWindowSeconds: 900, AllowRoutingHost: true},
		DataDir: "data",
		DNS: DNS{
			Listen:               []string{"127.0.0.1:5353"},
			Upstreams:            []string{"9.9.9.10", "149.112.112.10", "1.1.1.1"},
			Bootstrap:            dnsengine.DefaultBootstrapServers(),
			BlockMode:            "null",
			FilterAAAA:           "auto",
			ProbeIntervalSeconds: 15,
			CacheSize:            20000,
			LogSize:              20000,
		},
		Portal: Portal{Listen: "127.0.0.1:8787", IdleLockMinutes: 10},
	}
}

var listName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Load reads path over the defaults. A missing file yields the defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	// Decoding into the default's existing element would merge a partial user
	// list with it (a name without a url would inherit the default's url).
	cfg.Lists = nil
	if _, err := toml.DecodeFile(path, &cfg); err != nil && !errors.Is(err, os.ErrNotExist) {
		return cfg, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(cfg.Lists) == 0 && !cfg.NoDefaultLists {
		cfg.Lists = Default().Lists
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if c.DataDir == "" {
		return errors.New("data_dir must not be empty")
	}
	if len(c.DNS.Listen) == 0 {
		return errors.New("dns.listen needs at least one address")
	}
	if len(c.DNS.Upstreams) == 0 {
		return errors.New("dns.upstreams needs at least one resolver")
	}
	if len(c.DNS.Bootstrap) == 0 {
		return errors.New("dns.bootstrap needs at least one resolver (IP address)")
	}
	switch c.DNS.FilterAAAA {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("dns.filter_aaaa must be \"auto\", \"on\" or \"off\", got %q", c.DNS.FilterAAAA)
	}
	if c.DNS.BlockMode != "null" && c.DNS.BlockMode != "nxdomain" {
		return fmt.Errorf("dns.block_mode must be \"null\" or \"nxdomain\", got %q", c.DNS.BlockMode)
	}
	if c.DNS.ProbeIntervalSeconds < 1 {
		return errors.New("dns.probe_interval_seconds must be at least 1")
	}
	if c.History.Mode != "memory" && c.History.Mode != "encrypted" {
		return fmt.Errorf("history.mode must be \"memory\" or \"encrypted\", got %q", c.History.Mode)
	}
	if c.History.KeySource != "file" && c.History.KeySource != "passphrase" {
		return fmt.Errorf("history.key_source must be \"file\" or \"passphrase\", got %q", c.History.KeySource)
	}
	if c.History.RetentionDays < 0 || c.History.MaxMB < 0 {
		return errors.New("history.retention_days and history.max_mb must not be negative")
	}
	if c.Retention.MaxMB < 0 {
		return errors.New("retention.max_mb must not be negative")
	}
	if c.Devices.NeighborIntervalSeconds < 5 || c.Devices.SaveIntervalSeconds < 5 {
		return errors.New("devices.neighbor_interval_seconds and devices.save_interval_seconds must be at least 5")
	}
	if c.Classify.IntervalSeconds < 30 {
		return errors.New("classify.interval_seconds must be at least 30")
	}
	if c.Alarms.Enabled && c.Alarms.Ntfy.Enabled {
		if _, err := ntfy.BaseURL(c.Alarms.Ntfy.Server); err != nil {
			return fmt.Errorf("alarms.ntfy.server: %w", err)
		}
		if !ntfy.ValidTopic(c.Alarms.Ntfy.Topic) {
			return fmt.Errorf("alarms.ntfy.topic must be 1 to 64 letters, digits, - or _, got %q", c.Alarms.Ntfy.Topic)
		}
	}
	if smtp := c.Accountability.SMTP; smtp.Host != "" {
		if smtp.Port <= 0 || smtp.Port > 65535 {
			return fmt.Errorf("accountability.smtp.port %d is invalid", smtp.Port)
		}
		if smtp.From == "" {
			return errors.New("accountability.smtp.from is required once accountability.smtp.host is set")
		}
		switch smtp.TLS {
		case "starttls", "tls", "none":
		default:
			return fmt.Errorf(`accountability.smtp.tls must be "starttls", "tls" or "none", got %q`, smtp.TLS)
		}
		if smtp.Password != "" && smtp.PasswordFile != "" {
			return errors.New("accountability.smtp.password and accountability.smtp.password_file must not both be set")
		}
	}
	if c.Portscan.IntervalSeconds < 300 {
		return errors.New("portscan.interval_seconds must be at least 300")
	}
	if c.Portscan.WANExposure.Enabled && c.Portscan.WANExposure.RefreshIntervalSeconds < 300 {
		return errors.New("portscan.wan_exposure.refresh_interval_seconds must be at least 300")
	}
	if c.Portal.IdleLockMinutes < 0 {
		return errors.New("portal.idle_lock_minutes must not be negative")
	}
	if c.Update.Channel != "stable" && c.Update.Channel != "beta" {
		return fmt.Errorf("update.channel must be \"stable\" or \"beta\", got %q", c.Update.Channel)
	}
	if c.Update.CheckHours < 1 {
		return errors.New("update.check_hours must be at least 1")
	}
	if c.Threats.IntervalHours < 1 {
		return errors.New("threats.interval_hours must be at least 1")
	}
	if c.Vulnscan.IntervalSeconds < 300 {
		return errors.New("vulnscan.interval_seconds must be at least 300")
	}
	if c.Vulnscan.FeedURL != "" && c.Vulnscan.FeedRefreshSeconds < 300 {
		return errors.New("vulnscan.feed_refresh_seconds must be at least 300")
	}
	if c.TLS.Enabled {
		if c.TLS.Hostname == "" {
			return errors.New("tls.hostname is required when tls.enabled is true")
		}
		if c.TLS.Listen == "" {
			return errors.New("tls.listen is required when tls.enabled is true")
		}
		if c.TLS.CloudflareAPIToken != "" && c.TLS.CloudflareAPITokenFile != "" {
			return errors.New("tls.cloudflare_api_token and tls.cloudflare_api_token_file must not both be set")
		}
	}
	if err := c.validateReverseProxy(); err != nil {
		return err
	}
	if err := c.validateWatch(); err != nil {
		return err
	}
	if c.Nethealth.Enabled && c.Nethealth.IntervalSeconds < 60 {
		return errors.New("nethealth.interval_seconds must be at least 60")
	}
	if c.Nethealth.BufferbloatEnabled && c.Nethealth.BufferbloatIntervalSeconds < 600 {
		return errors.New("nethealth.bufferbloat_interval_seconds must be at least 600")
	}
	if st := c.Selftest; st.Enabled {
		switch {
		case st.IntervalSeconds < 10:
			return errors.New("selftest.interval_seconds must be at least 10")
		case st.GoodName == "":
			return errors.New("selftest.good_name must not be empty")
		case st.MaxErrorPercent <= 0 || st.MaxErrorPercent > 100:
			return errors.New("selftest.max_error_percent must be between 0 and 100")
		case st.WindowMinutes < 1 || st.AlarmCooldownMinutes < 1:
			return errors.New("selftest.window_minutes and selftest.alarm_cooldown_minutes must be at least 1")
		}
		for _, a := range st.NotServed {
			if net.ParseIP(a) == nil {
				return fmt.Errorf("selftest.not_served: %q is not an IP address", a)
			}
		}
	}
	if s := c.Devices.ReverseDNSServer; s != "" {
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("devices.reverse_dns_server must be an IP address, got %q", s)
		}
	}
	seen := map[string]bool{}
	for _, l := range c.Lists {
		if !listName.MatchString(l.Name) {
			return fmt.Errorf("list name %q must be lowercase letters, digits, - or _", l.Name)
		}
		if seen[l.Name] {
			return fmt.Errorf("duplicate list name %q", l.Name)
		}
		seen[l.Name] = true
		if l.URL == "" {
			return fmt.Errorf("list %q has no url", l.Name)
		}
	}
	return nil
}

func (c Config) validateReverseProxy() error {
	rp := c.ReverseProxy
	if !rp.Enabled {
		return nil
	}
	if rp.Domain == "" {
		return errors.New("reverseproxy.domain is required when reverseproxy.enabled is true")
	}
	if _, err := reverseproxy.NormalizeDomain(rp.BaseDomain()); err != nil {
		return fmt.Errorf("reverseproxy.domain: %w", err)
	}
	if rp.Listen == "" {
		return errors.New("reverseproxy.listen is required when reverseproxy.enabled is true")
	}
	if rp.CloudflareAPIToken != "" && rp.CloudflareAPITokenFile != "" {
		return errors.New("reverseproxy.cloudflare_api_token and reverseproxy.cloudflare_api_token_file must not both be set")
	}
	if c.TLS.Enabled && c.TLS.Listen == rp.Listen {
		return fmt.Errorf("tls.listen and reverseproxy.listen are the same address (%s); each needs its own", rp.Listen)
	}
	if rp.RedirectListen != "" {
		if rp.RedirectListen == rp.Listen {
			return fmt.Errorf("reverseproxy.redirect_listen and reverseproxy.listen are the same address (%s); each needs its own", rp.Listen)
		}
		if c.TLS.Enabled && c.TLS.Listen == rp.RedirectListen {
			return fmt.Errorf("tls.listen and reverseproxy.redirect_listen are the same address (%s); each needs its own", rp.RedirectListen)
		}
	}
	return nil
}

func (c Config) validateWatch() error {
	w := c.Watch
	switch w.Mode {
	case "auto", "xdp", "userspace", "off":
	default:
		return fmt.Errorf(`watch.mode must be "auto", "xdp", "userspace" or "off", got %q`, w.Mode)
	}
	if w.Workers < 0 || w.Workers > 64 {
		return errors.New("watch.workers must be between 0 (automatic) and 64")
	}
	if w.ActiveWindowSeconds < 60 {
		return errors.New("watch.active_window_seconds must be at least 60")
	}
	if w.HealthIntervalSeconds < 0 || w.IdleGraceSeconds < 0 || w.StartupGraceSeconds < 0 {
		return errors.New("watch.health_interval_seconds, watch.idle_grace_seconds and watch.startup_grace_seconds must not be negative")
	}
	return nil
}

// LoopbackEnabled reports whether dns.listen_loopback is on. It defaults to
// true, which is why the field is a pointer: an explicit "false" in the file
// has to be distinguishable from an absent key.
func (d DNS) LoopbackEnabled() bool { return d.ListenLoopback == nil || *d.ListenLoopback }

// ListenAddrs is the set of addresses to serve DNS on: everything in
// dns.listen, plus the loopback addresses when dns.listen_loopback is on
// (see ListenLoopback). The loopback port follows the first configured
// address, so the host reaches Shepherd the same way the network does.
// Addresses already covered by the configuration are never added twice.
func (d DNS) ListenAddrs() []string {
	all, _ := d.listenAddrs()
	return all
}

// AddedLoopbackAddrs is just the loopback addresses ListenAddrs adds, the
// ones the owner did not write in dns.listen. Shepherd puts them there
// itself, so they are best-effort: a NAS's own resolver commonly owns
// 127.0.0.1:53 already, and an address nobody asked for must never be able
// to stop Shepherd from starting. cmd/shepherd passes these to
// dnsengine.Optional.
func (d DNS) AddedLoopbackAddrs() []string {
	_, added := d.listenAddrs()
	return added
}

func (d DNS) listenAddrs() (all, added []string) {
	out := append([]string(nil), d.Listen...)
	if !d.LoopbackEnabled() || len(d.Listen) == 0 {
		return out, nil
	}
	_, port, err := net.SplitHostPort(d.Listen[0])
	if err != nil || port == "" {
		return out, nil
	}
	have := map[string]bool{}
	for _, a := range out {
		if host, p, err := net.SplitHostPort(a); err == nil {
			have[net.JoinHostPort(strings.ToLower(host), p)] = true
			// A wildcard listener already answers on loopback.
			if host == "" || host == "0.0.0.0" || host == "::" {
				return out, nil
			}
		}
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		if a := net.JoinHostPort(host, port); !have[a] {
			out = append(out, a)
			added = append(added, a)
		}
	}
	return out, added
}
