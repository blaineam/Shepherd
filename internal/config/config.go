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

	"github.com/BurntSushi/toml"

	"shepherd/internal/dnsengine"
	"shepherd/internal/ntfy"
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
	TLS            TLS            `toml:"tls"`
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
// enabled; Ntfy is the one delivery channel wired in so far. Web Push needs a
// secure context (HTTPS) the portal does not have yet, so it stays
// unconfigured; see docs/ALARMS.md.
type Alarms struct {
	Enabled bool       `toml:"enabled"`
	Ntfy    AlarmsNtfy `toml:"ntfy"`
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
// both a subscription is added in the portal and an SMTP relay is configured
// here.
type Accountability struct {
	Enabled bool               `toml:"enabled"`
	SMTP    AccountabilitySMTP `toml:"smtp"`
}

// AccountabilitySMTP is the outgoing mail relay accountability alerts send
// through: a relay you already have (a Gmail or iCloud app password, a
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
// matched against a small, curated, built-in vulnerability signature list
// (no external CVE API — see docs/VULNSCAN.md). Enabled defaults true, for
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
	// CloudflareAPIToken and CloudflareAPITokenFile supply the token
	// DNS-01 uses to create and remove the challenge TXT record. Scope it
	// to DNS edit on the one zone the hostname lives in, nothing broader
	// (docs/TLS.md). Exactly one must be set while tls.enabled is true;
	// setting both is a configuration error (Validate rejects it), the
	// same convention AccountabilitySMTP.Password/PasswordFile already
	// uses, for the same reason: never an ambiguous "which one wins".
	CloudflareAPIToken     string `toml:"cloudflare_api_token"`
	CloudflareAPITokenFile string `toml:"cloudflare_api_token_file"`
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
	// BlockMode is "null" (answer 0.0.0.0 / ::) or "nxdomain".
	BlockMode            string   `toml:"block_mode"`
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
		Alarms:         Alarms{Enabled: true, Ntfy: AlarmsNtfy{Topic: "shepherd-alarms"}},
		Accountability: Accountability{Enabled: true, SMTP: AccountabilitySMTP{Port: 587, TLS: "starttls"}},
		Portscan:       Portscan{Enabled: true, IntervalSeconds: 6 * 3600, WANExposure: WANExposure{Enabled: true, RefreshIntervalSeconds: 600}},
		Vulnscan:       Vulnscan{Enabled: true, IntervalSeconds: 24 * 3600},
		DataDir:        "data",
		DNS: DNS{
			Listen:               []string{"127.0.0.1:5353"},
			Upstreams:            []string{"9.9.9.10", "149.112.112.10", "1.1.1.1"},
			Bootstrap:            dnsengine.DefaultBootstrapServers(),
			BlockMode:            "null",
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
	if c.Vulnscan.IntervalSeconds < 300 {
		return errors.New("vulnscan.interval_seconds must be at least 300")
	}
	if c.TLS.Enabled {
		if c.TLS.Hostname == "" {
			return errors.New("tls.hostname is required when tls.enabled is true")
		}
		if c.TLS.Listen == "" {
			return errors.New("tls.listen is required when tls.enabled is true")
		}
		if c.TLS.CloudflareAPIToken == "" && c.TLS.CloudflareAPITokenFile == "" {
			return errors.New("tls.cloudflare_api_token or tls.cloudflare_api_token_file is required when tls.enabled is true")
		}
		if c.TLS.CloudflareAPIToken != "" && c.TLS.CloudflareAPITokenFile != "" {
			return errors.New("tls.cloudflare_api_token and tls.cloudflare_api_token_file must not both be set")
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
