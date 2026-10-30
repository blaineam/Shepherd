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
	Accountability Accountability `toml:"accountability"`
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
		Accountability: Accountability{Enabled: true, SMTP: AccountabilitySMTP{Port: 587, TLS: "starttls"}},
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
		Portal: Portal{Listen: "127.0.0.1:8787"},
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
