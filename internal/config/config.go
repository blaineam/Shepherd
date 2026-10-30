// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads Shepherd's single TOML configuration file.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/BurntSushi/toml"
)

type Config struct {
	DataDir string `toml:"data_dir"`
	// NoDefaultLists opts out of the blocklist Shepherd ships with. Lists you
	// define yourself are always kept.
	NoDefaultLists bool    `toml:"no_default_lists"`
	DNS            DNS     `toml:"dns"`
	Lists          []List  `toml:"lists"`
	Portal         Portal  `toml:"portal"`
	Privacy        Privacy `toml:"privacy"`
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
		Lists:   []List{defaultList},
		Privacy: Privacy{BlockPrivateRelay: true},
		DataDir: "data",
		DNS: DNS{
			Listen:               []string{"127.0.0.1:5353"},
			Upstreams:            []string{"9.9.9.10", "149.112.112.10", "1.1.1.1"},
			BlockMode:            "null",
			ProbeIntervalSeconds: 15,
			CacheSize:            20000,
			LogSize:              5000,
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
	if c.DNS.BlockMode != "null" && c.DNS.BlockMode != "nxdomain" {
		return fmt.Errorf("dns.block_mode must be \"null\" or \"nxdomain\", got %q", c.DNS.BlockMode)
	}
	if c.DNS.ProbeIntervalSeconds < 1 {
		return errors.New("dns.probe_interval_seconds must be at least 1")
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
