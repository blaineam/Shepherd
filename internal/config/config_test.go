// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMissingFileGivesValidDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.BlockMode != "null" || len(cfg.DNS.Upstreams) == 0 {
		t.Errorf("defaults = %+v", cfg)
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	cfg, err := Load("../../shepherd.example.toml")
	if err != nil {
		t.Fatalf("shepherd.example.toml must always load: %v", err)
	}
	if len(cfg.Lists) == 0 {
		t.Error("example should show a list")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		`[dns]
block_mode = "sinkhole"`: "block_mode",
		`[[lists]]
name = "Bad Name"
url = "file:///x"`: "list name",
		`[[lists]]
name = "a"
url = "file:///x"
[[lists]]
name = "a"
url = "file:///y"`: "duplicate",
		`[[lists]]
name = "a"`: "no url",
		`[dns]
upstreams = []`: "upstream",
	}
	for body, want := range cases {
		path := filepath.Join(t.TempDir(), "c.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("config %q: error %v, want mention of %q", body, err, want)
		}
	}
}

func TestMoreValidationAndSyntaxErrors(t *testing.T) {
	cases := map[string]string{
		"this is = not toml [":              "reading",
		"data_dir = \"\"":                   "data_dir",
		"[dns]\nlisten = []":                "dns.listen",
		"[dns]\nprobe_interval_seconds = 0": "probe_interval",
	}
	for body, want := range cases {
		path := filepath.Join(t.TempDir(), "c.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("config %q: error %v, want mention of %q", body, err, want)
		}
	}
}

func writeCfg(t *testing.T, body string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDefaultsProtectOutOfTheBox(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Privacy.BlockPrivateRelay {
		t.Error("Apple Private Relay blocking must be on by default")
	}
	if len(cfg.Lists) == 0 {
		t.Error("a fresh install must ship with a blocklist so it protects immediately")
	}
}

func TestEveryDefaultProtectionCanBeOptedOut(t *testing.T) {
	cfg := writeCfg(t, "no_default_lists = true\n[privacy]\nblock_private_relay = false\n")
	if cfg.Privacy.BlockPrivateRelay {
		t.Error("block_private_relay = false must opt out")
	}
	if len(cfg.Lists) != 0 {
		t.Errorf("no_default_lists = true must leave no lists, got %v", cfg.Lists)
	}
}

func TestOwnListsReplaceTheDefaultAndNeverMerge(t *testing.T) {
	cfg := writeCfg(t, "[[lists]]\nname = \"mine\"\nurl = \"file:///x\"\n")
	if len(cfg.Lists) != 1 || cfg.Lists[0].Name != "mine" {
		t.Errorf("own lists must replace the default, got %v", cfg.Lists)
	}
	// Opting out of the default must not delete a list the user wrote themselves.
	cfg = writeCfg(t, "no_default_lists = true\n[[lists]]\nname = \"mine\"\nurl = \"file:///x\"\n")
	if len(cfg.Lists) != 1 || cfg.Lists[0].Name != "mine" {
		t.Errorf("a user's own list must survive no_default_lists, got %v", cfg.Lists)
	}
}

func TestExampleConfigShowsTheRealDefaults(t *testing.T) {
	ex, err := Load("../../shepherd.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	def := Default()
	if ex.Privacy != def.Privacy {
		t.Errorf("example privacy %+v differs from the defaults %+v", ex.Privacy, def.Privacy)
	}
	if len(ex.Lists) != len(def.Lists) || ex.Lists[0].URL != def.Lists[0].URL {
		t.Errorf("example lists %v differ from the defaults %v", ex.Lists, def.Lists)
	}
}

func TestPartialListNeverInheritsTheDefaultURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(path, []byte("[[lists]]\nname = \"mine\"\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "no url") {
		t.Errorf("a list without a url must be an error, not the default's url: %v", err)
	}
}

func TestHistoryAndMapDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.History
	if h.Mode != "memory" || h.KeySource != "file" || h.RetentionDays != 30 || h.MaxMB != 2048 || h.KeyFile != "" {
		t.Errorf("history defaults = %+v (memory only until the user opts in to disk)", h)
	}
	if !cfg.Map.Enabled || !cfg.Map.AutoHome {
		t.Errorf("the globe's map data and automatic home are on by default: %+v", cfg.Map)
	}
	cfg = writeCfg(t, "[history]\nmode = \"encrypted\"\nkey_source = \"passphrase\"\nretention_days = 7\n[map]\nenabled = false\n")
	if cfg.History.Mode != "encrypted" || cfg.History.KeySource != "passphrase" || cfg.History.RetentionDays != 7 || cfg.Map.Enabled {
		t.Errorf("explicit settings = %+v %+v", cfg.History, cfg.Map)
	}
}

func TestHistoryValidation(t *testing.T) {
	cases := map[string]string{
		"[history]\nmode = \"disk\"":        "history.mode",
		"[history]\nkey_source = \"cloud\"": "history.key_source",
		"[history]\nretention_days = -1":    "must not be negative",
		"[history]\nmax_mb = -5":            "must not be negative",
	}
	for body, want := range cases {
		path := filepath.Join(t.TempDir(), "c.toml")
		os.WriteFile(path, []byte(body), 0o600)
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("config %q: error %v, want %q", body, err, want)
		}
	}
}

func TestAutoHomeCanBeOptedOut(t *testing.T) {
	cfg := writeCfg(t, "[map]\nauto_home = false\n")
	if cfg.Map.AutoHome || !cfg.Map.Enabled {
		t.Errorf("auto_home = false must only turn off the public-address lookup: %+v", cfg.Map)
	}
}

func TestMapDatabaseMirror(t *testing.T) {
	if cfg := writeCfg(t, ""); cfg.Map.DatabaseURL != "" {
		t.Errorf("the default database URL must be empty (use the built-in one): %q", cfg.Map.DatabaseURL)
	}
	if cfg := writeCfg(t, "[map]\ndatabase_url = \"https://mirror.example.net/geo\"\n"); cfg.Map.DatabaseURL != "https://mirror.example.net/geo" {
		t.Errorf("mirror = %q", cfg.Map.DatabaseURL)
	}
}

func TestDeviceAndBootstrapDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Devices
	if !d.Enabled || !d.DNS || !d.Neighbors || !d.MDNS || !d.ReverseDNS || !d.QuarantineNewDevices ||
		d.NeighborIntervalSeconds != 30 || d.SaveIntervalSeconds != 60 || d.ReverseDNSServer != "" {
		t.Errorf("devices defaults = %+v", d)
	}
	if len(cfg.DNS.Bootstrap) != 2 || cfg.DNS.Bootstrap[0] != "9.9.9.9" {
		t.Errorf("bootstrap default = %v", cfg.DNS.Bootstrap)
	}
	if !cfg.ListsAreDefault() {
		t.Error("an untouched config uses the default list")
	}
}

func TestDeviceAndBootstrapOverridesAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(path, []byte(`[dns]
bootstrap = ["203.0.113.1"]
[devices]
mdns = false
reverse_dns_server = "192.0.2.1:53"
neighbor_interval_seconds = 10
[[lists]]
name = "mine"
url = "file:///x"
`), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Devices.MDNS || !cfg.Devices.Neighbors || cfg.Devices.NeighborIntervalSeconds != 10 || cfg.DNS.Bootstrap[0] != "203.0.113.1" || cfg.ListsAreDefault() {
		t.Errorf("cfg = %+v", cfg)
	}
	bad := map[string]string{
		"[dns]\nbootstrap = []":                              "bootstrap",
		"[devices]\nneighbor_interval_seconds = 1":           "at least 5",
		"[devices]\nsave_interval_seconds = 0":               "at least 5",
		"[devices]\nreverse_dns_server = \"router.example\"": "IP address",
	}
	for body, want := range bad {
		os.WriteFile(path, []byte(body), 0o600)
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
	os.WriteFile(path, []byte("[devices]\nreverse_dns_server = \"2001:db8::1\"\n"), 0o600)
	if _, err := Load(path); err != nil {
		t.Errorf("a bare IPv6 address is valid: %v", err)
	}
}

func TestExampleConfigShowsTheDeviceAndBootstrapDefaults(t *testing.T) {
	ex, err := Load("../../shepherd.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	def := Default()
	if ex.Devices != def.Devices || !slices.Equal(ex.DNS.Bootstrap, def.DNS.Bootstrap) {
		t.Errorf("example %+v %v differs from the defaults %+v %v", ex.Devices, ex.DNS.Bootstrap, def.Devices, def.DNS.Bootstrap)
	}
}

func TestClassifyDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Classify.Enabled || cfg.Classify.IntervalSeconds != 300 {
		t.Errorf("classify defaults = %+v (protection is opt-out, so this is on by default)", cfg.Classify)
	}
}

func TestClassifyOverridesAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(path, []byte("[classify]\nenabled = false\ninterval_seconds = 60\n"), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Classify.Enabled || cfg.Classify.IntervalSeconds != 60 {
		t.Errorf("classify overrides = %+v", cfg.Classify)
	}
	os.WriteFile(path, []byte("[classify]\ninterval_seconds = 29\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "at least 30") {
		t.Errorf("too-short interval: %v", err)
	}
}

func TestExampleConfigShowsTheClassifyDefaults(t *testing.T) {
	ex, err := Load("../../shepherd.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Classify != Default().Classify {
		t.Errorf("example %+v differs from the defaults %+v", ex.Classify, Default().Classify)
	}
}

func TestARPDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ARP.Enabled || cfg.ARP.Interface != "" {
		t.Errorf("arp defaults = %+v (on by default, auto-detect interface)", cfg.ARP)
	}
}

func TestARPOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.toml")
	os.WriteFile(path, []byte("[arp]\nenabled = false\ninterface = \"eth9\"\n"), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ARP.Enabled || cfg.ARP.Interface != "eth9" {
		t.Errorf("arp overrides = %+v", cfg.ARP)
	}
}

func TestExampleConfigShowsTheARPDefaults(t *testing.T) {
	ex, err := Load("../../shepherd.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if ex.ARP != Default().ARP {
		t.Errorf("example %+v differs from the defaults %+v", ex.ARP, Default().ARP)
	}
}

func TestQuarantineCanBeOptedOut(t *testing.T) {
	cfg := writeCfg(t, "[devices]\nquarantine_new_devices = false\n")
	if cfg.Devices.QuarantineNewDevices || !cfg.Devices.Enabled {
		t.Errorf("quarantine_new_devices = false must only turn that off: %+v", cfg.Devices)
	}
}

func TestAlarmsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Alarms.Enabled {
		t.Error("the alarm engine must be on by default")
	}
	if cfg.Alarms.Ntfy.Enabled {
		t.Error("ntfy delivery needs a server address, so it must be off by default")
	}
	if cfg.Alarms.Ntfy.Topic != "shepherd-alarms" {
		t.Errorf("default ntfy topic = %q", cfg.Alarms.Ntfy.Topic)
	}
}

func TestAlarmsOverrides(t *testing.T) {
	cfg := writeCfg(t, `[alarms]
enabled = false
[alarms.ntfy]
enabled = true
server = "https://ntfy.example.com"
topic = "my-shepherd"
token = "secret"
`)
	a := cfg.Alarms
	if a.Enabled || !a.Ntfy.Enabled || a.Ntfy.Server != "https://ntfy.example.com" || a.Ntfy.Topic != "my-shepherd" || a.Ntfy.Token != "secret" {
		t.Errorf("alarms overrides = %+v", a)
	}
}

func TestAlarmsValidation(t *testing.T) {
	cases := map[string]string{
		"[alarms.ntfy]\nenabled = true\nserver = \"\"\ntopic = \"x\"":                                  "alarms.ntfy.server",
		"[alarms.ntfy]\nenabled = true\nserver = \"not a url\"\ntopic = \"x\"":                         "alarms.ntfy.server",
		"[alarms.ntfy]\nenabled = true\nserver = \"https://ntfy.example.com\"\ntopic = \"\"":           "alarms.ntfy.topic",
		"[alarms.ntfy]\nenabled = true\nserver = \"https://ntfy.example.com\"\ntopic = \"bad topic!\"": "alarms.ntfy.topic",
	}
	for body, want := range cases {
		path := filepath.Join(t.TempDir(), "c.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("config %q: error %v, want mention of %q", body, err, want)
		}
	}
	okPath := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(okPath, []byte("[alarms]\nenabled = true\n"), 0o600)
	if _, err := Load(okPath); err != nil {
		t.Errorf("alarms enabled with ntfy left off must be valid: %v", err)
	}
	// alarms.enabled = false must skip ntfy validation entirely.
	offPath := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(offPath, []byte("[alarms]\nenabled = false\n[alarms.ntfy]\nenabled = true\n"), 0o600)
	if _, err := Load(offPath); err != nil {
		t.Errorf("alarms.enabled = false must skip ntfy validation: %v", err)
	}
}

func TestExampleConfigShowsTheAlarmsDefaults(t *testing.T) {
	ex, err := Load("../../shepherd.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Alarms != Default().Alarms {
		t.Errorf("example %+v differs from the defaults %+v", ex.Alarms, Default().Alarms)
	}
}

func TestAccountabilityDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Accountability
	if !a.Enabled {
		t.Error("accountability is enabled by default (the library itself has zero subscriptions, so this is inert)")
	}
	if a.SMTP.Host != "" || a.SMTP.From != "" || a.SMTP.Password != "" || a.SMTP.PasswordFile != "" {
		t.Errorf("a fresh install must configure no SMTP relay: %+v", a.SMTP)
	}
	if a.SMTP.Port != 587 || a.SMTP.TLS != "starttls" {
		t.Errorf("port/tls defaults = %d %q, want 587 starttls (an empty host still leaves the feature inert)", a.SMTP.Port, a.SMTP.TLS)
	}
}

func TestAccountabilityOverridesAndValidation(t *testing.T) {
	cfg := writeCfg(t, `[accountability]
enabled = false
[accountability.smtp]
host = "smtp.example.com"
port = 587
username = "shepherd@example.com"
password = "hunter2"
from = "shepherd@example.com"
tls = "tls"
`)
	if cfg.Accountability.Enabled {
		t.Error("enabled = false must turn the feature off")
	}
	s := cfg.Accountability.SMTP
	if s.Host != "smtp.example.com" || s.Port != 587 || s.Username != "shepherd@example.com" || s.Password != "hunter2" || s.From != "shepherd@example.com" || s.TLS != "tls" {
		t.Errorf("smtp overrides = %+v", s)
	}

	bad := map[string]string{
		"[accountability.smtp]\nhost = \"h\"\nport = 0\nfrom = \"f\"":                                                 "port",
		"[accountability.smtp]\nhost = \"h\"\nport = 70000\nfrom = \"f\"":                                             "port",
		"[accountability.smtp]\nhost = \"h\"\nport = 587":                                                             "from",
		"[accountability.smtp]\nhost = \"h\"\nport = 587\nfrom = \"f\"\ntls = \"ssl\"":                                "tls",
		"[accountability.smtp]\nhost = \"h\"\nport = 587\nfrom = \"f\"\npassword = \"a\"\npassword_file = \"/tmp/x\"": "not both",
	}
	for body, want := range bad {
		path := filepath.Join(t.TempDir(), "c.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
	// An unconfigured host (the default) skips every other check.
	if _, err := Load(filepath.Join(t.TempDir(), "absent.toml")); err != nil {
		t.Errorf("an empty smtp host must need no other field: %v", err)
	}
}

func TestExampleConfigShowsTheAccountabilityDefaults(t *testing.T) {
	ex, err := Load("../../shepherd.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Accountability != Default().Accountability {
		t.Errorf("example %+v differs from the defaults %+v", ex.Accountability, Default().Accountability)
	}
}
