// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
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
