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
