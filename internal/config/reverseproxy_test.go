// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReverseProxyDefaultsAreOffAndInert(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatal(err)
	}
	rp := cfg.ReverseProxy
	if rp.Enabled {
		t.Error("reverseproxy must be off by default: it opens a new listener and needs a domain and a Cloudflare token")
	}
	if rp.Listen != ":8443" {
		t.Errorf("listen default = %q, want :8443 (never 443: binding it is the owner's call)", rp.Listen)
	}
	if rp.RedirectListen != "" {
		t.Errorf("redirect_listen default = %q, want empty: binding :80 by default needs a capability a fresh install does not have", rp.RedirectListen)
	}
	if rp.Domain != "" || rp.CloudflareAPIToken != "" || rp.CloudflareAPITokenFile != "" || rp.Email != "" {
		t.Errorf("a fresh install must configure no domain or secret under [reverseproxy]: %+v", rp)
	}
}

func TestReverseProxyOverridesAndValidation(t *testing.T) {
	cfg := writeCfg(t, `[reverseproxy]
enabled = true
listen = "0.0.0.0:9443"
domain = "example.com"
email = "owner@example.com"
cloudflare_api_token = "cf-test-token"
`)
	rp := cfg.ReverseProxy
	if !rp.Enabled || rp.Listen != "0.0.0.0:9443" || rp.Domain != "example.com" || rp.Email != "owner@example.com" || rp.CloudflareAPIToken != "cf-test-token" {
		t.Errorf("reverseproxy overrides = %+v", rp)
	}
	if got := rp.Wildcard(); got != "*.example.com" {
		t.Errorf("Wildcard() = %q, want *.example.com", got)
	}

	ok := "[reverseproxy]\nenabled = true\nlisten = \":9443\"\ncloudflare_api_token = \"t\"\n"
	bad := map[string]string{
		"[reverseproxy]\nenabled = true\nlisten = \":9443\"\ncloudflare_api_token = \"t\"": "reverseproxy.domain",
		ok + "domain = \"localhost\"":       "reverseproxy.domain",
		ok + "domain = \"exa mple.com\"":    "reverseproxy.domain",
		ok + "domain = \"*.*.example.com\"": "reverseproxy.domain",
		ok + "domain = \"example.com:443\"": "reverseproxy.domain",
		"[reverseproxy]\nenabled = true\nlisten = \"\"\ndomain = \"example.com\"\ncloudflare_api_token = \"t\"":                                                              "reverseproxy.listen",
		"[reverseproxy]\nenabled = true\ndomain = \"example.com\"\ncloudflare_api_token = \"t\"\ncloudflare_api_token_file = \"/tmp/x\"":                                     "not both",
		"[tls]\nenabled = true\nhostname = \"h.example.com\"\nlisten = \":9443\"\ncloudflare_api_token = \"t\"\n" + ok + "domain = \"example.com\"":                          "same address",
		ok + "domain = \"example.com\"\nredirect_listen = \":9443\"":                                                                                                         "same address",
		"[tls]\nenabled = true\nhostname = \"h.example.com\"\nlisten = \":80\"\ncloudflare_api_token = \"t\"\n" + ok + "domain = \"example.com\"\nredirect_listen = \":80\"": "same address",
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
}

func TestReverseProxyNeedsNoTokenInTheConfigFile(t *testing.T) {
	// The DNS provider token is managed in the portal; the config file's
	// token fields only seed it once (docs/REVERSEPROXY.md).
	cfg := writeCfg(t, "[reverseproxy]\nenabled = true\ndomain = \"example.com\"\n")
	if !cfg.ReverseProxy.Enabled {
		t.Error("reverseproxy enabled without a token in shepherd.toml must load")
	}
}

func TestReverseProxyDomainAcceptsAWildcardSpelling(t *testing.T) {
	cfg := writeCfg(t, "[reverseproxy]\nenabled = true\ndomain = \"*.Example.COM.\"\ncloudflare_api_token = \"t\"\n")
	if got := cfg.ReverseProxy.Wildcard(); got != "*.example.com" {
		t.Errorf("Wildcard() = %q, want *.example.com", got)
	}
	if got := cfg.ReverseProxy.BaseDomain(); got != "example.com" {
		t.Errorf("BaseDomain() = %q, want example.com", got)
	}
	if got := (ReverseProxy{}).Wildcard(); got != "" {
		t.Errorf("Wildcard() with no domain = %q, want empty", got)
	}
}

func TestExampleConfigShowsTheReverseProxyDefaults(t *testing.T) {
	ex, err := Load("../../shepherd.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if ex.ReverseProxy != Default().ReverseProxy {
		t.Errorf("example %+v differs from the defaults %+v", ex.ReverseProxy, Default().ReverseProxy)
	}
}
