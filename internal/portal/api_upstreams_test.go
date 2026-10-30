// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeResolver answers every query on a loopback UDP port.
func fakeResolver(t *testing.T, rcode int) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func configs(m map[string]any) []string {
	var out []string
	for _, u := range m["upstreams"].([]any) {
		out = append(out, u.(map[string]any)["config"].(string))
	}
	return out
}

func TestUpstreamsListPresetsAndShape(t *testing.T) {
	h := newHarness(t)
	m := h.ok("GET", "/api/upstreams", "", 200)
	u := m["upstreams"].([]any)[0].(map[string]any)
	for _, k := range []string{"config", "kind", "healthy", "rtt_ms", "consecutive_failures", "queries", "errors"} {
		if _, ok := u[k]; !ok {
			t.Errorf("upstream lacks %q: %v", k, u)
		}
	}
	if u["config"] != "192.0.2.53" || u["kind"] != "udp" {
		t.Errorf("upstream = %v", u)
	}
	if b := strs(m["bootstrap"]); len(b) != 2 || b[0] != "9.9.9.9" {
		t.Errorf("bootstrap = %v", b)
	}
	var cf map[string]any
	for _, p := range m["presets"].([]any) {
		if p.(map[string]any)["id"] == "cloudflare" {
			cf = p.(map[string]any)
		}
	}
	if cf == nil || cf["doh"] != "https://cloudflare-dns.com/dns-query" || cf["dot"] != "tls://one.one.one.one" || len(cf["plain"].([]any)) != 4 || cf["filtering"] != "none" || cf["notes"] == "" {
		t.Errorf("cloudflare preset = %v", cf)
	}
	for _, p := range m["presets"].([]any) {
		if p.(map[string]any)["id"] == "mullvad" && len(p.(map[string]any)["plain"].([]any)) != 0 {
			t.Error("a preset without plain addresses must list []")
		}
	}
}

func TestUpstreamAddRemoveReorderAndPersist(t *testing.T) {
	h := newHarness(t)
	good := fakeResolver(t, dns.RcodeNameError)

	r := h.ok("POST", "/api/upstreams/test", `{"addr":"`+good+`"}`, 200)
	if r["ok"] != true || r["rcode"] != "NXDOMAIN" {
		t.Errorf("test = %v", r)
	}
	if len(h.pool.List()) != 1 {
		t.Error("testing must not add")
	}
	r = h.ok("POST", "/api/upstreams/test", `{"addr":"127.0.0.1:1"}`, 200)
	if r["ok"] != false || r["error"] == "" {
		t.Errorf("dead upstream test = %v", r)
	}
	h.expect("POST", "/api/upstreams/test", `{"addr":"ftp://x"}`, 400)
	h.expect("POST", "/api/upstreams/test", `{"addr":""}`, 400)
	h.expect("POST", "/api/upstreams/test", `{"addr":"`+strings.Repeat("a", 600)+`"}`, 400)
	h.expect("POST", "/api/upstreams/test", `{"addr":"x","y":1}`, 400)

	m := h.ok("POST", "/api/upstreams", `{"addr":"`+good+`"}`, 200)
	if c := configs(m); len(c) != 2 || c[1] != good {
		t.Fatalf("after add = %v", c)
	}
	h.expect("POST", "/api/upstreams", `{"addr":"`+good+`"}`, 409)
	h.expect("POST", "/api/upstreams", `{"addr":"ftp://x"}`, 400)
	h.expect("POST", "/api/upstreams", `{"addr":"`+strings.Repeat("a", 600)+`"}`, 400)
	if b, err := os.ReadFile(filepath.Join(h.dir, "upstreams.json")); err != nil || !strings.Contains(string(b), good) {
		t.Errorf("upstreams.json = %s %v", b, err)
	}

	m = h.ok("PUT", "/api/upstreams", `{"addrs":["`+good+`","192.0.2.53","tls://dns.example"]}`, 200)
	if c := configs(m); len(c) != 3 || c[0] != good || c[2] != "tls://dns.example" || m["upstreams"].([]any)[2].(map[string]any)["kind"] != "dot" {
		t.Errorf("after put = %v", c)
	}
	for _, b := range []string{`{"addrs":[]}`, `{}`, `{"addrs":["ftp://x"]}`, `{"addrs":["192.0.2.1","192.0.2.1"]}`, `{"addrs":["` + strings.Repeat("a", 600) + `"]}`, `{"addrs":["1.1.1.1"],"z":1}`,
		`{"addrs":["192.0.2.1","192.0.2.2","192.0.2.3","192.0.2.4","192.0.2.5","192.0.2.6","192.0.2.7","192.0.2.8","192.0.2.9","192.0.2.10","192.0.2.11","192.0.2.12","192.0.2.13","192.0.2.14","192.0.2.15","192.0.2.16","192.0.2.17"]}`} {
		h.expect("PUT", "/api/upstreams", b, 400)
	}

	h.expect("DELETE", "/api/upstreams?addr=203.0.113.1", "", 404)
	h.expect("DELETE", "/api/upstreams", "", 400)
	h.expect("DELETE", "/api/upstreams?addr="+strings.Repeat("a", 600), "", 400)
	h.ok("DELETE", "/api/upstreams?addr=tls%3A%2F%2Fdns.example", "", 200)
	h.ok("DELETE", "/api/upstreams?addr=192.0.2.53", "", 200)
	h.expect("DELETE", "/api/upstreams?addr="+good, "", 409) // the last one stays
	if c := configs(h.ok("GET", "/api/upstreams", "", 200)); len(c) != 1 || c[0] != good {
		t.Errorf("final = %v", c)
	}
}

func TestUpstreamAddFillsTheLimit(t *testing.T) {
	h := newHarness(t)
	for i := 1; i < 16; i++ {
		h.ok("POST", "/api/upstreams", `{"addr":"192.0.2.`+itoa(i)+`"}`, 200)
	}
	h.expect("POST", "/api/upstreams", `{"addr":"192.0.2.200"}`, 400)
}

func itoa(n int) string {
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestBootstrapEndpoint(t *testing.T) {
	h := newHarness(t)
	m := h.ok("PUT", "/api/upstreams/bootstrap", `{"servers":["203.0.113.5","198.51.100.5:5353"]}`, 200)
	if b := strs(m["bootstrap"]); len(b) != 2 || b[1] != "198.51.100.5:5353" {
		t.Errorf("bootstrap = %v", b)
	}
	for _, b := range []string{`{"servers":[]}`, `{}`, `{"servers":["dns.example"]}`, `{"servers":["https://x.example/dns-query"]}`, `{"servers":["1.1.1.1"],"z":1}`,
		`{"servers":["192.0.2.1","192.0.2.2","192.0.2.3","192.0.2.4","192.0.2.5","192.0.2.6","192.0.2.7","192.0.2.8","192.0.2.9"]}`} {
		h.expect("PUT", "/api/upstreams/bootstrap", b, 400)
	}
	if b := h.pool.Bootstrap(); len(b) != 2 {
		t.Errorf("a rejected edit changed bootstrap: %v", b)
	}
}
