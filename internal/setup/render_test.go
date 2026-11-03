// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shepherd/internal/config"
)

func TestRenderIsValidTOMLForEveryShapeSetupProduces(t *testing.T) {
	for _, a := range []Answers{
		{DataDir: "data", DNSListen: []string{"192.0.2.10"}, DNSPort: 53, Upstreams: []string{"9.9.9.10"}, PortalHost: "127.0.0.1", PortalPort: 8787},
		{DataDir: "/var/lib/shepherd", DNSListen: []string{"2001:db8::10"}, DNSPort: 5353, Upstreams: []string{"tls://dns.example.com"}, PortalHost: "192.0.2.10", PortalPort: 80, RouterConnected: "unifi"},
	} {
		path := filepath.Join(t.TempDir(), "shepherd.toml")
		if err := os.WriteFile(path, []byte(Render(a)), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("%+v rendered a config that does not load: %v", a, err)
		}
		if cfg.DataDir != a.DataDir || len(cfg.DNS.Listen) != 1 {
			t.Errorf("%+v round tripped as %+v", a, cfg)
		}
		if a.RouterConnected != "" && !strings.Contains(Render(a), "secrets.json") {
			t.Error("a connected router should say where its credentials are, not carry them")
		}
	}
}

func TestRenderExplainsItselfRatherThanDumpingValues(t *testing.T) {
	// The file is what the owner edits for years afterwards; a bare list
	// of addresses would not tell them why these and not others.
	got := Render(Answers{DataDir: "data", DNSListen: []string{"192.0.2.10"}, DNSPort: 53,
		Upstreams: []string{"9.9.9.10"}, PortalHost: "127.0.0.1", PortalPort: 8787})
	for _, want := range []string{"shepherd setup", "shepherd.example.toml", "docs/UPSTREAMS.md", "listen_loopback", "ssh -L 8787:127.0.0.1:8787"} {
		if !strings.Contains(got, want) {
			t.Errorf("the written comments should mention %q:\n%s", want, got)
		}
	}
	if lines := strings.Count(got, "\n#"); lines < 20 {
		t.Errorf("only %d comment lines; this should read as documentation:\n%s", lines, got)
	}
	// A LAN portal gets the other warning, not the tunnel instructions.
	lan := Render(Answers{DataDir: "data", DNSListen: []string{"192.0.2.10"}, DNSPort: 53,
		Upstreams: []string{"9.9.9.10"}, PortalHost: "192.0.2.10", PortalPort: 8787})
	if strings.Contains(lan, "ssh -L") || !strings.Contains(lan, "reachable from") {
		t.Errorf("a LAN portal should carry the LAN comment:\n%s", lan)
	}
}

func TestDigHintNamesANonStandardPort(t *testing.T) {
	a := Answers{DNSListen: []string{"192.0.2.10"}, DNSPort: 5353}
	if got := a.digHint(); got != "@192.0.2.10 -p 5353" {
		t.Errorf("digHint = %q", got)
	}
	a.DNSPort = 53
	if got := a.digHint(); got != "@192.0.2.10" {
		t.Errorf("digHint = %q", got)
	}
	a.DNSListen = nil
	if got := a.digHint(); got != "@127.0.0.1" {
		t.Errorf("digHint with no listener = %q", got)
	}
}

func TestQuoteListEscapes(t *testing.T) {
	if got := quoteList([]string{`a"b`}); got != `"a\"b"` {
		t.Errorf("quoteList = %s", got)
	}
}

func TestJoinHostPortBracketsIPv6(t *testing.T) {
	if got := joinHostPort("2001:db8::10", 53); got != "[2001:db8::10]:53" {
		t.Errorf("joinHostPort = %s", got)
	}
}

func TestCollectKeepsOnlyWhatADeviceCouldBePointedAt(t *testing.T) {
	// net.Interface.Addrs reports the interface's own address with the
	// prefix's mask, which is not what ParseCIDR's second return is.
	ip := func(s string) net.Addr {
		addr, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return &net.IPNet{IP: addr, Mask: n.Mask}
	}
	got := collect([]iface{
		{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback, Addrs: []net.Addr{ip("127.0.0.1/8")}},
		{Name: "eth1", Flags: 0, Addrs: []net.Addr{ip("192.0.2.20/24")}}, // down
		{Name: "wlan0", Flags: net.FlagUp, Addrs: []net.Addr{
			ip("198.51.100.10/24"),
			ip("169.254.1.1/16"), // leakcheck:allow fixture: link-local, unreachable without a zone
			ip("2001:db8::10/64"),
			ip("fe80::1/64"),                          // leakcheck:allow fixture: link-local IPv6
			&net.IPAddr{IP: net.IPv4(203, 0, 113, 1)}, // not an *net.IPNet
		}},
		{Name: "eth0", Flags: net.FlagUp, Addrs: []net.Addr{ip("192.0.2.10/24"), ip("fd00::10/64")}}, // leakcheck:allow fixture: the ULA range's own base
	})
	var names []string
	for _, a := range got {
		names = append(names, a.Interface+" "+a.IP)
	}
	want := []string{"eth0 192.0.2.10", "wlan0 198.51.100.10", "eth0 fd00::10", "wlan0 2001:db8::10"} // leakcheck:allow fixture
	if strings.Join(names, ", ") != strings.Join(want, ", ") {
		t.Errorf("collect returned %v, want %v", names, want)
	}
}

func TestHostAddrsReadsThisHost(t *testing.T) {
	// The real reader has to work on whatever this host has; collect's
	// own test covers the shapes it does not.
	addrs, err := HostAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		parsed := net.ParseIP(a.IP)
		if parsed == nil {
			t.Errorf("%q is not an address", a.IP)
			continue
		}
		if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
			t.Errorf("%s should not have been offered", a.IP)
		}
		if a.V6 != (parsed.To4() == nil) {
			t.Errorf("%s: V6 is %v", a.IP, a.V6)
		}
	}
}

func TestPortFreeAnswersForBothProtocols(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if PortFree("127.0.0.1", l.Addr().(*net.TCPAddr).Port) {
		t.Error("a port held over TCP is not free")
	}
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if PortFree("127.0.0.1", p.LocalAddr().(*net.UDPAddr).Port) {
		t.Error("a port held over UDP is not free")
	}
	if !PortFree("127.0.0.1", 0) {
		t.Error("port 0 should always be free")
	}
	if PortFree("192.0.2.1", 8787) {
		t.Error("an address this host does not have cannot be bound")
	}
}

func ExampleRender() {
	fmt.Println(strings.Contains(Render(Answers{DataDir: "data"}), "[dns]"))
	// Output: true
}
