// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
)

func TestNodeIDUsesTheHostNameOrAStoredRandomID(t *testing.T) {
	old := hostname
	defer func() { hostname = old }()
	dir := t.TempDir()
	hostname = func() (string, error) { return "  shepherd-test  ", nil }
	if got := nodeID(dir); got != "shepherd-test" {
		t.Errorf("nodeID = %q", got)
	}
	for name, fn := range map[string]func() (string, error){
		"error": func() (string, error) { return "", errors.New("no hostname") },
		"blank": func() (string, error) { return "   ", nil },
	} {
		hostname = fn
		a := nodeID(dir)
		if !strings.HasPrefix(a, "node-") || len(a) < 12 {
			t.Errorf("%s: random node id = %q", name, a)
		}
		if b := nodeID(dir); a != b {
			t.Errorf("%s: the stored id must be stable: %q then %q", name, a, b)
		}
	}
}

func TestOnceLoggerLogsEachMessageOnce(t *testing.T) {
	var l onceLogger
	l.log("x", errors.New("boom"))
	l.log("x", errors.New("boom"))
	if len(l.seen) != 1 {
		t.Errorf("seen = %v", l.seen)
	}
	l.log("x", errors.New("other"))
	if len(l.seen) != 2 {
		t.Errorf("seen = %v", l.seen)
	}
}

func TestOpenPolicyFreshInstallsAreProtectedAndExistingOnesAreUnchanged(t *testing.T) {
	items := func(cfg config.Config, existing bool) map[string]bool {
		t.Helper()
		cfg.DataDir = t.TempDir()
		p, err := openPolicy(cfg, dnsengine.NewFilter(), existing)
		if err != nil {
			t.Fatal(err)
		}
		return p.Snapshot().Network.Items
	}
	def := config.Default()
	fresh := items(def, false)
	if !fresh["hagezi-pro"] || len(fresh) < 1 {
		t.Fatalf("fresh install items = %v", fresh)
	}
	cat, _ := dnsengine.DefaultCatalog()
	for _, id := range cat.Recommended() {
		if !fresh[id] {
			t.Errorf("recommended item %s is not on for a fresh install", id)
		}
	}
	if got := items(def, true); len(got) != 1 || !got["hagezi-pro"] {
		t.Errorf("an existing install keeps exactly its configured list: %v", got)
	}
	none := def
	none.NoDefaultLists, none.Lists = true, nil
	if got := items(none, false); len(got) != 0 {
		t.Errorf("no_default_lists leaves nothing on: %v", got)
	}
	own := def
	own.Lists = []config.List{{Name: "mine", URL: "https://lists.example/mine.txt"}}
	if got := items(own, false); len(got) != 1 || !got["custom-mine"] {
		t.Errorf("a config that defines its own lists gets only those: %v", got)
	}
}

func TestBadBootstrapStopsStartup(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	body, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, []byte(strings.Replace(string(body), "[dns]\n", "[dns]\nbootstrap = [\"dns.example\"]\n", 1)), 0o600)
	if err := run(context.Background(), cfg, false, os.Stdout); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Errorf("bad bootstrap: %v", err)
	}
}

func TestInvalidSavedUpstreamsFallBackToTheConfiguration(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	data := filepath.Join(filepath.Dir(cfg), "data")
	os.MkdirAll(data, 0o750)
	os.WriteFile(filepath.Join(data, "upstreams.json"), []byte(`{"version":1,"upstreams":["ftp://nope"],"bootstrap":["9.9.9.9"]}`), 0o600)
	r := start(t, cfg)
	defer r.stop()
	m := r.json("GET", "/api/upstreams", "", 200)
	if got := m["upstreams"].([]any); len(got) != 1 || got[0].(map[string]any)["config"] != "192.0.2.53" {
		t.Errorf("upstreams = %v", got)
	}
}

func TestUnreadableDeviceFileIsMovedAsideNotOverwritten(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	data := filepath.Join(filepath.Dir(cfg), "data")
	os.MkdirAll(data, 0o750)
	os.WriteFile(filepath.Join(data, "devices.json"), []byte("{not json"), 0o600)
	r := start(t, cfg)
	r.stop()
	b, err := os.ReadFile(filepath.Join(data, "devices.json.unreadable"))
	if err != nil || string(b) != "{not json" {
		t.Errorf("the unreadable file must be kept: %q %v", b, err)
	}
	// If it cannot even be moved aside, startup stops rather than overwriting it.
	cfg = writeConfig(t, freePort(t), freePort(t), "")
	data = filepath.Join(filepath.Dir(cfg), "data")
	blocked := filepath.Join(data, "devices.json.unreadable")
	os.MkdirAll(filepath.Join(blocked, "keep"), 0o750)
	// Deliberately left in a state os.Rename refuses to overwrite (a file
	// can never replace a non-empty directory), so TempDir's own recursive
	// cleanup is not relied on to clear it: remove it ourselves first.
	t.Cleanup(func() { os.RemoveAll(blocked) })
	os.WriteFile(filepath.Join(data, "devices.json"), []byte("{not json"), 0o600)
	if err := run(context.Background(), cfg, false, os.Stdout); err == nil {
		t.Error("expected an error when the unreadable file cannot be moved aside")
	}
}

func fakePTR(t *testing.T, names map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if ptr, ok := names[r.Question[0].Name]; ok {
			m.Answer = append(m.Answer, &dns.PTR{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: ptr})
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDeviceSourcesNameDevicesAndTheRegistryIsSaved(t *testing.T) {
	arp := filepath.Join(t.TempDir(), "arp")
	os.WriteFile(arp, []byte("IP address       HW type     Flags       HW address            Mask     Device\n"+
		"192.0.2.50       0x1         0x2         02:00:5e:00:00:50     *        eth0\n"+
		"192.0.2.51       0x1         0x2         02:00:5e:00:00:51     *        eth0\n"), 0o600)
	oldN, oldM, oldS := neighborSources, runMDNS, saveEvery
	neighborSources = func() []devices.NeighborSource {
		return []devices.NeighborSource{devices.FileNeighbors{Path: arp, Parse: devices.ParseProcNetARP}}
	}
	runMDNS = func(ctx context.Context, l *devices.MDNSListener) error {
		l.Sink.Observe(devices.Observation{Source: devices.SourceMDNS, IP: "192.0.2.50", Hostname: "studio-mac.local"})
		l.OnError(errors.New("synthetic socket warning"))
		<-ctx.Done()
		return nil
	}
	saveEvery = 30 * time.Millisecond
	defer func() { neighborSources, runMDNS, saveEvery = oldN, oldM, oldS }()
	ptr := fakePTR(t, map[string]string{"51.2.0.192.in-addr.arpa.": "nas-box.example."})

	cfg := writeConfig(t, freePort(t), freePort(t), "")
	body, _ := os.ReadFile(cfg)
	body = []byte(strings.Replace(string(body), "neighbors = false\nmdns = false\nreverse_dns = false",
		"neighbors = true\nneighbor_interval_seconds = 5\nmdns = true\nreverse_dns = true\nreverse_dns_server = \""+ptr+"\"", 1))
	os.WriteFile(cfg, body, 0o600)
	r := start(t, cfg)
	stopped := false
	defer func() {
		if !stopped {
			r.stop()
		}
	}()
	names := func() map[string]string {
		out := map[string]string{}
		m := r.json("GET", "/api/devices", "", 200)
		for _, d := range m["devices"].([]any) {
			dm := d.(map[string]any)
			out[dm["ips"].([]any)[0].(string)] = dm["name"].(string)
		}
		return out
	}
	waitUntil(t, "device names from mDNS and reverse DNS", func() bool {
		n := names()
		return n["192.0.2.50"] == "studio-mac" && n["192.0.2.51"] == "nas-box.example"
	})
	path := filepath.Join(filepath.Dir(cfg), "data", "devices.json")
	waitUntil(t, "the periodic save", func() bool { _, err := os.Stat(path); return err == nil })
	r.stop()
	stopped = true
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("devices.json: %v %v", info, err)
	}
	// A restart restores the names without any source running.
	body = []byte(strings.Replace(string(body), "neighbors = true", "neighbors = false", 1))
	body = []byte(strings.Replace(string(body), "mdns = true", "mdns = false", 1))
	body = []byte(strings.Replace(string(body), "reverse_dns = true", "reverse_dns = false", 1))
	os.WriteFile(cfg, body, 0o600)
	r2 := start(t, cfg)
	defer r2.stop()
	m := r2.json("GET", "/api/devices", "", 200)
	if m["total"].(float64) != 2 {
		t.Errorf("devices after restart = %v", m)
	}
}

func TestReverseDNSWithoutAResolverIsSkipped(t *testing.T) {
	old := procRoutePath
	procRoutePath = filepath.Join(t.TempDir(), "no-route-table")
	defer func() { procRoutePath = old }()
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	body, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, []byte(strings.Replace(string(body), "reverse_dns = false", "reverse_dns = true", 1)), 0o600)
	r := start(t, cfg)
	r.stop()
	// With a route table the gateway becomes the resolver (nothing is asked here: no devices).
	route := filepath.Join(t.TempDir(), "route")
	os.WriteFile(route, []byte("Iface\tDestination\tGateway\tFlags\neth0\t00000000\t010200C0\t0003\n"), 0o600)
	procRoutePath = route
	r = start(t, cfg)
	r.stop()
}

func TestDevicesCanBeSwitchedOffEntirely(t *testing.T) {
	cfg := writeConfig(t, freePort(t), freePort(t), "")
	body, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, []byte(strings.Replace(string(body), "[devices]\n", "[devices]\nenabled = false\n", 1)), 0o600)
	r := start(t, cfg)
	defer r.stop()
	q := new(dns.Msg)
	q.SetQuestion("mask.icloud.com.", dns.TypeA)
	_, _, _ = (&dns.Client{Timeout: time.Second}).Exchange(q, r.dnsAddr)
	if m := r.json("GET", "/api/devices", "", 200); m["total"].(float64) != 0 {
		t.Errorf("a disabled registry learns nothing: %v", m)
	}
}

func TestDeviceSourceFailuresAreLoggedNotFatal(t *testing.T) {
	allowLoopbackDevices(t)
	oldN, oldM, oldS := neighborSources, runMDNS, saveEvery
	neighborSources = func() []devices.NeighborSource {
		return []devices.NeighborSource{devices.FileNeighbors{Path: filepath.Join(t.TempDir(), "missing"), Parse: devices.ParseProcNetARP}}
	}
	runMDNS = func(context.Context, *devices.MDNSListener) error {
		return errors.New("synthetic: no multicast interface")
	}
	saveEvery = 20 * time.Millisecond
	defer func() { neighborSources, runMDNS, saveEvery = oldN, oldM, oldS }()

	cfg := writeConfig(t, freePort(t), freePort(t), "")
	body, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, []byte(strings.Replace(string(body), "neighbors = false\nmdns = false", "neighbors = true\nneighbor_interval_seconds = 5\nmdns = true", 1)), 0o600)
	// A saved file that is really a non-empty directory makes every save fail.
	path := filepath.Join(filepath.Dir(cfg), "data", "devices.json")
	r := start(t, cfg)
	os.Remove(path)
	os.MkdirAll(filepath.Join(path, "keep"), 0o750)
	q := new(dns.Msg)
	q.SetQuestion("mask.icloud.com.", dns.TypeA)
	_, _, _ = (&dns.Client{Timeout: time.Second}).Exchange(q, r.dnsAddr) // a client, so the registry changes and a save is attempted
	time.Sleep(150 * time.Millisecond)
	if m := r.json("GET", "/api/devices", "", 200); m["total"].(float64) != 1 {
		t.Errorf("the registry keeps working when saving fails: %v", m)
	}
	r.stop() // shutdown must still complete
}
