// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/decoy"
	"shepherd/internal/detect"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
)

// waitAlarms polls until at least n alarms of the type exist.
func waitAlarms(t *testing.T, eng *alarms.Engine, typ string, n int) alarms.Page {
	t.Helper()
	var page alarms.Page
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{typ}}})
		if page.Total >= n {
			return page
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d %s alarms, got %d", n, typ, page.Total)
	return page
}

// pipeListener is a decoy listener the test connects to by hand.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { close(l.closed); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

type addrConn struct {
	net.Conn
	from string
}

func (c addrConn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(c.from))
}
func (c addrConn) Close() error { return nil }

func TestStartDetectOffDoesNothing(t *testing.T) {
	cfg := config.Default()
	cfg.Detect.Enabled = false
	engine, reg := testEngineAndRegistry(t)
	parts := startDetect(context.Background(), cfg, engine, reg, nil, nil)
	if parts.engine != nil || parts.decoy != nil || parts.skipPort != nil || engine.OnEntry != nil {
		t.Errorf("detect off still built %+v", parts)
	}
}

func TestStartDetectChainsTheHookRaisesAlarmsAndOpensDecoys(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.Detect.DecoyPorts = []int{23, 445}
	engine, reg := testEngineAndRegistry(t)
	id := reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: "02:00:00:00:00:03", IP: "192.0.2.30", Hostname: "tv"})
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	ln := &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
	oldListen, oldAddrs, oldEvery := decoyListen, localAddrs, detectEvery
	decoyListen = func(network, addr string) (net.Listener, error) {
		if addr != ":23" {
			return nil, errors.New("address already in use")
		}
		return ln, nil
	}
	localAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.2")} }
	detectEvery = time.Hour
	t.Cleanup(func() { decoyListen, localAddrs, detectEvery = oldListen, oldAddrs, oldEvery })

	var earlier []string
	engine.OnEntry = func(e dnsengine.Entry) { earlier = append(earlier, e.Name) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parts := startDetect(ctx, cfg, engine, reg, openTraffic(cfg), eng)
	if parts.engine == nil || parts.decoy == nil {
		t.Fatalf("parts = %+v", parts)
	}
	if got := parts.decoy.Listening(); len(got) != 1 || got[0] != 23 {
		t.Errorf("listening = %v", got)
	}
	if !parts.engine.Status().Traffic {
		t.Error("the traffic store was not handed to the checks")
	}

	// The hook that was already there still hears every query, and the
	// checks hear it too.
	engine.OnEntry(dnsengine.Entry{Client: "192.0.2.30", DeviceID: id, Device: "tv", Name: "dns.google", Action: "allowed", Time: time.Now()})
	if len(earlier) != 1 {
		t.Errorf("the earlier hook heard %v", earlier)
	}
	page := waitAlarms(t, eng, alarms.TypeEncryptedDNSLookup, 1)
	if a := page.Alarms[0]; a.DeviceID != id || !strings.Contains(a.Title, "tv looked up an encrypted-DNS resolver") {
		t.Errorf("alarm = %+v", a)
	}

	// A neighbour tries the decoy; Shepherd's own port scan does not count.
	ln.conns <- addrConn{from: "192.0.2.2:50000"}
	ln.conns <- addrConn{from: "192.0.2.30:50001"}
	ln.conns <- addrConn{from: "192.0.2.77:50002"}
	page = waitAlarms(t, eng, alarms.TypeDecoyTouched, 2)
	titles := page.Alarms[0].Title + "|" + page.Alarms[1].Title
	if !strings.Contains(titles, "tv tried a decoy Telnet port") || !strings.Contains(titles, "192.0.2.77 tried a decoy Telnet port") {
		t.Errorf("titles = %s", titles)
	}

	// The port scan leaves the decoy on this host alone, and nothing else.
	for _, c := range []struct {
		ip   string
		port int
		want bool
	}{{"192.0.2.2", 23, true}, {"127.0.0.1", 23, true}, {"192.0.2.2", 445, false}, {"192.0.2.2", 80, false}, {"192.0.2.30", 23, false}, {"nonsense", 23, false}} {
		if got := parts.skipPort(c.ip, c.port); got != c.want {
			t.Errorf("skipPort(%s, %d) = %v", c.ip, c.port, got)
		}
	}
}

func TestStartDetectWithoutDecoysOrAlarms(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.Detect.DecoyPorts = nil
	engine, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parts := startDetect(ctx, cfg, engine, reg, nil, nil)
	if parts.engine == nil || parts.decoy != nil || parts.skipPort != nil || parts.engine.Status().Traffic {
		t.Fatalf("parts = %+v", parts)
	}
	engine.OnEntry(dnsengine.Entry{Client: "192.0.2.9", Name: "dns.google", Action: "allowed"})
	if len(parts.engine.Recent()) != 1 {
		t.Error("a finding without an alarm engine should still be recorded")
	}
	reportDecoyTouch(nil, nil, decoy.Touch{Source: "192.0.2.9", Port: 23, Count: 1}) // logs, must not panic
}

func TestStartDetectSurvivesAnUnreadableState(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.Detect.DecoyPorts = nil
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "detect.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, reg := testEngineAndRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if parts := startDetect(ctx, cfg, engine, reg, nil, nil); parts.engine == nil {
		t.Fatal("a bad state file stopped the checks")
	}
}

func TestDetectDeviceSkipsHostRouterAndExcluded(t *testing.T) {
	_, reg := testEngineAndRegistry(t)
	add := func(mac, ip, name string) string {
		return reg.Observe(devices.Observation{Source: devices.SourceNeighbor, MAC: mac, IP: ip, Hostname: name})
	}
	host, router, cam, out, mac := add("02:00:00:00:01:01", "192.0.2.2", "nas"), add("02:00:00:00:01:02", "192.0.2.1", "gw"),
		add("02:00:00:00:01:03", "192.0.2.40", "cam"), add("02:00:00:00:01:04", "192.0.2.41", "guest"), add("02:00:00:00:01:05", "192.0.2.42", "mac")
	for id, typ := range map[string]string{router: string(devices.TypeRouter), cam: string(devices.TypeCamera), mac: string(devices.TypeLaptop)} {
		if err := reg.SetType(id, typ); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.SetExcluded(out, true); err != nil {
		t.Fatal(err)
	}
	info := detectDevice(reg, []netip.Addr{netip.MustParseAddr("192.0.2.2")})
	for id, want := range map[string]detect.DeviceInfo{
		host: {Skip: true}, router: {Skip: true}, out: {Skip: true}, cam: {Narrow: true}, mac: {},
	} {
		got, ok := info(id)
		if !ok || got.Skip != want.Skip || got.Narrow != want.Narrow || got.Name == "" {
			t.Errorf("%s: %+v ok=%v", id, got, ok)
		}
	}
	if _, ok := info("nobody"); ok {
		t.Error("an unknown device should not be described")
	}
	if len(hostAddrs()) == 0 {
		t.Log("this host reports no interface addresses")
	}
}

func TestEveryFindingKindHasItsOwnAlarm(t *testing.T) {
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	_, reg := testEngineAndRegistry(t)
	want := map[detect.Kind]string{
		detect.KindEncryptedDNS: alarms.TypeEncryptedDNSLookup, detect.KindSilentDNS: alarms.TypeDNSBypass,
		detect.KindRandomNames: alarms.TypeDNSRandomNames, detect.KindTunnel: alarms.TypeDNSTunnel,
		detect.KindBeacon: alarms.TypeDNSBeacon, detect.KindNewCountry: alarms.TypeNewCountry,
		detect.KindUploadSpike: alarms.TypeUploadSpike,
	}
	for kind, typ := range want {
		f := detect.Finding{Time: time.Now(), Kind: kind, Device: "Thing", Client: "192.0.2.50", Subject: "x.example", Summary: "s",
			Evidence: []detect.Evidence{{Label: "L", Value: "V"}}}
		got, title := findingAlarm(f)
		if got != typ || !strings.HasPrefix(title, "Thing ") {
			t.Errorf("%s -> %s %q", kind, got, title)
		}
		if _, ok := eng.Type(typ); !ok {
			t.Errorf("%s is not a registered alarm type", typ)
		}
		reportFinding(eng, reg, f)
		waitAlarms(t, eng, typ, 1)
	}
	if typ, title := findingAlarm(detect.Finding{Kind: "future", Device: "Thing"}); typ != "future" || title == "" {
		t.Errorf("unknown kind -> %s %q", typ, title)
	}
	if _, ok := eng.Type(alarms.TypeDecoyTouched); !ok {
		t.Error("decoy-touched is not a registered alarm type")
	}
}
