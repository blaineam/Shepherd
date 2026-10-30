// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/dnsengine"
)

func TestStartAlarmsBuildsAWorkingEngine(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	pool, err := dnsengine.NewPool([]string{"192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	eng, stop, err := startAlarms(context.Background(), cfg, pool)
	if err != nil {
		t.Fatal(err)
	}
	// stop cancels the Router's own background loop and waits for it to
	// actually exit before closing the engine, so the test's TempDir
	// cleanup never races a save still in flight.
	t.Cleanup(stop)
	if eng == nil {
		t.Fatal("startAlarms must return a usable engine")
	}
	if pool.OnHealthChange == nil {
		t.Fatal("startAlarms must wire the pool's health callback")
	}
	a, err := eng.RaiseSync(alarms.Event{Type: alarms.TypeTest})
	if err != nil || a.ID == "" {
		t.Fatalf("the returned engine must work: %v %+v", err, a)
	}
	// Persistence lives under <data_dir>/alarms, like the other state Shepherd keeps.
	if err := eng.Save(); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(cfg.DataDir, "alarms", alarms.AlarmsFile)); statErr != nil {
		t.Errorf("alarms.json was not written under <data_dir>/alarms: %v", statErr)
	}
}

func TestStartAlarmsFailsIfTheDirCannotBeCreated(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	// A plain file where the alarms directory needs to go, so MkdirAll fails.
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "alarms"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := dnsengine.NewPool([]string{"192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := startAlarms(context.Background(), cfg, pool); err == nil {
		t.Error("expected an error when the alarms directory cannot be created")
	}
}

func TestStartAlarmsFailsOnACorruptDeliveriesFile(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	dir := filepath.Join(cfg.DataDir, "alarms")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, alarms.DeliveriesFile), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := dnsengine.NewPool([]string{"192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := startAlarms(context.Background(), cfg, pool); err == nil {
		t.Error("expected an error when the router's saved delivery log is corrupt")
	}
}

func TestNtfyPublisherForRespectsEnabled(t *testing.T) {
	if ntfyPublisherFor(config.AlarmsNtfy{Enabled: false, Server: "https://ntfy.example.com", Topic: "t"}) != nil {
		t.Error("disabled ntfy must yield no publisher")
	}
	if ntfyPublisherFor(config.AlarmsNtfy{Enabled: true, Server: "https://ntfy.example.com", Topic: "t"}) == nil {
		t.Error("enabled ntfy must yield a publisher")
	}
}

// deadThenLiveUpstream returns an upstream address that fails every query
// until start() is called, after which it answers every query. The address
// never changes, so health transitions on it are real, not a reconfiguration.
func deadThenLiveUpstream(t *testing.T) (addr string, start func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = pc.LocalAddr().String()
	pc.Close() // nothing listens here yet: queries fail with "connection refused"
	return addr, func() {
		live, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Fatalf("relisten on %s: %v", addr, err)
		}
		srv := &dns.Server{PacketConn: live, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.9")})
			_ = w.WriteMsg(m)
		})}
		go srv.ActivateAndServe()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
}

// fakeLiveUpstream starts a DNS server on loopback that answers every query,
// and returns its address.
func fakeLiveUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.9")})
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestWireUpstreamAlarmsRaisesDownOnTotalOutageAndRecoveredOnAnswer(t *testing.T) {
	addr, start := deadThenLiveUpstream(t)
	pool, err := dnsengine.NewPool([]string{addr})
	if err != nil {
		t.Fatal(err)
	}
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	wireUpstreamAlarms(eng, pool)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx := context.Background()
	for i := 0; i < 2; i++ { // the second failure crosses the unhealthy threshold
		_, _, _, _ = pool.Exchange(ctx, q)
	}
	eng.Drain()
	page := eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeUpstreamDown}}})
	if page.Total != 1 {
		t.Fatalf("expected one upstream-down alarm after a total outage, got %d", page.Total)
	}

	start()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, _, err := pool.Exchange(ctx, q); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	eng.Drain()
	page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeUpstreamRecovered}}})
	if page.Total != 1 {
		t.Fatalf("expected one upstream-recovered alarm after it answered again, got %d", page.Total)
	}
}

func TestWireUpstreamAlarmsNoDownAlarmWhileAnotherUpstreamIsHealthy(t *testing.T) {
	addr, _ := deadThenLiveUpstream(t)
	other := fakeLiveUpstream(t) // answers throughout, so it stays healthy
	pool, err := dnsengine.NewPool([]string{addr, other})
	if err != nil {
		t.Fatal(err)
	}
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	wireUpstreamAlarms(eng, pool)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_, _, _, _ = pool.Exchange(ctx, q)
	}
	eng.Drain()
	page := eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeUpstreamDown}}})
	if page.Total != 0 {
		t.Fatalf("must not raise upstream-down while another upstream is healthy, got %d", page.Total)
	}
}
