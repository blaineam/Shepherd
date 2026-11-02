package dnsengine

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestHostResolverAsksTheBootstrapServersNotResolvConf(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.7")})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	r := HostResolver(func() []string { return []string{pc.LocalAddr().String()} })
	got, err := r.LookupHost(context.Background(), "updates.example.test")
	if err != nil || len(got) == 0 || got[0] != "192.0.2.7" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestHostResolverAddsPort53AndFallsBackWithoutServers(t *testing.T) {
	r := HostResolver(func() []string { return []string{"192.0.2.1", "192.0.2.2:5353"} })
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		c, err := r.Dial(ctx, "udp", "ignored:53")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	empty := HostResolver(func() []string { return nil })
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	c, err := empty.Dial(context.Background(), "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
