// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

type atomicInt = atomic.Int32

// fakeUpstreamCounting answers every query (including probe names) with
// NXDOMAIN and counts them.
func fakeUpstreamCounting(t *testing.T, hits *atomicInt) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// freeUDPAndTCPPort returns a port that is free for both protocols.
func freeUDPAndTCPPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", "127.0.0.1:"+itoa(port))
		ln.Close()
		if err == nil {
			pc.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
