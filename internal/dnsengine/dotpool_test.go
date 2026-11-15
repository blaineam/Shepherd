// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// trackedListener counts accepted connections and lets a test sever every
// server-side connection, which is what a resolver's idle timeout or a NAT
// that forgot the flow looks like to the client.
type trackedListener struct {
	net.Listener
	accepted atomic.Int32
	closed   atomic.Int32
	mu       sync.Mutex
	conns    []net.Conn
}

type trackedConn struct {
	net.Conn
	l    *trackedListener
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.l.closed.Add(1) })
	return c.Conn.Close()
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.accepted.Add(1)
	tc := &trackedConn{Conn: c, l: l}
	l.mu.Lock()
	l.conns = append(l.conns, tc)
	l.mu.Unlock()
	return tc, nil
}

func (l *trackedListener) severAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = nil
}

func dotFixture(t *testing.T) (*trackedListener, *Pool, string) {
	t.Helper()
	certSrc := newDoHTest(t, func(http.ResponseWriter, *http.Request, *dns.Msg) {})
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := &trackedListener{Listener: raw}
	startDoT(t, tl, certSrc.cert())
	_, port, _ := net.SplitHostPort(raw.Addr().String())
	addr := "tls://127.0.0.1:" + port
	return tl, testPool(t, nil, certSrc.roots, addr), addr
}

func dotAsk(t *testing.T, p *Pool, name string) {
	t.Helper()
	resp, _, _, err := p.Exchange(context.Background(), aQuery(name))
	if err != nil || len(resp.Answer) != 1 {
		t.Fatalf("exchange %s: %v", name, err)
	}
}

func TestDoTReusesOneConnectionForSequentialQueries(t *testing.T) {
	tl, p, _ := dotFixture(t)
	for i := 0; i < 5; i++ {
		dotAsk(t, p, "reuse.example.org.")
	}
	if n := tl.accepted.Load(); n != 1 {
		t.Fatalf("5 sequential DoT queries used %d connections, want 1", n)
	}
}

func TestDoTStaleConnectionIsRetriedOnAFreshOneWithoutAnError(t *testing.T) {
	tl, p, _ := dotFixture(t)
	dotAsk(t, p, "a.example.org.")
	tl.severAll() // the server hung up on the idle connection
	dotAsk(t, p, "b.example.org.")
	if n := tl.accepted.Load(); n != 2 {
		t.Fatalf("accepted %d connections, want 2 (one stale, one fresh)", n)
	}
	for _, st := range p.Status() {
		if st.Errors != 0 {
			t.Fatalf("a stale pooled connection is not an upstream failure: %+v", st)
		}
	}
}

func TestDoTIdleConnectionExpires(t *testing.T) {
	tl, p, _ := dotFixture(t)
	u := p.snapshot()[0]
	now := time.Now()
	u.idle.now = func() time.Time { return now }
	dotAsk(t, p, "a.example.org.")
	now = now.Add(dotIdleTTL + time.Second)
	dotAsk(t, p, "b.example.org.")
	if n := tl.accepted.Load(); n != 2 {
		t.Fatalf("accepted %d, want 2: a connection idle past the TTL must not be reused", n)
	}
}

func TestDoTConcurrentQueriesShareTheIdleCap(t *testing.T) {
	tl, p, _ := dotFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); dotAsk(t, p, "c.example.org.") }()
	}
	wg.Wait()
	u := p.snapshot()[0]
	if n := u.idle.len(); n > dotMaxIdle {
		t.Fatalf("%d idle connections kept, cap is %d", n, dotMaxIdle)
	}
	if tl.accepted.Load() < 1 {
		t.Fatal("no connection was made")
	}
	// The surplus connections were closed rather than leaked.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if int(tl.accepted.Load()-tl.closed.Load()) <= dotMaxIdle {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("accepted %d, closed %d: more than %d left open", tl.accepted.Load(), tl.closed.Load(), dotMaxIdle)
}

func TestDoTRemoveClosesPooledConnections(t *testing.T) {
	tl, p, addr := dotFixture(t)
	dotAsk(t, p, "a.example.org.")
	if err := p.Add("192.0.2.9"); err != nil { // keep the pool non-empty
		t.Fatal(err)
	}
	if err := p.Remove(addr); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tl.closed.Load() == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("removing the upstream left its connection open (closed=%d)", tl.closed.Load())
}

func TestDoTCancelledContextDoesNotPoisonThePool(t *testing.T) {
	tl, p, _ := dotFixture(t)
	dotAsk(t, p, "a.example.org.")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := p.Exchange(ctx, aQuery("b.example.org.")); err == nil {
		t.Fatal("a cancelled context must fail")
	}
	dotAsk(t, p, "c.example.org.")
	if n := tl.accepted.Load(); n != 1 {
		t.Fatalf("accepted %d, want 1: the idle connection should have survived", n)
	}
}

func TestDoTFreshHandshakeUsesASessionCache(t *testing.T) {
	_, p, _ := dotFixture(t)
	u := p.snapshot()[0]
	if u.dotClientConfig().ClientSessionCache == nil {
		t.Fatal("DoT handshakes should resume TLS sessions")
	}
}
