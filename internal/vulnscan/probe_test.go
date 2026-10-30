// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// scriptedConn is a net.Conn that touches no real socket: Read returns the
// next chunk from a canned script (or io.EOF once exhausted), and every
// Write is recorded so tests can assert what probePort sent.
type scriptedConn struct {
	script  [][]byte
	writes  [][]byte
	closed  bool
	readErr error
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	if len(c.script) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		return 0, io.EOF
	}
	chunk := c.script[0]
	c.script = c.script[1:]
	n := copy(b, chunk)
	return n, nil
}
func (c *scriptedConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (c *scriptedConn) Close() error                     { c.closed = true; return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func dialScripted(conn *scriptedConn, err error) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

// scriptedTLSConn is a TLSConn that touches no real TLS at all: it embeds a
// scriptedConn for Read/Write/Close and reports a canned ConnectionState,
// so tests can control exactly what a signature sees was "negotiated"
// without ever running a real handshake.
type scriptedTLSConn struct {
	*scriptedConn
	state tls.ConnectionState
}

func (c *scriptedTLSConn) ConnectionState() tls.ConnectionState { return c.state }

// dialTLSScripted builds a TLSConnectFunc that ignores the real conn it is
// handed and returns tc (or err) instead — the TLS-handshake analog of
// dialScripted/dialByAddress.
func dialTLSScripted(tc TLSConn, err error) TLSConnectFunc {
	return func(ctx context.Context, conn net.Conn, cfg *tls.Config) (TLSConn, error) {
		if err != nil {
			return nil, err
		}
		return tc, nil
	}
}

// noTLSConnect is a TLSConnectFunc for tests that never probe a TLS port:
// calling it at all is a test bug, so it fails loudly rather than silently
// returning an empty TLSConn.
func noTLSConnect(ctx context.Context, conn net.Conn, cfg *tls.Config) (TLSConn, error) {
	return nil, errors.New("noTLSConnect: should never be called for a non-TLS port")
}

func TestProbePortDialFailureYieldsEmptyProbe(t *testing.T) {
	p := probePort(context.Background(), dialScripted(nil, errors.New("refused")), noTLSConnect, time.Second, "192.0.2.1", 22)
	if p.Port != 22 || p.Banner != "" {
		t.Fatalf("probePort on a dial failure = %+v, want empty", p)
	}
}

func TestProbePortClosesTheConnection(t *testing.T) {
	c := &scriptedConn{script: [][]byte{[]byte("SSH-2.0-OpenSSH_9.6\r\n")}}
	probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 22)
	if !c.closed {
		t.Fatal("probePort must close the connection it dialed")
	}
}

func TestProbePortSSHBanner(t *testing.T) {
	c := &scriptedConn{script: [][]byte{[]byte("SSH-2.0-OpenSSH_9.6\r\n")}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 22)
	if p.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("Banner = %q", p.Banner)
	}
}

func TestProbePortBannerIsCleanedAndBounded(t *testing.T) {
	dirty := "SSH-2.0-OpenSSH_9.6\x00\x01\r\n" + string(bytes.Repeat([]byte("x"), 400))
	c := &scriptedConn{script: [][]byte{[]byte(dirty)}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 25)
	if len(p.Banner) > 256 {
		t.Fatalf("Banner not bounded: %d bytes", len(p.Banner))
	}
	for _, r := range p.Banner {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("Banner contains a control byte: %q", p.Banner)
		}
	}
}

func TestProbePortFTPAnonymousLoginAccepted(t *testing.T) {
	c := &scriptedConn{script: [][]byte{
		[]byte("220 Ready\r\n"),
		[]byte("331 Please specify password\r\n"),
		[]byte("230 Login successful\r\n"),
	}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 21)
	if !p.FTPAnonLogin {
		t.Fatalf("probe = %+v, want FTPAnonLogin", p)
	}
	if len(c.writes) != 2 {
		t.Fatalf("writes = %q, want USER then PASS", c.writes)
	}
	if !bytes.HasPrefix(c.writes[0], []byte("USER anonymous")) {
		t.Fatalf("first write = %q, want a USER anonymous command", c.writes[0])
	}
	if !bytes.HasPrefix(c.writes[1], []byte("PASS")) {
		t.Fatalf("second write = %q, want a PASS command", c.writes[1])
	}
}

func TestProbePortFTPAnonymousLoginRejected(t *testing.T) {
	c := &scriptedConn{script: [][]byte{
		[]byte("220 Ready\r\n"),
		[]byte("530 Login incorrect\r\n"),
	}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 21)
	if p.FTPAnonLogin {
		t.Fatal("rejected USER anonymous must not report FTPAnonLogin")
	}
	if len(c.writes) != 1 {
		t.Fatalf("writes = %q, want only USER (no PASS after a non-331 reply)", c.writes)
	}
}

func TestProbePortFTPNonFTPBannerSkipsLogin(t *testing.T) {
	c := &scriptedConn{script: [][]byte{[]byte("not ftp at all\r\n")}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 21)
	if p.FTPAnonLogin || len(c.writes) != 0 {
		t.Fatalf("probe = %+v, writes = %q, want no login attempt against a non-FTP banner", p, c.writes)
	}
}

func TestProbePortHTTPServerHeader(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 0\r\n\r\n"
	c := &scriptedConn{script: [][]byte{[]byte(resp)}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 80)
	if p.HTTPServer != "Apache/2.4.49 (Unix)" || p.HTTPStatus != 200 {
		t.Fatalf("probe = %+v", p)
	}
	if len(c.writes) != 1 {
		t.Fatalf("writes = %q, want one GET request", c.writes)
	}
}

func TestProbePortDockerAPIOpen(t *testing.T) {
	body := `{"Version":"24.0.7","ApiVersion":"1.43","GitCommit":"abc123"}`
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	c := &scriptedConn{script: [][]byte{[]byte(resp)}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 2375)
	if !p.DockerAPIOpen {
		t.Fatalf("probe = %+v, want DockerAPIOpen", p)
	}
}

func TestProbePortDockerAPIClosedOrUnrelated(t *testing.T) {
	c := &scriptedConn{script: [][]byte{[]byte("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 2375)
	if p.DockerAPIOpen {
		t.Fatal("a 401 must not report DockerAPIOpen")
	}
}

func TestProbePortSMB1NegotiatedTrue(t *testing.T) {
	// 4-byte direct-TCP framing + an SMB1-signed response header.
	resp := append([]byte{0x00, 0x00, 0x00, 0x04}, []byte{0xFF, 'S', 'M', 'B'}...)
	c := &scriptedConn{script: [][]byte{resp}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 445)
	if !p.SMB1Negotiated {
		t.Fatalf("probe = %+v, want SMB1Negotiated", p)
	}
}

func TestProbePortSMB1NegotiatedFalseOnSMB2Reply(t *testing.T) {
	resp := append([]byte{0x00, 0x00, 0x00, 0x04}, []byte{0xFE, 'S', 'M', 'B'}...)
	c := &scriptedConn{script: [][]byte{resp}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 445)
	if p.SMB1Negotiated {
		t.Fatal("an SMB2-framed reply must not report SMB1Negotiated")
	}
}

func TestProbePortSMB1NoReply(t *testing.T) {
	c := &scriptedConn{}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 445)
	if p.SMB1Negotiated {
		t.Fatal("no reply at all must not report SMB1Negotiated")
	}
}

func TestProbePortUnknownPortDoesNothing(t *testing.T) {
	c := &scriptedConn{script: [][]byte{[]byte("whatever")}}
	p := probePort(context.Background(), dialScripted(c, nil), noTLSConnect, time.Second, "192.0.2.1", 3306)
	if p.Banner != "" || p.HTTPServer != "" || p.DockerAPIOpen || p.SMB1Negotiated || p.FTPAnonLogin {
		t.Fatalf("probe for an unhandled port = %+v, want empty", p)
	}
}

func TestProbePortTLSHandshakeFailureYieldsNoTLSFields(t *testing.T) {
	c := &scriptedConn{}
	p := probePort(context.Background(), dialScripted(c, nil), dialTLSScripted(nil, errors.New("handshake failure")), time.Second, "192.0.2.1", 443)
	if p.TLSNegotiated || p.TLSVersion != 0 || p.TLSCipherSuite != 0 {
		t.Fatalf("probe on a TLS handshake failure = %+v, want every TLS field zero", p)
	}
	if !p.Connected {
		t.Fatal("the TCP connect itself still succeeded; Connected must stay true")
	}
}

func TestProbePortTLSRecordsNegotiatedVersionCipherAndCertDates(t *testing.T) {
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}
	tc := &scriptedTLSConn{scriptedConn: &scriptedConn{}, state: tls.ConnectionState{
		Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{leaf},
	}}
	p := probePort(context.Background(), dialScripted(&scriptedConn{}, nil), dialTLSScripted(tc, nil), time.Second, "192.0.2.1", 993)
	if !p.TLSNegotiated || p.TLSVersion != tls.VersionTLS13 || p.TLSCipherSuite != tls.TLS_AES_128_GCM_SHA256 {
		t.Fatalf("probe = %+v, want the negotiated version and cipher recorded", p)
	}
	if !p.TLSCertNotBefore.Equal(notBefore) || !p.TLSCertNotAfter.Equal(notAfter) {
		t.Fatalf("probe cert dates = %v/%v, want %v/%v", p.TLSCertNotBefore, p.TLSCertNotAfter, notBefore, notAfter)
	}
}

func TestProbePortTLSNoCertificatePresentedLeavesDatesZero(t *testing.T) {
	tc := &scriptedTLSConn{scriptedConn: &scriptedConn{}, state: tls.ConnectionState{Version: tls.VersionTLS13}}
	p := probePort(context.Background(), dialScripted(&scriptedConn{}, nil), dialTLSScripted(tc, nil), time.Second, "192.0.2.1", 995)
	if !p.TLSNegotiated || !p.TLSCertNotBefore.IsZero() || !p.TLSCertNotAfter.IsZero() {
		t.Fatalf("probe = %+v, want zero cert dates when no certificate was presented", p)
	}
}

func TestProbePortTLSOnMailPortsRunsNoApplicationProbe(t *testing.T) {
	raw := &scriptedConn{}
	tc := &scriptedTLSConn{scriptedConn: raw, state: tls.ConnectionState{Version: tls.VersionTLS12}}
	p := probePort(context.Background(), dialScripted(raw, nil), dialTLSScripted(tc, nil), time.Second, "192.0.2.1", 465)
	if !p.TLSNegotiated {
		t.Fatal("want the TLS handshake itself recorded for an implicit-TLS mail port")
	}
	if p.HTTPServer != "" || p.DockerAPIOpen {
		t.Fatalf("probe = %+v, want no HTTP or Docker probe attempted over a mail port", p)
	}
	if len(raw.writes) != 0 {
		t.Fatalf("writes = %q, want none: nothing should be sent after the handshake on a mail port", raw.writes)
	}
}

func TestProbePortTLSHTTPGetsServerHeader(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 0\r\n\r\n"
	raw := &scriptedConn{}
	tc := &scriptedTLSConn{scriptedConn: &scriptedConn{script: [][]byte{[]byte(resp)}}, state: tls.ConnectionState{Version: tls.VersionTLS12}}
	p := probePort(context.Background(), dialScripted(raw, nil), dialTLSScripted(tc, nil), time.Second, "192.0.2.1", 443)
	if p.HTTPServer != "Apache/2.4.49 (Unix)" || p.HTTPStatus != 200 {
		t.Fatalf("probe = %+v, want the HTTPS Server header picked up over TLS", p)
	}
	if len(tc.scriptedConn.writes) != 1 {
		t.Fatalf("writes = %q, want one GET sent over the TLS connection, not the raw one", tc.scriptedConn.writes)
	}
	if len(raw.writes) != 0 {
		t.Fatalf("raw conn writes = %q, want nothing written to the pre-handshake connection", raw.writes)
	}
}

func TestProbePortTLSDockerOverTLS(t *testing.T) {
	body := `{"Version":"24.0.7","ApiVersion":"1.43","GitCommit":"abc123"}`
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	tc := &scriptedTLSConn{scriptedConn: &scriptedConn{script: [][]byte{[]byte(resp)}}, state: tls.ConnectionState{Version: tls.VersionTLS12}}
	p := probePort(context.Background(), dialScripted(&scriptedConn{}, nil), dialTLSScripted(tc, nil), time.Second, "192.0.2.1", 2376)
	if !p.DockerAPIOpen {
		t.Fatalf("probe = %+v, want DockerAPIOpen over Docker's TLS port", p)
	}
}

func TestProbePortTLSOnHTTPSPortNotReachedIfHandshakeFails(t *testing.T) {
	p := probePort(context.Background(), dialScripted(&scriptedConn{}, nil), dialTLSScripted(nil, errors.New("tls: handshake failure")), time.Second, "192.0.2.1", 8443)
	if p.HTTPServer != "" || p.TLSNegotiated {
		t.Fatalf("probe = %+v, want no HTTP probe attempted when the TLS handshake itself failed", p)
	}
}
