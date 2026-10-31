// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal RFC 5321 server, just enough of one to drive
// net/smtp (what SMTPSender uses) through every outcome this package
// classifies. It never touches a real network: it only ever listens on
// 127.0.0.1, and every test server is closed when its test ends. No real
// email is ever sent anywhere by this package's tests.
type fakeSMTP struct {
	ln            net.Listener
	tlsConfig     *tls.Config
	offerStartTLS bool
	implicitTLS   bool
	authFail      bool
	mailFail      bool
	rcptFail      bool
	dataFail      bool

	mu       sync.Mutex
	received []string // successfully queued message bodies, for assertions
	commands []string // every command verb received, for assertions
}

// commandsSeen returns every command verb (EHLO, AUTH, MAIL, ...) the
// server has received so far, in order.
func (s *fakeSMTP) commandsSeen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTP{ln: ln, tlsConfig: generateTestTLSConfig(t)}
	t.Cleanup(func() { ln.Close() })
	return s
}

// start launches the accept loop. Call it only after setting every field
// (offerStartTLS, implicitTLS, authFail, ...): they are read without a lock
// from the connection goroutines, which is safe only because tests never
// change them again afterward.
func (s *fakeSMTP) start() { go s.serve() }

func (s *fakeSMTP) addr() string { return s.ln.Addr().String() }

func (s *fakeSMTP) port() int {
	_, p, _ := net.SplitHostPort(s.addr())
	n, _ := strconv.Atoi(p)
	return n
}

func (s *fakeSMTP) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	if s.implicitTLS {
		tc := tls.Server(conn, s.tlsConfig)
		if err := tc.Handshake(); err != nil {
			return
		}
		conn = tc
	}
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 fake.example.com ESMTP fake SMTP for tests")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		verb, _, _ := strings.Cut(upper, " ")
		s.mu.Lock()
		s.commands = append(s.commands, verb)
		s.mu.Unlock()
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			_ = tp.PrintfLine("250-fake.example.com greets you")
			if s.offerStartTLS {
				_ = tp.PrintfLine("250-STARTTLS")
			}
			_ = tp.PrintfLine("250 AUTH PLAIN")
		case upper == "STARTTLS":
			_ = tp.PrintfLine("220 ready to start TLS")
			tc := tls.Server(conn, s.tlsConfig)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn = tc
			tp = textproto.NewConn(conn)
		case strings.HasPrefix(upper, "AUTH"):
			if s.authFail {
				_ = tp.PrintfLine("535 5.7.8 authentication failed")
			} else {
				_ = tp.PrintfLine("235 2.7.0 authentication succeeded")
			}
		case strings.HasPrefix(upper, "MAIL FROM"):
			if s.mailFail {
				_ = tp.PrintfLine("451 4.3.0 mail from temporarily rejected")
			} else {
				_ = tp.PrintfLine("250 2.1.0 OK")
			}
		case strings.HasPrefix(upper, "RCPT TO"):
			if s.rcptFail {
				_ = tp.PrintfLine("550 5.1.1 no such user")
			} else {
				_ = tp.PrintfLine("250 2.1.5 OK")
			}
		case upper == "DATA":
			if s.dataFail {
				_ = tp.PrintfLine("451 4.3.0 temporarily unable to accept data")
				continue
			}
			_ = tp.PrintfLine("354 go ahead")
			var body strings.Builder
			for {
				l, err := tp.ReadLine()
				if err != nil {
					return
				}
				if l == "." {
					break
				}
				body.WriteString(l)
				body.WriteString("\n")
			}
			s.mu.Lock()
			s.received = append(s.received, body.String())
			s.mu.Unlock()
			_ = tp.PrintfLine("250 2.0.0 OK: queued")
		case upper == "QUIT":
			_ = tp.PrintfLine("221 2.0.0 bye")
			return
		default:
			_ = tp.PrintfLine("500 5.5.1 unrecognized command")
		}
	}
}

// generateTestTLSConfig returns a server TLS config with a freshly
// generated, self-signed certificate for 127.0.0.1 and localhost. It is
// only ever used by this package's own tests, against this package's own
// loopback fake server.
func generateTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}
