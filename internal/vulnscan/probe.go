// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"shepherd/internal/portscan"
)

// DialFunc opens a bare TCP connection for one probe, the exact seam
// internal/portscan.Scanner already uses: production dials for real, tests
// inject a fake and never touch a real socket.
type DialFunc = portscan.DialFunc

func defaultDial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// TLSConn is the subset of *tls.Conn this package needs: Read/Write/Close
// like any net.Conn, plus ConnectionState so a signature can inspect what
// was actually negotiated. *tls.Conn satisfies this directly; tests inject
// a fake that never touches real TLS at all.
type TLSConn interface {
	net.Conn
	ConnectionState() tls.ConnectionState
}

// TLSConnectFunc performs the TLS handshake over an already-dialed TCP
// connection, the TLS analog of DialFunc: production wraps conn in a real
// *tls.Conn and runs a real handshake bounded by ctx; tests inject a fake
// TLSConn and never touch a real socket or certificate.
type TLSConnectFunc func(ctx context.Context, conn net.Conn, cfg *tls.Config) (TLSConn, error)

func defaultTLSConnect(ctx context.Context, conn net.Conn, cfg *tls.Config) (TLSConn, error) {
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tc, nil
}

// tlsProbeCipherSuites is every cipher suite Go's own TLS stack still
// implements, including the ones it marks insecure (tls.InsecureCipherSuites):
// offering the full list, rather than Go's safe-by-default set, is what lets
// a server that only supports a weak suite reveal that by what it actually
// picks, instead of the handshake simply failing against Go's modern
// defaults. See tlsWeakCipherSuiteName in signature.go for the other half.
var tlsProbeCipherSuites = buildTLSProbeCipherSuites()

func buildTLSProbeCipherSuites() []uint16 {
	var ids []uint16
	for _, c := range tls.CipherSuites() {
		ids = append(ids, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		ids = append(ids, c.ID)
	}
	return ids
}

// tlsProbeConfig returns the *tls.Config every TLS probe handshakes with:
// InsecureSkipVerify because this package judges certificate dates itself
// (see the tls-cert-* signatures) and deliberately never anything about a
// self-signed certificate or a hostname mismatch — both are routine on a
// home LAN and would be noise, not a finding (docs/VULNSCAN.md). MinVersion
// is TLS 1.0, the oldest version Go's own crypto/tls still implements (Go
// dropped SSLv3 outright, so this package cannot test for it at all — also
// documented), offered alongside every cipher suite Go knows, so a weak
// server reveals itself by what it negotiates rather than being refused a
// connection by Go's modern defaults.
func tlsProbeConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       tlsProbeCipherSuites,
	}
}

// interestingPorts is every port probePort knows how to interpret. Scanner
// filters a device's open ports down to this set before dialing anything,
// so vulnscan never opens a connection it would do nothing useful with (and
// never duplicates portscan's own "is this port open" check for ports it
// has no deeper signal for).
var interestingPorts = map[int]bool{
	21: true, 22: true, 23: true, 25: true, 80: true, 110: true, 143: true,
	443: true, 445: true, 465: true, 587: true, 993: true, 995: true,
	2375: true, 2376: true, 3000: true, 5000: true, 8000: true, 8080: true,
	8443: true, 8888: true,
}

// bannerPorts send a greeting immediately after the TCP handshake, before
// the client sends anything: a plain read is enough to grab it. 465, 993
// and 995 are deliberately absent: those are implicit-TLS ports (SMTPS,
// IMAPS, POP3S) whose first bytes are a TLS handshake, not a plaintext
// greeting; they are tlsPorts instead. 587 stays here: SMTP submission's
// TLS is explicit (STARTTLS, after a plaintext greeting), so a plain read
// is still the right first move there.
var bannerPorts = map[int]bool{22: true, 23: true, 25: true, 110: true, 143: true, 587: true}

// httpPorts get a minimal plaintext HTTP/1.0 GET /. TLS ports (443, 8443)
// are deliberately not probed this way: see tlsHTTPPorts and
// docs/VULNSCAN.md.
var httpPorts = map[int]bool{80: true, 3000: true, 5000: true, 8000: true, 8080: true, 8888: true}

// tlsPorts get a real TLS handshake (certificate and negotiated
// protocol/cipher inspected by the tls-* signatures) before anything else:
// the two HTTPS admin ports, Docker's TLS port, and the three implicit-TLS
// mail ports.
var tlsPorts = map[int]bool{443: true, 8443: true, 2376: true, 465: true, 993: true, 995: true}

// tlsHTTPPorts additionally get the same minimal plaintext-shaped HTTP/1.0
// GET / as httpPorts, but sent over the now-decrypted TLS channel: the
// HTTPS variant of the Apache/nginx/lighttpd Server-header signatures
// already in signature.go, with no new signature code needed since they
// match on Probe.HTTPServer regardless of which port it came from.
var tlsHTTPPorts = map[int]bool{443: true, 8443: true}

// probePort runs the single gentle, protocol-appropriate exchange for one
// open port and returns whatever it learned. It never returns an error: a
// failed, refused or empty probe just yields a mostly-empty Probe (no
// signature fires without positive evidence, so "could not learn anything"
// is handled correctly just by learning nothing).
func probePort(ctx context.Context, dial DialFunc, tlsConnect TLSConnectFunc, timeout time.Duration, ip string, port int) Probe {
	p := Probe{Port: port}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(cctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return p
	}
	defer conn.Close()
	p.Connected = true
	_ = conn.SetDeadline(time.Now().Add(timeout))

	switch {
	case port == 21:
		probeFTP(conn, &p)
	case bannerPorts[port]:
		p.Banner = readBanner(conn)
	case httpPorts[port]:
		probeHTTP(conn, &p)
	case port == 445:
		probeSMB1(conn, &p)
	case port == 2375:
		probeDocker(conn, &p)
	case tlsPorts[port]:
		probeTLSWrapped(cctx, tlsConnect, conn, &p, port)
	}
	return p
}

// probeTLSWrapped runs the TLS handshake over conn (already a live TCP
// connection) and, only once that succeeds, records what was negotiated and
// — for the ports where it makes sense — runs the same application-level
// probe plaintext ports get, now over the decrypted channel. A handshake
// failure (refused version/cipher, timeout, anything else) leaves every TLS
// field at its zero value: "could not learn anything" is handled by
// learning nothing, the same rule every other probe in this file follows.
func probeTLSWrapped(ctx context.Context, tlsConnect TLSConnectFunc, conn net.Conn, p *Probe, port int) {
	tc, err := tlsConnect(ctx, conn, tlsProbeConfig())
	if err != nil {
		return
	}
	defer tc.Close()

	state := tc.ConnectionState()
	p.TLSNegotiated = true
	p.TLSVersion = state.Version
	p.TLSCipherSuite = state.CipherSuite
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		p.TLSCertNotBefore = leaf.NotBefore
		p.TLSCertNotAfter = leaf.NotAfter
	}

	switch {
	case tlsHTTPPorts[port]:
		probeHTTP(tc, p)
	case port == 2376:
		probeDocker(tc, p)
	}
}

// readBanner reads whatever a server sent so far (one Read, bounded by the
// conn's own deadline) and returns it cleaned of control characters and
// bounded in length. A read that returns nothing, or errors immediately,
// yields "".
func readBanner(conn net.Conn) string {
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return cleanBanner(buf[:n])
}

const maxBannerLen = 256

func cleanBanner(b []byte) string {
	s := strings.ToValidUTF8(string(b), "")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxBannerLen {
		s = s[:maxBannerLen]
	}
	return s
}

func writeLine(conn net.Conn, s string) bool {
	_, err := conn.Write([]byte(s + "\r\n"))
	return err == nil
}

// probeFTP reads the greeting and, only when it actually looks like an FTP
// server (a "220" reply), tries the well-known anonymous account: USER
// anonymous, then (only on a 331 "need password" reply) PASS with a clearly
// placeholder value. A final 230 means the login succeeded.
func probeFTP(conn net.Conn, p *Probe) {
	p.Banner = readBanner(conn)
	if !strings.HasPrefix(p.Banner, "220") {
		return
	}
	if !writeLine(conn, "USER anonymous") {
		return
	}
	resp := readBanner(conn)
	if strings.HasPrefix(resp, "230") {
		p.FTPAnonLogin = true
		return
	}
	if !strings.HasPrefix(resp, "331") {
		return
	}
	// leakcheck:allow placeholder FTP password, never a real credential
	if !writeLine(conn, "PASS shepherd-vulnscan@invalid") {
		return
	}
	if strings.HasPrefix(readBanner(conn), "230") {
		p.FTPAnonLogin = true
	}
}

// probeHTTP sends a minimal HTTP/1.0 request and parses whatever comes back
// with the standard library's own response parser, rather than hand-rolling
// header parsing.
func probeHTTP(conn net.Conn, p *Probe) {
	req := "GET / HTTP/1.0\r\nHost: shepherd-vulnscan\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	p.HTTPStatus = resp.StatusCode
	p.HTTPServer = cleanBanner([]byte(resp.Header.Get("Server")))
}

// probeDocker asks the Docker Engine API's own unauthenticated /version
// endpoint. A real Docker daemon answers JSON containing "ApiVersion"; TLS
// Docker (2376) and anything else fails the plain-HTTP parse or the body
// check and reports nothing.
func probeDocker(conn net.Conn, p *Probe) {
	req := "GET /version HTTP/1.0\r\nHost: shepherd-vulnscan\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if bytes.Contains(body, []byte(`"ApiVersion"`)) || bytes.Contains(body, []byte(`"GitCommit"`)) {
		p.DockerAPIOpen = true
	}
}

// smb1Dialect is the dialect string that signals SMB1/CIFS support
// ("NT LM 0.12"), the one every SMB1-capable server since Windows NT has
// understood.
const smb1Dialect = "NT LM 0.12"

// smb1NegotiateRequest builds a minimal raw SMBv1 Negotiate Protocol
// Request offering exactly one dialect, framed for direct-TCP transport on
// port 445 (a 4-byte length header, the same framing NetBIOS session
// service uses, but with no NetBIOS session actually established).
func smb1NegotiateRequest() []byte {
	dialect := append([]byte{0x02}, append([]byte(smb1Dialect), 0x00)...)

	header := make([]byte, 32)
	header[0], header[1], header[2], header[3] = 0xFF, 'S', 'M', 'B'
	header[4] = 0x72 // SMB_COM_NEGOTIATE
	header[9] = 0x18 // Flags: case-insensitive, canonicalized paths (a typical client default)

	msg := make([]byte, 0, len(header)+3+len(dialect))
	msg = append(msg, header...)
	msg = append(msg, 0x00) // WordCount
	bc := len(dialect)
	msg = append(msg, byte(bc), byte(bc>>8)) // ByteCount, little-endian
	msg = append(msg, dialect...)

	out := make([]byte, 4+len(msg))
	l := len(msg)
	out[1], out[2], out[3] = byte(l>>16), byte(l>>8), byte(l)
	copy(out[4:], msg)
	return out
}

// probeSMB1 sends the negotiate request and inspects the raw reply's SMB
// header: 0xFF 'S' 'M' 'B' means the server answered in SMB1 itself (SMBv1
// is enabled); anything else (an SMB2 header 0xFE 'S' 'M' 'B', a short
// reply, or no reply at all) is left unflagged — this probe only reports a
// positive, confirmed finding, never a guess.
func probeSMB1(conn net.Conn, p *Probe) {
	if _, err := conn.Write(smb1NegotiateRequest()); err != nil {
		return
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n < 8 {
		return
	}
	body := buf[4:n] // skip the 4-byte direct-TCP length header
	if len(body) >= 4 && body[0] == 0xFF && body[1] == 'S' && body[2] == 'M' && body[3] == 'B' {
		p.SMB1Negotiated = true
	}
}
