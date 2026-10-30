// SPDX-License-Identifier: AGPL-3.0-or-later

package reverseproxy

// These tests prove WebSocket upgrades work end to end through the proxy
// with nothing but the standard library: a hand-rolled RFC 6455 handshake
// and framing on both ends (a hijacking backend and a raw TLS client), so
// no WebSocket module is added to go.mod just to test a byte pipe.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

const (
	opText  = 0x1
	opBin   = 0x2
	opClose = 0x8
)

// wsWrite writes one final frame; clients must mask, servers must not.
func wsWrite(w io.Writer, op byte, payload []byte, mask bool) error {
	var hdr bytes.Buffer
	hdr.WriteByte(0x80 | op)
	m := byte(0)
	if mask {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		hdr.WriteByte(m | byte(n))
	case n <= 0xffff:
		hdr.WriteByte(m | 126)
		binary.Write(&hdr, binary.BigEndian, uint16(n))
	default:
		hdr.WriteByte(m | 127)
		binary.Write(&hdr, binary.BigEndian, uint64(n))
	}
	body := payload
	if mask {
		var key [4]byte
		rand.Read(key[:])
		hdr.Write(key[:])
		body = make([]byte, len(payload))
		for i := range payload {
			body[i] = payload[i] ^ key[i%4]
		}
	}
	if _, err := w.Write(hdr.Bytes()); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// wsRead reads one unfragmented frame and unmasks it if needed.
func wsRead(r io.Reader) (op byte, payload []byte, masked bool, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	if h[0]&0x80 == 0 {
		return 0, nil, false, errors.New("fragmented frames are not used by these tests")
	}
	op, masked = h[0]&0x0f, h[1]&0x80 != 0
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var l uint16
		if err = binary.Read(r, binary.BigEndian, &l); err != nil {
			return
		}
		n = uint64(l)
	case 127:
		if err = binary.Read(r, binary.BigEndian, &n); err != nil {
			return
		}
	}
	var key [4]byte
	if masked {
		if _, err = io.ReadFull(r, key[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return
}

// wsBackend is a minimal WebSocket server in the shape Jellyfin's and
// Immich's live-update sockets have: it pushes a message first, unprompted,
// then echoes every client message back, and answers a close frame with
// its own before hanging up.
func wsBackend(t *testing.T, tlsBackend bool, sawHeaders chan<- http.Header) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			http.Error(w, "websocket upgrade expected", http.StatusBadRequest)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
			http.Error(w, "bad websocket handshake", http.StatusBadRequest)
			return
		}
		if sawHeaders != nil {
			hd := r.Header.Clone()
			hd.Set("Host", r.Host)
			sawHeaders <- hd
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		defer conn.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAccept(key))
		wsWrite(rw, opText, []byte("hello from backend"), false)
		rw.Flush()
		for {
			op, payload, masked, err := wsRead(rw)
			if err != nil {
				return
			}
			if !masked {
				t.Errorf("backend got an unmasked client frame; the proxy must pass frames through untouched")
			}
			if op == opClose {
				wsWrite(rw, opClose, payload, false)
				rw.Flush()
				return
			}
			out := append([]byte("echo: "), payload...)
			wsWrite(rw, op, out, false)
			rw.Flush()
		}
	})
	var srv *httptest.Server
	if tlsBackend {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv
}

// wsDial does what a browser does for wss://domain/path against the proxy's
// TLS listener: a fresh HTTP/1.1 connection (browsers only offer
// http/1.1 in ALPN for a WebSocket), the upgrade request, and a check of
// the 101 handshake. It returns the raw connection, ready for frames.
func wsDial(t *testing.T, addr, domain, path string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("dialing the proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if p := conn.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" {
		t.Fatalf("negotiated %q, want http/1.1", p)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var keyRaw [16]byte
	rand.Read(keyRaw[:])
	key := base64.StdEncoding.EncodeToString(keyRaw[:])
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nOrigin: https://%s\r\n\r\n", path, domain, key, domain)
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("reading the handshake response: %v", err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("handshake status %d (%s), want 101", res.StatusCode, b)
	}
	if got := res.Header.Get("Sec-WebSocket-Accept"); got != wsAccept(key) {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, wsAccept(key))
	}
	if !strings.EqualFold(res.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("Upgrade = %q", res.Header.Get("Upgrade"))
	}
	return conn, br
}

// exerciseSocket drives a full conversation: the backend's unprompted
// push (backend to client with no client byte to answer), several echoes,
// one frame over 64 KiB each way (the 64-bit length form), then a clean
// close handshake and the backend's hang-up reaching the client as EOF.
func exerciseSocket(t *testing.T, conn net.Conn, br *bufio.Reader) {
	t.Helper()
	op, payload, masked, err := wsRead(br)
	if err != nil || op != opText || string(payload) != "hello from backend" || masked {
		t.Fatalf("unprompted push = %d %q masked=%v err=%v", op, payload, masked, err)
	}
	for _, msg := range []string{"ping 1", "ping 2", `{"MessageType":"KeepAlive"}`} {
		if err := wsWrite(conn, opText, []byte(msg), true); err != nil {
			t.Fatalf("writing %q: %v", msg, err)
		}
		op, payload, _, err := wsRead(br)
		if err != nil || op != opText || string(payload) != "echo: "+msg {
			t.Fatalf("echo of %q = %d %q err=%v", msg, op, payload, err)
		}
	}
	big := make([]byte, 70000)
	rand.Read(big)
	if err := wsWrite(conn, opBin, big, true); err != nil {
		t.Fatalf("writing a large frame: %v", err)
	}
	op, payload, _, err = wsRead(br)
	if err != nil || op != opBin || !bytes.Equal(payload, append([]byte("echo: "), big...)) {
		t.Fatalf("large echo: op %d, %d bytes, err %v", op, len(payload), err)
	}
	if err := wsWrite(conn, opClose, []byte{0x03, 0xe8}, true); err != nil {
		t.Fatalf("writing close: %v", err)
	}
	op, _, _, err = wsRead(br)
	if err != nil || op != opClose {
		t.Fatalf("close reply = %d, %v", op, err)
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the backend hung up the client read %v, want EOF", err)
	}
}

func TestWebSocketUpgradeThroughTheProxy(t *testing.T) {
	saw := make(chan http.Header, 1)
	backend := wsBackend(t, false, saw)
	store := newTestStore(t, hostFor(t, "jellyfin.example.com", backend, "http", false))
	front, _ := frontDoor(t, New(Options{Hosts: store}))

	conn, br := wsDial(t, front.Listener.Addr().String(), "jellyfin.example.com", "/socket?api_key=k")
	hd := <-saw
	if hd.Get("Host") != "jellyfin.example.com" || hd.Get("X-Forwarded-Proto") != "https" || hd.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Errorf("backend saw Host %q, X-Forwarded-Proto %q, X-Forwarded-For %q", hd.Get("Host"), hd.Get("X-Forwarded-Proto"), hd.Get("X-Forwarded-For"))
	}
	if hd.Get("Origin") != "https://jellyfin.example.com" {
		t.Errorf("backend saw Origin %q; apps check it against the public name", hd.Get("Origin"))
	}
	exerciseSocket(t, conn, br)
}

func TestWebSocketUpgradeToAnHTTPSBackend(t *testing.T) {
	backend := wsBackend(t, true, nil)
	store := newTestStore(t, hostFor(t, "immich.example.com", backend, "https", true))
	front, _ := frontDoor(t, New(Options{Hosts: store}))
	conn, br := wsDial(t, front.Listener.Addr().String(), "immich.example.com", "/api/socket.io/?EIO=4&transport=websocket")
	exerciseSocket(t, conn, br)
}

func TestWebSocketUpgradeForAnUnknownHostIsA404(t *testing.T) {
	front, _ := frontDoor(t, New(Options{Hosts: newTestStore(t)}))
	conn, err := tls.Dial("tcp", front.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: nobody.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.StatusCode)
	}
}
