// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSSDPConn is an ssdpConn that never touches a real socket: WriteTo
// records what was sent, ReadFrom plays back a canned queue of responses
// (or blocks-then-errors once the queue is empty, simulating a deadline).
type fakeSSDPConn struct {
	writes  [][]byte
	queue   [][]byte
	closed  bool
	readErr error
}

func (c *fakeSSDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *fakeSSDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(c.queue) == 0 {
		if c.readErr != nil {
			return 0, nil, c.readErr
		}
		return 0, nil, errTestDeadline
	}
	next := c.queue[0]
	c.queue = c.queue[1:]
	n := copy(b, next)
	return n, nil, nil
}

func (c *fakeSSDPConn) SetDeadline(time.Time) error { return nil }
func (c *fakeSSDPConn) Close() error                { c.closed = true; return nil }

var errTestDeadline = errors.New("fakeSSDPConn: deadline exceeded")

func TestBuildSearchHasRequiredHeaders(t *testing.T) {
	msg := string(buildSearch("urn:schemas-upnp-org:device:InternetGatewayDevice:1", 2))
	for _, want := range []string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		`MAN: "ssdp:discover"`,
		"MX: 2",
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("M-SEARCH message missing %q:\n%s", want, msg)
		}
	}
}

func TestParseLocationFindsHeaderCaseInsensitively(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"location: http://192.0.2.1:5000/desc.xml\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	loc, ok := parseLocation(raw)
	if !ok || loc != "http://192.0.2.1:5000/desc.xml" {
		t.Fatalf("parseLocation() = %q, %v", loc, ok)
	}
}

func TestParseLocationMissing(t *testing.T) {
	if _, ok := parseLocation("HTTP/1.1 200 OK\r\n\r\n"); ok {
		t.Fatal("parseLocation() found a LOCATION header that was not there")
	}
}

func TestDiscoverLocationSendsEveryTargetAndReturnsFirstMatch(t *testing.T) {
	conn := &fakeSSDPConn{
		queue: [][]byte{
			[]byte("HTTP/1.1 200 OK\r\n\r\n"), // no LOCATION: skipped
			[]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.5:1900/desc.xml\r\n\r\n"),
		},
	}
	loc, err := discoverLocation(conn, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("discoverLocation: %v", err)
	}
	if loc != "http://192.0.2.5:1900/desc.xml" {
		t.Fatalf("discoverLocation() = %q", loc)
	}
	if len(conn.writes) != len(searchTargets) {
		t.Fatalf("wrote %d M-SEARCH requests, want %d (one per search target)", len(conn.writes), len(searchTargets))
	}
}

func TestDiscoverLocationNoResponder(t *testing.T) {
	conn := &fakeSSDPConn{}
	if _, err := discoverLocation(conn, time.Now().Add(time.Millisecond)); err == nil {
		t.Fatal("discoverLocation() with no responder must return an error")
	}
}

func TestDialSSDPOpensARealButUnconnectedSocket(t *testing.T) {
	conn, err := dialSSDP()
	if err != nil {
		t.Fatalf("dialSSDP: %v", err)
	}
	defer conn.Close()
	if conn == nil {
		t.Fatal("dialSSDP returned a nil conn with no error")
	}
}
