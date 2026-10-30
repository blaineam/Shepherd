// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"context"
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

// fakeSOAPDoer plays back a fixed sequence of HTTP responses, repeating
// the last one forever once the sequence is exhausted. It never dials a
// real socket.
type fakeSOAPDoer struct {
	responses []fakeHTTPResponse
	i         int
	calls     int
}

type fakeHTTPResponse struct {
	status int
	body   string
}

func (f *fakeSOAPDoer) add(status int, body string) *fakeSOAPDoer {
	f.responses = append(f.responses, fakeHTTPResponse{status, body})
	return f
}

func (f *fakeSOAPDoer) Do(*http.Request) (*http.Response, error) {
	f.calls++
	r := f.responses[f.i]
	if f.i < len(f.responses)-1 {
		f.i++
	}
	return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body))}, nil
}

const fault713 = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>
<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
<errorCode>713</errorCode><errorDescription>SpecifiedArrayIndexInvalid</errorDescription>
</UPnPError></detail></s:Fault>
</s:Body></s:Envelope>`

// mappingResponse renders a GetGenericPortMappingEntryResponse SOAP body
// for index idx, forwarding external/internal port port to 192.168.1.50.
func mappingResponse(port, idx int) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>%d</NewInternalPort><NewInternalClient>192.168.1.50</NewInternalClient>
<NewEnabled>1</NewEnabled><NewPortMappingDescription>m%d</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse>
</s:Body></s:Envelope>`, port, port, idx)
}

func TestGetGenericPortMappingEntry(t *testing.T) {
	doer := new(fakeSOAPDoer).add(http.StatusOK, mappingResponse(8000, 0))
	m, err := getGenericPortMappingEntry(context.Background(), doer, "http://192.0.2.1/ctl", "urn:schemas-upnp-org:service:WANIPConnection:1", 0)
	if err != nil {
		t.Fatalf("getGenericPortMappingEntry: %v", err)
	}
	if m.ExternalPort != 8000 || m.Protocol != "TCP" || m.InternalPort != 8000 || m.InternalClient != "192.168.1.50" || !m.Enabled {
		t.Fatalf("mapping = %+v", m)
	}
}

func TestEnumerateMappingsStopsAtFault713(t *testing.T) {
	doer := new(fakeSOAPDoer).
		add(http.StatusOK, mappingResponse(8000, 0)).
		add(http.StatusOK, mappingResponse(8001, 1)).
		add(http.StatusInternalServerError, fault713)
	c := &Client{HTTPClient: doer}
	mappings, err := c.enumerateMappings(context.Background(), "urn:schemas-upnp-org:service:WANIPConnection:1", "http://192.0.2.1/ctl")
	if err != nil {
		t.Fatalf("enumerateMappings: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("mappings = %+v, want 2", mappings)
	}
	if doer.calls != 3 {
		t.Fatalf("calls = %d, want 3 (two mappings plus the terminating fault)", doer.calls)
	}
}

func TestEnumerateMappingsPropagatesOtherErrors(t *testing.T) {
	doer := new(fakeSOAPDoer).add(http.StatusInternalServerError, "not xml at all")
	c := &Client{HTTPClient: doer}
	if _, err := c.enumerateMappings(context.Background(), "svc", "http://192.0.2.1/ctl"); err == nil {
		t.Fatal("enumerateMappings must propagate a non-713 error")
	}
}

func TestEnumerateMappingsCapsAtMaxEntries(t *testing.T) {
	doer := new(fakeSOAPDoer).add(http.StatusOK, mappingResponse(8000, 0)) // never faults
	c := &Client{HTTPClient: doer}
	mappings, err := c.enumerateMappings(context.Background(), "svc", "http://192.0.2.1/ctl")
	if err != nil {
		t.Fatalf("enumerateMappings: %v", err)
	}
	if len(mappings) != maxMappingEntries {
		t.Fatalf("mappings = %d entries, want the defensive cap of %d", len(mappings), maxMappingEntries)
	}
}

// queuedSSDPConn is an ssdpConn backed by a queue of canned ReadFrom
// payloads; WriteTo is a no-op. It lets a test hand discovery a LOCATION
// that points at a real httptest.Server without ever opening a real UDP
// socket.
type queuedSSDPConn struct{ queue [][]byte }

func (c *queuedSSDPConn) WriteTo(b []byte, addr net.Addr) (int, error) { return len(b), nil }

func (c *queuedSSDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(c.queue) == 0 {
		return 0, nil, errors.New("queuedSSDPConn: no more responses")
	}
	next := c.queue[0]
	c.queue = c.queue[1:]
	return copy(b, next), nil, nil
}

func (c *queuedSSDPConn) SetDeadline(time.Time) error { return nil }
func (c *queuedSSDPConn) Close() error                { return nil }

func TestClientMappingsEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleDescription))
	})
	mux.HandleFunc("/upnp/control/WANIPConn1", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "<NewPortMappingIndex>0</NewPortMappingIndex>") {
			w.Write([]byte(mappingResponse(8000, 0)))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fault713))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := &Client{
		HTTPClient:       srv.Client(),
		DiscoveryTimeout: time.Second,
		dialSSDP: func() (ssdpConn, error) {
			return &queuedSSDPConn{queue: [][]byte{[]byte("HTTP/1.1 200 OK\r\nLOCATION: " + srv.URL + "/desc.xml\r\n\r\n")}}, nil
		},
	}
	mappings, err := c.Mappings(context.Background())
	if err != nil {
		t.Fatalf("Mappings: %v", err)
	}
	if len(mappings) != 1 || mappings[0].InternalClient != "192.168.1.50" {
		t.Fatalf("Mappings() = %+v", mappings)
	}
}

func TestClientMappingsFailsOnUnparsableLocationURL(t *testing.T) {
	c := &Client{
		DiscoveryTimeout: time.Second,
		dialSSDP: func() (ssdpConn, error) {
			return &queuedSSDPConn{queue: [][]byte{[]byte("HTTP/1.1 200 OK\r\nLOCATION: http://[::1\r\n\r\n")}}, nil
		},
	}
	if _, err := c.Mappings(context.Background()); err == nil {
		t.Fatal("Mappings() must fail when the LOCATION header is not a valid URL")
	}
}

func TestClientMappingsFailsWhenDiscoveryFinds(t *testing.T) {
	c := &Client{
		DiscoveryTimeout: 10 * time.Millisecond,
		dialSSDP:         func() (ssdpConn, error) { return &queuedSSDPConn{}, nil },
	}
	if _, err := c.Mappings(context.Background()); err == nil {
		t.Fatal("Mappings() must fail when nothing answers discovery")
	}
}

func TestClientDiscoverFailsWhenDialFails(t *testing.T) {
	c := &Client{dialSSDP: func() (ssdpConn, error) { return nil, errors.New("no socket") }}
	if _, err := c.discover(context.Background()); err == nil {
		t.Fatal("discover() must fail when dialSSDP fails")
	}
}

func TestClientFetchDescriptionHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := &Client{HTTPClient: srv.Client()}
	if _, err := c.fetchDescription(context.Background(), srv.URL); err == nil {
		t.Fatal("fetchDescription() must fail on a non-200 status")
	}
}

func TestClientZeroValueFallbacks(t *testing.T) {
	c := &Client{}
	if _, ok := c.httpClient().(*http.Client); !ok {
		t.Error("httpClient() with no HTTPClient set should default to an *http.Client")
	}
	conn, err := c.dial()
	if err != nil {
		t.Fatalf("dial() with no dialSSDP set should fall back to the real one: %v", err)
	}
	conn.Close()
}

func TestNewClientDefaults(t *testing.T) {
	c := NewClient()
	if c.HTTPClient == nil {
		t.Error("NewClient must set an HTTPClient")
	}
	if c.discoveryTimeout() != defaultDiscoveryTimeout {
		t.Errorf("discoveryTimeout() = %v, want %v", c.discoveryTimeout(), defaultDiscoveryTimeout)
	}
	if _, err := c.dial(); err != nil {
		t.Errorf("dial(): %v", err)
	}
}
