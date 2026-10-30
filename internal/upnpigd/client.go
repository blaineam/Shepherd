// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Mapping is one entry in a router's NAT port-mapping table: an external
// (WAN-facing) port forwarded to one LAN device's address and port.
type Mapping struct {
	ExternalPort   int
	Protocol       string // "TCP" or "UDP", exactly as the router reports it
	InternalClient string // the LAN IP address the port is forwarded to
	InternalPort   int
	Enabled        bool
	Description    string
}

// maxMappingEntries bounds GetGenericPortMappingEntry enumeration. This is
// unauthenticated LAN discovery talking to a device Shepherd does not
// control, so a malformed or misbehaving response can never spin this loop
// forever; no home router has anywhere near this many port forwards.
const maxMappingEntries = 1000

// defaultDiscoveryTimeout bounds one SSDP discovery attempt.
const defaultDiscoveryTimeout = 3 * time.Second

// Client finds an IGD's WAN connection control URL via SSDP and device
// description, then queries its NAT port-mapping table over SOAP. Each
// call to Mappings is a fresh discovery + fetch + enumerate round trip —
// slower and far more fragile than internal/portscan's own TCP connect
// probes. Checker (checker.go) is what callers actually want for repeated
// use: it caches Mappings and rate-limits the round trip.
//
// The zero value is production-ready. HTTPClient and the private dialSSDP
// seam are overridden only in tests, the same way DialFunc lets
// portscan.Scanner avoid a real net.Dialer in its own tests.
type Client struct {
	// HTTPClient fetches the device description and makes SOAP calls.
	// Defaults to http.DefaultClient.
	HTTPClient httpDoer
	// DiscoveryTimeout bounds SSDP discovery. Defaults to 3s.
	DiscoveryTimeout time.Duration

	// dialSSDP opens the UDP socket discovery sends from. Set only by
	// tests; production always uses the package-level dialSSDP function.
	dialSSDP func() (ssdpConn, error)
}

// NewClient returns a production-ready Client: real SSDP multicast, real
// HTTP, sane default timeouts.
func NewClient() *Client {
	return &Client{HTTPClient: http.DefaultClient, DiscoveryTimeout: defaultDiscoveryTimeout, dialSSDP: dialSSDP}
}

func (c *Client) httpClient() httpDoer {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) discoveryTimeout() time.Duration {
	if c.DiscoveryTimeout > 0 {
		return c.DiscoveryTimeout
	}
	return defaultDiscoveryTimeout
}

func (c *Client) dial() (ssdpConn, error) {
	if c.dialSSDP != nil {
		return c.dialSSDP()
	}
	return dialSSDP()
}

// Mappings discovers the IGD and returns its full NAT port-mapping table.
// It returns an error — never a guess — whenever the IGD cannot be found,
// described, or queried: no responder to SSDP, a description with no
// WANIPConnection/WANPPPConnection service, or a SOAP call that fails for
// any reason other than the clean end of enumeration. See docs/PORTSCAN.md
// for what this means in practice for routers that do not cooperate
// (UPnP IGD disabled, or not implemented at all, as on some consumer mesh
// systems).
func (c *Client) Mappings(ctx context.Context) ([]Mapping, error) {
	locURL, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(locURL)
	if err != nil {
		return nil, fmt.Errorf("upnpigd: parsing LOCATION url %q: %w", locURL, err)
	}
	descBody, err := c.fetchDescription(ctx, locURL)
	if err != nil {
		return nil, err
	}
	serviceType, controlURL, err := parseDescription(descBody, base)
	if err != nil {
		return nil, err
	}
	return c.enumerateMappings(ctx, serviceType, controlURL.String())
}

func (c *Client) discover(ctx context.Context) (string, error) {
	conn, err := c.dial()
	if err != nil {
		return "", fmt.Errorf("upnpigd: opening discovery socket: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(c.discoveryTimeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	return discoverLocation(conn, deadline)
}

func (c *Client) fetchDescription(ctx context.Context, locURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, locURL, nil)
	if err != nil {
		return nil, fmt.Errorf("upnpigd: building device description request: %w", err)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("upnpigd: fetching device description: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upnpigd: device description: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSOAPResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("upnpigd: reading device description: %w", err)
	}
	return body, nil
}

func (c *Client) enumerateMappings(ctx context.Context, serviceType, controlURL string) ([]Mapping, error) {
	out := make([]Mapping, 0, 8)
	for i := 0; i < maxMappingEntries; i++ {
		m, err := getGenericPortMappingEntry(ctx, c.httpClient(), controlURL, serviceType, i)
		if err != nil {
			if errors.Is(err, errNoMoreEntries) {
				break
			}
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// genericPortMappingResponse mirrors GetGenericPortMappingEntryResponse's
// fields. It declares no XMLName, so encoding/xml matches it against
// doSOAP's response body regardless of what the enclosing
// "...Response" element happens to be called.
type genericPortMappingResponse struct {
	RemoteHost   string `xml:"NewRemoteHost"`
	ExternalPort int    `xml:"NewExternalPort"`
	Protocol     string `xml:"NewProtocol"`
	InternalPort int    `xml:"NewInternalPort"`
	Client       string `xml:"NewInternalClient"`
	Enabled      bool   `xml:"NewEnabled"`
	Description  string `xml:"NewPortMappingDescription"`
}

// getGenericPortMappingEntry calls GetGenericPortMappingEntry for index on
// the WAN connection service at controlURL. It returns errNoMoreEntries
// once index is past the end of the router's table.
func getGenericPortMappingEntry(ctx context.Context, client httpDoer, controlURL, serviceType string, index int) (Mapping, error) {
	raw, err := doSOAP(ctx, client, controlURL, serviceType, "GetGenericPortMappingEntry",
		[]soapArg{{Name: "NewPortMappingIndex", Value: strconv.Itoa(index)}})
	if err != nil {
		return Mapping{}, err
	}
	var resp genericPortMappingResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		return Mapping{}, fmt.Errorf("upnpigd: parsing GetGenericPortMappingEntry response: %w", err)
	}
	return Mapping{
		ExternalPort:   resp.ExternalPort,
		Protocol:       resp.Protocol,
		InternalClient: resp.Client,
		InternalPort:   resp.InternalPort,
		Enabled:        resp.Enabled,
		Description:    resp.Description,
	}, nil
}
