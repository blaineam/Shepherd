// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
)

// wanConnectionServiceTypes are the service types whose control URL this
// client wants. WANIPConnection covers the common "bridge" NAT case
// (cable, fiber); WANPPPConnection covers PPPoE. A device description may
// expose either, depending on the router's own WAN connection type.
var wanConnectionServiceTypes = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// errNoWANConnectionService is returned when a device description was
// fetched and parsed fine, but has no WANIPConnection or WANPPPConnection
// service anywhere in its device tree: an IGD answered SSDP, but is not
// exposing the control surface this package needs.
var errNoWANConnectionService = errors.New("upnpigd: device description has no WANIPConnection or WANPPPConnection service")

// descRoot is the root <root> element of a UPnP device description
// document (fetched from the SSDP LOCATION URL).
type descRoot struct {
	XMLName xml.Name   `xml:"root"`
	URLBase string     `xml:"URLBase"`
	Device  descDevice `xml:"device"`
}

// descDevice is one <device>, recursively: the WAN connection service
// this package wants is nested arbitrarily deep (typically
// Layer3Forwarding > WANDevice > WANConnectionDevice > WANConnection*), so
// parsing walks the whole tree rather than assuming a fixed depth.
type descDevice struct {
	DeviceList  []descDevice  `xml:"deviceList>device"`
	ServiceList []descService `xml:"serviceList>service"`
}

type descService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

// findWANService walks dev's tree depth-first for the first service whose
// type is in wanConnectionServiceTypes, returning its type and (relative)
// control URL.
func findWANService(dev descDevice) (serviceType, controlURL string, ok bool) {
	for _, svc := range dev.ServiceList {
		for _, want := range wanConnectionServiceTypes {
			if svc.ServiceType == want {
				return svc.ServiceType, svc.ControlURL, true
			}
		}
	}
	for _, child := range dev.DeviceList {
		if st, cu, ok := findWANService(child); ok {
			return st, cu, true
		}
	}
	return "", "", false
}

// parseDescription parses a device description document and resolves the
// WAN connection service's control URL to an absolute URL, against the
// description's own URLBase element when present, or else against base
// (the URL the description was fetched from) — exactly as the UPnP device
// architecture specification requires.
func parseDescription(body []byte, base *url.URL) (serviceType string, controlURL *url.URL, err error) {
	var root descRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return "", nil, fmt.Errorf("upnpigd: parsing device description: %w", err)
	}
	st, cu, ok := findWANService(root.Device)
	if !ok {
		return "", nil, errNoWANConnectionService
	}
	resolveBase := base
	if root.URLBase != "" {
		if b, err := url.Parse(root.URLBase); err == nil {
			resolveBase = b
		}
	}
	ref, err := url.Parse(cu)
	if err != nil {
		return "", nil, fmt.Errorf("upnpigd: parsing control URL %q: %w", cu, err)
	}
	return st, resolveBase.ResolveReference(ref), nil
}
