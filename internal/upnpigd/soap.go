// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// httpDoer is the part of an *http.Client this package needs to fetch a
// device description and make SOAP calls. Production uses
// http.DefaultClient; tests inject an httptest.Server-backed client, the
// same way internal/importers' eero Client takes an *http.Client so its
// own tests point at a fake server instead of the real internet.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// maxSOAPResponseBytes bounds how much of a SOAP (or device description)
// response this package ever reads: this is unauthenticated LAN discovery
// talking to a device Shepherd does not control, so a malformed or hostile
// reply must never be read without a limit.
const maxSOAPResponseBytes = 1 << 20 // 1 MiB

// errNoMoreEntries is what getGenericPortMappingEntry returns when the
// router answers with SOAP fault 713 (SpecifiedArrayIndexInvalid): the
// normal, documented way a UPnP IGD says "that index is past the end of
// the table", not a real error. Client.Mappings treats it as the clean,
// expected end of enumeration.
var errNoMoreEntries = errors.New("upnpigd: no more port mapping entries")

// soapIndexInvalidFaultCode is the UPnP IGD fault code for
// SpecifiedArrayIndexInvalid (UPnP Device Architecture errata, IGD WAN
// Common Interface Config / Connection services).
const soapIndexInvalidFaultCode = "713"

// soapArg is one request argument, in the order it must be written (SOAP
// argument order matters to some routers' parsers).
type soapArg struct {
	Name  string
	Value string
}

func soapRequestBody(serviceType, action string, args []soapArg) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	fmt.Fprintf(&b, `<u:%s xmlns:u=%q>`, action, serviceType)
	for _, a := range args {
		b.WriteString("<" + a.Name + ">")
		xml.EscapeText(&b, []byte(a.Value))
		b.WriteString("</" + a.Name + ">")
	}
	fmt.Fprintf(&b, `</u:%s>`, action)
	b.WriteString(`</s:Body></s:Envelope>`)
	return b.Bytes()
}

// soapEnvelope decodes just enough of a SOAP response to get at its
// <Body>'s raw inner XML: either the action's own …Response element, or a
// <Fault>, decoded separately by soapFaultCode.
type soapEnvelope struct {
	Body struct {
		Raw []byte `xml:",innerxml"`
	} `xml:"Body"`
}

// soapFaultDetail picks out a UPnP error code and description from a SOAP
// 1.1 Fault body. No XMLName/root constraint is declared, so this matches
// regardless of what the enclosing element (<s:Fault>, <SOAP-ENV:Fault>,
// ...) happens to be called.
type soapFaultDetail struct {
	Code string `xml:"detail>UPnPError>errorCode"`
	Desc string `xml:"detail>UPnPError>errorDescription"`
}

// soapFaultCode extracts the UPnP error code from a SOAP fault body (the
// envelope's raw Body content), returning ok=false if it is not shaped
// like one.
func soapFaultCode(bodyRaw []byte) (soapFaultDetail, bool) {
	var d soapFaultDetail
	if err := xml.Unmarshal(bodyRaw, &d); err != nil || d.Code == "" {
		return soapFaultDetail{}, false
	}
	return d, true
}

// doSOAP posts one SOAP action to controlURL and returns the raw inner XML
// of the response's <Body> on HTTP 200, or an error: errNoMoreEntries for
// SOAP fault 713, a descriptive error for any other fault or transport
// failure.
func doSOAP(ctx context.Context, client httpDoer, controlURL, serviceType, action string, args []soapArg) ([]byte, error) {
	body := soapRequestBody(serviceType, action, args)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, controlURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("upnpigd: building %s request: %w", action, err)
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPACTION", fmt.Sprintf(`"%s#%s"`, serviceType, action))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upnpigd: calling %s: %w", action, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSOAPResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("upnpigd: reading %s response: %w", action, err)
	}

	var env soapEnvelope
	if err := xml.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("upnpigd: parsing %s response: %w", action, err)
	}

	if resp.StatusCode == http.StatusOK {
		return env.Body.Raw, nil
	}
	if fault, ok := soapFaultCode(env.Body.Raw); ok {
		if fault.Code == soapIndexInvalidFaultCode {
			return nil, errNoMoreEntries
		}
		return nil, fmt.Errorf("upnpigd: %s: SOAP fault %s: %s", action, fault.Code, fault.Desc)
	}
	return nil, fmt.Errorf("upnpigd: %s: HTTP %d", action, resp.StatusCode)
}
