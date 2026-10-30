// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSoapRequestBodyShape(t *testing.T) {
	body := string(soapRequestBody("urn:schemas-upnp-org:service:WANIPConnection:1", "GetGenericPortMappingEntry",
		[]soapArg{{Name: "NewPortMappingIndex", Value: "0"}}))
	for _, want := range []string{
		`<s:Envelope`,
		`<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">`,
		`<NewPortMappingIndex>0</NewPortMappingIndex>`,
		`</u:GetGenericPortMappingEntry>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("SOAP body missing %q:\n%s", want, body)
		}
	}
}

func TestSoapRequestBodyEscapesArguments(t *testing.T) {
	body := string(soapRequestBody("svc", "Action", []soapArg{{Name: "NewX", Value: "<evil>&"}}))
	if strings.Contains(body, "<evil>") {
		t.Fatalf("argument value was not escaped: %s", body)
	}
	if !strings.Contains(body, "&lt;evil&gt;&amp;") {
		t.Fatalf("expected escaped argument, got: %s", body)
	}
}

// fakeDoer is an httpDoer that never dials: it either returns a canned
// error or delegates to a function, letting tests simulate pure transport
// failures without even httptest's loopback listener.
type fakeDoer struct {
	err error
}

func (f fakeDoer) Do(*http.Request) (*http.Response, error) { return nil, f.err }

func TestSoapFaultCodeNotAFault(t *testing.T) {
	if _, ok := soapFaultCode([]byte("<Something>no fault here</Something>")); ok {
		t.Fatal("soapFaultCode() must report ok=false for a body with no UPnPError code")
	}
}

func TestDoSOAPRequestBuildError(t *testing.T) {
	_, err := doSOAP(context.Background(), fakeDoer{}, "http://[::1", "svc", "Action", nil)
	if err == nil {
		t.Fatal("doSOAP() with an unparsable control URL must return an error")
	}
}

func TestDoSOAPTransportError(t *testing.T) {
	_, err := doSOAP(context.Background(), fakeDoer{err: errors.New("boom")}, "http://192.0.2.1/ctl", "svc", "Action", nil)
	if err == nil {
		t.Fatal("doSOAP must return an error when the transport fails")
	}
}

func newSOAPServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("SOAPACTION"); got == "" {
			t.Errorf("request had no SOAPACTION header")
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoSOAPSuccess(t *testing.T) {
	srv := newSOAPServer(t, http.StatusOK, `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>8080</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>8080</NewInternalPort>
<NewInternalClient>192.168.1.50</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>test</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse>
</s:Body></s:Envelope>`)
	raw, err := doSOAP(context.Background(), srv.Client(), srv.URL, "urn:schemas-upnp-org:service:WANIPConnection:1", "GetGenericPortMappingEntry",
		[]soapArg{{Name: "NewPortMappingIndex", Value: "0"}})
	if err != nil {
		t.Fatalf("doSOAP: %v", err)
	}
	if !strings.Contains(string(raw), "192.168.1.50") {
		t.Fatalf("doSOAP returned %s, want the response body", raw)
	}
}

func TestDoSOAPFault713BecomesErrNoMoreEntries(t *testing.T) {
	srv := newSOAPServer(t, http.StatusInternalServerError, `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<s:Fault>
<faultcode>s:Client</faultcode>
<faultstring>UPnPError</faultstring>
<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
<errorCode>713</errorCode>
<errorDescription>SpecifiedArrayIndexInvalid</errorDescription>
</UPnPError></detail>
</s:Fault>
</s:Body></s:Envelope>`)
	_, err := doSOAP(context.Background(), srv.Client(), srv.URL, "svc", "GetGenericPortMappingEntry", nil)
	if !errors.Is(err, errNoMoreEntries) {
		t.Fatalf("doSOAP() err = %v, want errNoMoreEntries", err)
	}
}

func TestDoSOAPOtherFault(t *testing.T) {
	srv := newSOAPServer(t, http.StatusInternalServerError, `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>
<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
<errorCode>402</errorCode><errorDescription>InvalidArgs</errorDescription>
</UPnPError></detail></s:Fault>
</s:Body></s:Envelope>`)
	_, err := doSOAP(context.Background(), srv.Client(), srv.URL, "svc", "Action", nil)
	if err == nil || errors.Is(err, errNoMoreEntries) {
		t.Fatalf("doSOAP() err = %v, want a non-713 fault error", err)
	}
	if !strings.Contains(err.Error(), "402") {
		t.Errorf("error %v should mention the fault code", err)
	}
}

func TestDoSOAPNonFaultHTTPError(t *testing.T) {
	srv := newSOAPServer(t, http.StatusNotFound, "not found")
	_, err := doSOAP(context.Background(), srv.Client(), srv.URL, "svc", "Action", nil)
	if err == nil {
		t.Fatal("doSOAP() with a plain HTTP error status must return an error")
	}
}
