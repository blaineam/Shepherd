// SPDX-License-Identifier: AGPL-3.0-or-later

package upnpigd

import (
	"net/url"
	"testing"
)

// A trimmed but realistic device description: the WAN connection service
// is nested three levels deep under the root device, as it is on real
// routers (Layer3Forwarding > WANDevice > WANConnectionDevice >
// WANConnection*), to make sure parsing actually walks the tree rather
// than assuming a fixed depth.
const sampleDescription = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Example Router</friendlyName>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
        <controlURL>/upnp/control/L3F</controlURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/upnp/control/WANIPConn1</controlURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>`

func TestParseDescriptionFindsNestedWANIPConnection(t *testing.T) {
	base, _ := url.Parse("http://192.0.2.1:5000/desc.xml")
	st, cu, err := parseDescription([]byte(sampleDescription), base)
	if err != nil {
		t.Fatalf("parseDescription: %v", err)
	}
	if st != "urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Errorf("serviceType = %q", st)
	}
	if cu.String() != "http://192.0.2.1:5000/upnp/control/WANIPConn1" {
		t.Errorf("controlURL = %q, want resolved against the description's own host", cu.String())
	}
}

func TestParseDescriptionUsesURLBaseWhenPresent(t *testing.T) {
	doc := `<root><URLBase>http://192.0.2.1:49152/</URLBase><device>
		<serviceList><service>
			<serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
			<controlURL>ctl/WANPPP</controlURL>
		</service></serviceList>
	</device></root>`
	base, _ := url.Parse("http://192.0.2.1:5000/desc.xml")
	_, cu, err := parseDescription([]byte(doc), base)
	if err != nil {
		t.Fatalf("parseDescription: %v", err)
	}
	if cu.String() != "http://192.0.2.1:49152/ctl/WANPPP" {
		t.Errorf("controlURL = %q, want resolved against URLBase, not the fetch URL's own host/port", cu.String())
	}
}

func TestParseDescriptionNoWANService(t *testing.T) {
	doc := `<root><device><serviceList><service>
		<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
		<controlURL>/ctl/L3F</controlURL>
	</service></serviceList></device></root>`
	base, _ := url.Parse("http://192.0.2.1:5000/desc.xml")
	if _, _, err := parseDescription([]byte(doc), base); err != errNoWANConnectionService {
		t.Fatalf("parseDescription() err = %v, want errNoWANConnectionService", err)
	}
}

func TestParseDescriptionInvalidControlURL(t *testing.T) {
	doc := `<root><device><serviceList><service>
		<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
		<controlURL>http://[::1</controlURL>
	</service></serviceList></device></root>`
	base, _ := url.Parse("http://192.0.2.1:5000/desc.xml")
	if _, _, err := parseDescription([]byte(doc), base); err == nil {
		t.Fatal("parseDescription() with an unparsable control URL must return an error")
	}
}

func TestParseDescriptionInvalidXML(t *testing.T) {
	base, _ := url.Parse("http://192.0.2.1:5000/desc.xml")
	if _, _, err := parseDescription([]byte("not xml"), base); err == nil {
		t.Fatal("parseDescription() with invalid XML must return an error")
	}
}
