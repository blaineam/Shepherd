// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import "strings"

// Evidence is what GuessType looks at.
type Evidence struct {
	Vendor   string
	Services []string // mDNS service types, e.g. "_ipp._tcp"
	Names    []string // hostnames and aliases
	Hints    []string // model strings and friendly names
}

// serviceTypes maps the first label of an mDNS service type to a guess.
var serviceTypes = []struct {
	label string
	typ   DeviceType
}{
	{"_ipp", TypePrinter}, {"_ipps", TypePrinter}, {"_printer", TypePrinter},
	{"_pdl-datastream", TypePrinter}, {"_scanner", TypePrinter}, {"_uscan", TypePrinter},
	{"_rtsp", TypeCamera}, {"_axis-video", TypeCamera}, {"_nvstream", TypeGameConsole},
	{"_sonos", TypeSpeaker}, {"_spotify-connect", TypeSpeaker}, {"_raop", TypeSpeaker},
	{"_hap", TypeSmartHome}, {"_homekit", TypeSmartHome}, {"_matter", TypeSmartHome},
	{"_matterc", TypeSmartHome}, {"_meshcop", TypeSmartHome}, {"_hue", TypeSmartHome},
	{"_googlecast", TypeTV}, {"_airplay", TypeTV},
}

// keyword rules over names and hints, checked in order; first match wins.
var keywordRules = []struct {
	typ  DeviceType
	keys []string
}{
	{TypeGameConsole, []string{"playstation", "ps5", "ps4", "xbox", "nintendo", "steamdeck"}},
	{TypePrinter, []string{"printer", "laserjet", "officejet", "deskjet", "pixma", "ecotank"}},
	{TypeCamera, []string{"camera", "doorbell", "ipcam", "cam-", "-cam", "wyzecam", "arlo", "hikvision"}},
	{TypeSpeaker, []string{"homepod", "audioaccessory", "echo", "sonos", "speaker", "nest mini", "nest audio", "nest hub", "google home", "soundbar", "nest-mini", "nest-audio", "nest-hub", "google-home"}},
	{TypeTV, []string{"appletv", "apple-tv", "apple tv", "chromecast", "roku", "firetv", "fire tv", "bravia", "webos", "smarttv", "smart-tv", "-tv", "tv-", "television"}},
	{TypeTablet, []string{"ipad", "tablet", "kindle", "galaxy tab", "galaxy-tab"}},
	{TypePhone, []string{"iphone", "pixel", "galaxy", "android", "oneplus", "xiaomi", "redmi", "phone"}},
	{TypeLaptop, []string{"macbook", "macmini", "imac", "macpro", "macstudio", "mac mini", "laptop", "notebook", "thinkpad", "desktop", "-pc", "workstation", "surface"}},
	{TypeRouter, []string{"router", "gateway", "accesspoint", "access-point", "unifi", "eero", "orbi"}},
}

// vendorRules map vendor-name fragments to a type, applied last because a
// vendor alone is weak evidence.
var vendorRules = []struct {
	typ   DeviceType
	frags []string
}{
	{TypeGameConsole, []string{"sony interactive", "nintendo", "valve"}},
	{TypeSpeaker, []string{"sonos", "bose"}},
	{TypeTV, []string{"roku", "vizio", "tcl"}},
	{TypePrinter, []string{"brother", "canon", "epson", "lexmark", "xerox", "ricoh", "kyocera", "hewlett", "hp inc", "konica"}},
	{TypeCamera, []string{"hikvision", "dahua", "axis comm", "wyze", "arlo", "reolink", "amcrest", "foscam"}},
	{TypeSmartHome, []string{"philips lighting", "signify", "ecobee", "lutron", "smartthings", "tuya", "espressif"}},
	{TypeRouter, []string{"ubiquiti", "tp-link", "netgear", "cisco", "aruba", "mikrotik", "juniper", "linksys", "eero", "avm", "zyxel", "d-link", "arris", "technicolor", "sagemcom", "ruckus"}},
}

// GuessType infers a device type from vendor, mDNS services and names, with
// a short human-readable reason. Strong evidence (a printing service, a
// model string) beats weak evidence (the vendor alone).
func GuessType(ev Evidence) (DeviceType, string) {
	// 1. Model strings and names are the most specific.
	texts := append(append([]string{}, ev.Hints...), ev.Names...)
	for _, rule := range keywordRules {
		for _, t := range texts {
			lt := strings.ToLower(t)
			for _, k := range rule.keys {
				if strings.Contains(lt, k) {
					return rule.typ, `name or model contains "` + k + `"`
				}
			}
		}
	}
	// 2. mDNS service types.
	var best DeviceType
	var bestSvc string
	for _, s := range ev.Services {
		label := strings.ToLower(strings.SplitN(strings.TrimPrefix(s, "."), ".", 2)[0])
		for _, st := range serviceTypes {
			if st.label != label {
				continue
			}
			// Printing beats everything; otherwise keep the first hit.
			if best == "" || st.typ == TypePrinter {
				best, bestSvc = st.typ, s
			}
		}
	}
	if best != "" {
		return best, "advertises mDNS service " + bestSvc
	}
	// 3. Vendor.
	lv := strings.ToLower(ev.Vendor)
	if lv != "" {
		for _, rule := range vendorRules {
			for _, f := range rule.frags {
				if strings.Contains(lv, f) {
					return rule.typ, "vendor " + ev.Vendor
				}
			}
		}
	}
	return TypeUnknown, ""
}
