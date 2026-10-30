// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import "testing"

func TestGuessType(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   Evidence
		want DeviceType
	}{
		{"printer service", Evidence{Services: []string{"_ipp._tcp", "_airplay._tcp"}}, TypePrinter},
		{"printer service wins late", Evidence{Services: []string{"_airplay._tcp", "_ipps._tcp"}}, TypePrinter},
		{"googlecast", Evidence{Services: []string{"_googlecast._tcp"}}, TypeTV},
		{"google home model", Evidence{Services: []string{"_googlecast._tcp"}, Hints: []string{"Google Home Mini"}}, TypeSpeaker},
		{"chromecast model", Evidence{Services: []string{"_googlecast._tcp"}, Hints: []string{"Chromecast Ultra"}}, TypeTV},
		{"raop speaker", Evidence{Services: []string{"_raop._tcp"}}, TypeSpeaker},
		{"homepod model", Evidence{Services: []string{"_airplay._tcp", "_raop._tcp"}, Hints: []string{"AudioAccessory5,1"}}, TypeSpeaker},
		{"appletv model", Evidence{Services: []string{"_airplay._tcp"}, Hints: []string{"AppleTV6,2"}}, TypeTV},
		{"hap", Evidence{Services: []string{"_hap._tcp"}}, TypeSmartHome},
		{"matter", Evidence{Services: []string{"_matter._tcp"}}, TypeSmartHome},
		{"thread border router", Evidence{Services: []string{"_meshcop._udp"}}, TypeSmartHome},
		{"rtsp camera", Evidence{Services: []string{"_rtsp._tcp"}}, TypeCamera},
		{"service with dot", Evidence{Services: []string{"._ipp._tcp.local"}}, TypePrinter},
		{"iphone name", Evidence{Names: []string{"Sam-iPhone"}}, TypePhone},
		{"ipad hint", Evidence{Hints: []string{"iPad13,1"}}, TypeTablet},
		{"macbook hint", Evidence{Hints: []string{"MacBookPro18,3"}}, TypeLaptop},
		{"windows default", Evidence{Names: []string{"DESKTOP-4F2K9"}}, TypeLaptop},
		{"console name", Evidence{Names: []string{"PS5-living"}}, TypeGameConsole},
		{"console vendor", Evidence{Vendor: "Nintendo"}, TypeGameConsole},
		{"speaker vendor", Evidence{Vendor: "Sonos"}, TypeSpeaker},
		{"tv vendor", Evidence{Vendor: "Roku"}, TypeTV},
		{"printer vendor", Evidence{Vendor: "Brother Industries"}, TypePrinter},
		{"camera vendor", Evidence{Vendor: "Hikvision Digital"}, TypeCamera},
		{"hub vendor", Evidence{Vendor: "Signify Netherlands"}, TypeSmartHome},
		{"router vendor", Evidence{Vendor: "Ubiquiti"}, TypeRouter},
		{"router name", Evidence{Names: []string{"home-router"}}, TypeRouter},
		{"service beats vendor", Evidence{Vendor: "Ubiquiti", Services: []string{"_rtsp._tcp"}}, TypeCamera},
		{"hint beats service", Evidence{Services: []string{"_googlecast._tcp"}, Hints: []string{"Nest Hub"}}, TypeSpeaker},
		{"nothing", Evidence{Vendor: "Obscure Widgets"}, TypeUnknown},
		{"empty", Evidence{}, TypeUnknown},
	} {
		got, reason := GuessType(tc.ev)
		if got != tc.want {
			t.Errorf("%s: got %q (%s), want %q", tc.name, got, reason, tc.want)
		}
		if (got == TypeUnknown) != (reason == "") {
			t.Errorf("%s: reason %q inconsistent with type %q", tc.name, reason, got)
		}
	}
}
