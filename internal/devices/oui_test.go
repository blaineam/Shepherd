// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/iotest"
)

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"00:00:5E:00:53:01": "00:00:5e:00:53:01",
		"00-00-5e-00-53-01": "00:00:5e:00:53:01",
		"00005e005301":      "00:00:5e:00:53:01",
		"0000.5e00.5301":    "00:00:5e:00:53:01",
		" 2:0:5e:0:0:1 ":    "02:00:5e:00:00:01",
	} {
		if got, ok := NormalizeMAC(in); !ok || got != want {
			t.Errorf("NormalizeMAC(%q) = %q,%v", in, got, ok)
		}
	}
	bcast := strings.Repeat("ff:", 5) + "ff"
	for _, bad := range []string{"", "zz:00:5e:00:53:01", "00:00:5e:00:53", "00:00:5e:00:53:01:02", "000:00:5e:00:53:01",
		"00:00:00:00:00:00", bcast, "01" + ":00:5e:00:00:fb", "00005e00530", "::::::", "00:00:5e:00:53:"} {
		if got, ok := NormalizeMAC(bad); ok {
			t.Errorf("NormalizeMAC(%q) accepted as %q", bad, got)
		}
	}
	if !IsLocallyAdministered("02:00:5e:00:00:01") || IsLocallyAdministered("00:00:5e:00:00:01") || IsLocallyAdministered("") || IsLocallyAdministered("zz") {
		t.Fatal("IsLocallyAdministered")
	}
}

func TestLookupVendorEmbedded(t *testing.T) {
	if n := OUICount(); n < 30000 {
		t.Fatalf("embedded table too small: %d", n)
	}
	for mac, want := range map[string]string{
		"00:03:93:12:34:56":      "Apple",
		"B8:27:" + "EB:00:00:01": "Raspberry Pi",
		"00:50:F2:00:00:01":      "Microsoft",
	} {
		if got := LookupVendor(mac); !strings.HasPrefix(got, want) {
			t.Errorf("LookupVendor(%s) = %q, want prefix %q", mac, got, want)
		}
	}
	// Locally administered (randomized) and garbage inputs have no vendor.
	for _, mac := range []string{"02:00:5e:00:00:01", "garbage", ""} {
		if got := LookupVendor(mac); got != "" {
			t.Errorf("LookupVendor(%q) = %q", mac, got)
		}
	}
	if got := LookupVendor("00:ff:ff:00:00:01"); got != "" {
		t.Errorf("unassigned prefix resolved to %q", got)
	}
}

func TestNormalizeVendor(t *testing.T) {
	for in, want := range map[string]string{
		"Apple, Inc.":                            "Apple",
		"Cisco Systems, Inc":                     "Cisco Systems",
		"HUAWEI TECHNOLOGIES CO.,LTD":            "Huawei Technologies",
		"TP-LINK TECHNOLOGIES CO.,LTD.":          "TP-Link Technologies",
		"Samsung Electronics Co.,Ltd":            "Samsung Electronics",
		"Hon Hai Precision Industry Co., Ltd":    "Hon Hai Precision Industry",
		"Sonos, Inc.":                            "Sonos",
		"LG Electronics (Mobile Communications)": "LG Electronics (Mobile Communications)",
		"Foo GmbH & Co. KG":                      "Foo",
		"  spaced   out  ":                       "spaced out",
		"Inc":                                    "Inc",
		"IEEE Registration Authority":            "",
		"Private":                                "",
		"":                                       "",
	} {
		if got := NormalizeVendor(in); got != want {
			t.Errorf("NormalizeVendor(%q) = %q, want %q", in, got, want)
		}
	}
}

const sampleOUI = `OUI/MA-L			Organization
company_id			Organization Name


00-03-93   (hex)		Apple, Inc.
000393     (base 16)		Apple, Inc.
				1 Infinite Loop
				Cupertino  CA  95014
				US

B8-27-EB   (hex)		Raspberry Pi Foundation
00-1B-C5   (hex)		IEEE Registration Authority
XX-YY-ZZ   (hex)		Bad Hex
12-34      (hex)		Short
00-50-F2   (hex)		MICROSOFT CORP.
`

func TestParseAndEncodeOUI(t *testing.T) {
	es, err := ParseIEEEOUI(strings.NewReader(sampleOUI))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 3 || es[0] != (OUIEntry{"000393", "Apple"}) || es[2].Vendor != "Microsoft" {
		t.Fatalf("%v", es)
	}
	var buf bytes.Buffer
	if err := EncodeOUITable(es, &buf); err != nil {
		t.Fatal(err)
	}
	tab, err := parseOUITable(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := tab.lookup(0x000393); got != "Apple" {
		t.Fatalf("round trip: %q", got)
	}
	if tab.lookup(0x123456) != "" {
		t.Fatal("phantom prefix")
	}
	if len(tab.keys) != 3 || len(tab.vendors) != 3 {
		t.Fatal("table shape")
	}
	if _, err := parseOUITable(strings.NewReader("not gzip")); err == nil {
		t.Fatal("garbage accepted")
	}
	// Malformed lines inside valid gzip are skipped.
	var g bytes.Buffer
	zw := gzip.NewWriter(&g)
	zw.Write([]byte("nope\nZZZZZZ\tBad\n00000A\tGood\n00000B\tGood\n"))
	zw.Close()
	tab, err = parseOUITable(&g)
	if err != nil || len(tab.keys) != 2 || len(tab.vendors) != 1 {
		t.Fatalf("%v %+v", err, tab)
	}
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}
	f.after--
	return len(p), nil
}

func TestOUIIOErrors(t *testing.T) {
	if _, err := ParseIEEEOUI(iotest.ErrReader(errors.New("read failed"))); err == nil {
		t.Fatal("read error swallowed")
	}
	es := []OUIEntry{{"000393", "Apple"}}
	if EncodeOUITable(es, &failWriter{}) == nil {
		t.Fatal("write error swallowed (immediate)")
	}
	// Large input so the gzip stream flushes mid-write, then fails on close.
	big := make([]OUIEntry, 20000)
	for i := range big {
		big[i] = OUIEntry{Prefix: strings.ToUpper(fmt.Sprintf("%06x", i)), Vendor: fmt.Sprintf("Vendor %d", i*7919)}
	}
	for n := 0; n < 3; n++ {
		if EncodeOUITable(big, &failWriter{after: n}) == nil {
			t.Fatalf("write error swallowed after %d writes", n)
		}
	}
}
