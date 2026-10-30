// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"shepherd/internal/devices"
)

func parse(t *testing.T, s string) (Plan, []RowError) {
	t.Helper()
	p, errs, err := ImportCSV(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return p, errs
}

func TestCSVRoundTrip(t *testing.T) {
	src := newReg(t)
	mustApply(t, samplePlan(), src, Options{})
	id := byMAC(t, src, "02:00:5e:00:00:01").ID
	_ = src.SetNotes(id, "has, comma and \"quotes\"\nand a newline")
	_ = src.SetType(id, "tablet")

	var buf bytes.Buffer
	if err := ExportCSV(&buf, src); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "mac,ip,name,vendor,type,groups,tags,excluded,notes\n") {
		t.Fatalf("header: %q", buf.String())
	}
	plan, rowErrs, err := ImportCSV(&buf)
	if err != nil || len(rowErrs) != 0 {
		t.Fatalf("%v %v", err, rowErrs)
	}
	dst := newReg(t)
	rep := mustApply(t, plan, dst, Options{})
	if rep.Created != 3 {
		t.Fatalf("%+v", rep)
	}
	for _, d := range src.List() {
		got := byMAC(t, dst, d.MACs[0])
		if got.Alias != d.Alias || got.Notes != cleanText(d.Notes, MaxNotesBytes) || got.Excluded != d.Excluded ||
			!reflect.DeepEqual(got.Tags, d.Tags) || !reflect.DeepEqual(groupNames(dst, got), groupNames(src, d)) ||
			got.Type != d.Type && d.TypeUser {
			t.Errorf("round trip lost data:\n src %+v\n dst %+v", d, got)
		}
	}
	if g, _ := dst.GroupByName("Kids"); len(g.Members) != 1 {
		t.Fatalf("%+v", g)
	}
	// Importing the export into the source changes nothing.
	again, _ := Preview(plan, src)
	if again.Changed() {
		t.Fatalf("re-import would change: %s", again)
	}
}

func TestCSVExportInjectionGuard(t *testing.T) {
	reg := newReg(t)
	evil := []string{"=HYPERLINK(\"x\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"}
	for i, name := range evil {
		id := reg.Observe(devices.Observation{Source: devices.SourceManual, MAC: macN(i + 1), IP: "192.0.2." + itoa(i+1)})
		_ = reg.Rename(id, name)
		_ = reg.SetNotes(id, name)
		_ = reg.SetTags(id, []string{name})
	}
	g, _ := reg.CreateGroup("=evil", "")
	_, _ = reg.BulkAssignGroup([]string{reg.List()[0].ID}, g.ID)
	var buf bytes.Buffer
	if err := ExportCSV(&buf, reg); err != nil {
		t.Fatal(err)
	}
	for _, r := range mustRead(t, buf.String())[1:] {
		for _, f := range r {
			if f != "" && strings.ContainsRune("=+-@\t\r", rune(f[0])) {
				t.Errorf("unguarded field %q", f)
			}
		}
	}
	// And the guard round-trips.
	plan, errs := parse(t, buf.String())
	if len(errs) != 0 || len(plan.Devices) != len(evil) {
		t.Fatalf("%v %d", errs, len(plan.Devices))
	}
	names := map[string]bool{}
	for _, d := range plan.Devices {
		names[d.Name] = true
	}
	for _, n := range []string{"=HYPERLINK(\"x\")", "+1+1", "-2+3", "@SUM(A1)"} {
		if !names[n] {
			t.Errorf("name %q not restored (got %v)", n, names)
		}
	}
}

func mustRead(t *testing.T, s string) [][]string {
	t.Helper()
	p, _, err := ImportCSV(strings.NewReader(s))
	_ = p
	if err != nil {
		t.Fatal(err)
	}
	// Re-read raw with the standard reader for field inspection.
	return rawRecords(t, s)
}

func TestCSVExportErrors(t *testing.T) {
	if err := ExportCSV(&bytes.Buffer{}, nil); err != ErrNoRegistry {
		t.Fatal(err)
	}
	reg := newReg(t)
	mustApply(t, samplePlan(), reg, Options{})
	if err := ExportCSV(failWriter{}, reg); err == nil {
		t.Fatal("expected a write error")
	}
	for i := 0; i < 300; i++ {
		id := reg.Observe(devices.Observation{Source: devices.SourceManual, MAC: macN(i + 10), IP: "198.51.100." + itoa(i%250+1)})
		_ = reg.Rename(id, strings.Repeat("n", 60))
	}
	if err := ExportCSV(failWriter{after: 10}, reg); err == nil {
		t.Fatal("expected a mid-stream write error")
	}
}

func TestCSVTolerance(t *testing.T) {
	body := "MAC Address;Hostname;Nickname;Profile;Extra;IP Address;Notes\r\n" +
		"\r\n" +
		"02:00:5E:00:00:01;tab;\"Kids Tablet\";Kids;ignored;192.0.2.10;\r\n" +
		"  \r\n" +
		"00-00-5e-00-00-02;;Living Room TV;Living Room;x;\"192.0.2.11, 192.0.2.12\";note\r\n"
	for name, text := range map[string]string{
		"semicolon+CRLF": body,
		"BOM":            "\xef\xbb\xbf" + body,
		"tab":            strings.ReplaceAll(body, ";", "\t"),
	} {
		t.Run(name, func(t *testing.T) {
			p, errs := parse(t, text)
			if len(errs) != 0 || len(p.Devices) != 2 {
				t.Fatalf("errs %v devices %+v", errs, p.Devices)
			}
			a, b := p.Devices[0], p.Devices[1]
			if a.Name != "Kids Tablet" || a.Hostname != "tab" || !reflect.DeepEqual(a.Groups, []string{"Kids"}) || a.IPs[0] != "192.0.2.10" {
				t.Errorf("a: %+v", a)
			}
			if b.Name != "Living Room TV" || len(b.IPs) != 2 || b.Notes != "note" {
				t.Errorf("b: %+v", b)
			}
		})
	}
}

func TestCSVColumnVariants(t *testing.T) {
	p, errs := parse(t, "Device Name,Brand,Category,Tags,Excluded,Group,hw addr\n"+
		"Hall Cam,ExampleCo,camera,\"a;b\",yes,\"Cameras;Hall\",02:00:5e:00:00:05\n"+
		"Plain,,,,no,,02:00:5e:00:00:06\n")
	if len(errs) != 0 || len(p.Devices) != 2 {
		t.Fatalf("%v %+v", errs, p.Devices)
	}
	d := p.Devices[0]
	if d.Vendor != "ExampleCo" || d.Type != "camera" || !d.Excluded || !reflect.DeepEqual(d.Tags, []string{"a", "b"}) || !reflect.DeepEqual(d.Groups, []string{"Cameras", "Hall"}) {
		t.Fatalf("%+v", d)
	}
}

func TestCSVRowErrorsDoNotAbort(t *testing.T) {
	text := "mac,ip,name,type,excluded\n" +
		"02:00:5e:00:00:01,192.0.2.1,Good One,,\n" +
		"not-a-mac,192.0.2.2,Bad MAC Good IP,,\n" +
		"02:00:5e:00:00:03,999.1.1.1,Bad IP Good MAC,,\n" +
		",,Nothing to identify,,\n" +
		"02:00:5e:00:00:04,,Odd Type,spaceship,maybe\n" +
		"02:00:5e:00:00:05;02:00:5e:00:00:06,,Two MACs,,\n" +
		"02:00:5e:00:00:07,,\"unterminated\n" +
		"02:00:5e:00:00:08,,Bare\"quote,,\n" +
		"02:00:5e:00:00:09,,Last One,,\n"
	p, errs := parse(t, text)
	var names []string
	for _, d := range p.Devices {
		names = append(names, d.Name)
	}
	if len(errs) < 7 {
		t.Fatalf("errors: %v", errs)
	}
	for _, want := range []string{"Good One", "Bad MAC Good IP", "Bad IP Good MAC", "Odd Type", "Two MACs"} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Errorf("missing %q in %v", want, names)
		}
	}
	if errs[0].Line != 3 || !strings.Contains(errs[0].Error(), "line 3") {
		t.Errorf("first error %+v", errs[0])
	}
	for _, e := range errs {
		if e.Line == 0 || e.Msg == "" {
			t.Errorf("bad row error %+v", e)
		}
	}
	if len(p.Warnings) != len(errs) || !strings.HasPrefix(p.Warnings[0], "CSV line 3") {
		t.Errorf("warnings %v", p.Warnings)
	}
	// The plan still applies cleanly.
	rep := mustApply(t, p, newReg(t), Options{})
	if rep.Created < 5 {
		t.Fatalf("%+v", rep)
	}
}

func TestCSVParseErrorMidFileContinues(t *testing.T) {
	p, errs := parse(t, "mac,name\n02:00:5e:00:00:01,A\n02:00:5e:00:00:02,B\"x\n02:00:5e:00:00:03,C\n")
	if len(p.Devices) != 2 || len(errs) != 1 || errs[0].Line != 3 {
		t.Fatalf("%+v %v", p.Devices, errs)
	}
}

func TestCSVFileLevelErrors(t *testing.T) {
	for in, want := range map[string]error{
		"":                             ErrCSVEmpty,
		"\xef\xbb\xbf  \n\n":           ErrCSVEmpty,
		"name,notes\nA,B\n":            ErrCSVNoHeader,
		"na\"me,mac\nx\n":              ErrCSVNoHeader,
		strings.Repeat("a", 10) + "\n": ErrCSVNoHeader,
	} {
		_, _, err := ImportCSV(strings.NewReader(in))
		if !errors.Is(err, want) {
			t.Errorf("%q: got %v want %v", in, err, want)
		}
	}
	big := "mac\n" + strings.Repeat("x", MaxCSVBytes)
	if _, _, err := ImportCSV(strings.NewReader(big)); err != ErrCSVTooLarge {
		t.Errorf("big: %v", err)
	}
	if _, _, err := ImportCSV(errReader{}); err == nil {
		t.Error("read error not reported")
	}
}

func TestCSVRowCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("ip\n")
	for i := 0; i < MaxDevices+5; i++ {
		b.WriteString("192.0.2.1\n")
	}
	p, errs := parse(t, b.String())
	if len(p.Devices) != MaxDevices || len(errs) != 1 || !strings.Contains(errs[0].Msg, "too many rows") {
		t.Fatalf("%d %v", len(p.Devices), errs)
	}
}

func TestCSVWarningsCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("mac\n")
	for i := 0; i < MaxWarnings+20; i++ {
		b.WriteString("zz\n")
	}
	p, errs := parse(t, b.String())
	if len(errs) < MaxWarnings+20 || len(p.Warnings) != MaxWarnings {
		t.Fatalf("errs %d warnings %d", len(errs), len(p.Warnings))
	}
}

func TestDetectDelimiter(t *testing.T) {
	cases := map[string]rune{
		"a,b,c\n":       ',',
		"a;b;c\n":       ';',
		"a\tb\tc\n":     '\t',
		"\n\na;b\n":     ';',
		"\"a;b;c\",d\n": ',',
		"":              ',',
		"a,b;c\n":       ',',
	}
	for in, want := range cases {
		if got := detectDelimiter([]byte(in)); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func TestTruthy(t *testing.T) {
	for _, s := range []string{"yes", "Y", "true", "1", "x", "On"} {
		if v, ok := truthy(s); !v || !ok {
			t.Errorf("%q", s)
		}
	}
	for _, s := range []string{"", "no", "false", "0", "off"} {
		if v, ok := truthy(s); v || !ok {
			t.Errorf("%q", s)
		}
	}
	if _, ok := truthy("perhaps"); ok {
		t.Error("perhaps")
	}
}

func TestCSVUnsafeKeepsOrdinaryApostrophes(t *testing.T) {
	for in, want := range map[string]string{"'quoted'": "'quoted'", "'": "'", "'=x": "=x", "'-1": "-1", "plain": "plain"} {
		if got := csvUnsafe(in); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}
