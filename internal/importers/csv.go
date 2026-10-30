// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"

	"shepherd/internal/devices"
)

// MaxCSVBytes caps how much of a CSV file is read.
const MaxCSVBytes = 8 << 20

// CSVHeader is the column order of ExportCSV.
var CSVHeader = []string{"mac", "ip", "name", "vendor", "type", "groups", "tags", "excluded", "notes"}

// ErrCSVTooLarge, ErrCSVNoHeader and ErrCSVEmpty are file-level CSV errors.
// Problems in single rows never abort an import; they are RowErrors.
var (
	ErrCSVTooLarge = errors.New("importers: the CSV file is too large")
	ErrCSVNoHeader = errors.New("importers: the CSV needs a header row with a MAC or IP column")
	ErrCSVEmpty    = errors.New("importers: the CSV file is empty")
)

// RowError is a problem with one CSV row. The row is skipped (or imported
// without the offending field) and the import goes on.
type RowError struct {
	Line int
	Msg  string
}

func (e RowError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

// ---- export -----------------------------------------------------------------

// csvSafe prefixes a text field that a spreadsheet would run as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// csvUnsafe undoes csvSafe, so an export imports back to the same text.
func csvUnsafe(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}

// ExportCSV writes the registry's devices and groups as CSV that ImportCSV
// (and any spreadsheet) can read back. Group names are used, not IDs. Text
// fields that start with =, +, - or @ are prefixed with an apostrophe so a
// spreadsheet never runs them as formulas.
func ExportCSV(w io.Writer, reg *devices.Registry) error {
	if reg == nil {
		return ErrNoRegistry
	}
	names := map[string]string{}
	for _, g := range reg.Groups() {
		names[g.ID] = g.Name
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}
	for _, d := range reg.List() {
		var gs []string
		for _, id := range d.Groups {
			if n := names[id]; n != "" {
				gs = append(gs, csvSafe(n))
			}
		}
		typ := ""
		if d.TypeUser {
			typ = string(d.Type)
		}
		excluded := ""
		if d.Excluded {
			excluded = "yes"
		}
		tags := make([]string, len(d.Tags))
		for i, t := range d.Tags {
			tags[i] = csvSafe(t)
		}
		rec := []string{
			strings.Join(d.MACs, ";"),
			strings.Join(d.IPs, ";"),
			csvSafe(d.Alias),
			csvSafe(d.Vendor),
			csvSafe(typ),
			strings.Join(gs, ";"),
			strings.Join(tags, ";"),
			excluded,
			csvSafe(d.Notes),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ---- import -----------------------------------------------------------------

var headerAliases = map[string]string{
	"mac": "mac", "macaddress": "mac", "macaddr": "mac", "hwaddr": "mac", "hardwareaddress": "mac",
	"physicaladdress": "mac", "ethernetaddress": "mac", "clientmac": "mac", "devicemac": "mac",
	"ip": "ip", "ipaddress": "ip", "ipaddr": "ip", "ipv4": "ip", "ipv4address": "ip", "ips": "ip",
	"clientip": "ip", "deviceip": "ip", "lastip": "ip", "address": "ip",
	"name": "name", "nickname": "name", "alias": "name", "devicename": "name", "displayname": "name",
	"label": "name", "friendlyname": "name", "title": "name",
	"hostname": "hostname", "host": "hostname", "dnsname": "hostname", "dhcpname": "hostname",
	"vendor": "vendor", "manufacturer": "vendor", "brand": "vendor", "make": "vendor", "oui": "vendor",
	"type": "type", "devicetype": "type", "category": "type", "kind": "type", "devicecategory": "type",
	"group": "groups", "groups": "groups", "profile": "groups", "profiles": "groups",
	"tag": "tags", "tags": "tags", "labels": "tags",
	"excluded": "excluded", "exclude": "excluded", "ignore": "excluded", "ignored": "excluded",
	"note": "notes", "notes": "notes", "comment": "notes", "comments": "notes", "description": "notes",
}

func normHeader(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// detectDelimiter picks the delimiter of the first non-blank line: the one of
// comma, semicolon and tab that occurs most outside quotes (comma wins ties).
func detectDelimiter(data []byte) rune {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		counts := map[rune]int{}
		quoted := false
		for _, r := range string(line) {
			switch {
			case r == '"':
				quoted = !quoted
			case !quoted && (r == ',' || r == ';' || r == '\t'):
				counts[r]++
			}
		}
		best := ','
		for _, d := range []rune{';', '\t'} {
			if counts[d] > counts[best] {
				best = d
			}
		}
		return best
	}
	return ','
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '|' })
}

func splitIPs(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == ' ' || r == '|' })
}

func truthy(s string) (v, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "n", "no", "false", "f", "off":
		return false, true
	case "1", "y", "yes", "true", "t", "on", "x":
		return true, true
	}
	return false, false
}

// ImportCSV reads a CSV file into a Plan. It accepts a UTF-8 byte-order
// mark; comma, semicolon or tab delimiters; quoted fields; Windows line
// endings; blank lines; and extra or reordered columns identified by header
// names (see docs/IMPORT.md for the aliases). Bad rows become RowErrors and
// warnings and never stop the import; only an unusable file returns an error.
func ImportCSV(r io.Reader) (Plan, []RowError, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxCSVBytes+1))
	if err != nil {
		return Plan{}, nil, err
	}
	if len(data) > MaxCSVBytes {
		return Plan{}, nil, ErrCSVTooLarge
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(data)) == 0 {
		return Plan{}, nil, ErrCSVEmpty
	}
	cr := csv.NewReader(bytes.NewReader(data))
	cr.Comma = detectDelimiter(data)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = cr.Comma != '\t' // a tab delimiter must keep empty fields

	plan := Plan{Source: "CSV file"}
	var rowErrs []RowError
	fail := func(line int, format string, a ...any) {
		re := RowError{Line: line, Msg: fmt.Sprintf(format, a...)}
		rowErrs = append(rowErrs, re)
		if len(rowErrs) <= MaxWarnings {
			plan.Warnings = append(plan.Warnings, "CSV "+re.Error())
		}
	}

	var cols map[string]int
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		line := 0
		if err == nil {
			line, _ = cr.FieldPos(0)
		}
		if err != nil {
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				line = pe.StartLine
			}
			if cols == nil {
				return Plan{}, rowErrs, ErrCSVNoHeader
			}
			fail(line, "malformed row skipped (%v)", unwrapParse(err))
			continue
		}
		if cols == nil {
			cols = map[string]int{}
			for i, h := range rec {
				if k, ok := headerAliases[normHeader(h)]; ok {
					if _, dup := cols[k]; !dup {
						cols[k] = i
					}
				}
			}
			_, hasMAC := cols["mac"]
			_, hasIP := cols["ip"]
			if !hasMAC && !hasIP {
				return Plan{}, nil, ErrCSVNoHeader
			}
			continue
		}
		if len(plan.Devices) >= MaxDevices {
			fail(line, "too many rows; the rest of the file was ignored (limit %d)", MaxDevices)
			break
		}
		pd, ok := csvRow(rec, cols, line, fail)
		if ok {
			plan.Devices = append(plan.Devices, pd)
		}
	}
	return plan, rowErrs, nil
}

func unwrapParse(err error) error {
	var pe *csv.ParseError
	if errors.As(err, &pe) && pe.Err != nil {
		return pe.Err
	}
	return err
}

func csvRow(rec []string, cols map[string]int, line int, fail func(int, string, ...any)) (PlanDevice, bool) {
	get := func(k string) string {
		if i, ok := cols[k]; ok && i < len(rec) {
			return csvUnsafe(strings.TrimSpace(rec[i]))
		}
		return ""
	}
	allBlank := true
	for _, f := range rec {
		if strings.TrimSpace(f) != "" {
			allBlank = false
			break
		}
	}
	if allBlank {
		return PlanDevice{}, false
	}
	var pd PlanDevice
	macs := splitList(get("mac"))
	if len(macs) > 0 {
		if _, ok := devices.NormalizeMAC(macs[0]); !ok {
			fail(line, "%q is not a valid MAC address", cleanText(macs[0], 40))
		} else {
			pd.MAC = macs[0]
		}
		if len(macs) > 1 {
			fail(line, "only the first of %d MAC addresses was imported", len(macs))
		}
	}
	for _, s := range splitIPs(get("ip")) {
		if _, ok := normIP(s); !ok {
			fail(line, "%q is not a usable IP address", cleanText(s, 45))
			continue
		}
		pd.IPs = append(pd.IPs, s)
	}
	if pd.MAC == "" && len(pd.IPs) == 0 {
		fail(line, "row skipped: it needs a valid MAC or IP address")
		return PlanDevice{}, false
	}
	pd.Name, pd.Hostname, pd.Vendor = get("name"), get("hostname"), get("vendor")
	pd.Notes = get("notes")
	pd.Groups, pd.Tags = splitList(get("groups")), splitList(get("tags"))
	for i, t := range pd.Groups {
		pd.Groups[i] = csvUnsafe(t)
	}
	for i, t := range pd.Tags {
		pd.Tags[i] = csvUnsafe(t)
	}
	if t := get("type"); t != "" {
		if _, ok := devices.ParseType(t); !ok {
			fail(line, "unknown device type %q was ignored", cleanText(t, 40))
		} else {
			pd.Type = t
		}
	}
	v, ok := truthy(get("excluded"))
	if !ok {
		fail(line, "%q is not yes or no; the excluded column was ignored", cleanText(get("excluded"), 20))
	}
	pd.Excluded = v
	return pd, true
}
