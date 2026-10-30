// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sort"
	"strings"
)

// OUIEntry is one 24-bit manufacturer prefix (six upper-case hex digits)
// with its normalized vendor name.
type OUIEntry struct {
	Prefix string
	Vendor string
}

// legalSuffixes are corporate-form words stripped from the end of vendor
// names so the table reads "Apple", not "Apple, Inc.".
var legalSuffixes = map[string]bool{
	"inc": true, "incorporated": true, "corp": true, "corporation": true,
	"co": true, "company": true, "ltd": true, "limited": true, "llc": true,
	"gmbh": true, "ag": true, "sa": true, "bv": true, "nv": true, "plc": true,
	"pte": true, "oy": true, "ab": true, "as": true, "kg": true, "srl": true,
	"spa": true, "sarl": true, "kk": true, "pty": true, "lp": true, "llp": true,
	"sas": true, "sro": true, "ooo": true, "bhd": true, "sdn": true, "cv": true,
	"a/s": true, "&": true, "and": true, "s.a": true, "b.v": true, "s.r.l": true,
	"l.l.c": true, "k.k": true, "s.p.a": true, "co.,ltd": true,
}

// NormalizeVendor strips legal suffixes and tames SHOUTING names. It returns
// "" for the registry's placeholder entries.
func NormalizeVendor(name string) string {
	name = strings.TrimSpace(strings.ReplaceAll(name, ",", ", "))
	fields := strings.Fields(name)
	for len(fields) > 1 {
		last := strings.ToLower(strings.Trim(fields[len(fields)-1], ".,"))
		if !legalSuffixes[last] {
			break
		}
		fields = fields[:len(fields)-1]
	}
	if len(fields) > 0 {
		fields[len(fields)-1] = strings.TrimRight(fields[len(fields)-1], ".,")
	}
	out := strings.Join(fields, " ")
	out = strings.TrimRight(out, ",& ")
	if out == strings.ToUpper(out) && out != strings.ToLower(out) {
		out = titleCaps(out)
	}
	switch strings.ToLower(out) {
	case "", "private", "ieee registration authority":
		return ""
	}
	return out
}

// titleCaps converts an all-caps name to Title Case, leaving words of three
// letters or fewer (acronyms such as "TP", "LG", "HP") alone.
func titleCaps(s string) string {
	return strings.Join(mapWords(s, func(w string) string {
		if len(w) <= 3 {
			return w
		}
		return w[:1] + strings.ToLower(w[1:])
	}), "")
}

// mapWords splits s into runs of letters/digits and separators and maps the
// word runs, preserving separators.
func mapWords(s string, f func(string) string) []string {
	var out []string
	start := -1
	for i, c := range s {
		isWord := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		switch {
		case isWord && start < 0:
			start = i
		case !isWord && start >= 0:
			out = append(out, f(s[start:i]), string(c))
			start = -1
		case !isWord:
			out = append(out, string(c))
		}
	}
	if start >= 0 {
		out = append(out, f(s[start:]))
	}
	return out
}

// ParseIEEEOUI reads the IEEE MA-L text registry (oui.txt), keeping the
// "(hex)" lines. Placeholder and blank vendors are dropped.
func ParseIEEEOUI(r io.Reader) ([]OUIEntry, error) {
	var out []OUIEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, "(hex)")
		if i < 0 {
			continue
		}
		prefix := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(line[:i]), "-", ""))
		if len(prefix) != 6 || !isHex(prefix) {
			continue
		}
		vendor := NormalizeVendor(line[i+len("(hex)"):])
		if vendor == "" {
			continue
		}
		out = append(out, OUIEntry{Prefix: prefix, Vendor: vendor})
	}
	return out, sc.Err()
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// EncodeOUITable writes entries as a gzip-compressed, sorted "PREFIX<TAB>vendor"
// listing: the format of the embedded oui_data.gz.
func EncodeOUITable(entries []OUIEntry, w io.Writer) error {
	sorted := append([]OUIEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Prefix < sorted[j].Prefix })
	zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, e := range sorted {
		fmt.Fprintf(&buf, "%s\t%s\n", e.Prefix, e.Vendor)
	}
	if _, err := zw.Write(buf.Bytes()); err != nil {
		return err
	}
	return zw.Close()
}
