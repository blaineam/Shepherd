// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed" // oui_data.gz
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed oui_data.gz
var ouiGz []byte

// ouiTable is a sorted prefix table with interned vendor names.
type ouiTable struct {
	keys    []uint32
	vendor  []uint16
	vendors []string
}

var (
	ouiOnce sync.Once
	ouiTab  *ouiTable
)

func embeddedOUI() *ouiTable {
	ouiOnce.Do(func() {
		t, err := parseOUITable(bytes.NewReader(ouiGz))
		if err != nil {
			t = &ouiTable{}
		}
		ouiTab = t
	})
	return ouiTab
}

func parseOUITable(r io.Reader) (*ouiTable, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	t := &ouiTable{}
	idx := map[string]uint16{}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		prefix, vendor, ok := strings.Cut(sc.Text(), "\t")
		if !ok || len(prefix) != 6 {
			continue
		}
		k, err := strconv.ParseUint(prefix, 16, 32)
		if err != nil {
			continue
		}
		i, seen := idx[vendor]
		if !seen {
			i = uint16(len(t.vendors))
			idx[vendor] = i
			t.vendors = append(t.vendors, vendor)
		}
		t.keys = append(t.keys, uint32(k))
		t.vendor = append(t.vendor, i)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *ouiTable) lookup(key uint32) string {
	i := sort.Search(len(t.keys), func(i int) bool { return t.keys[i] >= key })
	if i < len(t.keys) && t.keys[i] == key {
		return t.vendors[t.vendor[i]]
	}
	return ""
}

// OUICount reports how many manufacturer prefixes are embedded.
func OUICount() int { return len(embeddedOUI().keys) }

// LookupVendor returns the registered manufacturer of a MAC address, or ""
// when the prefix is unknown or the address is locally administered
// (randomized), in which case the prefix says nothing about the maker.
func LookupVendor(mac string) string {
	m, ok := NormalizeMAC(mac)
	if !ok || IsLocallyAdministered(m) {
		return ""
	}
	// m is "aa:bb:cc:..."; the first three octets are the prefix.
	k, err := strconv.ParseUint(m[0:2]+m[3:5]+m[6:8], 16, 32)
	if err != nil {
		return ""
	}
	return embeddedOUI().lookup(uint32(k))
}
