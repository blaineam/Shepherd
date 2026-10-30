// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"shepherd/internal/devices"
)

// Limits on what a single import may contain. Names come from a third party,
// so every text field is capped (in bytes, cut on a character boundary).
const (
	MaxDevices        = 5000
	MaxGroups         = 200
	MaxIPsPerDevice   = 8
	MaxGroupsPerDev   = 16
	MaxTagsPerDevice  = 16
	MaxAliasBytes     = 100
	MaxHostnameBytes  = 100
	MaxVendorBytes    = 64
	MaxGroupBytes     = 64 // the registry's own group-name limit
	MaxTagBytes       = 32
	MaxNotesBytes     = 500
	MaxHintBytes      = 64
	MaxHintsPerDevice = 8
	MaxWarnings       = 200
)

// ErrPlanTooLarge is returned when a plan exceeds MaxDevices or MaxGroups.
var ErrPlanTooLarge = errors.New("importers: the import is too large")

// ErrNoRegistry is returned when no registry is given.
var ErrNoRegistry = errors.New("importers: no device registry")

// Plan is the neutral, source-independent description of what to import.
type Plan struct {
	Source   string // human-readable origin, e.g. "CSV file" or "eero (Home)"
	Devices  []PlanDevice
	Groups   []PlanGroup
	Warnings []string
}

// PlanDevice is one device to import. At least one of MAC and IPs must be
// usable; a device with neither is skipped with a warning.
type PlanDevice struct {
	MAC            string   // any common form; normalized to lower-case colon form
	IPs            []string // current addresses
	Name           string   // display name to use as the alias
	Hostname       string   // evidence only
	Vendor         string   // evidence only
	Connection     string   // "wireless", "wired" or empty (informational)
	Type           string   // a Shepherd device type ("tv", "camera"...) or empty
	Hints          []string // extra identity evidence, e.g. the source's device type
	Groups         []string // group names
	Tags           []string
	Notes          string
	Excluded       bool // opt out of protection and traffic steering
	Infrastructure bool // a router or access point; implies Excluded and the router type
	Paused         bool // a hint only; Shepherd does not pause anything on import
}

// PlanGroup is a group to create. Color is optional ("#rrggbb").
type PlanGroup struct {
	Name  string
	Color string
}

var colorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// cleanText strips control and invisible formatting characters, turns every
// kind of whitespace into one space, trims, and caps the result at max bytes
// on a character boundary.
func cleanText(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == utf8.RuneError:
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
		for !utf8.ValidString(out) {
			out = out[:len(out)-1]
		}
		out = strings.TrimSpace(out)
	}
	return out
}

// cleanLabel is cleanText for group and tag names: the CSV list separator
// cannot appear inside one.
func cleanLabel(s string, max int) string {
	return cleanText(strings.NewReplacer(";", ",").Replace(s), max)
}

func normIP(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	a = a.Unmap().WithZone("")
	if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
		return "", false
	}
	return a.String(), true
}

func addUniqueFold(list []string, s string, limit int) []string {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return list
		}
	}
	if len(list) >= limit {
		return list
	}
	return append(list, s)
}

type warner struct{ list []string }

func (w *warner) add(format string, a ...any) {
	if len(w.list) == MaxWarnings {
		w.list = append(w.list, "more warnings were left out")
	}
	if len(w.list) > MaxWarnings {
		return
	}
	w.list = append(w.list, fmt.Sprintf(format, a...))
}

// Sanitize returns a cleaned copy of p: MACs normalized, IPs validated, text
// sanitized and capped, duplicates merged, groups used by devices added to
// the group list. Problems become warnings; it errors only when the plan is
// over the size limits.
func Sanitize(p Plan) (Plan, error) {
	if len(p.Devices) > MaxDevices || len(p.Groups) > MaxGroups {
		return Plan{}, ErrPlanTooLarge
	}
	w := &warner{}
	for _, s := range p.Warnings {
		w.add("%s", cleanText(s, 300))
	}
	out := Plan{Source: cleanText(p.Source, 100)}

	var groups []PlanGroup
	groupIdx := map[string]int{}
	addGroup := func(name, color string) {
		k := strings.ToLower(name)
		if i, ok := groupIdx[k]; ok {
			if groups[i].Color == "" {
				groups[i].Color = color
			}
			return
		}
		groupIdx[k] = len(groups)
		groups = append(groups, PlanGroup{Name: name, Color: color})
	}
	for _, g := range p.Groups {
		name := cleanLabel(g.Name, MaxGroupBytes)
		if name == "" {
			w.add("a group with an empty name was ignored")
			continue
		}
		color := strings.TrimSpace(g.Color)
		if color != "" && !colorRE.MatchString(color) {
			w.add("group %q: ignored the color, it is not of the form #rrggbb", name)
			color = ""
		}
		addGroup(name, color)
	}

	byKey := map[string]int{}
	for i, d := range p.Devices {
		nd, ok := sanitizeDevice(d, i+1, w)
		if !ok {
			continue
		}
		key := "mac:" + nd.MAC
		if nd.MAC == "" {
			key = "ip:" + nd.IPs[0]
		}
		if j, dup := byKey[key]; dup {
			out.Devices[j] = mergeDevice(out.Devices[j], nd)
			continue
		}
		byKey[key] = len(out.Devices)
		out.Devices = append(out.Devices, nd)
	}
	for _, d := range out.Devices {
		for _, g := range d.Groups {
			addGroup(g, "")
		}
	}
	if len(groups) > MaxGroups {
		return Plan{}, ErrPlanTooLarge
	}
	out.Groups = groups
	out.Warnings = w.list
	return out, nil
}

func sanitizeDevice(d PlanDevice, n int, w *warner) (PlanDevice, bool) {
	label := cleanText(d.Name, MaxAliasBytes)
	if label == "" {
		label = fmt.Sprintf("entry %d", n)
	}
	nd := PlanDevice{
		Name:           cleanText(d.Name, MaxAliasBytes),
		Hostname:       cleanText(d.Hostname, MaxHostnameBytes),
		Vendor:         cleanText(d.Vendor, MaxVendorBytes),
		Connection:     cleanText(d.Connection, 16),
		Notes:          cleanText(d.Notes, MaxNotesBytes),
		Excluded:       d.Excluded || d.Infrastructure,
		Infrastructure: d.Infrastructure,
		Paused:         d.Paused,
	}
	if strings.TrimSpace(d.MAC) != "" {
		if m, ok := devices.NormalizeMAC(d.MAC); ok {
			nd.MAC = m
		} else {
			w.add("%s: %q is not a usable MAC address and was ignored", label, cleanText(d.MAC, 40))
		}
	}
	for _, s := range d.IPs {
		if strings.TrimSpace(s) == "" {
			continue
		}
		ip, ok := normIP(s)
		if !ok {
			w.add("%s: %q is not a usable IP address and was ignored", label, cleanText(s, 45))
			continue
		}
		nd.IPs = addUniqueFold(nd.IPs, ip, MaxIPsPerDevice)
	}
	if nd.MAC == "" && len(nd.IPs) == 0 {
		w.add("%s: skipped, it has neither a usable MAC nor a usable IP address", label)
		return nd, false
	}
	switch {
	case nd.Infrastructure:
		nd.Type = string(devices.TypeRouter)
	case strings.TrimSpace(d.Type) != "":
		if t, ok := devices.ParseType(d.Type); ok {
			nd.Type = string(t)
		} else {
			w.add("%s: unknown device type %q was ignored", label, cleanText(d.Type, 40))
		}
	}
	for _, h := range d.Hints {
		if h = cleanText(h, MaxHintBytes); h != "" {
			nd.Hints = addUniqueFold(nd.Hints, h, MaxHintsPerDevice)
		}
	}
	for _, g := range d.Groups {
		if g = cleanLabel(g, MaxGroupBytes); g != "" {
			nd.Groups = addUniqueFold(nd.Groups, g, MaxGroupsPerDev)
		}
	}
	for _, t := range d.Tags {
		if t = strings.ToLower(cleanLabel(t, MaxTagBytes)); t != "" {
			nd.Tags = addUniqueFold(nd.Tags, t, MaxTagsPerDevice)
		}
	}
	return nd, true
}

func mergeDevice(a, b PlanDevice) PlanDevice {
	first := func(x, y string) string {
		if x != "" {
			return x
		}
		return y
	}
	a.Name, a.Hostname, a.Vendor = first(a.Name, b.Name), first(a.Hostname, b.Hostname), first(a.Vendor, b.Vendor)
	a.Connection, a.Type, a.Notes = first(a.Connection, b.Connection), first(a.Type, b.Type), first(a.Notes, b.Notes)
	for _, s := range b.IPs {
		a.IPs = addUniqueFold(a.IPs, s, MaxIPsPerDevice)
	}
	for _, s := range b.Hints {
		a.Hints = addUniqueFold(a.Hints, s, MaxHintsPerDevice)
	}
	for _, s := range b.Groups {
		a.Groups = addUniqueFold(a.Groups, s, MaxGroupsPerDev)
	}
	for _, s := range b.Tags {
		a.Tags = addUniqueFold(a.Tags, s, MaxTagsPerDevice)
	}
	a.Excluded = a.Excluded || b.Excluded
	a.Infrastructure = a.Infrastructure || b.Infrastructure
	a.Paused = a.Paused || b.Paused
	if a.Infrastructure {
		a.Type = string(devices.TypeRouter)
	}
	return a
}
