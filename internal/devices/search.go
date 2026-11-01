// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// SortKey orders search results.
type SortKey int

const (
	SortRecent SortKey = iota // most recently seen first
	SortName                  // display name, A to Z
)

// SearchOptions controls ordering and pagination.
type SearchOptions struct {
	Sort   SortKey
	Offset int
	Limit  int // default 50, at most 500
}

// Page is one page of search results.
type Page struct {
	Items  []Device
	Total  int // matches before pagination
	Offset int
	Limit  int
}

type term struct {
	key, val string // key is "" for free text
	neg      bool
}

// tokenize splits on spaces, honoring double quotes (key:"two words").
func tokenize(q string) []string {
	var out []string
	var cur strings.Builder
	inQ, has := false, false
	for _, c := range q {
		switch {
		case c == '"':
			inQ, has = !inQ, true
		case unicode.IsSpace(c) && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(c)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

var filterKeys = map[string]bool{
	"group": true, "vendor": true, "type": true, "ip": true, "mac": true, "seen": true,
	"excluded": true, "wandering": true, "unnamed": true, "tag": true, "name": true, "watch": true,
}

func parseQuery(q string) []term {
	var terms []term
	for _, tok := range tokenize(q) {
		t := term{}
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			t.neg, tok = true, tok[1:]
		}
		if k, v, ok := strings.Cut(tok, ":"); ok && filterKeys[strings.ToLower(k)] {
			t.key, t.val = strings.ToLower(k), strings.ToLower(v)
		} else {
			t.val = strings.ToLower(tok)
		}
		terms = append(terms, t)
	}
	return terms
}

// parseSince understands "90s", "30m", "1h", "2d", "1w" and Go durations.
func parseSince(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	unit := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour}
	if u, ok := unit[s[len(s)-1]]; ok {
		if n, err := strconv.ParseFloat(s[:len(s)-1], 64); err == nil && n >= 0 {
			return time.Duration(n * float64(u)), true
		}
	}
	d, err := time.ParseDuration(s)
	return d, err == nil && d >= 0
}

func parseBool(s string) (v, ok bool) {
	switch s {
	case "true", "yes", "1", "y":
		return true, true
	case "false", "no", "0", "n":
		return false, true
	}
	return false, false
}

func stripMAC(s string) string {
	return strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
}

// Search finds devices. The query is free text plus filters, all ANDed:
//
//	group:kids vendor:apple type:camera ip:192.0.2. mac:02:00:5e seen:1h
//	excluded:true unnamed:true tag:guest name:tv watch:off
//
// A leading "-" negates a term (-group:kids, -printer). Free text matches
// any of display name, aliases, hostnames, IPs, MACs, vendor, type, tags,
// group names and notes. Values may be quoted: group:"smart home".
func (r *Registry) Search(query string, opts SearchOptions) Page {
	terms := parseQuery(query)
	now := r.now()
	r.mu.RLock()
	var hits []Device
	for _, d := range r.devices {
		if !d.Deleted && r.matchLocked(d, terms, now) {
			hits = append(hits, *r.copyOut(d))
		}
	}
	r.mu.RUnlock()

	sortDevices(hits, opts.Sort)
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 500)
	off := min(max(opts.Offset, 0), len(hits))
	end := min(off+limit, len(hits))
	return Page{Items: hits[off:end], Total: len(hits), Offset: off, Limit: limit}
}

func sortDevices(ds []Device, key SortKey) {
	names := make(map[string]string, len(ds))
	for i := range ds {
		names[ds[i].ID] = strings.ToLower(ds[i].DisplayName())
	}
	sort.Slice(ds, func(i, j int) bool {
		a, b := &ds[i], &ds[j]
		if key == SortRecent && !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		if names[a.ID] != names[b.ID] {
			return names[a.ID] < names[b.ID]
		}
		return a.ID < b.ID
	})
}

func (r *Registry) groupNames(d *Device) []string {
	var out []string
	for _, id := range r.liveGroups(d.Groups) {
		out = append(out, strings.ToLower(r.groups[id].Name))
	}
	return out
}

func (r *Registry) matchLocked(d *Device, terms []term, now time.Time) bool {
	var hay string
	for _, t := range terms {
		ok := true
		switch t.key {
		case "":
			if hay == "" {
				hay = r.haystack(d)
			}
			ok = strings.Contains(hay, t.val)
		case "group":
			ok = r.matchGroup(d, t.val)
		case "vendor":
			ok = strings.Contains(strings.ToLower(d.Vendor), t.val)
		case "type":
			ok = matchType(d, t.val)
		case "ip":
			ok = false
			for _, s := range append(append([]string(nil), d.IPs...), d.PastIPs...) {
				if strings.HasPrefix(s, t.val) {
					ok = true
					break
				}
			}
		case "mac":
			ok = false
			for _, m := range d.MACs {
				if strings.HasPrefix(stripMAC(m), stripMAC(t.val)) {
					ok = true
					break
				}
			}
		case "seen":
			dur, valid := parseSince(t.val)
			ok = valid && now.Sub(d.LastSeen) <= dur
		case "excluded":
			want, valid := parseBool(t.val)
			ok = valid && d.Excluded == want
		case "watch":
			want, valid := ParseWatchMode(t.val)
			ok = valid && t.val != "" && d.Watch == want
		case "wandering":
			want, valid := parseBool(t.val)
			active := d.Wandering && (d.WanderingUntil.IsZero() || d.WanderingUntil.After(now))
			ok = valid && active == want
		case "unnamed":
			want, valid := parseBool(t.val)
			ok = valid && !d.Named() == want
		case "tag":
			ok = false
			for _, tag := range d.Tags {
				if strings.Contains(tag, t.val) {
					ok = true
					break
				}
			}
		case "name":
			ok = strings.Contains(strings.ToLower(d.DisplayName()+"\n"+d.Alias+"\n"+d.MDNSName+"\n"+d.Hostname+"\n"+d.ReverseName), t.val)
		}
		if ok == t.neg {
			return false
		}
	}
	return true
}

func (r *Registry) matchGroup(d *Device, val string) bool {
	live := r.liveGroups(d.Groups)
	if val == "none" || val == "" {
		return len(live) == 0
	}
	for _, id := range live {
		if id == val || strings.Contains(strings.ToLower(r.groups[id].Name), val) {
			return true
		}
	}
	return false
}

func matchType(d *Device, val string) bool {
	if t, ok := ParseType(val); ok {
		return d.Type == t || (t == TypeUnknown && d.Type == "")
	}
	return strings.Contains(strings.ToLower(string(d.Type)), val)
}

func (r *Registry) haystack(d *Device) string {
	parts := []string{d.DisplayName(), d.Alias, d.MDNSName, d.Hostname, d.ReverseName, d.Vendor, string(d.Type), d.Notes}
	parts = append(parts, d.IPs...)
	parts = append(parts, d.PastIPs...)
	for _, m := range d.MACs {
		parts = append(parts, m, stripMAC(m))
	}
	parts = append(parts, d.Tags...)
	parts = append(parts, r.groupNames(d)...)
	return strings.ToLower(strings.Join(parts, "\n"))
}
