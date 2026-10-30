// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"fmt"
	"strings"

	"shepherd/internal/devices"
)

// Options tunes Apply.
type Options struct {
	// OverwriteNames lets an imported name replace an alias the user already
	// set. By default the user's own name always wins.
	OverwriteNames bool
}

// Report describes what a Preview would do or what Apply did.
type Report struct {
	DryRun bool
	Source string

	Created      int // devices created
	MatchedByMAC int
	MatchedByIP  int
	Updated      int // existing devices that gained addresses, hostname, vendor or hints
	Named        int // aliases set on devices that had none
	Renamed      int // existing aliases replaced (only with OverwriteNames)
	Skipped      int
	Unchanged    int // matched devices that needed nothing

	GroupsCreated    int
	MembershipsAdded int
	TagsAdded        int // devices that gained tags
	MarkedExcluded   int
	NotesSet         int
	TypesSet         int

	Lines     []string // one human-readable line per change
	Conflicts []string // things left alone because they differ from what is already there
	Warnings  []string
}

// Changed reports whether anything was (or would be) changed.
func (r Report) Changed() bool {
	return r.Created+r.Updated+r.Named+r.Renamed+r.GroupsCreated+r.MembershipsAdded+
		r.TagsAdded+r.MarkedExcluded+r.NotesSet+r.TypesSet > 0
}

// String renders the report for people.
func (r Report) String() string {
	var b strings.Builder
	verb := "Applied"
	if r.DryRun {
		verb = "Preview (nothing has been changed)"
	}
	fmt.Fprintf(&b, "%s: import from %s\n", verb, orDefault(r.Source, "an unknown source"))
	fmt.Fprintf(&b, "Devices: %d to create, %d matched by MAC, %d matched by IP, %d skipped\n",
		r.Created, r.MatchedByMAC, r.MatchedByIP, r.Skipped)
	fmt.Fprintf(&b, "Names: %d to set, %d to replace\n", r.Named, r.Renamed)
	fmt.Fprintf(&b, "Groups: %d to create, %d memberships to add\n", r.GroupsCreated, r.MembershipsAdded)
	if !r.Changed() {
		b.WriteString("Nothing to change.\n")
	}
	for _, l := range r.Lines {
		b.WriteString("  + " + l + "\n")
	}
	for _, c := range r.Conflicts {
		b.WriteString("  ! " + c + "\n")
	}
	for _, w := range r.Warnings {
		b.WriteString("  ? " + w + "\n")
	}
	return b.String()
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Preview reports what Apply would do with the plan, changing nothing.
func Preview(plan Plan, reg *devices.Registry) (Report, error) {
	return run(plan, reg, Options{}, true)
}

// PreviewWith is Preview for a given set of options (so the preview of an
// overwriting import shows the replacements).
func PreviewWith(plan Plan, reg *devices.Registry, opts Options) (Report, error) {
	return run(plan, reg, opts, true)
}

// Apply performs the plan. It never deletes anything and is idempotent:
// applying the same plan again changes nothing.
func Apply(plan Plan, reg *devices.Registry, opts Options) (Report, error) {
	return run(plan, reg, opts, false)
}

type engine struct {
	reg    *devices.Registry
	opts   Options
	dry    bool
	rep    *Report
	groups map[string]string // lower-case name -> group ID ("" while only previewed)
	assign map[string][]string
}

func run(plan Plan, reg *devices.Registry, opts Options, dry bool) (Report, error) {
	if reg == nil {
		return Report{}, ErrNoRegistry
	}
	p, err := Sanitize(plan)
	if err != nil {
		return Report{}, err
	}
	rep := Report{DryRun: dry, Source: p.Source, Warnings: p.Warnings}
	e := &engine{reg: reg, opts: opts, dry: dry, rep: &rep, groups: map[string]string{}, assign: map[string][]string{}}
	e.doGroups(p.Groups)
	randomized := 0
	var order []string
	for _, pd := range p.Devices {
		if pd.MAC != "" && devices.IsLocallyAdministered(pd.MAC) {
			randomized++
		}
		e.doDevice(pd)
	}
	for _, g := range p.Groups {
		order = append(order, strings.ToLower(g.Name))
	}
	e.flushMemberships(order)
	if randomized > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"%d device(s) use randomized (private) MAC addresses; they can show up again under a new address, and Shepherd folds them into a device by IP or hostname", randomized))
	}
	return rep, nil
}

func (e *engine) doGroups(gs []PlanGroup) {
	for _, g := range gs {
		key := strings.ToLower(g.Name)
		if ex, ok := e.reg.GroupByName(g.Name); ok {
			e.groups[key] = ex.ID
			if ex.Color == "" && g.Color != "" {
				e.rep.Lines = append(e.rep.Lines, fmt.Sprintf("set the color of group %q", ex.Name))
				if !e.dry {
					_ = e.reg.SetGroupColor(ex.ID, g.Color)
				}
			}
			continue
		}
		e.rep.GroupsCreated++
		e.rep.Lines = append(e.rep.Lines, fmt.Sprintf("create group %q", g.Name))
		if e.dry {
			e.groups[key] = ""
			continue
		}
		ng, err := e.reg.CreateGroup(g.Name, g.Color)
		if err != nil {
			e.rep.GroupsCreated--
			e.rep.Warnings = append(e.rep.Warnings, fmt.Sprintf("group %q could not be created: %v", g.Name, err))
			continue
		}
		e.groups[key] = ng.ID
	}
}

// holderConflict says whether another device's hold on ip must be respected.
func holderConflict(mac string, existing *devices.Device, holder devices.Device) bool {
	if existing != nil && holder.ID == existing.ID {
		return false
	}
	if len(holder.MACs) == 0 {
		return false // an IP-only device: the registry folds it in
	}
	if existing == nil && mac != "" && devices.IsLocallyAdministered(mac) && holder.Randomized() {
		return false // a rotated private address
	}
	return true
}

func label(d devices.Device) string { return d.DisplayName() }

func (e *engine) resolve(pd PlanDevice) (existing *devices.Device, how string, ips []string) {
	if pd.MAC != "" {
		if d, ok := e.reg.FindByMAC(pd.MAC); ok {
			existing, how = &d, "mac"
		}
	}
	for _, ip := range pd.IPs {
		h, ok := e.reg.FindByIP(ip)
		if !ok {
			ips = append(ips, ip)
			continue
		}
		if pd.MAC == "" {
			if existing == nil {
				hh := h
				existing, how = &hh, "ip"
			}
			ips = append(ips, ip)
			continue
		}
		if holderConflict(pd.MAC, existing, h) {
			e.rep.Conflicts = append(e.rep.Conflicts, fmt.Sprintf(
				"%s: address %s is held by %q, which has other hardware addresses; the address was not moved", ident(pd), ip, label(h)))
			continue
		}
		if existing == nil {
			hh := h
			existing, how = &hh, "ip"
		}
		ips = append(ips, ip)
	}
	return existing, how, trimIPs(pd, existing, ips)
}

// trimIPs keeps what the registry can hold without churn: no-MAC devices are
// keyed by one address, a device keeps one IPv4 (an imported lease never
// displaces the address a device holds now) and any number of IPv6.
func trimIPs(pd PlanDevice, existing *devices.Device, ips []string) []string {
	if pd.MAC == "" && len(ips) > 1 {
		ips = ips[:1]
	}
	haveV4 := false
	if existing != nil {
		for _, s := range existing.IPs {
			if !strings.Contains(s, ":") {
				haveV4 = true
			}
		}
	}
	var out []string
	for _, ip := range ips {
		if !strings.Contains(ip, ":") {
			if haveV4 && (existing == nil || !containsStr(existing.IPs, ip)) {
				continue
			}
			haveV4 = true
		}
		out = append(out, ip)
	}
	return out
}

func ident(pd PlanDevice) string {
	switch {
	case pd.Name != "" && pd.MAC != "":
		return fmt.Sprintf("%q (%s)", pd.Name, pd.MAC)
	case pd.Name != "":
		return fmt.Sprintf("%q", pd.Name)
	case pd.MAC != "":
		return pd.MAC
	}
	return pd.IPs[0]
}

func missing(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if strings.EqualFold(h, w) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func (e *engine) doDevice(pd PlanDevice) {
	rep := e.rep
	existing, how, ips := e.resolve(pd)
	snap := devices.Device{}
	id := ""
	changed := false
	who := ident(pd)

	if existing == nil {
		rep.Created++
		changed = true
		rep.Lines = append(rep.Lines, "create device "+who)
		if !e.dry {
			id = e.observe(pd, ips, true)
			if id == "" {
				rep.Created--
				rep.Skipped++
				rep.Warnings = append(rep.Warnings, who+": the registry could not use this device")
				return
			}
			snap, _ = e.reg.Get(id)
		}
	} else {
		id, snap = existing.ID, *existing
		if how == "mac" {
			rep.MatchedByMAC++
		} else {
			rep.MatchedByIP++
		}
		needObs := (pd.MAC != "" && missing(snap.MACs, []string{pd.MAC})) ||
			missing(snap.IPs, ips) ||
			(pd.Hostname != "" && snap.Hostname == "") ||
			(pd.Vendor != "" && snap.Vendor == "") ||
			missing(snap.Hints, pd.Hints)
		if needObs {
			rep.Updated++
			changed = true
			rep.Lines = append(rep.Lines, fmt.Sprintf("add identity evidence to %q (matched by %s)", label(snap), strings.ToUpper(how)))
			if !e.dry {
				e.observe(pd, ips, snap.Hostname == "")
				snap, _ = e.reg.Get(id)
			}
		}
	}

	// name
	if pd.Name != "" {
		switch {
		case snap.Alias == pd.Name:
		case snap.Alias == "":
			rep.Named++
			changed = true
			rep.Lines = append(rep.Lines, fmt.Sprintf("name %s %q", who, pd.Name))
			e.do(func() { _ = e.reg.Rename(id, pd.Name) })
		case e.opts.OverwriteNames:
			rep.Renamed++
			changed = true
			rep.Lines = append(rep.Lines, fmt.Sprintf("rename %q to %q", snap.Alias, pd.Name))
			e.do(func() { _ = e.reg.Rename(id, pd.Name) })
		default:
			rep.Conflicts = append(rep.Conflicts, fmt.Sprintf("%s: kept your name %q instead of %q", who, snap.Alias, pd.Name))
		}
	}

	// type
	if pd.Type != "" {
		switch {
		case snap.TypeUser && string(snap.Type) != pd.Type:
			rep.Conflicts = append(rep.Conflicts, fmt.Sprintf("%s: kept your type %q instead of %q", who, snap.Type, pd.Type))
		case !snap.TypeUser:
			rep.TypesSet++
			changed = true
			rep.Lines = append(rep.Lines, fmt.Sprintf("set the type of %s to %s", who, pd.Type))
			e.do(func() { _ = e.reg.SetType(id, pd.Type) })
		}
	}

	// tags, exclusion, notes
	if missing(snap.Tags, pd.Tags) {
		rep.TagsAdded++
		changed = true
		rep.Lines = append(rep.Lines, fmt.Sprintf("tag %s: %s", who, strings.Join(pd.Tags, ", ")))
		e.do(func() { e.reg.BulkSetTags([]string{id}, pd.Tags, nil) })
	}
	if pd.Excluded && !snap.Excluded {
		rep.MarkedExcluded++
		changed = true
		rep.Lines = append(rep.Lines, fmt.Sprintf("exclude %s from protection and steering", who))
		e.do(func() { e.reg.BulkSetExcluded([]string{id}, true) })
	}
	if pd.Notes != "" {
		switch {
		case snap.Notes == pd.Notes:
		case snap.Notes == "":
			rep.NotesSet++
			changed = true
			rep.Lines = append(rep.Lines, fmt.Sprintf("add notes to %s", who))
			e.do(func() { _ = e.reg.SetNotes(id, pd.Notes) })
		default:
			rep.Conflicts = append(rep.Conflicts, fmt.Sprintf("%s: kept your existing notes", who))
		}
	}
	if pd.Paused {
		rep.Lines = append(rep.Lines, fmt.Sprintf("note: %s is paused at the source; Shepherd does not pause devices on import", who))
	}

	// groups
	for _, g := range pd.Groups {
		key := strings.ToLower(g)
		gid, known := e.groups[key]
		if !known {
			continue // the group could not be created; already warned
		}
		if gid != "" && containsStr(snap.Groups, gid) {
			continue
		}
		rep.MembershipsAdded++
		changed = true
		rep.Lines = append(rep.Lines, fmt.Sprintf("add %s to group %q", who, g))
		if !e.dry {
			e.assign[key] = append(e.assign[key], id)
		}
	}
	if !changed {
		rep.Unchanged++
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (e *engine) do(fn func()) {
	if !e.dry {
		fn()
	}
}

// observe feeds the plan device to the registry as identity evidence and
// returns the device ID.
func (e *engine) observe(pd PlanDevice, ips []string, withHost bool) string {
	o := devices.Observation{
		Source:     devices.SourceManual,
		MAC:        pd.MAC,
		VendorHint: pd.Vendor,
		Hints:      pd.Hints,
	}
	if withHost {
		o.Hostname = pd.Hostname
	}
	if len(ips) > 0 {
		o.IP = ips[0]
	}
	id := e.reg.Observe(o)
	if id == "" {
		return ""
	}
	for _, ip := range ips[min(1, len(ips)):] {
		e.reg.Observe(devices.Observation{Source: devices.SourceManual, MAC: pd.MAC, IP: ip})
	}
	return id
}

func (e *engine) flushMemberships(order []string) {
	for _, key := range order {
		ids := e.assign[key]
		if len(ids) == 0 {
			continue
		}
		_, _ = e.reg.BulkAssignGroup(ids, e.groups[key])
	}
}
