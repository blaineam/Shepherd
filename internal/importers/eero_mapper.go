// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"sort"
	"strings"

	"shepherd/internal/devices"
)

// MapEero turns a Snapshot into a Plan: profiles become groups, a device in
// a profile joins that group, nicknames become aliases, hostnames and
// manufacturers become evidence, and eero's own routers and nodes become
// excluded infrastructure. Anything uncertain becomes a Warning, never a
// guess.
func MapEero(s Snapshot) Plan {
	w := &warner{}
	for _, x := range s.Warnings {
		w.add("%s", x)
	}
	src := "eero"
	if n := cleanText(s.Network.Name, 60); n != "" {
		src = "eero (" + n + ")"
	}
	plan := Plan{Source: src}

	// Which profile does each device belong to? Both the profile lists and
	// each device's own profile field are used; when they disagree, the
	// device joins no group and a warning says why.
	byMAC := map[string]*PlanDevice{}
	var order []string
	get := func(mac string) *PlanDevice {
		if p := byMAC[mac]; p != nil {
			return p
		}
		p := &PlanDevice{MAC: mac}
		byMAC[mac] = p
		order = append(order, mac)
		return p
	}
	urlToMAC := map[string]string{}
	nodeMACs := map[string]EeroNode{}
	for _, n := range s.Nodes {
		if m, ok := devices.NormalizeMAC(n.MAC); ok {
			nodeMACs[m] = n
		} else {
			w.add("an eero node (%s) has no usable MAC address and was left out", cleanText(n.Location, 40))
		}
	}

	profName := map[string]string{} // profile URL -> sanitized name
	for _, p := range s.Profiles {
		name := cleanLabel(p.Name, MaxGroupBytes)
		if name == "" {
			w.add("a profile with an empty name was ignored")
			continue
		}
		profName[p.URL] = name
		plan.Groups = append(plan.Groups, PlanGroup{Name: name})
	}

	devMemberships := map[string]map[string]bool{} // mac -> group names
	addMember := func(mac, group string) {
		if devMemberships[mac] == nil {
			devMemberships[mac] = map[string]bool{}
		}
		devMemberships[mac][group] = true
	}
	for _, d := range s.Devices {
		mac, ok := devices.NormalizeMAC(d.MAC)
		if d.URL != "" && ok {
			urlToMAC[d.URL] = mac
		}
	}

	infra := 0
	for _, d := range s.Devices {
		mac, macOK := devices.NormalizeMAC(d.MAC)
		who := cleanText(firstNonEmpty(d.Nickname, d.Hostname, d.MAC), 50)
		if d.MAC != "" && !macOK {
			w.add("%s: the MAC address %q is not usable", who, cleanText(d.MAC, 40))
		}
		pd := PlanDevice{
			IPs:        d.IPs,
			Name:       d.Nickname,
			Hostname:   d.Hostname,
			Vendor:     d.Manufacturer,
			Connection: d.Connection,
			Paused:     d.Paused,
		}
		if macOK {
			pd.MAC = mac
		}
		if d.DeviceType != "" {
			pd.Hints = append(pd.Hints, d.DeviceType)
		}
		if d.Guest {
			pd.Tags = append(pd.Tags, "guest")
		}
		if d.Connection != "" {
			note := "Imported from eero: " + d.Connection
			if d.NodeLocation != "" {
				note += " via " + cleanText(d.NodeLocation, 60)
			}
			pd.Notes = note
		}
		if n, isNode := nodeMACs[mac]; macOK && isNode {
			pd.Infrastructure = true
			if pd.Name == "" {
				pd.Name = nodeName(n)
			}
			infra++
		} else if strings.EqualFold(strings.TrimSpace(d.Manufacturer), "eero") {
			w.add("%s is made by eero but is not in the list of eero routers and nodes; it was not marked as infrastructure, check it by hand", who)
		}
		if !macOK && len(d.IPs) == 0 {
			continue // nothing identifies it; Sanitize would warn too
		}
		// Own profile field.
		own := cleanLabel(d.ProfileName, MaxGroupBytes)
		if own == "" && d.ProfileURL != "" {
			own = profName[d.ProfileURL]
		}
		if macOK {
			if own != "" {
				addMember(mac, own)
				if !hasGroup(plan.Groups, own) {
					plan.Groups = append(plan.Groups, PlanGroup{Name: own})
				}
			}
		}
		if macOK {
			*get(mac) = mergeDevice(*get(mac), pd)
		} else {
			// No MAC: keep it keyed by its first address.
			plan.Devices = append(plan.Devices, pd)
			if own != "" {
				plan.Devices[len(plan.Devices)-1].Groups = []string{own}
			}
		}
	}

	// Profile lists.
	for _, p := range s.Profiles {
		name := profName[p.URL]
		if name == "" {
			continue
		}
		var macs []string
		for _, m := range p.DeviceMACs {
			if mac, ok := devices.NormalizeMAC(m); ok {
				macs = append(macs, mac)
			}
		}
		for _, u := range p.DeviceURLs {
			mac, ok := urlToMAC[u]
			if !ok {
				if m, ok2 := devices.NormalizeMAC(macFromURL(u)); ok2 {
					mac, ok = m, true
				}
			}
			if !ok {
				w.add("profile %q lists a device that could not be identified and was left out", name)
				continue
			}
			macs = append(macs, mac)
		}
		for _, mac := range macs {
			if byMAC[mac] == nil {
				get(mac) // known only from the profile: a MAC with a group
			}
			addMember(mac, name)
		}
	}

	for _, mac := range order {
		pd := byMAC[mac]
		names := sortedKeys(devMemberships[mac])
		switch {
		case len(names) > 1:
			w.add("%s is listed in more than one profile (%s); it was not added to any group",
				cleanText(firstNonEmpty(pd.Name, pd.Hostname, mac), 50), strings.Join(names, ", "))
		case len(names) == 1:
			pd.Groups = names
		}
		plan.Devices = append(plan.Devices, *pd)
	}

	// Nodes that the devices list did not mention.
	nodeKeys := make([]string, 0, len(nodeMACs))
	for mac := range nodeMACs {
		nodeKeys = append(nodeKeys, mac)
	}
	sort.Strings(nodeKeys)
	for _, mac := range nodeKeys {
		n := nodeMACs[mac]
		if byMAC[mac] != nil {
			continue
		}
		pd := PlanDevice{MAC: mac, Name: nodeName(n), Vendor: "eero", Infrastructure: true, Notes: "Imported from eero: router/node " + cleanText(n.Model, 40)}
		if n.IP != "" {
			pd.IPs = []string{n.IP}
		}
		plan.Devices = append(plan.Devices, pd)
		infra++
	}
	if len(s.Nodes) > 0 && infra == 0 {
		w.add("no eero router or node was matched to a device")
	}
	plan.Warnings = w.list
	return plan
}

func nodeName(n EeroNode) string {
	switch {
	case n.Location != "":
		return n.Location + " eero"
	case n.Model != "":
		return "eero " + n.Model
	}
	return "eero"
}

func hasGroup(gs []PlanGroup, name string) bool {
	for _, g := range gs {
		if strings.EqualFold(g.Name, name) {
			return true
		}
	}
	return false
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
