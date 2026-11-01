// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log"
	"sort"

	"shepherd/internal/alarms"
	"shepherd/internal/arp"
	"shepherd/internal/devices"
)

// The passive ARP monitor's events (internal/arp, docs/ARP.md) as alarms
// (internal/alarms, docs/ALARMS.md). Each event type maps to one alarm
// type, or deliberately to none; the mapping is a pure function so the
// table in docs/ARP.md can be tested line by line without a socket.

// arpAlarm maps one ARP event to the alarm it raises. ok is false for an
// event that raises none:
//
//   - new-mac-seen: the device registry already raises new-device for a
//     device Shepherd has not seen, with its own learning period; raising
//     a second alarm for the same arrival would only be noise, and a
//     phone rotating its private address would ring it every time.
//   - any event with Baseline set, except a gateway change or suspected
//     spoofing: for the first minutes after start every device looks new
//     and every lease looks like a handover, and the monitor says so.
//   - ip-moved-to-new-mac at info severity: the monitor rates a rotation
//     between two randomized addresses after a quiet period as info,
//     which is a phone doing what phones do.
//
// Everything else becomes an alarm of the matching type, at the severity
// the monitor assigned (it rates the same event type differently by what
// it saw: a gratuitous flood for the gateway's address is worse than one
// for a laptop's), keyed by the monitor's own stable key so a repeat
// folds into the open alarm, and attributed to the registry's device for
// the suspect MAC where there is one.
func arpAlarm(e arp.Event, reg *devices.Registry) (alarms.Event, bool) {
	var typ string
	switch e.Type {
	case arp.EventGatewayMACChanged:
		typ = alarms.TypeARPGatewayChanged
	case arp.EventSpoofingSuspected:
		typ = alarms.TypeARPSpoofing
	case arp.EventIPMoved:
		if e.Severity == arp.SeverityInfo {
			return alarms.Event{}, false
		}
		typ = alarms.TypeARPIPMoved
	case arp.EventDuplicateIP:
		typ = alarms.TypeARPDuplicateIP
	case arp.EventManyIPs:
		typ = alarms.TypeARPManyIPs
	case arp.EventGratuitousFlood:
		typ = alarms.TypeARPFlood
	case arp.EventUnsolicitedStorm:
		typ = alarms.TypeARPReplyStorm
	default: // new-mac-seen and anything added later
		return alarms.Event{}, false
	}
	if e.Baseline && typ != alarms.TypeARPGatewayChanged && typ != alarms.TypeARPSpoofing {
		return alarms.Event{}, false
	}

	ev := alarms.Event{
		Type:     typ,
		Severity: alarms.Severity(e.Severity),
		Body:     e.Summary,
		Key:      string(e.Type) + "|" + e.Key + "|",
		Source:   "arp",
		Time:     e.Time,
	}
	if e.MAC != "" {
		ev.Evidence = append(ev.Evidence, alarms.Evidence{Label: "MAC", Value: e.MAC})
		if reg != nil {
			if d, found := reg.FindByMAC(e.MAC); found {
				ev.DeviceID = d.ID
				ev.GroupIDs = append([]string(nil), d.Groups...)
				ev.Evidence = append(ev.Evidence, alarms.Evidence{Label: "Device", Value: d.DisplayName()})
			}
		}
	}
	if e.OtherMAC != "" {
		ev.Evidence = append(ev.Evidence, alarms.Evidence{Label: "Other MAC", Value: e.OtherMAC})
	}
	if e.IP != "" {
		ev.Evidence = append(ev.Evidence, alarms.Evidence{Label: "IP", Value: e.IP})
	}
	keys := make([]string, 0, len(e.Evidence))
	for k := range e.Evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ev.Evidence = append(ev.Evidence, alarms.Evidence{Label: k, Value: e.Evidence[k]})
	}
	return ev, true
}

// reportARPEvent logs the event, as startARP did before anything consumed
// them, and raises its alarm when eng is wired and the event maps to one.
func reportARPEvent(eng *alarms.Engine, reg *devices.Registry, e arp.Event) {
	log.Printf("arp: %s (%s): %s", e.Type, e.Severity, e.Summary)
	if eng == nil {
		return
	}
	if ev, ok := arpAlarm(e, reg); ok {
		eng.Raise(ev)
	}
}
