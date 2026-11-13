// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/decoy"
	"shepherd/internal/detect"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
	"shepherd/internal/traffic"
)

// Test seams. Production leaves them at their defaults: detectEvery zero
// (five minutes), decoyListen nil (net.Listen) and localAddrs the host's
// real interface addresses.
var (
	detectEvery time.Duration
	decoyListen func(network, addr string) (net.Listener, error)
	localAddrs  = hostAddrs
)

const detectInterval = 5 * time.Minute

// detectParts is what startDetect built; every field is nil when [detect]
// is off.
type detectParts struct {
	engine *detect.Engine
	decoy  *decoy.Decoy
	// skipPort tells the port scan to leave Shepherd's own decoy ports on
	// this host out of its findings.
	skipPort func(ip string, port int) bool
}

// hostAddrs lists this host's own interface addresses.
func hostAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// narrowTypes are the device types that do one job and so talk to a small,
// steady set of places: the ones a new country is news for.
var narrowTypes = []devices.DeviceType{
	devices.TypeTV, devices.TypeStreamingBox, devices.TypeSpeaker, devices.TypeCamera, devices.TypeDoorbell,
	devices.TypePrinter, devices.TypeSmartHome, devices.TypeSmartPlug, devices.TypeThermostat, devices.TypeEReader,
}

// detectDevice describes a registry device to the checks. own are this
// host's addresses: Shepherd's host resolves through itself or not at all,
// and either way is not a device taking its lookups elsewhere.
func detectDevice(reg *devices.Registry, own []netip.Addr) func(string) (detect.DeviceInfo, bool) {
	return func(id string) (detect.DeviceInfo, bool) {
		d, ok := reg.Get(id)
		if !ok {
			return detect.DeviceInfo{}, false
		}
		info := detect.DeviceInfo{
			Name:   d.DisplayName(),
			Skip:   d.Excluded || d.Type == devices.TypeRouter,
			Narrow: slices.Contains(narrowTypes, d.Type),
		}
		for _, ip := range d.IPs {
			if a, err := netip.ParseAddr(ip); err == nil && slices.Contains(own, a.Unmap()) {
				info.Skip = true
			}
		}
		return info, true
	}
}

// startDetect builds the behaviour checks and the decoy ports
// (docs/DETECT.md), chains the checks onto the DNS engine's per-query hook
// after whatever is already there, and raises each finding as an alarm.
// eng may be nil (alarms disabled): findings are still recorded and logged.
// store may be nil: the traffic checks are then off. A decoy port that
// cannot be opened is logged and skipped; nothing here can stop Shepherd
// starting.
func startDetect(ctx context.Context, cfg config.Config, engine *dnsengine.Engine, reg *devices.Registry, store *traffic.Store, eng *alarms.Engine) detectParts {
	if !cfg.Detect.Enabled {
		return detectParts{}
	}
	own := localAddrs()
	opt := detect.Options{
		Dir:       cfg.DataDir,
		Device:    detectDevice(reg, own),
		OnFinding: func(f detect.Finding) { reportFinding(eng, reg, f) },
	}
	if store != nil { // avoid a non-nil interface over a nil *traffic.Store
		opt.Traffic = store
	}
	det, err := detect.New(opt)
	if err != nil {
		log.Printf("detect: starting fresh, could not read what was learned: %v", err)
	}
	prev := engine.OnEntry
	engine.OnEntry = func(e dnsengine.Entry) {
		if prev != nil {
			prev(e)
		}
		det.Observe(e)
	}
	every := detectInterval
	if detectEvery > 0 {
		every = detectEvery
	}
	go det.Run(ctx, every)

	parts := detectParts{engine: det}
	if len(cfg.Detect.DecoyPorts) == 0 {
		return parts
	}
	isOwn := func(a netip.Addr) bool { return slices.Contains(own, a) }
	dc := decoy.New(decoy.Options{
		Ports:   cfg.Detect.DecoyPorts,
		Listen:  decoyListen,
		Ignore:  isOwn,
		OnTouch: func(t decoy.Touch) { reportDecoyTouch(eng, reg, t) },
	})
	for _, p := range dc.Start(ctx) {
		if !p.Listening {
			log.Printf("detect: decoy port %d not opened: %s", p.Port, p.Error)
		}
	}
	open := dc.Listening()
	log.Printf("detect: decoy ports listening: %v", open)
	parts.decoy = dc
	parts.skipPort = func(ip string, port int) bool {
		a, err := netip.ParseAddr(ip)
		return err == nil && slices.Contains(open, port) && (a.IsLoopback() || isOwn(a.Unmap()))
	}
	return parts
}

// findingAlarm is the alarm type and the short title each kind of finding
// is raised as.
func findingAlarm(f detect.Finding) (typ, title string) {
	switch f.Kind {
	case detect.KindEncryptedDNS:
		return alarms.TypeEncryptedDNSLookup, f.Device + " looked up an encrypted-DNS resolver"
	case detect.KindSilentDNS:
		return alarms.TypeDNSBypass, f.Device + " is not using Shepherd for DNS"
	case detect.KindRandomNames:
		return alarms.TypeDNSRandomNames, f.Device + " asked for a burst of machine-made names"
	case detect.KindTunnel:
		return alarms.TypeDNSTunnel, f.Device + " may be carrying data in DNS"
	case detect.KindBeacon:
		return alarms.TypeDNSBeacon, f.Device + " checks in with " + f.Subject + " on a fixed interval"
	case detect.KindNewCountry:
		return alarms.TypeNewCountry, f.Device + " reached " + f.Subject + " for the first time"
	case detect.KindUploadSpike:
		return alarms.TypeUploadSpike, f.Device + " made an unusually large upload"
	}
	return string(f.Kind), f.Device + ": " + string(f.Kind)
}

// reportFinding logs a finding and raises it as an alarm attributed to the
// device, keyed by device, kind and subject so a repeat folds into the
// open alarm.
func reportFinding(eng *alarms.Engine, reg *devices.Registry, f detect.Finding) {
	log.Printf("detect: %s: %s", f.Kind, f.Summary)
	if eng == nil {
		return
	}
	typ, title := findingAlarm(f)
	var groups []string
	if reg != nil && f.DeviceID != "" {
		if d, ok := reg.Get(f.DeviceID); ok {
			groups = d.Groups
		}
	}
	subject := f.DeviceID
	if subject == "" {
		subject = f.Client
	}
	ev := make([]alarms.Evidence, 0, len(f.Evidence))
	for _, e := range f.Evidence {
		ev = append(ev, alarms.Evidence{Label: e.Label, Value: e.Value})
	}
	domain := ""
	if f.Kind != detect.KindNewCountry {
		domain = f.Subject
	}
	eng.Raise(alarms.Event{
		Type:     typ,
		Source:   "detect",
		Title:    title,
		Body:     f.Summary,
		Key:      typ + "|" + subject + "|" + f.Subject + "|",
		DeviceID: f.DeviceID,
		GroupIDs: groups,
		Domain:   domain,
		Time:     f.Time,
		Evidence: ev,
	})
}

// reportDecoyTouch logs a connection to a decoy port and raises it as an
// alarm naming the device behind the source address when the registry
// knows it.
func reportDecoyTouch(eng *alarms.Engine, reg *devices.Registry, t decoy.Touch) {
	who, deviceID := t.Source, ""
	var groups []string
	if reg != nil {
		if d, ok := reg.FindByIP(t.Source); ok {
			who, deviceID, groups = d.DisplayName(), d.ID, d.Groups
		}
	}
	what := decoy.PortName(t.Port)
	log.Printf("detect: %s (%s) connected to decoy port %d (%s)", who, t.Source, t.Port, what)
	if eng == nil {
		return
	}
	eng.Raise(alarms.Event{
		Type:   alarms.TypeDecoyTouched,
		Source: "decoy",
		Title:  who + " tried a decoy " + what + " port",
		Body: fmt.Sprintf("%s connected to port %d on Shepherd's host, where Shepherd listens and serves nothing. Nothing on a home network has a reason to; a device scanning its neighbours does. A network scanner you run yourself does too, and can be muted.",
			who, t.Port),
		Key:      "decoy-touched|" + t.Source + "|" + strconv.Itoa(t.Port) + "|",
		DeviceID: deviceID,
		GroupIDs: groups,
		Time:     t.Time,
		Evidence: []alarms.Evidence{
			{Label: "From", Value: t.Source},
			{Label: "Port", Value: strconv.Itoa(t.Port) + " (" + what + ")"},
			{Label: "Connections so far", Value: strconv.Itoa(t.Count)},
		},
	})
}
