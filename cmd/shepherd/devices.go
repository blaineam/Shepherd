// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/devices"
	"shepherd/internal/dnsengine"
)

// Test seams. Production leaves them at their defaults.
var (
	registryOptions  = func(*devices.Options) {}
	procRoutePath    = "/proc/net/route"
	neighborSources  = func() []devices.NeighborSource { return devices.DefaultNeighborSources(runtime.GOOS) }
	runMDNS          = func(ctx context.Context, l *devices.MDNSListener) error { return l.Run(ctx) }
	deviceDNSGap     = time.Minute // how often one client address is reported to the registry
	reverseDNSLookup = devices.PTRLookup
	hostname         = os.Hostname
	saveEvery        time.Duration // when set, overrides devices.save_interval_seconds
)

// deviceCodec is where the device file's encryption plugs in. The registry
// file holds MAC addresses, names and groups, so it should be sealed like the
// query history; until that lands it is stored as plain JSON with mode 0600.
func deviceCodec(config.Config) devices.Codec { return devices.PlainCodec{} }

// nodeID names this Shepherd in the registry's change stamps: the host name,
// or a random ID kept in <data>/node-id when there is none.
func nodeID(dataDir string) string {
	if h, err := hostname(); err == nil {
		if h = strings.TrimSpace(h); h != "" {
			return h
		}
	}
	path := filepath.Join(dataDir, "node-id")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	id := "node-" + hex.EncodeToString(raw)
	_ = os.WriteFile(path, []byte(id+"\n"), 0o600)
	return id
}

// onceLogger logs each distinct message once, so a source that fails every
// poll does not fill the log.
type onceLogger struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (o *onceLogger) log(prefix string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	msg := prefix + ": " + err.Error()
	if o.seen == nil {
		o.seen = map[string]bool{}
	}
	if !o.seen[msg] {
		o.seen[msg] = true
		log.Print(msg)
	}
}

// startDevices builds the device registry, restores it from <data>/devices.json,
// connects it to the DNS engine and starts every enabled source. The returned
// stop function waits for the sources (cancel ctx first) and saves the registry.
func startDevices(ctx context.Context, cfg config.Config, engine *dnsengine.Engine) (*devices.Registry, func(), error) {
	dc := cfg.Devices
	opts := devices.Options{NodeID: nodeID(cfg.DataDir), Codec: deviceCodec(cfg)}
	registryOptions(&opts)
	reg := devices.New(opts)
	path := filepath.Join(cfg.DataDir, "devices.json")
	if err := reg.Load(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Do not run on top of a file we cannot read and then overwrite it.
		bad := path + ".unreadable"
		log.Printf("devices: cannot read %s (%v); moved aside to %s and starting empty", path, err, bad)
		if rerr := os.Rename(path, bad); rerr != nil {
			return nil, nil, rerr
		}
	}
	engine.Clients = reg
	lookup := devices.NewLookup(reg)
	engine.Names = lookup
	if dc.Enabled && dc.DNS {
		feeder := &devices.DNSFeeder{Sink: reg, Interval: deviceDNSGap}
		engine.ClientSeen = feeder.Seen
	}

	var wg sync.WaitGroup
	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil {
				log.Printf("devices: %s stopped: %v", name, err)
			}
		}()
	}
	var logs onceLogger
	if dc.Enabled && dc.Neighbors {
		p := &devices.Poller{Sources: neighborSources(), Sink: reg, Interval: time.Duration(dc.NeighborIntervalSeconds) * time.Second,
			OnError: func(err error) { logs.log("devices: neighbor table", err) }}
		run("neighbor poller", p.Run)
	}
	if dc.Enabled && dc.MDNS {
		l := devices.NewMDNSListener(reg)
		l.OnError = func(err error) { logs.log("devices: mdns", err) }
		run("mdns listener", func(ctx context.Context) error { return runMDNS(ctx, l) })
	}
	if dc.Enabled && dc.ReverseDNS {
		server := dc.ReverseDNSServer
		if server == "" {
			server, _ = devices.ReadDefaultGateway(procRoutePath)
		}
		if server == "" {
			log.Print("devices: reverse DNS is on but no resolver was found (set devices.reverse_dns_server); names from PTR records are skipped")
		} else {
			rd := devices.NewReverseDNS(reverseDNSLookup(server), reg, devices.ReverseDNSOptions{})
			unsub := devices.AttachReverseDNS(reg, rd)
			run("reverse DNS", func(ctx context.Context) error { defer unsub(); return rd.Run(ctx) })
		}
	}

	save := func() {
		if err := reg.Save(path); err != nil {
			logs.log("devices: saving", err)
		}
	}
	last := reg.Clock()
	run("saver", func(ctx context.Context) error {
		every := time.Duration(dc.SaveIntervalSeconds) * time.Second
		if saveEvery > 0 {
			every = saveEvery
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
				reg.ExpireWandering(time.Now())
				if c := reg.Clock(); c != last {
					last = c
					save()
				}
			}
		}
	})
	stop := func() {
		wg.Wait()
		lookup.Close()
		save()
	}
	return reg, stop, nil
}
