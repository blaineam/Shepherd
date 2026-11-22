// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log"
	"path/filepath"

	"shepherd/internal/backends"
	"shepherd/internal/devices"
	"shepherd/internal/importers"
	"shepherd/internal/namesync"
	"shepherd/internal/routerusage"
	"shepherd/internal/secrets"
)

// startNames wires the device-name sync (docs/BACKENDS.md, "Device
// names"): Shepherd's registry, the connected router or firewall, and the
// eero account, whichever of them exist right now. Nothing is read or
// written until the owner previews a sync or switches the automatic one on.
func startNames(ctx context.Context, sec *secrets.Store, reg *devices.Registry, backend *backendManager, dataDir string) *namesync.Engine {
	eero := &eeroNames{sec: sec}
	e := namesync.New(namesync.Options{
		StatePath: filepath.Join(dataDir, "names-sync.json"),
		Logf:      log.Printf,
		// Shepherd first: when two names are equally good, the one the
		// owner sees here stays. eero is next because its names are the
		// ones a household has usually typed.
		Sources: func() []namesync.Source {
			out := []namesync.Source{registryNames{reg}}
			if eero.connected() {
				out = append(out, eero)
			}
			if b, ok := newBackendNames(backend); ok {
				out = append(out, b)
			}
			return out
		},
	})
	// A name edited in Shepherd goes out within seconds, not at the next
	// interval.
	reg.Subscribe(func(ev devices.Event) {
		if ev.Kind == devices.EventRenamed {
			e.Kick()
		}
	})
	go e.Run(ctx)
	return e
}

// ---- Shepherd's own registry ------------------------------------------------

type registryNames struct{ reg *devices.Registry }

func (registryNames) ID() string       { return "shepherd" }
func (registryNames) Label() string    { return "Shepherd" }
func (registryNames) ReadOnly() string { return "" }
func (registryNames) MaxLen() int      { return 128 }

// Entries lists every device by each of its MACs. The name is the owner's
// alias when there is one, otherwise what the device calls itself.
func (r registryNames) Entries(context.Context) ([]namesync.Entry, error) {
	var out []namesync.Entry
	for _, d := range r.reg.List() {
		name, typed := d.Alias, d.Alias != ""
		if !typed {
			name = d.MDNSName
			if name == "" {
				name = d.Hostname
			}
		}
		for _, mac := range d.MACs {
			if m := routerusage.NormalizeMAC(mac); m != "" {
				out = append(out, namesync.Entry{MAC: m, Name: name, Typed: typed, Learned: !typed, Vendor: d.Vendor, Handle: d.ID})
			}
		}
	}
	return out, nil
}

func (r registryNames) Rename(_ context.Context, e namesync.Entry, name string) error {
	return r.reg.Rename(e.Handle.(string), name)
}

// ---- the connected router or firewall ---------------------------------------

// backendNames is the dashboard hub's backend (Firewalla, UniFi) as a place
// names live. It reads the hub's latest device list rather than asking the
// product again.
type backendNames struct {
	m     *backendManager
	name  string
	ro    string
	limit int
}

var backendLabels = map[string]string{"firewalla": "Firewalla", "unifi": "UniFi"}

// newBackendNames reports ok false when no backend is running or it cannot
// list devices.
func newBackendNames(m *backendManager) (*backendNames, bool) {
	if m == nil {
		return nil, false
	}
	snap, ok := m.Snapshot()
	if !ok || !hasCap(snap.Capabilities, backends.CapDevices) {
		return nil, false
	}
	b := &backendNames{m: m, name: snap.Name}
	label := b.Label()
	switch {
	case hasCap(snap.Capabilities, backends.CapDeviceRename):
	case snap.ReadOnly && m.canRename():
		b.ro = "Allow changes is off for your " + label + ", so names are read from it but not written to it"
	default:
		b.ro = label + " has no way to rename a device from outside, so names are read from it but not written to it"
	}
	if snap.Name == "firewalla" {
		b.limit = 32 // MSP's limit
	}
	return b, true
}

func hasCap(caps []backends.Capability, c backends.Capability) bool {
	for _, have := range caps {
		if have == c {
			return true
		}
	}
	return false
}

func (b *backendNames) ID() string { return b.name }
func (b *backendNames) Label() string {
	if l, ok := backendLabels[b.name]; ok {
		return l
	}
	return b.name
}
func (b *backendNames) ReadOnly() string { return b.ro }
func (b *backendNames) MaxLen() int      { return b.limit }

func (b *backendNames) Entries(context.Context) ([]namesync.Entry, error) {
	snap, ok := b.m.Snapshot()
	if !ok {
		return nil, errNoBackend
	}
	if msg := snap.Status.Errors["devices"]; msg != "" {
		return nil, errors.New(msg)
	}
	out := make([]namesync.Entry, 0, len(snap.Devices))
	for _, d := range snap.Devices {
		if d.MAC == "" {
			continue
		}
		out = append(out, namesync.Entry{MAC: d.MAC, Name: d.Name, Vendor: d.Vendor, Handle: d.Ref()})
	}
	return out, nil
}

func (b *backendNames) Rename(ctx context.Context, e namesync.Entry, name string) error {
	return b.m.RenameDevice(ctx, e.Handle.(backends.DeviceRef), name)
}

// ---- eero -------------------------------------------------------------------

// eeroNames is the owner's eero account as a place names live, through the
// sign-in kept for the bandwidth reader. A client is opened per call and
// discarded; the token stays in the secrets store.
type eeroNames struct {
	sec *secrets.Store
	// open replaces how a client is made, for tests.
	open func(importers.TokenStore) (*importers.Client, error)
}

func (*eeroNames) ID() string       { return "eero" }
func (*eeroNames) Label() string    { return "eero" }
func (*eeroNames) ReadOnly() string { return "" }
func (*eeroNames) MaxLen() int      { return 0 }

func (e *eeroNames) connected() bool {
	s, ok := e.sec.Eero()
	return ok && s.NetworkID != ""
}

func (e *eeroNames) client() (*importers.Client, string, error) {
	s, ok := e.sec.Eero()
	if !ok || s.NetworkID == "" {
		return nil, "", importers.ErrEeroNoSession
	}
	store := secrets.EeroTokenStore{S: e.sec}
	var (
		c   *importers.Client
		err error
	)
	if e.open != nil {
		c, err = e.open(store)
	} else {
		c, err = importers.NewClient(importers.ClientOptions{TokenStore: store})
	}
	if err != nil {
		return nil, "", err
	}
	if resumed, err := c.Resume(); err != nil || !resumed {
		if err == nil {
			err = importers.ErrEeroNoSession
		}
		return nil, "", err
	}
	return c, s.NetworkID, nil
}

func (e *eeroNames) Entries(ctx context.Context) ([]namesync.Entry, error) {
	c, network, err := e.client()
	if err != nil {
		return nil, err
	}
	defer c.Discard()
	devs, err := c.Devices(ctx, network)
	if err != nil {
		return nil, err
	}
	out := make([]namesync.Entry, 0, len(devs))
	for _, d := range devs {
		mac := routerusage.NormalizeMAC(d.MAC)
		if mac == "" {
			continue
		}
		en := namesync.Entry{MAC: mac, Name: d.Nickname, Vendor: d.Manufacturer, Handle: mac}
		switch {
		case d.Nickname == "":
			en.Name, en.Learned = d.Hostname, true
		case d.Nickname == d.Hostname || d.Nickname == d.Manufacturer:
			// eero fills an unset nickname with the hostname or the maker.
			en.Learned = true
		default:
			en.Typed = true
		}
		out = append(out, en)
	}
	return out, nil
}

func (e *eeroNames) Rename(ctx context.Context, en namesync.Entry, name string) error {
	c, network, err := e.client()
	if err != nil {
		return err
	}
	defer c.Discard()
	return c.RenameDevice(ctx, network, en.Handle.(string), name)
}
