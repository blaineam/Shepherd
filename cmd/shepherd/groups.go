// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"strings"

	"shepherd/internal/backends"
	"shepherd/internal/devices"
	"shepherd/internal/namesync"
	"shepherd/internal/routerusage"
)

// startGroups wires the device-group sync (docs/BACKENDS.md, "Device
// groups"): which group each device is in, kept the same in Shepherd's
// registry and on the connected router or firewall when it has groups. It
// is the name sync's engine with different rules: being in a group beats
// being in none, and taking a device out of its group in one place takes
// it out in the other. Nothing is read or written until the owner
// previews a sync or switches the automatic one on.
func startGroups(ctx context.Context, reg *devices.Registry, backend *backendManager, dataDir string) *namesync.Engine {
	e := namesync.New(namesync.Options{
		StatePath:   filepath.Join(dataDir, "groups-sync.json"),
		Logf:        log.Printf,
		Rank:        groupRank,
		ClearIsEdit: true,
		// Shepherd first: when both places have a device in a group and
		// they differ, Shepherd's stays.
		Sources: func() []namesync.Source {
			out := []namesync.Source{registryGroups{reg}}
			if b, ok := newBackendGroups(backend); ok {
				out = append(out, b)
			}
			return out
		},
	})
	reg.Subscribe(func(ev devices.Event) {
		switch ev.Kind {
		case devices.EventGroupMembers, devices.EventGroupUpdated, devices.EventGroupDeleted:
			e.Kick()
		}
	})
	go e.Run(ctx)
	return e
}

// groupRank ranks a membership: any group beats none, and no group is
// better than another.
func groupRank(e namesync.Entry) int {
	if strings.TrimSpace(e.Name) == "" {
		return namesync.Useless
	}
	return namesync.Machine
}

// ---- Shepherd's own registry ------------------------------------------------

// registryGroups offers each device's group. A Shepherd device can be in
// several groups and a router's device in only one, so one of them is
// offered: the first by ID that is a real group. Quarantine, where
// Shepherd holds devices nobody has sorted yet, and a group called
// "Unassigned" both mean "no group" and are never offered.
type registryGroups struct{ reg *devices.Registry }

func (registryGroups) ID() string       { return "shepherd" }
func (registryGroups) Label() string    { return "Shepherd" }
func (registryGroups) ReadOnly() string { return "" }
func (registryGroups) MaxLen() int      { return 64 }

// groupHandle is what moving a device needs: the device, and the group it
// is being moved out of.
type groupHandle struct{ device, group string }

// notAGroup reports whether a registry group stands for "not sorted yet".
func notAGroup(g devices.Group) bool {
	return g.ID == devices.QuarantineGroupID || strings.EqualFold(strings.TrimSpace(g.Name), "unassigned")
}

func (r registryGroups) Entries(context.Context) ([]namesync.Entry, error) {
	names := map[string]string{}
	for _, g := range r.reg.Groups() {
		if !notAGroup(g) {
			names[g.ID] = g.Name
		}
	}
	var out []namesync.Entry
	for _, d := range r.reg.List() {
		h := groupHandle{device: d.ID}
		name := ""
		for _, id := range d.Groups {
			if n, ok := names[id]; ok {
				h.group, name = id, n
				break
			}
		}
		for _, mac := range d.MACs {
			if m := routerusage.NormalizeMAC(mac); m != "" {
				out = append(out, namesync.Entry{MAC: m, Name: name, Typed: true, Handle: h})
			}
		}
	}
	return out, nil
}

// Rename moves the device: out of the group it was offered in, and into
// the one called name, which is made if Shepherd has none by that name.
// An empty name only takes it out.
func (r registryGroups) Rename(_ context.Context, e namesync.Entry, name string) error {
	h := e.Handle.(groupHandle)
	var into devices.Group
	if name = strings.TrimSpace(name); name != "" {
		g, ok := r.reg.GroupByName(name)
		if !ok {
			var err error
			if g, err = r.reg.CreateGroup(name, ""); err != nil {
				return err
			}
		}
		into = g
	}
	if h.group != "" && h.group != into.ID {
		if _, err := r.reg.BulkRemoveGroup([]string{h.device}, h.group); err != nil && !errors.Is(err, devices.ErrGroupNotFound) {
			return err
		}
	}
	if into.ID == "" {
		return nil
	}
	res, err := r.reg.BulkAssignGroup([]string{h.device}, into.ID)
	if err == nil && len(res.Missing) > 0 {
		err = devices.ErrNotFound
	}
	return err
}

// ---- the connected router or firewall ---------------------------------------

// backendGroups is the dashboard hub's backend as a place devices are
// grouped, for a product that has device groups.
type backendGroups struct {
	m    *backendManager
	name string
	ro   string
}

// newBackendGroups reports ok false when no backend is running or its
// product has no device groups.
func newBackendGroups(m *backendManager) (*backendGroups, bool) {
	if m == nil {
		return nil, false
	}
	snap, ok := m.Snapshot()
	if !ok || !hasCap(snap.Capabilities, backends.CapGroups) || !hasCap(snap.Capabilities, backends.CapDevices) {
		return nil, false
	}
	b := &backendGroups{m: m, name: snap.Name}
	if !hasCap(snap.Capabilities, backends.CapGroupWrite) {
		b.ro = "Allow changes is off for your " + b.Label() + ", so groups are read from it but not written to it"
	}
	return b, true
}

func (b *backendGroups) ID() string { return b.name }
func (b *backendGroups) Label() string {
	if l, ok := backendLabels[b.name]; ok {
		return l
	}
	return b.name
}
func (b *backendGroups) ReadOnly() string { return b.ro }
func (b *backendGroups) MaxLen() int      { return 64 }

func (b *backendGroups) Entries(context.Context) ([]namesync.Entry, error) {
	snap, ok := b.m.Snapshot()
	if !ok {
		return nil, errNoBackend
	}
	for _, res := range []string{"devices", "groups"} {
		if msg := snap.Status.Errors[res]; msg != "" {
			return nil, errors.New(msg)
		}
	}
	out := make([]namesync.Entry, 0, len(snap.Devices))
	for _, d := range snap.Devices {
		if d.MAC != "" {
			out = append(out, namesync.Entry{MAC: d.MAC, Name: d.Group, Handle: d.Ref()})
		}
	}
	return out, nil
}

func (b *backendGroups) Rename(ctx context.Context, e namesync.Entry, name string) error {
	return b.m.SetDeviceGroup(ctx, e.Handle.(backends.DeviceRef), name)
}
