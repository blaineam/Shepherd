// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"errors"
	"fmt"

	"shepherd/internal/importers"
)

// ErrNoUsage says the router answered, and named devices, but carried no
// usage figures at all. On eero that is a property of the account or the
// firmware rather than a fault, so the portal says so plainly instead of
// showing a stuck collector.
var ErrNoUsage = errors.New("routerusage: the router returned devices but no usage figures")

// EeroDevices is the part of importers.Client the eero Source uses.
type EeroDevices interface {
	Devices(ctx context.Context, networkID string) ([]importers.EeroDevice, error)
}

// Eero reads per-device usage from eero's cloud API. eero reports only the
// rate right now, so this is a KindRates source and its numbers are
// estimates once integrated; see the package doc.
//
// The integration is unofficial: eero publishes no API for this, and the
// one its app uses can change without notice.
type Eero struct {
	client    EeroDevices
	networkID string
}

// NewEero returns a Source reading networkID through client.
func NewEero(client EeroDevices, networkID string) *Eero {
	return &Eero{client: client, networkID: networkID}
}

// Name implements Source.
func (e *Eero) Name() string { return "eero" }

// Kind implements Source: eero exposes instantaneous rates only.
func (e *Eero) Kind() Kind { return KindRates }

// Poll implements Source. A device eero lists without a usage object is
// reported at zero rather than dropped, so a quiet device still counts as
// seen; if no device in the whole answer carried usage, Poll returns
// ErrNoUsage so the owner is told rather than left watching an empty chart.
func (e *Eero) Poll(ctx context.Context) ([]Sample, error) {
	devs, err := e.client.Devices(ctx, e.networkID)
	if err != nil {
		return nil, err
	}
	out := make([]Sample, 0, len(devs))
	anyUsage := false
	for _, d := range devs {
		mac := NormalizeMAC(d.MAC)
		if mac == "" {
			continue
		}
		if d.HasUsage {
			anyUsage = true
		}
		out = append(out, Sample{
			MAC:               mac,
			Name:              firstNonEmpty(d.Nickname, d.Hostname),
			DownBitsPerSecond: d.DownMbps * 1e6,
			UpBitsPerSecond:   d.UpMbps * 1e6,
		})
	}
	if len(out) > 0 && !anyUsage {
		return out, fmt.Errorf("%w (%d devices)", ErrNoUsage, len(out))
	}
	return out, nil
}

// EeroNeedsSignIn reports whether err means the stored session is no
// longer good, so the portal asks the owner to sign in again instead of
// showing a transient failure.
func EeroNeedsSignIn(err error) bool {
	return errors.Is(err, importers.ErrEeroSessionExpire) ||
		errors.Is(err, importers.ErrEeroUnauthorized) ||
		errors.Is(err, importers.ErrEeroNoSession)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
