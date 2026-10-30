// SPDX-License-Identifier: AGPL-3.0-or-later

package geo

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"shepherd/internal/dnsengine"
	"shepherd/internal/settings"
)

// Detector finds the network's public address.
type Detector interface {
	Detect(ctx context.Context) (net.IP, error)
}

// Placer locates an address and says whether its database is loaded.
type Placer interface {
	Locate(ip net.IP) (dnsengine.Dest, bool)
	Ready() bool
}

// AutoHome works out where home is from the network's public address and
// saves it, unless the user has chosen a location themselves. IP geolocation
// is approximate (usually the right city), so the user can always override it
// by clicking the globe.
type AutoHome struct {
	Detector Detector
	Placer   Placer
	Store    *settings.Store

	Every     time.Duration // re-check interval when it works (default 6h)
	Retry     time.Duration // after a failure (default 15m)
	WaitForDB time.Duration // while the map data is still downloading (default 20s)
	Now       func() time.Time
}

func (a *AutoHome) defaults() {
	if a.Every <= 0 {
		a.Every = 6 * time.Hour
	}
	if a.Retry <= 0 {
		a.Retry = 15 * time.Minute
	}
	if a.WaitForDB <= 0 {
		a.WaitForDB = 20 * time.Second
	}
	if a.Now == nil {
		a.Now = time.Now
	}
}

var errMapNotReady = errors.New("map data is not ready yet")

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// Once detects and saves the automatic home now.
func (a *AutoHome) Once(ctx context.Context) error {
	a.defaults()
	if !a.Placer.Ready() {
		return errMapNotReady
	}
	ip, err := a.Detector.Detect(ctx)
	if err != nil {
		return err
	}
	d, ok := a.Placer.Locate(ip)
	if !ok {
		return errors.New("this network's location is not in the map data")
	}
	label := d.City
	switch {
	case label != "" && d.Country != "":
		label += ", " + d.Country
	case label == "":
		label = d.Country
	}
	if err := a.Store.SetAuto(settings.Home{Lat: round2(d.Lat), Lon: round2(d.Lon), Label: label, At: a.Now()}); err != nil {
		return fmt.Errorf("saving the detected home: %w", err)
	}
	return nil
}

// Run keeps the automatic home current until ctx ends. While the user has
// chosen a home it does nothing at all, so no lookup leaves the machine.
func (a *AutoHome) Run(ctx context.Context) {
	a.defaults()
	for {
		delay := a.Every
		if a.Store.UserHome() == nil {
			switch err := a.Once(ctx); {
			case errors.Is(err, errMapNotReady):
				delay = a.WaitForDB
			case err != nil:
				delay = a.Retry
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}
