// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package watch

import (
	"context"
	"net/netip"

	"shepherd/internal/arp"
	"shepherd/internal/intercept"
)

// RealPlatform is the operating system. Off Linux every method reports
// ErrUnsupported, so the engine reports itself unavailable and Shepherd
// runs without Watch mode.
type RealPlatform struct{}

func (RealPlatform) DefaultRoute() (string, netip.Addr, error) {
	return "", netip.Addr{}, ErrUnsupported
}
func (RealPlatform) DefaultRoute6() (Route6, error)        { return Route6{}, ErrUnsupported }
func (RealPlatform) Link(string) (Link, error)             { return Link{}, ErrUnsupported }
func (RealPlatform) Driver(string) (string, error)         { return "", ErrUnsupported }
func (RealPlatform) CarrierChanges(string) (uint64, error) { return 0, ErrUnsupported }
func (RealPlatform) LocalAddrs() ([]arp.MAC, []netip.Addr, error) {
	return nil, nil, ErrUnsupported
}
func (RealPlatform) GatewayMAC(context.Context, string, netip.Addr) (arp.MAC, error) {
	return arp.MAC{}, ErrUnsupported
}
func (RealPlatform) Neighbors(string) ([]Neighbor, error) { return nil, ErrUnsupported }
func (RealPlatform) OpenSender(string) (intercept.Sender, func() error, error) {
	return nil, nil, ErrUnsupported
}
func (RealPlatform) AttachXDP(context.Context, *intercept.Controller, string, intercept.XDPOptions) error {
	return ErrUnsupported
}
func (RealPlatform) ParallelRelay(context.Context, *intercept.Controller, string, int) error {
	return ErrUnsupported
}
func (RealPlatform) GRO(string) (bool, error)  { return false, ErrUnsupported }
func (RealPlatform) SetGRO(string, bool) error { return ErrUnsupported }

var _ Platform = RealPlatform{}
