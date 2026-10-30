// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package intercept

import "context"

// ParallelRelay, like Open, is Linux only (PACKET_FANOUT is a Linux
// socket option with no equivalent elsewhere).
func (c *Controller) ParallelRelay(ctx context.Context, iface string, n int) error {
	return ErrUnsupported
}
