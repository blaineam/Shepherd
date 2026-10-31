// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package intercept

import "context"

// AttachXDP, like ParallelRelay, is Linux only: XDP is a Linux kernel
// facility with no equivalent elsewhere.
func (c *Controller) AttachXDP(ctx context.Context, iface string, opts XDPOptions) error {
	return ErrUnsupported
}
