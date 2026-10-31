// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package watch

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// GRO (generic receive offload) coalesces several inbound TCP segments into
// one oversized frame before any socket, raw ones included, sees them. The
// userspace relay retransmits what it captures unchanged, and a coalesced
// super-frame is larger than the wire allows, so the send fails with
// EMSGSIZE and the health loop fails that device open (correctly, but for
// a capture artifact, not a fault). cmd/intercept-trial shelled out to
// ethtool for this; the container image has no ethtool, so this file does
// the same thing ethtool does, with the SIOCETHTOOL ioctl and the
// ETHTOOL_GGRO/ETHTOOL_SGRO commands. XDP native mode sees frames before
// GRO happens and does not need any of this.

var errGROFixed = errors.New("watch: generic receive offload cannot be changed on this interface")

// ethtoolValue is struct ethtool_value from linux/ethtool.h.
type ethtoolValue struct {
	cmd  uint32
	data uint32
}

// ifreq is struct ifreq with the union as a pointer, which is the shape
// SIOCETHTOOL wants (ifr_data points at the ethtool command). The union is
// 24 bytes on 64-bit kernels; the pointer fills the first 8 and the rest
// is padding, so the struct is the kernel's 40 bytes on amd64/arm64.
type ifreq struct {
	name [unix.IFNAMSIZ]byte
	data uintptr
	_    [24 - unsafe.Sizeof(uintptr(0))]byte
}

// ethtoolGRO reads GRO's state on iface and, when set is not nil, sets it
// first. It returns the state after the call.
func ethtoolGRO(iface string, set *bool) (bool, error) {
	if len(iface) >= unix.IFNAMSIZ {
		return false, fmt.Errorf("watch: interface name %q too long", iface)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("watch: ethtool socket: %w", err)
	}
	defer unix.Close(fd)

	do := func(cmd, data uint32) (uint32, error) {
		val := ethtoolValue{cmd: cmd, data: data}
		var req ifreq
		copy(req.name[:], iface)
		req.data = uintptr(unsafe.Pointer(&val))
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&req)))
		runtime.KeepAlive(&val)
		if errno != 0 {
			return 0, errno
		}
		return val.data, nil
	}

	if set != nil {
		var want uint32
		if *set {
			want = 1
		}
		if _, err := do(unix.ETHTOOL_SGRO, want); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
				return false, fmt.Errorf("%w: %v", errGROFixed, err)
			}
			return false, fmt.Errorf("watch: set GRO on %s (needs CAP_NET_ADMIN): %w", iface, err)
		}
	}
	cur, err := do(unix.ETHTOOL_GGRO, 0)
	if err != nil {
		return false, fmt.Errorf("watch: read GRO on %s: %w", iface, err)
	}
	return cur != 0, nil
}
