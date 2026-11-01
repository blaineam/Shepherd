// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import (
	"os"
	"syscall"
)

// reexec replaces this process with exe, keeping the arguments and the
// environment, so a supervisor sees the same process carry on. It only
// returns on failure.
func reexec(exe string) error {
	return syscall.Exec(exe, os.Args, os.Environ())
}
