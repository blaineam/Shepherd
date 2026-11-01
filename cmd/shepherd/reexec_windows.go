// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import "errors"

// reexec cannot replace a running process on Windows; the new binary runs
// on the next start.
func reexec(string) error { return errors.New("restarting in place is not supported on Windows") }
