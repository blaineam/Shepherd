// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package dnsengine

import (
	"syscall"
	"testing"
)

// refusePort makes connections to 127.0.0.1:port refused for the rest of
// the test, by binding the port without listening on it. It reports false
// when the port is already taken.
func refusePort(t *testing.T, port int) bool {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		syscall.Close(fd)
		return false
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return true
}
