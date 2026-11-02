package main

import "testing"

func TestAAAAFilterModes(t *testing.T) {
	if f, v6 := aaaaFilter("off"); f != nil || v6 != nil {
		t.Error("off must not filter or probe")
	}
	if f, v6 := aaaaFilter("on"); f == nil || !f() || v6 != nil {
		t.Error("on must always filter, without probing")
	}
	f, v6 := aaaaFilter("auto")
	if f == nil || v6 == nil || f() {
		t.Error("auto starts by not filtering, until the probe finds IPv6 unreachable")
	}
	logIPv6Change(true)
	logIPv6Change(false)
}
