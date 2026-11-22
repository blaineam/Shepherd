// SPDX-License-Identifier: AGPL-3.0-or-later

package wanrate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type counters struct {
	mu     sync.Mutex
	rx, tx uint64
	err    error
}

func (c *counters) read() (uint64, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rx, c.tx, c.err
}

func (c *counters) set(rx, tx uint64) { c.mu.Lock(); c.rx, c.tx = rx, tx; c.mu.Unlock() }

func TestTwoReadingsMakeARate(t *testing.T) {
	c := &counters{rx: 1000, tx: 500}
	now := time.Unix(1000, 0)
	m := New(c.read, func() time.Time { return now })
	if _, _, ok := m.Rate(); ok {
		t.Fatal("a rate before any reading")
	}
	if err := m.Sample(); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := m.Rate(); ok {
		t.Fatal("a rate from one reading")
	}
	now = now.Add(2 * time.Second)
	c.set(1000+4000, 500+600)
	if err := m.Sample(); err != nil {
		t.Fatal(err)
	}
	down, up, ok := m.Rate()
	if !ok || down != 2000 || up != 300 {
		t.Fatalf("rate = %v down, %v up, %v", down, up, ok)
	}

	// A reading at the same instant changes nothing.
	c.set(9000, 9000)
	if err := m.Sample(); err != nil {
		t.Fatal(err)
	}
	if down, _, _ := m.Rate(); down != 2000 {
		t.Fatalf("a zero-length interval made a rate: %v", down)
	}

	// A counter that went backwards starts again rather than inventing a rate.
	now = now.Add(time.Second)
	c.set(10, 10)
	_ = m.Sample()
	if down, _, _ := m.Rate(); down != 2000 {
		t.Fatalf("a reset counter made a rate: %v", down)
	}
	now = now.Add(time.Second)
	c.set(110, 60)
	_ = m.Sample()
	if down, up, ok := m.Rate(); !ok || down != 100 || up != 50 {
		t.Fatalf("after the reset: %v %v %v", down, up, ok)
	}

	// A failed reading is an error, and the rate goes stale.
	c.err = errors.New("no such interface")
	if err := m.Sample(); err == nil {
		t.Fatal("a failed reading was hidden")
	}
	now = now.Add(staleAfter + time.Second)
	if _, _, ok := m.Rate(); ok {
		t.Fatal("a stale rate was offered")
	}
	if New(c.read, nil).now == nil {
		t.Fatal("no clock")
	}
}

func TestCountersAreReadFromSysfsFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := fileReader(dir)
	if _, _, err := read(); err == nil {
		t.Fatal("missing files read")
	}
	write("rx_bytes", "39540984094\n")
	if _, _, err := read(); err == nil {
		t.Fatal("a missing tx counter read")
	}
	write("tx_bytes", " 46788998030 \n")
	rx, tx, err := read()
	if err != nil || rx != 39540984094 || tx != 46788998030 {
		t.Fatalf("read = %d %d %v", rx, tx, err)
	}
	write("rx_bytes", "many")
	if _, _, err := read(); err == nil || !strings.Contains(err.Error(), "wanrate") {
		t.Fatalf("a counter that is not a number = %v", err)
	}
	// The real path is formed, whether or not this machine has it.
	if _, _, err := SysReader("no-such-interface-xyz")(); err == nil {
		t.Fatal("an interface that does not exist read")
	}
}

func TestRunSamplesUntilStopped(t *testing.T) {
	c := &counters{}
	m := New(c.read, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		c.rx += 1000
		c.mu.Unlock()
		if down, _, ok := m.Rate(); ok && down > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if down, _, ok := m.Rate(); !ok || down <= 0 {
		t.Fatalf("no rate from a running meter: %v %v", down, ok)
	}
	cancel()
	<-done
	// A zero interval falls back to the default rather than spinning.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	m.Run(ctx2, 0)
}
