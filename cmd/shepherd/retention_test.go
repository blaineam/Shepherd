// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
)

func TestCapsForSplitsTheBudget(t *testing.T) {
	cfg := config.Default()
	// No budget: history keeps history.max_mb, the rest their defaults.
	if c := capsFor(cfg); c.History != int64(cfg.History.MaxMB)<<20 || c.Traffic != 0 || c.Nethealth != 0 {
		t.Fatalf("no budget: %+v", c)
	}
	// A roomy budget: 8 MiB each for the small stores, 32 MiB reserved,
	// history gets the rest but never more than history.max_mb.
	cfg.Retention.MaxMB = 1024
	c := capsFor(cfg)
	if c.Traffic != 8<<20 || c.Nethealth != 8<<20 || c.History != (1024-8-8-32)<<20 {
		t.Fatalf("1 GiB: %+v", c)
	}
	cfg.History.MaxMB = 100
	if c := capsFor(cfg); c.History != 100<<20 {
		t.Fatalf("history.max_mb smaller than its share should win: %+v", c)
	}
	// A small budget shrinks the shares proportionally and floors history.
	cfg.History.MaxMB = 0
	cfg.Retention.MaxMB = 16
	c = capsFor(cfg)
	if c.Traffic != 2<<20 || c.Nethealth != 2<<20 || c.History != (16-2-2-4)<<20 {
		t.Fatalf("16 MiB: %+v", c)
	}
	cfg.Retention.MaxMB = 1
	if c := capsFor(cfg); c.History != historyFloor {
		t.Fatalf("a 1 MiB budget floors history: %+v", c)
	}
}

func TestRetentionCheckRaisesWhenOverBudget(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	os.WriteFile(filepath.Join(cfg.DataDir, "traffic.json"), bytes.Repeat([]byte("x"), 3<<20), 0o600)
	os.MkdirAll(filepath.Join(cfg.DataDir, "history"), 0o700)
	os.WriteFile(filepath.Join(cfg.DataDir, "history", "seg"), bytes.Repeat([]byte("y"), 1<<20), 0o600)
	eng, err := alarms.New(alarms.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	// Under budget: nothing. No budget: nothing starts.
	checkRetention(cfg, eng, 8<<20)
	startRetention(context.Background(), cfg, eng)
	eng.Drain()
	if p := eng.List(alarms.Query{}); p.Total != 0 {
		t.Fatalf("under budget raised %+v", p.Alarms)
	}
	// Without an engine the check only logs.
	checkRetention(cfg, nil, 1<<20)

	// Over budget, through the running check.
	old := retentionEvery
	retentionEvery = time.Hour
	t.Cleanup(func() { retentionEvery = old })
	cfg.Retention.MaxMB = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startRetention(ctx, cfg, eng)
	var page alarms.Page
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.Drain()
		page = eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeStorageOverBudget}}})
		if page.Total > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page.Total != 1 {
		t.Fatalf("over budget: %+v", page.Alarms)
	}
	body := page.Alarms[0].Body
	if !strings.Contains(body, "4.0 MiB against a budget of 2.0 MiB") || !strings.Contains(body, "largest part is traffic.json at 3.0 MiB") {
		t.Fatalf("body = %q", body)
	}
	// A second check folds into the same alarm.
	checkRetention(cfg, eng, 2<<20)
	eng.Drain()
	if p := eng.List(alarms.Query{Filter: alarms.Filter{Types: []string{alarms.TypeStorageOverBudget}}}); p.Total != 1 || p.Alarms[0].Count < 2 {
		t.Fatalf("second check: %+v", p.Alarms)
	}
	if mib(0) != "0.0 MiB" || mib(1<<20+512<<10) != "1.5 MiB" || itoa(1234) != "1234" {
		t.Fatal("mib/itoa")
	}
}
