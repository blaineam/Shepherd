// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/update"
)

// The retention budget (docs/UPDATE.md "Retention"): one number in
// shepherd.toml, [retention] max_mb, that caps the data directory as a
// whole. It is split into caps for the stores that can grow, and a
// housekeeping check says when the directory has grown past it anyway.
const (
	// smallStoreCap is the most the bandwidth and network-health stores
	// each take under a budget: their own default cap.
	smallStoreCap = 8 << 20
	// budgetReserve is set aside for the small files (devices, alarms, the
	// threat-feed cache, lists) before query history gets the rest.
	budgetReserve = 32 << 20
	// historyFloor is the least query history is ever given under a
	// budget, so a tiny budget still leaves it something to work with.
	historyFloor = 1 << 20
)

// retentionEvery is how often the housekeeping check runs; tests shorten it.
var retentionEvery = 6 * time.Hour

// retentionCaps is what each growable store may hold. Zero means the
// store's own default (or, for history, history.max_mb).
type retentionCaps struct {
	History   int64
	Traffic   int
	Nethealth int
}

// capsFor splits the budget. Without one, every store keeps its own cap.
func capsFor(cfg config.Config) retentionCaps {
	caps := retentionCaps{History: int64(cfg.History.MaxMB) << 20}
	budget := int64(cfg.Retention.MaxMB) << 20
	if budget <= 0 {
		return caps
	}
	small := min(int64(smallStoreCap), budget/8)
	reserve := min(int64(budgetReserve), budget/4)
	hist := max(budget-2*small-reserve, int64(historyFloor))
	if caps.History > 0 && caps.History < hist {
		hist = caps.History
	}
	caps.History = hist
	caps.Traffic, caps.Nethealth = int(small), int(small)
	return caps
}

// startRetention runs the housekeeping check: at start and every
// retentionEvery it measures the data directory and raises (or clears,
// by its key) a storage-over-budget alarm. Nothing runs without a budget.
func startRetention(ctx context.Context, cfg config.Config, eng *alarms.Engine) {
	budget := int64(cfg.Retention.MaxMB) << 20
	if budget <= 0 {
		return
	}
	go func() {
		tk := time.NewTicker(retentionEvery)
		defer tk.Stop()
		for {
			checkRetention(cfg, eng, budget)
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
			}
		}
	}()
}

// checkRetention measures once and reports.
func checkRetention(cfg config.Config, eng *alarms.Engine, budget int64) {
	total, parts := update.DirSize(cfg.DataDir)
	if total <= budget {
		return
	}
	biggest, bigN := "", int64(0)
	for k, v := range parts {
		if v > bigN {
			biggest, bigN = k, v
		}
	}
	log.Printf("retention: %s holds %d MiB, over the %d MiB budget; the largest part is %s (%d MiB)", cfg.DataDir, total>>20, budget>>20, biggest, bigN>>20)
	if eng == nil {
		return
	}
	eng.Raise(alarms.Event{
		Type:   alarms.TypeStorageOverBudget,
		Source: "retention",
		Title:  "Shepherd's data is over its storage budget",
		Body:   "The data directory holds " + mib(total) + " against a budget of " + mib(budget) + ". The largest part is " + biggest + " at " + mib(bigN) + ". The stores that can grow are already capped; raise retention.max_mb in shepherd.toml, or clear what grew.",
		Key:    "storage-over-budget|",
	})
}

func mib(n int64) string {
	whole := n >> 20
	tenths := ((n - whole<<20) * 10) >> 20
	return itoa(whole) + "." + itoa(tenths) + " MiB"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
