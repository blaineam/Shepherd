// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"context"
	"sync"
	"time"
)

// DeviceResult is the outcome of one device in a broadcast.
type DeviceResult struct {
	ID      string
	Name    string
	Outcome Outcome
	Status  int
	Err     string
	// RetryAfter is the push service's Retry-After, when it sent one.
	RetryAfter time.Duration
}

// Report summarizes a broadcast.
type Report struct {
	Subscribed int // live subscriptions when the broadcast started
	Delivered  int // accepted by the push service
	Gone       int // 404/410, retired from the store
	Failed     int // everything else
	Results    []DeviceResult
}

// Broadcaster sends one payload to every subscription in a Store, records
// success and failure on each, and retires the ones the push service reports
// gone.
type Broadcaster struct {
	Store  *Store
	Sender *Sender
	// Parallel bounds concurrent sends; zero means 4.
	Parallel int
}

// Broadcast delivers payload to every live subscription. Devices are tried
// independently: one slow or failing push service never blocks the others
// beyond the Parallel bound.
func (b *Broadcaster) Broadcast(ctx context.Context, payload []byte, o Options) Report {
	recs := b.Store.Records()
	rep := Report{Subscribed: len(recs), Results: make([]DeviceResult, len(recs))}
	par := b.Parallel
	if par <= 0 {
		par = 4
	}
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for i, rec := range recs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := b.Sender.Send(ctx, rec.Subscription(), payload, o)
			dr := DeviceResult{ID: rec.ID, Name: rec.Name, Outcome: res.Outcome, Status: res.Status, RetryAfter: res.RetryAfter}
			if res.Err != nil {
				dr.Err = res.Err.Error()
			}
			switch res.Outcome {
			case OutcomeOK:
				b.Store.MarkOK(rec.ID)
			case OutcomeGone:
				b.Store.Retire(rec.ID, "gone")
			default:
				b.Store.MarkError(rec.ID, res.Err)
			}
			rep.Results[i] = dr
		}()
	}
	wg.Wait()
	for _, dr := range rep.Results {
		switch dr.Outcome {
		case OutcomeOK:
			rep.Delivered++
		case OutcomeGone:
			rep.Gone++
		default:
			rep.Failed++
		}
	}
	return rep
}
