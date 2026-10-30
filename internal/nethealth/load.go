// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// DefaultLoadURL is Cloudflare's own public speed-test endpoint: a plain,
// no-auth, no-API-key download of exactly as many bytes as asked for,
// published specifically for this purpose (the same endpoint browser-based
// speed tests like speed.cloudflare.com use). bytesHint keeps the request
// itself bounded (see DefaultLoadFunc) even if the caller's own context
// deadline were somehow not honored by an intermediary.
const DefaultLoadURL = "https://speed.cloudflare.com/__down?bytes=%d"

// maxLoadBytes is the hard ceiling on how much DefaultLoadFunc ever reads
// in one burst, independent of its context deadline: a second, belt-and-
// suspenders bound (see BufferbloatOptions.Duration for the primary one)
// so a slow or misbehaving path can never turn one bufferbloat check into
// an extended, unbounded download. 20MB comfortably saturates even a
// fairly fast residential uplink for the Duration this package defaults to
// (5s) without risking a materially longer transfer than intended.
const maxLoadBytes = 20 << 20

// DefaultLoadFunc returns a LoadFunc that downloads a bounded burst of
// bytes from urlTemplate (a %d format string for the byte count, matching
// DefaultLoadURL's own "?bytes=%d" shape) and discards them, generating
// real but tightly bounded load for a bufferbloat check. It is bounded
// twice over: by ctx (BufferbloatOptions.Duration, enforced by whoever
// calls the LoadFunc) and by maxLoadBytes (enforced here, independent of
// ctx, in case a server or proxy along the way does not honor cancellation
// promptly).
//
// This is Shepherd's one concession, in this package, to needing a
// real external endpoint: everything else nethealth does talks only to
// the configured DNS upstreams and a couple of well-known public resolvers
// (see targets.go). There is no live hardware in this project's test
// environment to confirm this endpoint behaves as expected end-to-end;
// see docs/NETHEALTH.md's "What is verified, and what is not" section.
func DefaultLoadFunc(urlTemplate string) LoadFunc {
	return func(ctx context.Context) error {
		url := fmt.Sprintf(urlTemplate, maxLoadBytes)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("nethealth: load burst: HTTP %d", resp.StatusCode)
		}
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxLoadBytes))
		return err
	}
}
