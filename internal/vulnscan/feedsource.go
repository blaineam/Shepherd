// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultFeedURL is where Shepherd's own published signature feed lives:
// feeds/vulnscan.json on this repository's main branch, rebuilt daily by
// the vulnfeed workflow from the NVD and CISA's Known Exploited
// Vulnerabilities catalog (docs/VULNSCAN.md's "Signature feed" section).
const DefaultFeedURL = "https://raw.githubusercontent.com/blaineam/shepherd/main/feeds/vulnscan.json"

// FeedStatus is what the portal shows about the feed.
type FeedStatus struct {
	URL string `json:"url"`
	// Signatures is how many feed signatures are compiled in right now;
	// Skipped how many the feed carried for products this build cannot
	// fingerprint (a newer feed on an older Shepherd).
	Signatures int `json:"signatures"`
	Skipped    int `json:"skipped,omitempty"`
	// GeneratedAt is the feed document's own timestamp: when its contents
	// were last built upstream, as opposed to when this Shepherd fetched it.
	GeneratedAt time.Time `json:"generated_at,omitzero"`
	LastChecked time.Time `json:"last_checked,omitzero"`
	LastUpdated time.Time `json:"last_updated,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}

// FeedUpdater keeps a Scanner supplied with the current signature feed: it
// restores the last good copy from disk at start, fetches the published
// one on an interval, and hands every change to OnChange. A failed or
// invalid download never replaces a working feed — exactly the rule
// internal/geo's database downloads follow.
type FeedUpdater struct {
	// URL is where the feed is fetched from; "file://" URLs are read from
	// disk (tests, and an install that wants to pin its own copy).
	URL string
	// Path is where the last good feed is cached (mode 0600), so a restart
	// with no internet still has signatures. Empty keeps it in memory only.
	Path string
	// Client defaults to a 2 minute timeout.
	Client *http.Client
	// Every is how often Run re-fetches (default 6 hours).
	Every time.Duration
	Now   func() time.Time

	// OnChange receives the compiled signatures whenever the effective
	// feed changes. initial is true for the cached copy restored at start
	// (nothing new has been learned, so no rescan is warranted) and false
	// for a genuinely new feed fetched from URL.
	OnChange func(sigs []Signature, initial bool)

	mu     sync.Mutex
	status FeedStatus
	etag   string
	sum    string
}

func (u *FeedUpdater) defaults() {
	if u.Client == nil {
		u.Client = &http.Client{Timeout: 2 * time.Minute}
	}
	if u.Every <= 0 {
		u.Every = 6 * time.Hour
	}
	if u.Now == nil {
		u.Now = time.Now
	}
}

// Status reports the feed's current state.
func (u *FeedUpdater) Status() FeedStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.status
	st.URL = u.URL
	return st
}

// Load restores the cached feed from Path, if there is one, and applies
// it. A missing cache is not an error; a corrupt one is reported and
// ignored.
func (u *FeedUpdater) Load() error {
	u.defaults()
	if u.Path == "" {
		return nil
	}
	b, err := os.ReadFile(u.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	f, err := ParseFeed(b)
	if err != nil {
		return fmt.Errorf("cached feed %s: %w", u.Path, err)
	}
	u.apply(f, b, true)
	return nil
}

// Refresh fetches URL once and applies it if it changed. It reports
// whether the effective feed changed. Any failure leaves the current feed
// in place and is recorded in Status.
func (u *FeedUpdater) Refresh(ctx context.Context) (changed bool, err error) {
	u.defaults()
	changed, err = u.refresh(ctx)
	u.mu.Lock()
	u.status.LastChecked = u.Now()
	if err != nil {
		u.status.LastError = err.Error()
	} else {
		u.status.LastError = ""
	}
	u.mu.Unlock()
	return changed, err
}

func (u *FeedUpdater) refresh(ctx context.Context) (bool, error) {
	if u.URL == "" {
		return false, errors.New("no feed URL configured")
	}
	var b []byte
	var etag string
	if path, ok := strings.CutPrefix(u.URL, "file://"); ok {
		var err error
		b, err = os.ReadFile(path)
		if err != nil {
			return false, err
		}
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("User-Agent", "shepherd")
		u.mu.Lock()
		if u.etag != "" {
			req.Header.Set("If-None-Match", u.etag)
		}
		u.mu.Unlock()
		resp, err := u.Client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotModified:
			return false, nil
		case resp.StatusCode != http.StatusOK:
			return false, fmt.Errorf("feed download failed: HTTP %d", resp.StatusCode)
		}
		b, err = io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
		if err != nil {
			return false, fmt.Errorf("feed download interrupted: %w", err)
		}
		etag = resp.Header.Get("ETag")
	}
	f, err := ParseFeed(b)
	if err != nil {
		return false, err
	}
	sum := checksum(b)
	u.mu.Lock()
	same := sum == u.sum
	u.etag = etag
	u.mu.Unlock()
	if same {
		return false, nil
	}
	if u.Path != "" {
		if err := writeFileAtomic(u.Path, b); err != nil {
			return false, fmt.Errorf("caching feed: %w", err)
		}
	}
	u.apply(f, b, false)
	return true, nil
}

// apply compiles f, records its status and tells OnChange.
func (u *FeedUpdater) apply(f *Feed, raw []byte, initial bool) {
	sigs, skipped := f.Compile()
	u.mu.Lock()
	u.sum = checksum(raw)
	u.status.Signatures = len(sigs)
	u.status.Skipped = len(skipped)
	u.status.GeneratedAt = f.GeneratedAt
	u.status.LastUpdated = u.Now()
	u.mu.Unlock()
	if u.OnChange != nil {
		u.OnChange(sigs, initial)
	}
}

// Run restores the cache, refreshes now, then refreshes every Every until
// ctx ends. Errors are recorded in Status; Run itself never stops on one.
func (u *FeedUpdater) Run(ctx context.Context) {
	u.defaults()
	if err := u.Load(); err != nil {
		u.mu.Lock()
		u.status.LastError = err.Error()
		u.mu.Unlock()
	}
	_, _ = u.Refresh(ctx)
	t := time.NewTicker(u.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ctx.Err() != nil {
				return
			}
			_, _ = u.Refresh(ctx)
		}
	}
}

func checksum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
