// SPDX-License-Identifier: AGPL-3.0-or-later

// Command vulnfeed builds feeds/vulnscan.json, Shepherd's vulnerability
// signature feed, from the NVD CVE API and CISA's Known Exploited
// Vulnerabilities catalog (docs/VULNSCAN.md, "Signature feed"). The daily
// GitHub Actions workflow (.github/workflows/vulnfeed.yml) runs it and
// commits the result; a maintainer can run it by hand the same way:
//
//	go run ./cmd/vulnfeed -o feeds/vulnscan.json
//
// NVD_API_KEY (or -nvd-key) is optional and only raises the NVD rate limit.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"shepherd/internal/vulnfeed"
	"shepherd/internal/vulnscan"
)

func main() {
	out := flag.String("o", "feeds/vulnscan.json", "where to write the feed")
	key := flag.String("nvd-key", os.Getenv("NVD_API_KEY"), "NVD API key (optional; raises the rate limit)")
	timeout := flag.Duration("timeout", 45*time.Minute, "give up after this long")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if err := run(ctx, &vulnfeed.Client{APIKey: *key, Log: log.Printf}, *out); err != nil {
		log.Fatal(err)
	}
}

// run fetches, builds, validates and writes the feed. The client is a
// parameter so a test can point it at fake NVD and KEV servers.
func run(ctx context.Context, c *vulnfeed.Client, out string) error {
	kev, err := c.KEV(ctx)
	if err != nil {
		return err
	}
	cves := map[string][]vulnfeed.CVE{}
	for _, p := range vulnfeed.Products {
		seen := map[string]bool{}
		for _, cpe := range p.CPEs {
			list, err := c.CVEsFor(ctx, cpe)
			if err != nil {
				return err
			}
			for _, cve := range list {
				if !seen[cve.ID] {
					seen[cve.ID] = true
					cves[p.Name] = append(cves[p.Name], cve)
				}
			}
		}
	}
	feed, st := vulnfeed.Build(time.Now(), cves, kev)
	log.Printf("built %d signatures: %d exploited-in-the-wild, %d products with critical CVEs, %d with high; %d CVEs considered, %d without a usable version range, %d rejected",
		len(feed.Signatures), st.KEV, countTier(feed, "nvd-critical-"), countTier(feed, "nvd-high-"), st.Considered, st.NoRange, st.Rejected)

	b, err := json.MarshalIndent(feed, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	// The consumer must accept exactly what was written.
	if _, err := vulnscan.ParseFeed(b); err != nil {
		return fmt.Errorf("built feed does not parse: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o644)
}

func countTier(f *vulnscan.Feed, prefix string) int {
	n := 0
	for _, s := range f.Signatures {
		if len(s.ID) >= len(prefix) && s.ID[:len(prefix)] == prefix {
			n++
		}
	}
	return n
}
