// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/vulnfeed"
	"shepherd/internal/vulnscan"
)

// fakeSources answers like the NVD (one OpenSSH CVE for the OpenSSH CPE,
// nothing for every other product) and like CISA (that CVE is in KEV).
func fakeSources(t *testing.T) (nvd, kev *httptest.Server) {
	t.Helper()
	nvd = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("virtualMatchString") != "cpe:2.3:a:openbsd:openssh" {
			fmt.Fprint(w, `{"totalResults": 0, "resultsPerPage": 0, "startIndex": 0, "vulnerabilities": []}`)
			return
		}
		fmt.Fprint(w, `{"totalResults": 1, "resultsPerPage": 1, "startIndex": 0, "vulnerabilities": [{"cve": {
		  "id": "CVE-2024-6387", "vulnStatus": "Analyzed",
		  "descriptions": [{"lang": "en", "value": "A signal handler race condition."}],
		  "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 8.1, "attackVector": "NETWORK", "privilegesRequired": "NONE", "userInteraction": "NONE"}}]},
		  "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"}]}]}]
		}}]}`)
	}))
	t.Cleanup(nvd.Close)
	kev = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"vulnerabilities": [{"cveID": "CVE-2024-6387", "dateAdded": "2024-07-02", "shortDescription": "regreSSHion"}]}`)
	}))
	t.Cleanup(kev.Close)
	return nvd, kev
}

func TestRunWritesAFeedTheScannerAccepts(t *testing.T) {
	nvd, kev := fakeSources(t)
	out := filepath.Join(t.TempDir(), "nested", "vulnscan.json")
	c := &vulnfeed.Client{NVDURL: nvd.URL, KEVURL: kev.URL, Sleep: func(time.Duration) {}}
	if err := run(context.Background(), c, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), "}\n") {
		t.Fatal("feed should end with a newline, as a committed file does")
	}
	feed, err := vulnscan.ParseFeed(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(feed.Signatures) != 1 || feed.Signatures[0].ID != "kev-cve-2024-6387" {
		t.Fatalf("signatures = %+v", feed.Signatures)
	}
	if countTier(feed, "kev-") != 1 || countTier(feed, "nvd-critical-") != 0 {
		t.Fatal("countTier miscounts")
	}
	// Pretty-printed: a human diff on the committed file should be readable.
	var pretty json.RawMessage
	if err := json.Unmarshal(b, &pretty); err != nil || !strings.Contains(string(b), "\n  \"schema\": 1,") {
		t.Fatal("feed is not indented JSON")
	}
}

func TestRunFailsWhenASourceFails(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	defer down.Close()
	nvd, kev := fakeSources(t)
	out := filepath.Join(t.TempDir(), "vulnscan.json")
	if err := run(context.Background(), &vulnfeed.Client{NVDURL: nvd.URL, KEVURL: down.URL, Sleep: func(time.Duration) {}}, out); err == nil || !strings.Contains(err.Error(), "KEV") {
		t.Fatalf("KEV failure: %v", err)
	}
	if err := run(context.Background(), &vulnfeed.Client{NVDURL: down.URL, KEVURL: kev.URL, Sleep: func(time.Duration) {}}, out); err == nil || !strings.Contains(err.Error(), "NVD") {
		t.Fatalf("NVD failure: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("no feed may be written when a source failed")
	}
	// An unwritable destination is reported too: a directory cannot be
	// created underneath a regular file.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), &vulnfeed.Client{NVDURL: nvd.URL, KEVURL: kev.URL, Sleep: func(time.Duration) {}}, filepath.Join(blocker, "x", "y.json")); err == nil {
		t.Fatal("writing under a file should fail")
	}
}
