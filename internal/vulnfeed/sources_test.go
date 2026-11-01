// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestCVEsForFollowsPaginationAndSendsTheKey(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Header.Get("apiKey") != "k" {
			t.Errorf("apiKey header = %q", r.Header.Get("apiKey"))
		}
		if r.URL.Query().Get("virtualMatchString") != "cpe:2.3:a:openbsd:openssh" || r.URL.Query().Get("resultsPerPage") != "2000" {
			t.Errorf("query = %v", r.URL.Query())
		}
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		// Three records total, served one per page.
		fmt.Fprintf(w, `{"totalResults": 3, "resultsPerPage": 1, "startIndex": %d, "vulnerabilities": [{"cve": {"id": "CVE-%d"}}]}`, start, start)
	}))
	defer srv.Close()
	var slept []time.Duration
	c := &Client{NVDURL: srv.URL, APIKey: "k", Sleep: func(d time.Duration) { slept = append(slept, d) }}
	got, err := c.CVEsFor(t.Context(), "cpe:2.3:a:openbsd:openssh")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2].ID != "CVE-2" || hits != 3 {
		t.Fatalf("got %+v after %d hits", got, hits)
	}
	if len(slept) != 3 || slept[0] != 700*time.Millisecond {
		t.Fatalf("pauses = %v, want the keyed pause before every request", slept)
	}
}

func TestClientRetriesRateLimitsThenGivesUp(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"totalResults": 1, "resultsPerPage": 1, "startIndex": 0, "vulnerabilities": [{"cve": {"id": "CVE-1"}}]}`)
	}))
	defer srv.Close()
	c := &Client{NVDURL: srv.URL, Sleep: func(time.Duration) {}}
	got, err := c.CVEsFor(t.Context(), "cpe:2.3:a:x:y")
	if err != nil || len(got) != 1 || hits != 3 {
		t.Fatalf("got %v err %v hits %d", got, err, hits)
	}
	if c.Pause != 6500*time.Millisecond {
		t.Fatalf("keyless pause = %v", c.Pause)
	}

	always := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer always.Close()
	c = &Client{NVDURL: always.URL, Sleep: func(time.Duration) {}}
	if _, err := c.CVEsFor(t.Context(), "cpe:2.3:a:x:y"); err == nil {
		t.Fatal("permanent 503 must eventually fail")
	}

	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	c = &Client{NVDURL: notFound.URL, Sleep: func(time.Duration) {}}
	if _, err := c.CVEsFor(t.Context(), "cpe:2.3:a:x:y"); err == nil {
		t.Fatal("a 404 is not retried and fails")
	}
}

func TestKEVIsKeyedByCVE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "" {
			t.Error("the NVD key must not be sent to CISA")
		}
		fmt.Fprint(w, `{"vulnerabilities": [{"cveID": "CVE-2024-6387", "vendorProject": "OpenBSD", "product": "OpenSSH", "dateAdded": "2024-07-02", "shortDescription": "x"}]}`)
	}))
	defer srv.Close()
	c := &Client{KEVURL: srv.URL, APIKey: "k", Sleep: func(time.Duration) {}}
	kev, err := c.KEV(t.Context())
	if err != nil || kev["CVE-2024-6387"].DateAdded != "2024-07-02" {
		t.Fatalf("kev = %v err %v", kev, err)
	}
}

func TestGetJSONStopsOnCancelAndRejectsBadJSON(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "{not json") }))
	defer bad.Close()
	c := &Client{NVDURL: bad.URL, Sleep: func(time.Duration) {}}
	if _, err := c.CVEsFor(t.Context(), "cpe:2.3:a:x:y"); err == nil {
		t.Fatal("bad JSON must fail without retrying forever")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c = &Client{NVDURL: "http://127.0.0.1:1/", Sleep: func(time.Duration) {}}
	if _, err := c.CVEsFor(ctx, "cpe:2.3:a:x:y"); err == nil {
		t.Fatal("a canceled context must fail at once")
	}
	c = &Client{KEVURL: "http://127.0.0.1:1/", Sleep: func(time.Duration) {}}
	if _, err := c.KEV(t.Context()); err == nil {
		t.Fatal("an unreachable KEV must fail")
	}
}
