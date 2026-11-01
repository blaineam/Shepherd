// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Where the two sources live. Both are public and need no key; an NVD API
// key only raises the rate limit.
const (
	DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// CVE is the slice of one NVD record the builder needs. Field names follow
// the NVD 2.0 API so a fixture can be a verbatim API response.
type CVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []cvssMetric `json:"cvssMetricV31"`
		V30 []cvssMetric `json:"cvssMetricV30"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []CPEMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type cvssMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore          float64 `json:"baseScore"`
		AttackVector       string  `json:"attackVector"`
		PrivilegesRequired string  `json:"privilegesRequired"`
		UserInteraction    string  `json:"userInteraction"`
	} `json:"cvssData"`
}

// CPEMatch is one affected-configuration entry: a CPE 2.3 criteria string
// plus the version bounds NVD attaches when the criteria's own version
// field is a wildcard.
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdPage struct {
	TotalResults    int `json:"totalResults"`
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	Vulnerabilities []struct {
		CVE CVE `json:"cve"`
	} `json:"vulnerabilities"`
}

// KEVEntry is one row of CISA's catalog.
type KEVEntry struct {
	CVEID            string `json:"cveID"`
	VendorProject    string `json:"vendorProject"`
	Product          string `json:"product"`
	DateAdded        string `json:"dateAdded"`
	ShortDescription string `json:"shortDescription"`
}

type kevDoc struct {
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// Client fetches from the two sources, politely. The NVD allows 5 requests
// per rolling 30 seconds without a key and 50 with one; Pause is the gap
// kept between requests to stay under that, and a 403/429/5xx is retried
// with a growing back-off rather than failing the whole build.
type Client struct {
	HTTP   *http.Client
	NVDURL string
	KEVURL string
	APIKey string
	// Pause between NVD requests; defaults to 6.5s without a key, 0.7s
	// with one.
	Pause time.Duration
	// Sleep is time.Sleep unless a test replaces it.
	Sleep func(time.Duration)
	// Log receives one line per request when set.
	Log func(format string, args ...any)
}

func (c *Client) defaults() {
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 2 * time.Minute}
	}
	if c.NVDURL == "" {
		c.NVDURL = DefaultNVDURL
	}
	if c.KEVURL == "" {
		c.KEVURL = DefaultKEVURL
	}
	if c.Pause <= 0 {
		if c.APIKey != "" {
			c.Pause = 700 * time.Millisecond
		} else {
			c.Pause = 6500 * time.Millisecond
		}
	}
	if c.Sleep == nil {
		c.Sleep = time.Sleep
	}
	if c.Log == nil {
		c.Log = func(string, ...any) {}
	}
}

// pageSize is the NVD's own maximum.
const pageSize = 2000

// CVEsFor returns every CVE the NVD files under cpe (a
// "cpe:2.3:a:vendor:product" prefix), following pagination.
func (c *Client) CVEsFor(ctx context.Context, cpe string) ([]CVE, error) {
	c.defaults()
	var out []CVE
	start := 0
	for {
		q := url.Values{}
		q.Set("virtualMatchString", cpe)
		q.Set("resultsPerPage", strconv.Itoa(pageSize))
		q.Set("startIndex", strconv.Itoa(start))
		var page nvdPage
		if err := c.getJSON(ctx, c.NVDURL+"?"+q.Encode(), true, &page); err != nil {
			return nil, fmt.Errorf("NVD %s from %d: %w", cpe, start, err)
		}
		for _, v := range page.Vulnerabilities {
			out = append(out, v.CVE)
		}
		c.Log("nvd %s: %d/%d", cpe, len(out), page.TotalResults)
		start += len(page.Vulnerabilities)
		if start >= page.TotalResults || len(page.Vulnerabilities) == 0 {
			return out, nil
		}
	}
}

// KEV returns CISA's catalog keyed by CVE ID.
func (c *Client) KEV(ctx context.Context) (map[string]KEVEntry, error) {
	c.defaults()
	var doc kevDoc
	if err := c.getJSON(ctx, c.KEVURL, false, &doc); err != nil {
		return nil, fmt.Errorf("KEV: %w", err)
	}
	out := make(map[string]KEVEntry, len(doc.Vulnerabilities))
	for _, e := range doc.Vulnerabilities {
		out[e.CVEID] = e
	}
	c.Log("kev: %d entries", len(out))
	return out, nil
}

const maxRetries = 5

// getJSON fetches u into v, pausing before NVD requests and retrying the
// statuses the NVD uses for rate limiting or a bad moment.
func (c *Client) getJSON(ctx context.Context, u string, nvd bool, v any) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if nvd {
			c.Sleep(c.Pause)
		}
		if attempt > 0 {
			c.Log("retry %d for %s after: %v", attempt, u, lastErr)
			c.Sleep(time.Duration(attempt) * 10 * time.Second)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "shepherd-vulnfeed")
		if nvd && c.APIKey != "" {
			req.Header.Set("apiKey", c.APIKey)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return err
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			if err := json.Unmarshal(body, v); err != nil {
				return fmt.Errorf("decoding: %w", err)
			}
			return nil
		case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		default:
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
	return fmt.Errorf("gave up after %d retries: %w", maxRetries, lastErr)
}
