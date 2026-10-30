// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CloudflareBaseURL is Cloudflare's production API v4 base URL.
const CloudflareBaseURL = "https://api.cloudflare.com/client/v4"

// CloudflareProvider creates and removes the DNS-01 challenge's TXT record
// through Cloudflare's API, using a scoped API token (recommended minimum
// scope: DNS edit on the one zone the hostname lives in — see docs/TLS.md).
// It satisfies DNS01Provider. The zone is found automatically by walking the
// hostname's labels outward (shepherd.fort.example.com, fort.example.com,
// example.com, ...) until Cloudflare reports a zone by that name, so only
// the hostname itself needs configuring, not the zone separately.
type CloudflareProvider struct {
	// APIToken authenticates every request as "Authorization: Bearer <token>".
	APIToken string
	// BaseURL overrides CloudflareBaseURL. Tests point it at a local fake
	// server so this type never makes a real network call; production
	// leaves it empty.
	BaseURL string
	// HTTPClient issues the requests. Default: http.DefaultClient.
	HTTPClient *http.Client
}

var _ DNS01Provider = (*CloudflareProvider)(nil)

type cfAPIError struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func (e cfAPIError) String() string {
	if len(e.Errors) == 0 {
		return "cloudflare rejected the request"
	}
	parts := make([]string, len(e.Errors))
	for i, er := range e.Errors {
		parts[i] = fmt.Sprintf("%d: %s", er.Code, er.Message)
	}
	return strings.Join(parts, "; ")
}

type cfZonesResponse struct {
	cfAPIError
	Result []struct {
		ID string `json:"id"`
	} `json:"result"`
}

type cfRecordResponse struct {
	cfAPIError
	Result struct {
		ID string `json:"id"`
	} `json:"result"`
}

func (p *CloudflareProvider) baseURL() string {
	if p.BaseURL != "" {
		return p.BaseURL
	}
	return CloudflareBaseURL
}

func (p *CloudflareProvider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

// do issues one API request and decodes its JSON body into out.
func (p *CloudflareProvider) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL()+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decoding response (HTTP %d): %w", resp.StatusCode, err)
	}
	return nil
}

// findZoneID walks fqdn's labels outward, skipping the challenge label
// itself, and returns the id of the first Cloudflare zone found, stopping
// at the first match — the same convention other ACME DNS-01 clients use so
// a subdomain's own hostname is all that needs configuring.
func (p *CloudflareProvider) findZoneID(ctx context.Context, fqdn string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for start := 1; start <= len(labels)-2; start++ {
		candidate := strings.Join(labels[start:], ".")
		var resp cfZonesResponse
		if err := p.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(candidate), nil, &resp); err != nil {
			return "", fmt.Errorf("looking up zone %q: %w", candidate, err)
		}
		if !resp.Success {
			return "", fmt.Errorf("looking up zone %q: %s", candidate, resp.String())
		}
		if len(resp.Result) > 0 {
			return resp.Result[0].ID, nil
		}
	}
	return "", fmt.Errorf("no Cloudflare zone found that covers %s", fqdn)
}

// Present creates fqdn as a TXT record holding value and returns Cloudflare's
// record id, which CleanUp needs to remove exactly that record.
func (p *CloudflareProvider) Present(ctx context.Context, fqdn, value string) (string, error) {
	zoneID, err := p.findZoneID(ctx, fqdn)
	if err != nil {
		return "", err
	}
	body := map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 120}
	var resp cfRecordResponse
	if err := p.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body, &resp); err != nil {
		return "", fmt.Errorf("creating TXT record %s: %w", fqdn, err)
	}
	if !resp.Success {
		return "", fmt.Errorf("creating TXT record %s: %s", fqdn, resp.String())
	}
	return resp.Result.ID, nil
}

// CleanUp removes the TXT record Present created.
func (p *CloudflareProvider) CleanUp(ctx context.Context, fqdn, recordID string) error {
	zoneID, err := p.findZoneID(ctx, fqdn)
	if err != nil {
		return err
	}
	var resp cfAPIError
	if err := p.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, &resp); err != nil {
		return fmt.Errorf("deleting TXT record %s: %w", fqdn, err)
	}
	if !resp.Success {
		return fmt.Errorf("deleting TXT record %s: %s", fqdn, resp.String())
	}
	return nil
}
