// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Firewalla reads per-device bandwidth from a Firewalla MSP account, over
// the documented MSP API (https://docs.firewalla.net).
//
// It is a KindCounters source. GET /v2/devices lists every device the
// account's boxes know, with the bytes each has downloaded and uploaded
// (totalDownload, totalUpload). Differencing consecutive reads gives the
// traffic between them, and a total that falls -- Firewalla restarting its
// accounting, say -- is treated as a reset, which costs one interval and
// never records negative traffic.
//
// The credential is a personal access token the owner creates in the MSP
// portal (MSP Settings -> MSP API). A Read Only token is enough, because
// this never writes: it issues one GET per poll and nothing else.
//
// The token is sent to exactly one place. The address is limited to
// firewalla.net, over https, with redirects refused, so a mistyped
// address can never carry it to someone else's server.
type Firewalla struct {
	cfg  FirewallaConfig
	base string
	hc   *http.Client
}

// FirewallaConfig is what the owner provides.
type FirewallaConfig struct {
	// BaseURL is the owner's MSP instance. Either of the two forms
	// Firewalla issues works, with or without the scheme:
	//
	//	mydomain.firewalla.net   an MSP with its own domain
	//	firewalla.net            the shared domain (its API lives under /api)
	BaseURL string
	// Token is the personal access token.
	Token string
	// Box limits the reading to one Firewalla box by its ID (gid). Empty
	// reads every box in the account.
	Box string
	// Timeout per request (default 15s).
	Timeout time.Duration
	// Transport replaces the HTTP transport, for tests.
	Transport http.RoundTripper
}

// Errors a Firewalla source reports. Use errors.Is.
var (
	ErrFirewallaBadURL      = errors.New("firewalla: the MSP address must be your own domain on firewalla.net, such as mydomain.firewalla.net")
	ErrFirewallaNoToken     = errors.New("firewalla: a personal access token is required")
	ErrFirewallaAuth        = errors.New("firewalla: MSP refused the token")
	ErrFirewallaRateLimited = errors.New("firewalla: MSP is rate limiting requests")
	ErrFirewallaRefused     = errors.New("firewalla: MSP refused the request")
)

const maxFirewallaResponse = 16 << 20

// NormalizeFirewallaURL turns what an owner types into the https origin
// requests are sent to, or ErrFirewallaBadURL. The shared domain gets its
// /api prefix; a domain of the owner's own gets none.
func NormalizeFirewallaURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrFirewallaBadURL
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", ErrFirewallaBadURL
	}
	host := strings.ToLower(u.Hostname())
	path := strings.TrimRight(u.Path, "/")
	switch {
	case host == "firewalla.net":
		if path != "" && path != "/api" {
			return "", ErrFirewallaBadURL
		}
		return "https://firewalla.net/api", nil
	case strings.HasSuffix(host, ".firewalla.net") && len(host) > len(".firewalla.net"):
		// Labels are letters, digits and hyphens: nothing that could
		// smuggle another host past the suffix check.
		for _, r := range strings.TrimSuffix(host, ".firewalla.net") {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
				return "", ErrFirewallaBadURL
			}
		}
		if path != "" {
			return "", ErrFirewallaBadURL
		}
		return "https://" + host, nil
	}
	return "", ErrFirewallaBadURL
}

// NewFirewalla returns a Source reading cfg's MSP account. The connection
// is not made until the first Poll.
func NewFirewalla(cfg FirewallaConfig) (*Firewalla, error) {
	base, err := NormalizeFirewallaURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	cfg.Token = strings.TrimSpace(cfg.Token)
	if cfg.Token == "" {
		return nil, ErrFirewallaNoToken
	}
	cfg.Box = strings.TrimSpace(cfg.Box)
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	tr := cfg.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	return &Firewalla{
		cfg: cfg, base: base,
		hc: &http.Client{
			Transport: tr, Timeout: cfg.Timeout,
			// MSP never redirects these calls, and following one would
			// walk the request somewhere the owner did not choose.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("firewalla: redirects are not followed")
			},
		},
	}, nil
}

// Name implements Source.
func (f *Firewalla) Name() string { return "firewalla" }

// Kind implements Source: MSP reports cumulative byte totals.
func (f *Firewalla) Kind() Kind { return KindCounters }

// Poll implements Source.
func (f *Firewalla) Poll(ctx context.Context) ([]Sample, error) {
	endpoint := f.base + "/v2/devices"
	if f.cfg.Box != "" {
		endpoint += "?box=" + url.QueryEscape(f.cfg.Box)
	}
	// The address is limited to firewalla.net by NewFirewalla and the
	// token goes nowhere else; see the type's comment.
	// codeql[go/request-forgery]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+f.cfg.Token)
	req.Header.Set("Accept", "application/json")
	// codeql[go/request-forgery]
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, scrubFirewallaError(err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, ErrFirewallaAuth
	case http.StatusTooManyRequests:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, ErrFirewallaRateLimited
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: HTTP %d", ErrFirewallaRefused, resp.StatusCode)
	}
	var devices []map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxFirewallaResponse)).Decode(&devices); err != nil {
		return nil, fmt.Errorf("firewalla: MSP answered with something that is not a device list: %w", err)
	}
	return firewallaSamples(devices), nil
}

// firewallaSamples reads the device list. A device's id is its MAC; a VPN
// profile or a network interface, which Firewalla also lists as devices,
// has no MAC and is left out, as is a device with no byte totals. A MAC
// listed by more than one box is the sum of what each box saw, since each
// box counts only its own traffic.
func firewallaSamples(devices []map[string]any) []Sample {
	byMAC := map[string]int{}
	out := make([]Sample, 0, len(devices))
	for _, m := range devices {
		mac := NormalizeMAC(str(m, "id", "mac"))
		if mac == "" {
			continue
		}
		down, dok := u64(m, "totalDownload")
		up, uok := u64(m, "totalUpload")
		if !dok && !uok {
			continue
		}
		if i, seen := byMAC[mac]; seen {
			out[i].DownBytes += down
			out[i].UpBytes += up
			continue
		}
		byMAC[mac] = len(out)
		out = append(out, Sample{MAC: mac, Name: str(m, "name"), DownBytes: down, UpBytes: up})
	}
	return out
}

// FirewallaNeedsSignIn reports whether err means the stored token no
// longer works, so the portal asks for a new one instead of showing a
// transient failure.
func FirewallaNeedsSignIn(err error) bool { return errors.Is(err, ErrFirewallaAuth) }

// scrubFirewallaError replaces net/http's `Get "https://host/v2/devices":
// ...` with something an owner can read. The token is a header and is
// never part of net/http's message; this is tidying, not redaction.
func scrubFirewallaError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("firewalla: %s MSP: %w", strings.ToLower(ue.Op), ue.Err)
	}
	return err
}
