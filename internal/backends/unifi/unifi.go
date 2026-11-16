// SPDX-License-Identifier: AGPL-3.0-or-later

// Package unifi is the UniFi Network backend (docs/BACKENDS.md), over the
// Network application's official Integration API: an API key sent as
// X-API-KEY, under /proxy/network/integration on a UniFi OS console (or
// /integration on a self-hosted application). It needs UniFi Network 9 or
// newer.
//
// What the published API offers is a management surface, not a request
// log: no flows, no alarms. So this backend lists clients and adopted
// devices and the user-defined firewall policies, can pause, resume and
// delete a policy, and can block a client. It cannot create a policy: that
// needs zone and traffic-filter bodies the published reference does not
// describe, and guessing them against someone's firewall is not something
// Shepherd does. Pair it with Shepherd's own DNS history for requests.
//
// The controller is the owner's own, on their LAN, usually with a
// self-signed certificate, so verification can be switched off (and is off
// unless they do). Redirects are refused so the key is never sent anywhere
// the owner did not type.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shepherd/internal/backends"
	"shepherd/internal/routerusage"
)

// Config is what the owner provides.
type Config struct {
	// BaseURL is the console, e.g. "https://192.0.2.10". The path is
	// ignored; the API prefix is discovered.
	BaseURL string
	APIKey  string
	// Site is a site's name, internal reference or ID. Empty means the
	// default site.
	Site string
	// AllowSelfSigned skips TLS verification. Consoles ship a certificate
	// nothing can verify, so this is usually needed on a LAN address.
	AllowSelfSigned bool
	ReadOnly        bool
	Timeout         time.Duration
	// Transport replaces the HTTP transport, for tests.
	Transport http.RoundTripper
}

// Errors specific to this backend. Use errors.Is.
var (
	ErrBadURL  = errors.New("unifi: the console address must be an http or https URL such as https://192.0.2.10")
	ErrNoKey   = errors.New("unifi: an API key is required")
	ErrNoSite  = errors.New("unifi: no such site on this console")
	ErrNoAPI   = errors.New("unifi: this console has no Integration API; it needs UniFi Network 9 or newer")
	errSystem  = errors.New("that is one of UniFi's own built-in policies")
	maxPageLen = 200
)

// Client is the UniFi backend.
type Client struct {
	cfg  Config
	base string
	hc   *http.Client
	ro   atomic.Bool

	mu     sync.Mutex
	prefix string // discovered API prefix
	siteID string
}

// NormalizeURL turns what an owner types into the console's origin, or
// ErrBadURL.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrBadURL
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrBadURL
	}
	return u.Scheme + "://" + u.Host, nil
}

// New returns a Client. The connection is not made until the first call.
func New(cfg Config) (*Client, error) {
	base, err := NormalizeURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	if cfg.APIKey == "" {
		return nil, ErrNoKey
	}
	cfg.Site = strings.TrimSpace(cfg.Site)
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	tr := cfg.Transport
	if tr == nil {
		t := &http.Transport{}
		if cfg.AllowSelfSigned {
			// The owner asked for this: a console on a LAN address almost
			// always has a certificate nothing can verify.
			t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, see Config.AllowSelfSigned
		}
		tr = t
	}
	c := &Client{cfg: cfg, base: base, hc: &http.Client{
		Transport: tr, Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("unifi: redirects are not followed")
		},
	}}
	c.ro.Store(cfg.ReadOnly)
	return c, nil
}

// Name implements backends.Backend.
func (c *Client) Name() string { return "unifi" }

// ReadOnly implements backends.Backend.
func (c *Client) ReadOnly() bool { return c.ro.Load() }

// SetReadOnly changes whether writes are refused, without reconnecting.
func (c *Client) SetReadOnly(ro bool) { c.ro.Store(ro) }

func (c *Client) writable() error {
	if c.ro.Load() {
		return backends.ErrReadOnly
	}
	return nil
}

const maxResponse = 16 << 20

// raw sends one request to prefix+path and decodes a JSON answer into out
// when it is not nil. It returns the HTTP status for the caller that needs
// to tell "not found" apart, with err nil only on a 2xx.
func (c *Client) raw(ctx context.Context, prefix, method, path string, query url.Values, body any, out any) (int, error) {
	endpoint := c.base + prefix + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	// The console is the owner's own, typed into the portal by someone
	// already signed in to it; NewClient limited it to an http(s) origin
	// and redirects are refused.
	// codeql[go/request-forgery]
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-API-KEY", c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// codeql[go/request-forgery]
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return 0, fmt.Errorf("unifi: %s the console: %w", strings.ToLower(ue.Op), ue.Err)
		}
		return 0, err
	}
	defer resp.Body.Close()
	st := resp.StatusCode
	switch {
	case st >= 200 && st < 300:
	case st == http.StatusUnauthorized || st == http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return st, backends.ErrAuth
	case st == http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return st, backends.ErrNotFound
	case st == http.StatusTooManyRequests:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return st, backends.ErrRateLimited
	default:
		var e struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		msg := fmt.Sprintf("HTTP %d", st)
		if e.Message != "" {
			msg += ": " + e.Message
		}
		return st, fmt.Errorf("%w: %s", backends.ErrRefused, msg)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		return st, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(out); err != nil {
		return st, fmt.Errorf("unifi: the console answered with something unexpected: %w", err)
	}
	return st, nil
}

// prefixes are where the Integration API lives: behind UniFi OS's proxy on
// a console, directly on a self-hosted application.
var prefixes = []string{"/proxy/network/integration", "/integration"}

// api calls the Integration API, discovering its prefix on first use.
func (c *Client) api(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	c.mu.Lock()
	prefix := c.prefix
	c.mu.Unlock()
	if prefix == "" {
		for _, p := range prefixes {
			st, err := c.raw(ctx, p, http.MethodGet, "/v1/info", nil, nil, nil)
			if err == nil {
				prefix = p
				break
			}
			if st != http.StatusNotFound {
				return err // refused, unreachable: not a wrong prefix
			}
		}
		if prefix == "" {
			return ErrNoAPI
		}
		c.mu.Lock()
		c.prefix = prefix
		c.mu.Unlock()
	}
	_, err := c.raw(ctx, prefix, method, path, query, body, out)
	return err
}

type pageOf[T any] struct {
	Offset     int `json:"offset"`
	Count      int `json:"count"`
	TotalCount int `json:"totalCount"`
	Data       []T `json:"data"`
}

// list reads every page of a collection.
func list[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	for offset := 0; ; {
		var p pageOf[T]
		q := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(maxPageLen)}}
		if err := c.api(ctx, http.MethodGet, path, q, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		offset += len(p.Data)
		if len(p.Data) == 0 || offset >= p.TotalCount {
			return all, nil
		}
	}
}

type wireSite struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"`
	Name              string `json:"name"`
}

// site resolves the configured site to its ID, once.
func (c *Client) site(ctx context.Context) (string, error) {
	c.mu.Lock()
	id := c.siteID
	c.mu.Unlock()
	if id != "" {
		return id, nil
	}
	sites, err := list[wireSite](ctx, c, "/v1/sites")
	if err != nil {
		return "", err
	}
	want := c.cfg.Site
	if want == "" {
		want = "default"
	}
	for _, s := range sites {
		if strings.EqualFold(s.ID, want) || strings.EqualFold(s.InternalReference, want) || strings.EqualFold(s.Name, want) {
			id = s.ID
			break
		}
	}
	if id == "" && c.cfg.Site == "" && len(sites) > 0 {
		id = sites[0].ID // no site named, no "default": the only one there is
	}
	if id == "" {
		return "", ErrNoSite
	}
	c.mu.Lock()
	c.siteID = id
	c.mu.Unlock()
	return id, nil
}

func (c *Client) sitePath(ctx context.Context, rest string) (string, error) {
	id, err := c.site(ctx)
	if err != nil {
		return "", err
	}
	return "/v1/sites/" + url.PathEscape(id) + rest, nil
}

// ---- wire types -------------------------------------------------------------

type wireClient struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	IPAddress  string `json:"ipAddress"`
	MACAddress string `json:"macAddress"`
}

type wireDevice struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Model      string `json:"model"`
	State      string `json:"state"`
	MACAddress string `json:"macAddress"`
	IPAddress  string `json:"ipAddress"`
}

type wirePolicy struct {
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Action      struct {
		Type string `json:"type"`
	} `json:"action"`
	Schedule struct {
		Mode string `json:"mode"`
	} `json:"schedule"`
	Metadata struct {
		Origin string `json:"origin"`
	} `json:"metadata"`
}

// ---- reading ----------------------------------------------------------------

// Devices implements backends.DeviceReader: connected clients, which can be
// blocked, then the UniFi devices themselves, which cannot.
func (c *Client) Devices(ctx context.Context) ([]backends.Device, error) {
	site, err := c.site(ctx)
	if err != nil {
		return nil, err
	}
	clients, err := list[wireClient](ctx, c, "/v1/sites/"+url.PathEscape(site)+"/clients")
	if err != nil {
		return nil, err
	}
	out := make([]backends.Device, 0, len(clients))
	for _, cl := range clients {
		out = append(out, backends.Device{
			MAC: routerusage.NormalizeMAC(cl.MACAddress), Name: cl.Name, IP: cl.IPAddress, Online: true,
			Network: strings.ToLower(cl.Type), Box: site, Native: cl.ID,
		})
	}
	devs, err := list[wireDevice](ctx, c, "/v1/sites/"+url.PathEscape(site)+"/devices")
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		out = append(out, backends.Device{
			MAC: routerusage.NormalizeMAC(d.MACAddress), Name: d.Name, IP: d.IPAddress, Vendor: "Ubiquiti",
			Online: strings.EqualFold(d.State, "ONLINE"), Group: "UniFi device", Box: site,
		})
	}
	return out, nil
}

func toRule(p wirePolicy, site string) backends.Rule {
	action := strings.ToLower(p.Action.Type)
	if action == "reject" {
		action = "block"
	}
	r := backends.Rule{
		ID: p.ID, Name: p.Name, Action: action, TargetType: "policy", Target: p.Name,
		Paused: !p.Enabled, Notes: p.Description, Box: site,
	}
	if m := p.Schedule.Mode; m != "" && m != "EVERY_DAY" {
		r.Schedule = strings.ToLower(strings.ReplaceAll(m, "_", " "))
	}
	return r
}

// Rules implements backends.RuleManager: the user-defined firewall
// policies. UniFi's built-in ones are left out, because pausing or
// deleting one is not something a dashboard should offer.
func (c *Client) Rules(ctx context.Context) ([]backends.Rule, error) {
	site, err := c.site(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := list[wirePolicy](ctx, c, "/v1/sites/"+url.PathEscape(site)+"/firewall/policies")
	if err != nil {
		return nil, err
	}
	out := make([]backends.Rule, 0, len(policies))
	for _, p := range policies {
		if p.Metadata.Origin == "SYSTEM_DEFINED" {
			continue
		}
		out = append(out, toRule(p, site))
	}
	return out, nil
}

// ---- writing ----------------------------------------------------------------

// SetRulePaused implements backends.RuleManager: a paused policy is a
// disabled one.
func (c *Client) SetRulePaused(ctx context.Context, id string, paused bool) error {
	if err := c.writable(); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%w: a policy id is required", backends.ErrInvalid)
	}
	path, err := c.sitePath(ctx, "/firewall/policies/"+url.PathEscape(id))
	if err != nil {
		return err
	}
	return c.api(ctx, http.MethodPatch, path, nil, map[string]bool{"enabled": !paused}, nil)
}

// DeleteRule implements backends.RuleManager. It refuses a built-in policy.
func (c *Client) DeleteRule(ctx context.Context, id string) error {
	if err := c.writable(); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%w: a policy id is required", backends.ErrInvalid)
	}
	path, err := c.sitePath(ctx, "/firewall/policies/"+url.PathEscape(id))
	if err != nil {
		return err
	}
	var p wirePolicy
	if err := c.api(ctx, http.MethodGet, path, nil, nil, &p); err != nil {
		return err
	}
	if p.Metadata.Origin == "SYSTEM_DEFINED" {
		return fmt.Errorf("%w: %v", backends.ErrInvalid, errSystem)
	}
	return c.api(ctx, http.MethodDelete, path, nil, nil, nil)
}

func (c *Client) clientAction(ctx context.Context, d backends.DeviceRef, action string) error {
	if err := c.writable(); err != nil {
		return err
	}
	if strings.TrimSpace(d.Native) == "" {
		return fmt.Errorf("%w: that device cannot be blocked", backends.ErrInvalid)
	}
	site := d.Box
	if site == "" {
		var err error
		if site, err = c.site(ctx); err != nil {
			return err
		}
	}
	path := "/v1/sites/" + url.PathEscape(site) + "/clients/" + url.PathEscape(d.Native) + "/actions"
	return c.api(ctx, http.MethodPost, path, nil, map[string]string{"action": action}, nil)
}

// BlockClient implements backends.ClientBlocker.
func (c *Client) BlockClient(ctx context.Context, d backends.DeviceRef) error {
	return c.clientAction(ctx, d, "BLOCK")
}

// UnblockClient implements backends.ClientBlocker.
func (c *Client) UnblockClient(ctx context.Context, d backends.DeviceRef) error {
	return c.clientAction(ctx, d, "UNBLOCK")
}
