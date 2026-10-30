// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultEeroBaseURL is eero's production user-API host. The API is
// undocumented (reverse-engineered by open-source clients) and can change.
const DefaultEeroBaseURL = "https://api-user.e2ro.com"

const eeroAPIVersion = "/2.2"

// Errors returned by the eero client. Use errors.Is.
var (
	ErrEeroInvalidCode   = errors.New("eero: the verification code was not accepted")
	ErrEeroCodeExpired   = errors.New("eero: the verification code has expired, start the login again")
	ErrEeroUnauthorized  = errors.New("eero: not signed in, or the login was refused")
	ErrEeroSessionExpire = errors.New("eero: the session has expired, sign in again")
	ErrEeroRateLimited   = errors.New("eero: too many requests, try again later")
	ErrEeroNoSession     = errors.New("eero: no signed-in session (verify a code first)")
	ErrEeroBadResponse   = errors.New("eero: unexpected response")
	ErrEeroTooLarge      = errors.New("eero: the response was too large")
	ErrEeroBadURL        = errors.New("eero: the API address must be https")
)

// APIError is an error reported by the eero API. Message is the server's
// error text with secrets removed, sanitized and shortened.
type APIError struct {
	Status     int
	Code       int           // meta.code from the envelope, when present
	Message    string        // e.g. "error.session.refresh"
	RetryAfter time.Duration // set for rate limiting
	kind       error
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("eero: HTTP %d", e.Status)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

func (e *APIError) Unwrap() error { return e.kind }

// TokenStore lets a caller keep the session token between runs. The default
// is none: the token lives in memory and is discarded after the import. A
// caller that stores it takes on the job of protecting it.
type TokenStore interface {
	Load() (string, error)
	Save(token string) error
	Delete() error
}

// ClientOptions configures a Client. The zero value is production-ready.
type ClientOptions struct {
	// BaseURL defaults to DefaultEeroBaseURL and must be https.
	BaseURL string
	// HTTPClient is for tests, to trust a test server. The default verifies
	// TLS normally, times out, and never follows a redirect to another host.
	HTTPClient *http.Client
	// Logger receives method, path and status only, never a credential.
	Logger *slog.Logger
	// TokenStore is optional; see TokenStore.
	TokenStore TokenStore
	// MinInterval spaces requests (default 500ms; negative disables).
	MinInterval time.Duration
	// MaxRetries is how often a rate-limited request is retried (default 3).
	MaxRetries int
	// MaxRetryWait caps one wait; a longer Retry-After is returned as an
	// error instead (default 30s).
	MaxRetryWait time.Duration
	// MaxResponseBytes caps a response body (default 8 MiB).
	MaxResponseBytes int64
	// Sleep and Now are test hooks.
	Sleep func(ctx context.Context, d time.Duration) error
	Now   func() time.Time
}

// Client is a one-time-import client for eero's cloud API. It is safe for
// concurrent use, though it spaces requests one after another.
type Client struct {
	base    *url.URL
	hc      *http.Client
	log     *slog.Logger
	store   TokenStore
	minGap  time.Duration
	retries int
	maxWait time.Duration
	maxBody int64
	sleep   func(context.Context, time.Duration) error
	now     func() time.Time

	mu      sync.Mutex
	pending string // token from login start, awaiting the code
	token   string // verified session token
	secrets []string
	last    time.Time
}

// NewClient builds a client that talks to eero over https.
func NewClient(opts ClientOptions) (*Client, error) {
	raw := opts.BaseURL
	if raw == "" {
		raw = DefaultEeroBaseURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, ErrEeroBadURL
	}
	return newClient(u, opts), nil
}

// NewTestClient is for tests only: it also accepts a plain http address, but
// only on a loopback host, so credentials can never travel in clear text off
// the machine.
func NewTestClient(baseURL string, opts ClientOptions) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, ErrEeroBadURL
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, ErrEeroBadURL
		}
	default:
		return nil, ErrEeroBadURL
	}
	return newClient(u, opts), nil
}

func newClient(u *url.URL, o ClientOptions) *Client {
	c := &Client{
		base: u, hc: o.HTTPClient, log: o.Logger, store: o.TokenStore,
		minGap: o.MinInterval, retries: o.MaxRetries, maxWait: o.MaxRetryWait,
		maxBody: o.MaxResponseBytes, sleep: o.Sleep, now: o.Now,
	}
	if c.minGap == 0 {
		c.minGap = 500 * time.Millisecond
	}
	if c.minGap < 0 {
		c.minGap = 0
	}
	if c.retries == 0 {
		c.retries = 3
	}
	if c.retries < 0 {
		c.retries = 0
	}
	if c.maxWait <= 0 {
		c.maxWait = 30 * time.Second
	}
	if c.maxBody <= 0 {
		c.maxBody = 8 << 20
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if c.sleep == nil {
		c.sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		c.hc = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}
	host := u.Host
	hc := *c.hc
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("eero: too many redirects")
		}
		if req.URL.Host != host {
			return errors.New("eero: refused a redirect to another host")
		}
		return nil
	}
	c.hc = &hc
	return c
}

// ---- session ----------------------------------------------------------------

// HasSession reports whether a verified session token is held in memory.
func (c *Client) HasSession() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token != ""
}

// Discard drops every token and secret from memory. Call it when the import
// is done. A token the caller saved through a TokenStore is left there; use
// Forget to remove that too.
func (c *Client) Discard() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending, c.token, c.secrets = "", "", nil
}

// Forget is Discard plus removing a stored token.
func (c *Client) Forget() error {
	c.Discard()
	if c.store != nil {
		return c.store.Delete()
	}
	return nil
}

// Resume loads a previously stored token, if a TokenStore is configured and
// holds one. It reports whether a session was restored.
func (c *Client) Resume() (bool, error) {
	if c.store == nil {
		return false, nil
	}
	tok, err := c.store.Load()
	if err != nil || tok == "" {
		return false, err
	}
	c.mu.Lock()
	c.token = tok
	c.secrets = append(c.secrets, tok)
	c.mu.Unlock()
	return true, nil
}

func (c *Client) remember(s string) {
	if s != "" {
		c.secrets = append(c.secrets, s)
	}
}

// StartLogin asks eero to send a verification code to the account's email
// address or phone number. Accounts that sign in with a third party are not
// supported by eero's login endpoint.
func (c *Client) StartLogin(ctx context.Context, login string) error {
	login = strings.TrimSpace(login)
	if login == "" {
		return errors.New("eero: enter the account's email address or phone number")
	}
	c.mu.Lock()
	c.remember(login)
	c.mu.Unlock()
	body, _ := json.Marshal(map[string]string{"login": login})
	data, err := c.do(ctx, http.MethodPost, eeroAPIVersion+"/login", body, "", false)
	if err != nil {
		return err
	}
	var d struct {
		UserToken string `json:"user_token"`
	}
	if json.Unmarshal(data, &d) != nil || d.UserToken == "" {
		return fmt.Errorf("%w: no login token", ErrEeroBadResponse)
	}
	c.mu.Lock()
	c.pending = d.UserToken
	c.remember(d.UserToken)
	c.mu.Unlock()
	return nil
}

// Verify completes the login with the code eero sent.
func (c *Client) Verify(ctx context.Context, code string) error {
	code = strings.TrimSpace(code)
	c.mu.Lock()
	pending := c.pending
	c.remember(code)
	c.mu.Unlock()
	if pending == "" {
		return errors.New("eero: start the login first")
	}
	if code == "" {
		return ErrEeroInvalidCode
	}
	body, _ := json.Marshal(map[string]string{"code": code})
	_, err := c.do(ctx, http.MethodPost, eeroAPIVersion+"/login/verify", body, pending, true)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.token, c.pending = pending, ""
	c.mu.Unlock()
	if c.store != nil {
		if err := c.store.Save(pending); err != nil {
			return fmt.Errorf("eero: the token store failed: %w", err)
		}
	}
	return nil
}

// ---- reading ----------------------------------------------------------------

// Network is one eero network on the account.
type Network struct {
	ID   string
	Name string
	URL  string
}

// EeroDevice is a device eero knows about (tolerantly parsed).
type EeroDevice struct {
	URL, MAC, IP string
	IPs          []string
	Nickname     string
	Hostname     string
	Manufacturer string
	Connection   string // "wireless", "wired" or ""
	DeviceType   string
	NodeLocation string // the eero node it connects to
	NodeURL      string
	ProfileName  string
	ProfileURL   string
	Paused       bool
	Guest        bool
}

// EeroProfile is a profile and the devices it lists.
type EeroProfile struct {
	URL, Name  string
	Paused     bool
	DeviceURLs []string
	DeviceMACs []string
}

// EeroNode is an eero router or node itself.
type EeroNode struct {
	URL, MAC, IP string
	Location     string
	Model        string
	Serial       string
	Gateway      bool
}

// Snapshot is everything read from one network.
type Snapshot struct {
	Network  Network
	Devices  []EeroDevice
	Profiles []EeroProfile
	Nodes    []EeroNode
	Warnings []string
}

// Networks lists the account's networks.
func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	data, err := c.get(ctx, eeroAPIVersion+"/account")
	if err != nil {
		return nil, err
	}
	var acc struct {
		Networks json.RawMessage `json:"networks"`
	}
	if err := json.Unmarshal(data, &acc); err != nil {
		return nil, fmt.Errorf("%w: account", ErrEeroBadResponse)
	}
	items := listOf(acc.Networks)
	var out []Network
	for _, m := range items {
		n := Network{URL: str(m, "url"), Name: cleanText(str(m, "name"), 100)}
		n.ID = idFromURL(n.URL)
		if n.ID == "" {
			n.ID = idFromURL(str(m, "id"))
		}
		if n.ID != "" {
			out = append(out, n)
		}
	}
	return out, nil
}

// Devices lists a network's devices.
func (c *Client) Devices(ctx context.Context, networkID string) ([]EeroDevice, error) {
	items, err := c.getList(ctx, c.netPath(networkID, "devices"))
	if err != nil {
		return nil, err
	}
	out := make([]EeroDevice, 0, len(items))
	for _, m := range items {
		out = append(out, parseDevice(m))
	}
	return out, nil
}

// Profiles lists a network's profiles with their devices.
func (c *Client) Profiles(ctx context.Context, networkID string) ([]EeroProfile, error) {
	items, err := c.getList(ctx, c.netPath(networkID, "profiles"))
	if err != nil {
		return nil, err
	}
	out := make([]EeroProfile, 0, len(items))
	for _, m := range items {
		out = append(out, parseProfile(m))
	}
	return out, nil
}

// Nodes lists the eero routers and nodes of a network.
func (c *Client) Nodes(ctx context.Context, networkID string) ([]EeroNode, error) {
	items, err := c.getList(ctx, c.netPath(networkID, "eeros"))
	if err != nil {
		return nil, err
	}
	out := make([]EeroNode, 0, len(items))
	for _, m := range items {
		out = append(out, parseNode(m))
	}
	return out, nil
}

// Snapshot reads devices, profiles and nodes of a network. Profiles and
// nodes that cannot be read become warnings, not failures, so a name import
// still works; the devices list is required.
func (c *Client) Snapshot(ctx context.Context, n Network) (Snapshot, error) {
	s := Snapshot{Network: n}
	var err error
	if s.Devices, err = c.Devices(ctx, n.ID); err != nil {
		return Snapshot{}, err
	}
	if s.Profiles, err = c.Profiles(ctx, n.ID); err != nil {
		if isFatal(err) {
			return Snapshot{}, err
		}
		s.Warnings = append(s.Warnings, "profiles could not be read, so no groups are imported: "+briefErr(err))
	}
	if s.Nodes, err = c.Nodes(ctx, n.ID); err != nil {
		if isFatal(err) {
			return Snapshot{}, err
		}
		s.Warnings = append(s.Warnings, "the eero routers and nodes could not be read, so they are not marked as infrastructure: "+briefErr(err))
	}
	return s, nil
}

func isFatal(err error) bool {
	return errors.Is(err, ErrEeroRateLimited) || errors.Is(err, ErrEeroSessionExpire) ||
		errors.Is(err, ErrEeroUnauthorized) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func briefErr(err error) string { return cleanText(err.Error(), 160) }

func (c *Client) netPath(id, what string) string {
	return eeroAPIVersion + "/networks/" + url.PathEscape(idFromURL(id)) + "/" + what
}

// ---- transport --------------------------------------------------------------

func (c *Client) tokenValue() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *Client) get(ctx context.Context, path string) (json.RawMessage, error) {
	tok := c.tokenValue()
	if tok == "" {
		return nil, ErrEeroNoSession
	}
	return c.do(ctx, http.MethodGet, path, nil, tok, false)
}

const maxPages = 50

func (c *Client) getList(ctx context.Context, path string) ([]map[string]any, error) {
	var all []map[string]any
	seen := map[string]bool{}
	next := path
	for pages := 0; next != "" && pages < maxPages; pages++ {
		if seen[next] {
			break
		}
		seen[next] = true
		tok := c.tokenValue()
		if tok == "" {
			return nil, ErrEeroNoSession
		}
		env, err := c.doEnvelope(ctx, http.MethodGet, next, nil, tok, false)
		if err != nil {
			return nil, err
		}
		all = append(all, listOf(env.Data)...)
		if len(all) > 50000 {
			return nil, fmt.Errorf("%w: too many items", ErrEeroTooLarge)
		}
		var err2 error
		next, err2 = c.nextPage(env, path)
		if err2 != nil {
			return nil, err2
		}
	}
	return all, nil
}

// nextPage finds the next-page link in the several shapes the API uses: a URL
// or path under pagination/meta/data, or a bare cursor. It never leaves the
// API host.
func (c *Client) nextPage(env envelope, path string) (string, error) {
	cand := func(m map[string]any) (link, cursor string) {
		for _, k := range []string{"next", "next_url", "next_page"} {
			if s, ok := m[k].(string); ok && s != "" {
				return s, ""
			}
		}
		for _, k := range []string{"next_cursor", "cursor"} {
			if s, ok := m[k].(string); ok && s != "" {
				return "", s
			}
		}
		return "", ""
	}
	var sources []map[string]any
	var dataObj map[string]any
	if json.Unmarshal(env.Data, &dataObj) == nil {
		sources = append(sources, dataObj)
	}
	if env.Pagination != nil {
		sources = append(sources, env.Pagination)
	}
	if env.Meta != nil {
		if p, ok := env.Meta["pagination"].(map[string]any); ok {
			sources = append(sources, p)
		}
		sources = append(sources, env.Meta)
	}
	for _, m := range sources {
		link, cursor := cand(m)
		if cursor != "" {
			base, _, _ := strings.Cut(path, "?")
			return base + "?cursor=" + url.QueryEscape(cursor), nil
		}
		if link == "" {
			continue
		}
		u, err := url.Parse(link)
		if err != nil {
			return "", fmt.Errorf("%w: bad next link", ErrEeroBadResponse)
		}
		if u.IsAbs() {
			if u.Host != c.base.Host || u.Scheme != c.base.Scheme {
				return "", fmt.Errorf("%w: a next link pointed to another host", ErrEeroBadResponse)
			}
		}
		out := u.EscapedPath()
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		return out, nil
	}
	return "", nil
}

type envelope struct {
	Meta       map[string]any  `json:"meta"`
	Pagination map[string]any  `json:"pagination"`
	Data       json.RawMessage `json:"data"`
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, token string, verify bool) (json.RawMessage, error) {
	env, err := c.doEnvelope(ctx, method, path, body, token, verify)
	if err != nil {
		return nil, err
	}
	return env.Data, nil
}

func (c *Client) throttle(ctx context.Context) error {
	if c.minGap <= 0 {
		return nil
	}
	c.mu.Lock()
	wait := c.minGap - c.now().Sub(c.last)
	c.last = c.now()
	if wait > 0 {
		c.last = c.last.Add(wait)
	}
	c.mu.Unlock()
	if wait > 0 {
		return c.sleep(ctx, wait)
	}
	return nil
}

func (c *Client) doEnvelope(ctx context.Context, method, path string, body []byte, token string, verify bool) (envelope, error) {
	u := *c.base
	rel, err := url.Parse(path)
	if err != nil {
		return envelope{}, ErrEeroBadResponse
	}
	u.Path, u.RawQuery = rel.Path, rel.RawQuery
	idempotent := method == http.MethodGet

	for attempt := 0; ; attempt++ {
		if err := c.throttle(ctx); err != nil {
			return envelope{}, err
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
		if err != nil {
			return envelope{}, ErrEeroBadResponse
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "shepherd-importer")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.AddCookie(&http.Cookie{Name: "s", Value: token})
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			// A *url.Error carries the URL and the cause, never the body or cookie.
			c.log.Warn("eero request failed", "method", method, "path", rel.Path)
			if ctx.Err() != nil {
				return envelope{}, ctx.Err()
			}
			return envelope{}, fmt.Errorf("eero: the request failed: %s", c.scrub(causeOf(err)))
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
		resp.Body.Close()
		c.log.Info("eero request", "method", method, "path", rel.Path, "status", resp.StatusCode)
		if rerr != nil {
			return envelope{}, fmt.Errorf("eero: reading the response failed: %s", c.scrub(rerr.Error()))
		}
		if int64(len(raw)) > c.maxBody {
			return envelope{}, ErrEeroTooLarge
		}

		retryable := resp.StatusCode == http.StatusTooManyRequests ||
			idempotent && (resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusGatewayTimeout)
		if retryable {
			wait := c.retryAfter(resp)
			if attempt >= c.retries || wait > c.maxWait {
				e := c.apiError(resp.StatusCode, raw, verify)
				e.RetryAfter = wait
				if resp.StatusCode == http.StatusTooManyRequests {
					e.kind = ErrEeroRateLimited
				}
				return envelope{}, e
			}
			if err := c.sleep(ctx, wait); err != nil {
				return envelope{}, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return envelope{}, c.apiError(resp.StatusCode, raw, verify)
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return envelope{}, fmt.Errorf("%w: not JSON", ErrEeroBadResponse)
		}
		if code := metaCode(env.Meta); code != 0 && code != 200 && code != 201 {
			return envelope{}, c.apiError(code, raw, verify)
		}
		return env, nil
	}
}

func causeOf(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

func metaCode(m map[string]any) int {
	if f, ok := m["code"].(float64); ok {
		return int(f)
	}
	return 0
}

func (c *Client) retryAfter(resp *http.Response) time.Duration {
	h := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if h == "" {
		return 2 * time.Second
	}
	if n, err := strconv.Atoi(h); err == nil {
		if n < 0 {
			n = 0
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(c.now()); d > 0 {
			return d
		}
		return 0
	}
	return 2 * time.Second
}

// apiError builds the error for a failed call, with the server's message
// scrubbed of every secret the client has seen.
func (c *Client) apiError(status int, raw []byte, verify bool) *APIError {
	var env envelope
	_ = json.Unmarshal(raw, &env)
	msg, _ := env.Meta["error"].(string)
	if code := metaCode(env.Meta); code >= 400 {
		status = code
	}
	e := &APIError{Status: status, Code: metaCode(env.Meta), Message: c.scrub(cleanText(msg, 120))}
	low := strings.ToLower(msg)
	switch {
	case status == http.StatusTooManyRequests:
		e.kind = ErrEeroRateLimited
	case verify && strings.Contains(low, "expire"):
		e.kind = ErrEeroCodeExpired
	case verify && status >= 400 && status < 500:
		e.kind = ErrEeroInvalidCode
	case strings.Contains(low, "session"):
		e.kind = ErrEeroSessionExpire
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.kind = ErrEeroUnauthorized
	}
	return e
}

// scrub removes every credential the client has handled from s.
func (c *Client) scrub(s string) string {
	c.mu.Lock()
	secrets := append([]string(nil), c.secrets...)
	c.mu.Unlock()
	for _, sec := range secrets {
		if len(sec) >= 3 {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

// ---- tolerant parsing -------------------------------------------------------

func listOf(raw json.RawMessage) []map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil {
		for _, k := range []string{"data", "devices", "items", "results", "profiles", "eeros", "networks"} {
			if v, ok := obj[k]; ok {
				b, _ := json.Marshal(v)
				return listOf(b)
			}
		}
	}
	return nil
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		case float64:
			return strconv.FormatInt(int64(v), 10)
		}
	}
	return ""
}

func boolean(m map[string]any, keys ...string) (v, present bool) {
	for _, k := range keys {
		switch x := m[k].(type) {
		case bool:
			return x, true
		case string:
			if b, err := strconv.ParseBool(x); err == nil {
				return b, true
			}
		}
	}
	return false, false
}

func strList(m map[string]any, keys ...string) []string {
	var out []string
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				out = append(out, s)
			}
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
		}
	}
	return out
}

// sub returns a nested object that may also arrive as a bare URL string.
func sub(m map[string]any, key string) (obj map[string]any, asString string) {
	switch v := m[key].(type) {
	case map[string]any:
		return v, ""
	case string:
		return nil, v
	}
	return nil, ""
}

func idFromURL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func parseDevice(m map[string]any) EeroDevice {
	d := EeroDevice{
		URL:          str(m, "url"),
		MAC:          str(m, "mac", "mac_address", "eui48"),
		IP:           str(m, "ip", "ip_address"),
		Nickname:     str(m, "nickname", "name", "display_name"),
		Hostname:     str(m, "hostname", "host_name"),
		Manufacturer: str(m, "manufacturer", "vendor", "make"),
		DeviceType:   str(m, "device_type", "device_category", "type"),
		Connection:   strings.ToLower(str(m, "connection_type", "connectionType")),
	}
	d.IPs = strList(m, "ips", "ip_addresses")
	if d.IP != "" {
		d.IPs = append([]string{d.IP}, d.IPs...)
	}
	if d.MAC == "" {
		if mac := macFromURL(d.URL); mac != "" {
			d.MAC = mac
		}
	}
	if d.Connection == "" {
		if w, ok := boolean(m, "wireless"); ok {
			d.Connection = map[bool]string{true: "wireless", false: "wired"}[w]
		}
	}
	d.Paused, _ = boolean(m, "paused")
	d.Guest, _ = boolean(m, "is_guest", "guest")
	if o, s := sub(m, "source"); o != nil {
		d.NodeLocation = cleanText(str(o, "location", "name"), 100)
		d.NodeURL = str(o, "url")
	} else if s != "" {
		d.NodeURL = s
	}
	if o, s := sub(m, "profile"); o != nil {
		d.ProfileName = str(o, "name")
		d.ProfileURL = str(o, "url")
	} else if s != "" {
		d.ProfileURL = s
	}
	return d
}

func macFromURL(u string) string {
	return idFromURL(u)
}

func parseProfile(m map[string]any) EeroProfile {
	p := EeroProfile{URL: str(m, "url"), Name: str(m, "name", "display_name")}
	p.Paused, _ = boolean(m, "paused")
	var devs []any
	switch v := m["devices"].(type) {
	case []any:
		devs = v
	case map[string]any:
		devs, _ = v["data"].([]any)
	}
	for _, e := range devs {
		switch x := e.(type) {
		case string:
			p.DeviceURLs = append(p.DeviceURLs, x)
		case map[string]any:
			if mac := str(x, "mac", "mac_address"); mac != "" {
				p.DeviceMACs = append(p.DeviceMACs, mac)
			}
			if u := str(x, "url"); u != "" {
				p.DeviceURLs = append(p.DeviceURLs, u)
			}
		}
	}
	return p
}

func parseNode(m map[string]any) EeroNode {
	n := EeroNode{
		URL:      str(m, "url"),
		MAC:      str(m, "mac_address", "mac"),
		IP:       str(m, "ip_address", "ip"),
		Location: cleanText(str(m, "location", "name"), 100),
		Model:    cleanText(str(m, "model", "model_number"), 40),
		Serial:   str(m, "serial"),
	}
	n.Gateway, _ = boolean(m, "gateway", "is_gateway")
	return n
}
