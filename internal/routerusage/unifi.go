// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// UniFi reads per-device bandwidth from a UniFi Network controller.
//
// Unlike eero this is a KindCounters source: the controller keeps bytes
// per client since it last restarted, so differencing consecutive reads
// is exact rather than an estimate. That is the whole argument for it.
//
// The endpoint is the controller's own, the one its web interface uses.
// Ubiquiti's documented API lists clients but does not expose their
// traffic counters, so this reads `stat/sta` like every open-source UniFi
// client does. It is read-only and changes nothing on the controller.
//
// Two shapes of controller exist and this handles both: a UniFi OS
// console (a Dream Machine, a Cloud Gateway, a UDR) answers under
// /proxy/network and wants a CSRF token, while a self-hosted Network
// Application answers directly. Which one is in front is discovered at
// login rather than configured.
type UniFi struct {
	cfg UniFiConfig

	mu       sync.Mutex
	hc       *http.Client
	unifiOS  bool
	csrf     string
	loggedIn bool
}

// UniFiConfig is what the owner provides. Username and Password are a
// local controller account; a read-only one is enough and is what the
// docs recommend.
type UniFiConfig struct {
	// BaseURL is the controller, e.g. "https://192.0.2.10" or
	// "https://unifi.example.com:8443". The path is ignored.
	BaseURL  string
	Username string
	Password string
	// Site is the controller's site name, not its label. "default" unless
	// the owner runs more than one.
	Site string
	// AllowSelfSigned skips TLS verification. Controllers ship with a
	// self-signed certificate, so this is usually needed on a LAN address
	// and is why it exists; it is off unless the owner turns it on, and
	// the portal says what it costs.
	AllowSelfSigned bool
	// Timeout per request (default 15s).
	Timeout time.Duration
}

// Errors a UniFi source reports. Use errors.Is.
var (
	ErrUniFiAuth    = errors.New("unifi: the controller refused the username or password")
	ErrUniFiBadURL  = errors.New("unifi: the controller address must be an http or https URL")
	ErrUniFiRefused = errors.New("unifi: the controller refused the request")
)

// NewUniFi returns a Source reading cfg's controller. The connection is
// not made until the first Poll.
func NewUniFi(cfg UniFiConfig) (*UniFi, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, ErrUniFiBadURL
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: put the username and password in their own fields", ErrUniFiBadURL)
	}
	cfg.BaseURL = u.Scheme + "://" + u.Host
	if strings.TrimSpace(cfg.Site) == "" {
		cfg.Site = "default"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &UniFi{cfg: cfg}, nil
}

// Name implements Source.
func (u *UniFi) Name() string { return "unifi" }

// Kind implements Source: the controller keeps real byte counters.
func (u *UniFi) Kind() Kind { return KindCounters }

// SetHTTPClient replaces the client, for tests. It also marks the source
// as needing a fresh login.
func (u *UniFi) SetHTTPClient(hc *http.Client) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.hc, u.loggedIn = hc, false
}

func (u *UniFi) client() *http.Client {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.hc == nil {
		jar, _ := cookiejar.New(nil)
		tr := &http.Transport{}
		if u.cfg.AllowSelfSigned {
			// The owner asked for this: a controller on a LAN address
			// almost always has a certificate nothing can verify.
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, see AllowSelfSigned
		}
		u.hc = &http.Client{
			Jar: jar, Transport: tr, Timeout: u.cfg.Timeout,
			// A controller never redirects these calls, and following one
			// would let a wrong address walk this client somewhere else
			// with the session cookie attached.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("unifi: redirects are not followed")
			},
		}
	}
	return u.hc
}

// Poll implements Source. It logs in on the first call and again whenever
// the controller stops accepting the session.
func (u *UniFi) Poll(ctx context.Context) ([]Sample, error) {
	samples, err := u.clients(ctx)
	if !errors.Is(err, ErrUniFiAuth) {
		return samples, err
	}
	// The session lapsed, which is routine on a controller restart.
	u.mu.Lock()
	u.loggedIn = false
	u.mu.Unlock()
	return u.clients(ctx)
}

func (u *UniFi) clients(ctx context.Context) ([]Sample, error) {
	if err := u.ensureLogin(ctx); err != nil {
		return nil, err
	}
	u.mu.Lock()
	prefix := ""
	if u.unifiOS {
		prefix = "/proxy/network"
	}
	u.mu.Unlock()
	path := prefix + "/api/s/" + url.PathEscape(u.cfg.Site) + "/stat/sta"
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := u.get(ctx, path, &body); err != nil {
		return nil, err
	}
	out := make([]Sample, 0, len(body.Data))
	for _, m := range body.Data {
		if s, ok := unifiSample(m); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// unifiSample reads one client record. A wired client reports its bytes
// under "wired-" keys, and the controller's directions are its own:
// tx_bytes is what it sent to the client, which is the device's download.
func unifiSample(m map[string]any) (Sample, bool) {
	mac := NormalizeMAC(str(m, "mac"))
	if mac == "" {
		return Sample{}, false
	}
	down, dok := u64(m, "tx_bytes", "wired-tx_bytes")
	up, uok := u64(m, "rx_bytes", "wired-rx_bytes")
	if !dok && !uok {
		return Sample{}, false
	}
	return Sample{
		MAC:       mac,
		Name:      str(m, "name", "hostname", "display_name"),
		DownBytes: down,
		UpBytes:   up,
	}, true
}

func (u *UniFi) ensureLogin(ctx context.Context) error {
	u.mu.Lock()
	done := u.loggedIn
	u.mu.Unlock()
	if done {
		return nil
	}
	body, err := json.Marshal(map[string]any{
		"username": u.cfg.Username,
		"password": u.cfg.Password,
		"remember": true,
	})
	if err != nil {
		return err
	}
	// A UniFi OS console answers /api/auth/login; a self-hosted Network
	// Application answers /api/login and 404s the other. Try the console
	// first, since every current gateway is one.
	for _, attempt := range []struct {
		path    string
		unifiOS bool
	}{
		{"/api/auth/login", true},
		{"/api/login", false},
	} {
		status, hdr, err := u.post(ctx, attempt.path, body)
		if err != nil {
			return err
		}
		switch {
		case status == http.StatusOK:
			u.mu.Lock()
			u.unifiOS, u.csrf, u.loggedIn = attempt.unifiOS, hdr.Get("X-Csrf-Token"), true
			u.mu.Unlock()
			return nil
		case status == http.StatusUnauthorized || status == http.StatusBadRequest:
			return ErrUniFiAuth
		case status == http.StatusNotFound:
			continue // the other shape of controller
		default:
			return fmt.Errorf("%w: HTTP %d from %s", ErrUniFiRefused, status, attempt.path)
		}
	}
	return fmt.Errorf("%w: neither login endpoint answered; is this a UniFi controller?", ErrUniFiRefused)
}

func (u *UniFi) post(ctx context.Context, path string, body []byte) (int, http.Header, error) {
	// The address is the owner's own controller, typed into the portal by
	// someone already signed in to it, and NewUniFi has already limited it
	// to an http or https URL with no credentials in it. Redirects are
	// refused above, so this cannot be walked anywhere else.
	// codeql[go/request-forgery]
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := u.client().Do(req)
	if err != nil {
		return 0, nil, scrubURLError(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, resp.Header, nil
}

const maxUniFiResponse = 8 << 20

func (u *UniFi) get(ctx context.Context, path string, into any) error {
	// The owner's own controller; see the note in post.
	// codeql[go/request-forgery]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.cfg.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	u.mu.Lock()
	if u.csrf != "" {
		req.Header.Set("X-Csrf-Token", u.csrf)
	}
	u.mu.Unlock()
	resp, err := u.client().Do(req)
	if err != nil {
		return scrubURLError(err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUniFiAuth
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: HTTP %d", ErrUniFiRefused, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxUniFiResponse)).Decode(into)
}

// UniFiNeedsSignIn reports whether err means the stored credentials no
// longer work, so the portal asks for them again rather than showing a
// transient failure.
func UniFiNeedsSignIn(err error) bool { return errors.Is(err, ErrUniFiAuth) }

// scrubURLError replaces net/http's "Post \"https://host/api/auth/login\":
// ..." with something an owner can read. It is tidying, not redaction: the
// address is not a secret (NewUniFi refuses a URL with credentials in it)
// and the cause underneath still names the host, which is what makes the
// message useful.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("unifi: %s the controller: %w", ue.Op, ue.Err)
	}
	return err
}

// ---- tolerant readers -------------------------------------------------------

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		}
	}
	return ""
}

// u64 reads a byte counter, which JSON gives as a float and some
// controller versions as a string. A negative or absurd value is refused
// rather than wrapping into an enormous unsigned number.
func u64(m map[string]any, keys ...string) (uint64, bool) {
	var total uint64
	found := false
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			if v >= 0 && v < 1<<62 {
				total += uint64(v)
				found = true
			}
		case string:
			var n uint64
			if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil && n < 1<<62 {
				total += n
				found = true
			}
		}
	}
	return total, found
}
