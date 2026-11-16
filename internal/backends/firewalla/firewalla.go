// SPDX-License-Identifier: AGPL-3.0-or-later

// Package firewalla is the Firewalla MSP backend (docs/BACKENDS.md): it
// reads devices, flows, alarms and rules over the documented MSP API
// (https://docs.firewalla.net) and, unless the owner marked the token
// read-only, changes rules, device names and alarms through the same API.
//
// The token goes to exactly one place: the address must be the owner's own
// domain on firewalla.net over https, and redirects are refused.
package firewalla

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"shepherd/internal/backends"
	"shepherd/internal/routerusage"
)

// Config is what the owner provides.
type Config struct {
	// BaseURL is the MSP instance; see routerusage.NormalizeFirewallaURL.
	BaseURL string
	Token   string
	// Box limits reading, and is where new rules go, to one box (its gid).
	// Empty reads every box; creating a rule then needs the box named.
	Box string
	// ReadOnly refuses every write before it is sent. Set it when the
	// token was made Read Only, so the portal never offers what MSP would
	// refuse.
	ReadOnly bool
	// Timeout per request (default 15s).
	Timeout time.Duration
	// Transport replaces the HTTP transport, for tests.
	Transport http.RoundTripper
}

// Client is the Firewalla backend.
type Client struct {
	cfg  Config
	base string
	hc   *http.Client
	ro   atomic.Bool
}

// New returns a Client. The connection is not made until the first call.
func New(cfg Config) (*Client, error) {
	base, err := routerusage.NormalizeFirewallaURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	cfg.Token = strings.TrimSpace(cfg.Token)
	if cfg.Token == "" {
		return nil, routerusage.ErrFirewallaNoToken
	}
	cfg.Box = strings.TrimSpace(cfg.Box)
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	tr := cfg.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	c := &Client{cfg: cfg, base: base, hc: &http.Client{
		Transport: tr, Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("firewalla: redirects are not followed")
		},
	}}
	c.ro.Store(cfg.ReadOnly)
	return c, nil
}

// Name implements backends.Backend.
func (c *Client) Name() string { return "firewalla" }

// ReadOnly implements backends.Backend.
func (c *Client) ReadOnly() bool { return c.ro.Load() }

// SetReadOnly changes whether writes are refused, without reconnecting,
// so the owner can switch write access on or off from the portal.
func (c *Client) SetReadOnly(ro bool) { c.ro.Store(ro) }

const maxResponse = 16 << 20

// do sends one request and decodes a JSON answer into out when it is not
// nil. Status codes are mapped onto the backends errors.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	endpoint := c.base + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	// The address is limited to firewalla.net by New; the token goes
	// nowhere else.
	// codeql[go/request-forgery]
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// codeql[go/request-forgery]
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("firewalla: %s MSP: %w", strings.ToLower(ue.Op), ue.Err)
		}
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return backends.ErrAuth
	case resp.StatusCode == http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return backends.ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return backends.ErrRateLimited
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: HTTP %d", backends.ErrRefused, resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(out); err != nil {
		return fmt.Errorf("firewalla: MSP answered with something unexpected: %w", err)
	}
	return nil
}

func (c *Client) writable() error {
	if c.ro.Load() {
		return backends.ErrReadOnly
	}
	return nil
}

// ---- wire types -------------------------------------------------------------

// num reads a JSON number that MSP sometimes sends as a string.
type num float64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil // an unreadable figure is a zero, not a failed poll
	}
	*n = num(f)
	return nil
}

func (n num) bytes() uint64 {
	if n < 0 || n >= 1<<62 {
		return 0
	}
	return uint64(n)
}

func (n num) time() time.Time {
	if n <= 0 {
		return time.Time{}
	}
	sec := float64(n)
	return time.Unix(int64(sec), int64((sec-float64(int64(sec)))*1e9)).UTC()
}

type wireRef struct {
	ID   string `json:"id"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

type wireDevice struct {
	ID            string  `json:"id"`
	GID           string  `json:"gid"`
	Name          string  `json:"name"`
	IP            string  `json:"ip"`
	MACVendor     string  `json:"macVendor"`
	Online        bool    `json:"online"`
	Network       wireRef `json:"network"`
	Group         wireRef `json:"group"`
	TotalDownload num     `json:"totalDownload"`
	TotalUpload   num     `json:"totalUpload"`
}

type wireFlow struct {
	TS        num      `json:"ts"`
	GID       string   `json:"gid"`
	Protocol  string   `json:"protocol"`
	Direction string   `json:"direction"`
	Block     bool     `json:"block"`
	Download  num      `json:"download"`
	Upload    num      `json:"upload"`
	Category  string   `json:"category"`
	Region    string   `json:"region"`
	Count     num      `json:"count"`
	Device    wireRef  `json:"device"`
	Source    *wireRef `json:"source"`
	Dest      *wireRef `json:"destination"`
}

type wireAlarm struct {
	AID     json.Number `json:"aid"`
	Type    json.Number `json:"type"`
	Message string      `json:"message"`
	TS      num         `json:"ts"`
	GID     string      `json:"gid"`
	Device  wireRef     `json:"device"`
	Remote  struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	} `json:"remote"`
}

type wireTarget struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	DNSOnly *bool  `json:"dnsOnly,omitempty"`
}

type wireScope struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type wireRule struct {
	ID        string     `json:"id"`
	Name      string     `json:"name,omitempty"`
	Action    string     `json:"action"`
	Direction string     `json:"direction,omitempty"`
	GID       string     `json:"gid,omitempty"`
	Notes     string     `json:"notes"`
	Status    string     `json:"status"`
	TS        num        `json:"ts"`
	Target    wireTarget `json:"target"`
	Scope     *wireScope `json:"scope,omitempty"`
}

type page[T any] struct {
	Results    []T    `json:"results"`
	NextCursor string `json:"next_cursor"`
}

// ---- reading ----------------------------------------------------------------

// Devices implements backends.DeviceReader.
func (c *Client) Devices(ctx context.Context) ([]backends.Device, error) {
	q := url.Values{}
	if c.cfg.Box != "" {
		q.Set("box", c.cfg.Box)
	}
	var raw []wireDevice
	if err := c.do(ctx, http.MethodGet, "/v2/devices", q, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]backends.Device, 0, len(raw))
	for _, d := range raw {
		out = append(out, backends.Device{
			MAC: routerusage.NormalizeMAC(d.ID), Name: d.Name, IP: d.IP, Vendor: d.MACVendor,
			Online: d.Online, Group: d.Group.Name, Network: d.Network.Name,
			Down24h: d.TotalDownload.bytes(), Up24h: d.TotalUpload.bytes(),
			Box: d.GID, Native: d.ID,
		})
	}
	return out, nil
}

// Flows implements backends.FlowReader. The device filter is applied by
// the caller; MSP's query syntax for it is not documented.
func (c *Client) Flows(ctx context.Context, fq backends.FlowQuery) (backends.FlowPage, error) {
	q := url.Values{}
	var terms []string
	if !fq.From.IsZero() {
		to := fq.To
		if to.IsZero() {
			to = time.Now()
		}
		terms = append(terms, fmt.Sprintf("ts:%d-%d", fq.From.Unix(), to.Unix()))
	}
	if c.cfg.Box != "" {
		terms = append(terms, "box:"+c.cfg.Box)
	}
	if len(terms) > 0 {
		q.Set("query", strings.Join(terms, " "))
	}
	setPaging(q, fq.Limit, fq.Cursor)
	var raw page[wireFlow]
	if err := c.do(ctx, http.MethodGet, "/v2/flows", q, nil, &raw); err != nil {
		return backends.FlowPage{}, err
	}
	out := backends.FlowPage{Next: raw.NextCursor, Flows: make([]backends.Flow, 0, len(raw.Results))}
	for _, f := range raw.Results {
		fl := backends.Flow{
			Time: f.TS.time(), DeviceMAC: routerusage.NormalizeMAC(f.Device.ID), Device: f.Device.Name,
			DeviceIP: f.Device.IP, Protocol: f.Protocol, Outbound: f.Direction == "outbound",
			Blocked: f.Block, Download: f.Download.bytes(), Upload: f.Upload.bytes(),
			Category: f.Category, Country: f.Region, Box: f.GID,
		}
		// The remote end is the destination of an outbound flow and the
		// source of an inbound one. A local flow has no remote host.
		remote := f.Dest
		if f.Direction == "inbound" {
			remote = f.Source
		}
		if remote != nil && f.Direction != "local" {
			fl.RemoteIP = remote.IP
			// MSP names a remote host by its domain when it knows one and
			// by its address otherwise.
			if remote.Name != "" && remote.Name != remote.IP {
				fl.Domain = strings.ToLower(strings.TrimSuffix(remote.Name, "."))
			}
		}
		fl.Count = int(f.Count)
		out.Flows = append(out.Flows, fl)
	}
	return out, nil
}

// Alarms implements backends.AlarmReader.
func (c *Client) Alarms(ctx context.Context, aq backends.AlarmQuery) (backends.AlarmPage, error) {
	q := url.Values{}
	var terms []string
	if aq.ActiveOnly {
		terms = append(terms, "status:active")
	}
	if c.cfg.Box != "" {
		terms = append(terms, "box:"+c.cfg.Box)
	}
	if len(terms) > 0 {
		q.Set("query", strings.Join(terms, " "))
	}
	setPaging(q, aq.Limit, aq.Cursor)
	var raw page[wireAlarm]
	if err := c.do(ctx, http.MethodGet, "/v2/alarms", q, nil, &raw); err != nil {
		return backends.AlarmPage{}, err
	}
	out := backends.AlarmPage{Next: raw.NextCursor, Alarms: make([]backends.Alarm, 0, len(raw.Results))}
	for _, a := range raw.Results {
		out.Alarms = append(out.Alarms, backends.Alarm{
			ID: a.AID.String(), Time: a.TS.time(), Type: alarmTypeName(a.Type.String()), Message: a.Message,
			Domain: strings.ToLower(strings.TrimSuffix(a.Remote.Domain, ".")), DeviceMAC: routerusage.NormalizeMAC(a.Device.ID), Device: a.Device.Name, Box: a.GID,
		})
	}
	return out, nil
}

// alarmTypes are MSP's numbered alarm kinds (docs.firewalla.net, Alarm).
var alarmTypes = map[string]string{
	"1": "Security Activity", "2": "Abnormal Upload", "3": "Large Bandwidth Usage", "4": "Monthly Data Plan",
	"5": "New Device", "6": "Device Back Online", "7": "Device Offline", "8": "Video Activity",
	"9": "Gaming Activity", "10": "Porn Activity", "11": "VPN Activity", "12": "VPN Connection Restored",
	"13": "VPN Connection Error", "14": "Open Port", "15": "Internet Connectivity Update", "16": "Large Upload",
}

func alarmTypeName(n string) string {
	if name, ok := alarmTypes[n]; ok {
		return name
	}
	return "Alarm " + n
}

func setPaging(q url.Values, limit int, cursor string) {
	if limit > 0 {
		if limit > 500 {
			limit = 500
		}
		q.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
}

// Rules implements backends.RuleManager.
func (c *Client) Rules(ctx context.Context) ([]backends.Rule, error) {
	q := url.Values{}
	if c.cfg.Box != "" {
		q.Set("query", "box.id:"+c.cfg.Box)
	}
	var raw page[wireRule]
	if err := c.do(ctx, http.MethodGet, "/v2/rules", q, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]backends.Rule, 0, len(raw.Results))
	for _, r := range raw.Results {
		out = append(out, toRule(r))
	}
	return out, nil
}

func toRule(r wireRule) backends.Rule {
	rule := backends.Rule{
		ID: r.ID, Name: r.Name, Action: r.Action, TargetType: r.Target.Type, Target: r.Target.Value,
		DNSOnly: r.Target.DNSOnly != nil && *r.Target.DNSOnly, Paused: r.Status == "paused", Notes: r.Notes, Created: r.TS.time(), Box: r.GID,
	}
	if r.Scope != nil {
		rule.ScopeType, rule.Scope = r.Scope.Type, r.Scope.Value
		if rule.ScopeType == "device" {
			if mac := routerusage.NormalizeMAC(rule.Scope); mac != "" {
				rule.Scope = mac
			}
		}
	}
	return rule
}

// ---- writing ----------------------------------------------------------------

// CreateRule implements backends.RuleManager.
func (c *Client) CreateRule(ctx context.Context, spec backends.RuleSpec) (backends.Rule, error) {
	if err := c.writable(); err != nil {
		return backends.Rule{}, err
	}
	if err := spec.Validate(); err != nil {
		return backends.Rule{}, err
	}
	// With no box named the rule applies to every box on the account, which
	// is what MSP does with a rule that has no gid.
	body := wireRule{
		Action: spec.Action, Direction: "bidirection", GID: firstNonEmpty(spec.Box, c.cfg.Box), Notes: spec.Notes,
		Target: wireTarget{Type: spec.TargetType, Value: strings.TrimSpace(spec.Target)},
	}
	switch spec.TargetType {
	case "domain", "category", "app", "targetlist":
		// MSP defaults these to DNS-only; say so explicitly either way so
		// what is sent is what the preview described.
		dnsOnly := !spec.BlockConnections
		body.Target.DNSOnly = &dnsOnly
	}
	if spec.ScopeType != "" {
		value := strings.TrimSpace(spec.Scope)
		if spec.ScopeType == "device" {
			value = macWithColons(value)
		}
		body.Scope = &wireScope{Type: spec.ScopeType, Value: value}
	}
	var got wireRule
	if err := c.do(ctx, http.MethodPost, "/v2/rules", nil, body, &got); err != nil {
		return backends.Rule{}, err
	}
	return toRule(got), nil
}

// SetRulePaused implements backends.RuleManager.
func (c *Client) SetRulePaused(ctx context.Context, id string, paused bool) error {
	if err := c.writable(); err != nil {
		return err
	}
	if err := validID(id); err != nil {
		return err
	}
	verb := "resume"
	if paused {
		verb = "pause"
	}
	return c.do(ctx, http.MethodPost, "/v2/rules/"+url.PathEscape(id)+"/"+verb, nil, nil, nil)
}

// DeleteRule implements backends.RuleManager.
func (c *Client) DeleteRule(ctx context.Context, id string) error {
	if err := c.writable(); err != nil {
		return err
	}
	if err := validID(id); err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/v2/rules/"+url.PathEscape(id), nil, nil, nil)
}

// RenameDevice implements backends.DeviceRenamer. MSP limits a name to 32
// characters.
func (c *Client) RenameDevice(ctx context.Context, d backends.DeviceRef, name string) error {
	if err := c.writable(); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 32 {
		return fmt.Errorf("%w: a device name is 1 to 32 characters", backends.ErrInvalid)
	}
	if d.Box == "" || d.Native == "" {
		return fmt.Errorf("%w: the device is not identified", backends.ErrInvalid)
	}
	path := "/v2/boxes/" + url.PathEscape(d.Box) + "/devices/" + url.PathEscape(d.Native)
	return c.do(ctx, http.MethodPatch, path, nil, map[string]string{"name": name}, nil)
}

// DismissAlarm implements backends.AlarmDismisser.
func (c *Client) DismissAlarm(ctx context.Context, a backends.AlarmRef) error {
	if err := c.writable(); err != nil {
		return err
	}
	if a.Box == "" || a.ID == "" {
		return fmt.Errorf("%w: the alarm is not identified", backends.ErrInvalid)
	}
	return c.do(ctx, http.MethodDelete, "/v2/alarms/"+url.PathEscape(a.Box)+"/"+url.PathEscape(a.ID), nil, nil, nil)
}

func validID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%w: a rule id is required", backends.ErrInvalid)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// macWithColons writes a normalized MAC the way MSP does (AA:BB:...), and
// returns anything that is not one unchanged.
func macWithColons(mac string) string {
	n := routerusage.NormalizeMAC(mac)
	if n == "" {
		return mac
	}
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = strings.ToUpper(n[i*2 : i*2+2])
	}
	return strings.Join(parts, ":")
}
