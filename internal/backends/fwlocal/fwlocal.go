// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fwlocal is the backend for a Firewalla box that Shepherd runs
// on (docs/BACKENDS.md, "Firewalla, on the box"). It talks to the API the
// box serves on its own loopback address, the one Firewalla's app uses,
// so it needs no MSP account and no token, and it sees traffic as it
// happens rather than minutes later.
//
// That API is not published. It is read here from Firewalla's open source
// (github.com/firewalla/firewalla, controllers/netbot.js and
// api/routes/encipher.js) and can change with a firmware update. Only the
// calls verified against a running box are made; creating a rule is not
// among them.
//
// The API has no authentication because it listens on loopback only, so
// this client refuses any address that is not loopback: it must never be
// pointed across a network.
package fwlocal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shepherd/internal/backends"
	"shepherd/internal/routerusage"
)

// DefaultURL is where a Firewalla box serves its local API.
const DefaultURL = "http://127.0.0.1:8834"

// ErrBadURL is returned for an address that is not a loopback http origin.
var ErrBadURL = errors.New("firewalla: the local API address must be http on this machine's loopback address, such as http://127.0.0.1:8834")

// Config is what the owner provides, which is nothing but the switches.
type Config struct {
	// BaseURL defaults to DefaultURL; see NormalizeURL.
	BaseURL string
	// ReadOnly refuses every write before it is sent.
	ReadOnly bool
	// Timeout per request (default 15s).
	Timeout time.Duration
	// Transport replaces the HTTP transport, for tests.
	Transport http.RoundTripper
	Now       func() time.Time
}

// Client is the on-box Firewalla backend.
type Client struct {
	cfg  Config
	base string
	hc   *http.Client
	ro   atomic.Bool

	mu    sync.Mutex
	names map[string]string // MAC to name, from the last Devices call
}

// NormalizeURL turns raw into the origin requests are sent to, or
// ErrBadURL. Empty means DefaultURL.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" ||
		strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrBadURL
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return "", ErrBadURL
	}
	return "http://" + u.Host, nil
}

// New returns a Client. The connection is not made until the first call.
func New(cfg Config) (*Client, error) {
	base, err := NormalizeURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	tr := cfg.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	c := &Client{cfg: cfg, base: base, names: map[string]string{}, hc: &http.Client{
		Transport: tr, Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("firewalla: redirects are not followed")
		},
	}}
	c.ro.Store(cfg.ReadOnly)
	return c, nil
}

// Name implements backends.Backend. It is the same product as the MSP
// backend, so it carries the same name.
func (c *Client) Name() string { return "firewalla" }

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

const maxResponse = 32 << 20

// call sends one message to the box. command is "get", "set" or "cmd";
// target is a device's MAC for the calls that are about one device. value
// is the message's body and out receives the answer's data, when not nil.
func (c *Client) call(ctx context.Context, command, item, target string, query url.Values, value map[string]string, out any) error {
	var body map[string]any
	if value != nil {
		body = make(map[string]any, len(value))
		for k, v := range value {
			body[k] = v
		}
	}
	return c.send(ctx, command, item, target, query, body, out)
}

// callBody is call for a message whose body is not all strings.
func (c *Client) callBody(ctx context.Context, command, item, target string, value map[string]any, out any) error {
	return c.send(ctx, command, item, target, nil, value, out)
}

func (c *Client) send(ctx context.Context, command, item, target string, query url.Values, value map[string]any, out any) error {
	q := url.Values{"command": {command}, "item": {item}}
	if target != "" {
		q.Set("target", target)
	}
	for k, v := range query {
		q[k] = v
	}
	method, body := http.MethodGet, io.Reader(nil)
	if value != nil {
		b, _ := json.Marshal(value)
		method, body = http.MethodPost, bytes.NewReader(b)
	}
	// The address is limited to loopback by New.
	// codeql[go/request-forgery]
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/v1/encipher/simple?"+q.Encode(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if value != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// codeql[go/request-forgery]
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("firewalla: the box's local API did not answer: %w", ue.Err)
		}
		return err
	}
	defer resp.Body.Close()
	var env struct {
		Code    int             `json:"code"`
		Data    json.RawMessage `json:"data"`
		Message string          `json:"message"`
		Error   string          `json:"error"`
	}
	derr := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&env)
	code := resp.StatusCode
	if env.Code != 0 {
		code = env.Code
	}
	if code < 200 || code > 299 {
		msg := strings.TrimSpace(strings.TrimPrefix(firstNonEmpty(env.Message, env.Error), "Error:"))
		if code == http.StatusNotFound {
			return backends.ErrNotFound
		}
		if msg == "" {
			msg = "HTTP " + strconv.Itoa(code)
		}
		return fmt.Errorf("%w: %s", backends.ErrRefused, msg)
	}
	if derr != nil {
		return fmt.Errorf("firewalla: the box answered with something unexpected: %w", derr)
	}
	if out == nil || len(env.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("firewalla: the box answered with something unexpected: %w", err)
	}
	return nil
}

// ---- wire types -------------------------------------------------------------

// flex reads a value the box sends as a string, a number or a boolean
// depending on where it was stored, and keeps it as text.
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return nil // unreadable is empty, not a failed poll
		}
		*f = flex(v)
		return nil
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return nil
	}
	*f = flex(s)
	return nil
}

func (f flex) float() float64 {
	v, _ := strconv.ParseFloat(string(f), 64)
	return v
}

func (f flex) time() time.Time {
	sec := f.float()
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(sec), int64((sec-float64(int64(sec)))*1e9)).UTC()
}

func (f flex) bytes() uint64 {
	v := f.float()
	if v < 0 || v >= 1<<62 {
		return 0
	}
	return uint64(v)
}

func (f flex) truthy() bool { return f == "1" || f == "true" }

type wireHost struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
	// Tags are the IDs of the device groups the host is in: at most one.
	Tags        []flex `json:"tags"`
	Name        string `json:"name"`
	BName       string `json:"bname"`
	DHCPName    string `json:"dhcpName"`
	BonjourName string `json:"bonjourName"`
	Vendor      string `json:"macVendor"`
	LastActive  flex   `json:"lastActive"`
}

type wireFlow struct {
	TS       flex   `json:"ts"`
	FD       string `json:"fd"`
	Count    flex   `json:"count"`
	Protocol string `json:"protocol"`
	IP       string `json:"ip"`
	DeviceIP string `json:"deviceIP"`
	Upload   flex   `json:"upload"`
	Download flex   `json:"download"`
	Device   string `json:"device"`
	Host     string `json:"host"`
	Country  string `json:"country"`
	Category string `json:"category"`
}

type wirePolicy struct {
	PID         flex     `json:"pid"`
	Action      string   `json:"action"`
	Type        string   `json:"type"`
	Target      string   `json:"target"`
	Disabled    flex     `json:"disabled"`
	DNSOnly     flex     `json:"dnsmasq_only"`
	Scope       []string `json:"scope"`
	Tag         []string `json:"tag"`
	Notes       string   `json:"notes"`
	Timestamp   flex     `json:"timestamp"`
	CronTime    string   `json:"cronTime"`
	Duration    flex     `json:"duration"`
	IdleTS      flex     `json:"idleTs"`
	Description string   `json:"description"`
}

// ---- reading ----------------------------------------------------------------

// onlineWithin is how recently a device must have been active to count as
// online. The box has no single "online" flag on a host.
const onlineWithin = 5 * time.Minute

// Devices implements backends.DeviceReader.
func (c *Client) Devices(ctx context.Context) ([]backends.Device, error) {
	var raw struct {
		Hosts []wireHost `json:"hosts"`
	}
	// A host names its group by ID, so the groups are read first to name
	// it. If they cannot be read the devices are still worth having.
	groupName := map[string]string{}
	if groups, err := c.Groups(ctx); err == nil {
		for _, g := range groups {
			groupName[g.ID] = g.Name
		}
	}
	if err := c.call(ctx, "get", "hosts", "", nil, nil, &raw); err != nil {
		return nil, err
	}
	now := c.cfg.Now()
	out := make([]backends.Device, 0, len(raw.Hosts))
	names := make(map[string]string, len(raw.Hosts))
	for _, h := range raw.Hosts {
		d := backends.Device{
			MAC: routerusage.NormalizeMAC(h.MAC), IP: h.IP, Vendor: h.Vendor, Native: h.MAC,
			// name is set only when a person typed one; the rest are what
			// the device or the box worked out.
			Name:     firstNonEmpty(h.Name, h.BName, h.DHCPName, h.BonjourName),
			NameFrom: backends.NameLearned,
		}
		if h.Name != "" {
			d.NameFrom = backends.NameTyped
		}
		if len(h.Tags) > 0 {
			d.Group = groupName[string(h.Tags[0])]
		}
		if t := h.LastActive.time(); !t.IsZero() && now.Sub(t) < onlineWithin {
			d.Online = true
		}
		if d.MAC != "" {
			names[d.MAC] = d.Name
		}
		out = append(out, d)
	}
	c.mu.Lock()
	c.names = names
	c.mu.Unlock()
	return out, nil
}

// flowPage is how many records the box returns per call.
const flowPage = 100

// The box keeps two logs: flows, which are the connections it let
// through, and an audit log, which are the ones it turned away, including
// those that arrived at the WAN port from outside. Flows reads both and
// returns them as one list, newest first.
//
// Each log pages by time: a page's last record tells where the next call
// reads up to. The cursor carries both positions as "flows,audit"; a
// position of "-" means that log has nothing older in the range.
const logDone = "-"

// Flows implements backends.FlowReader.
func (c *Client) Flows(ctx context.Context, fq backends.FlowQuery) (backends.FlowPage, error) {
	ends := [2]string{"", ""}
	if fq.Cursor != "" {
		a, b, ok := strings.Cut(fq.Cursor, ",")
		if !ok || !validLogPos(a) || !validLogPos(b) {
			return backends.FlowPage{}, fmt.Errorf("%w: that is not a page of requests", backends.ErrInvalid)
		}
		ends = [2]string{a, b}
	}
	target := ""
	if fq.DeviceMAC != "" {
		target = macWithColons(fq.DeviceMAC)
		if routerusage.NormalizeMAC(target) == "" {
			return backends.FlowPage{}, fmt.Errorf("%w: that is not a device address", backends.ErrInvalid)
		}
	}
	c.mu.Lock()
	names := c.names
	c.mu.Unlock()

	var out backends.FlowPage
	next := [2]string{logDone, logDone}
	for i, item := range []string{"flows", "auditLogs"} {
		if ends[i] == logDone {
			continue
		}
		q := url.Values{}
		if !fq.From.IsZero() {
			q.Set("start", strconv.FormatInt(fq.From.Unix(), 10))
		}
		end := fq.To
		if ends[i] != "" {
			sec, _ := strconv.ParseFloat(ends[i], 64)
			end = time.Unix(int64(sec), 0)
		}
		if !end.IsZero() {
			q.Set("end", strconv.FormatInt(end.Unix(), 10))
		}
		var raw struct {
			Flows  []wireFlow `json:"flows"`
			Logs   []wireFlow `json:"logs"`
			NextTS flex       `json:"nextTs"`
		}
		if err := c.call(ctx, "get", item, target, q, nil, &raw); err != nil {
			// The audit log is worth having, not worth losing the flows over.
			if item == "auditLogs" {
				continue
			}
			return backends.FlowPage{}, err
		}
		records := append(raw.Flows, raw.Logs...)
		for _, f := range records {
			out.Flows = append(out.Flows, toFlow(f, names, item == "auditLogs"))
		}
		// A full page means there may be older records still in the range.
		if n := raw.NextTS.float(); len(records) >= flowPage && n > 0 && (fq.From.IsZero() || n > float64(fq.From.Unix())) {
			next[i] = strconv.FormatFloat(n, 'f', 3, 64)
		}
	}
	sort.SliceStable(out.Flows, func(i, j int) bool { return out.Flows[i].Time.After(out.Flows[j].Time) })
	if next != [2]string{logDone, logDone} {
		out.Next = next[0] + "," + next[1]
	}
	return out, nil
}

func validLogPos(s string) bool {
	if s == logDone {
		return true
	}
	sec, err := strconv.ParseFloat(s, 64)
	return err == nil && sec > 0
}

// toFlow turns one record of either log into a Flow. A record the box
// turned away at the WAN port names the WAN interface where a device would
// be; it has no device.
func toFlow(f wireFlow, names map[string]string, blocked bool) backends.Flow {
	mac := routerusage.NormalizeMAC(f.Device)
	fl := backends.Flow{
		Time: f.TS.time(), DeviceMAC: mac, Device: names[mac], DeviceIP: f.DeviceIP,
		RemoteIP: f.IP, Protocol: f.Protocol,
		// "in" is a connection a device inside opened, which is outbound;
		// "out" is one that came from outside.
		Outbound: f.FD != "out", Blocked: blocked,
		Download: f.Download.bytes(), Upload: f.Upload.bytes(),
		Category: f.Category, Country: f.Country, Count: int(f.Count.float()),
	}
	if f.Host != "" && f.Host != f.IP {
		fl.Domain = strings.ToLower(strings.TrimSuffix(f.Host, "."))
	}
	return fl
}

// Alarms implements backends.AlarmReader. The box returns its active
// alarms, newest first.
func (c *Client) Alarms(ctx context.Context, _ backends.AlarmQuery) (backends.AlarmPage, error) {
	var raw struct {
		Alarms []map[string]flex `json:"alarms"`
	}
	if err := c.call(ctx, "get", "alarms", "", nil, nil, &raw); err != nil {
		return backends.AlarmPage{}, err
	}
	out := backends.AlarmPage{Alarms: make([]backends.Alarm, 0, len(raw.Alarms))}
	for _, a := range raw.Alarms {
		out.Alarms = append(out.Alarms, backends.Alarm{
			ID: string(a["aid"]), Time: firstTime(a["alarmTimestamp"], a["timestamp"]),
			Type: alarmTypeName(string(a["type"])), Message: string(a["message"]),
			Domain:    strings.ToLower(strings.TrimSuffix(string(a["p.dest.name"]), ".")),
			DeviceMAC: routerusage.NormalizeMAC(string(a["p.device.mac"])), Device: string(a["p.device.name"]),
		})
	}
	return out, nil
}

func firstTime(vals ...flex) time.Time {
	for _, v := range vals {
		if t := v.time(); !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// alarmTypeName turns "ALARM_NEW_DEVICE" into "New Device".
func alarmTypeName(s string) string {
	words := strings.Split(strings.ToLower(strings.TrimPrefix(s, "ALARM_")), "_")
	for i, w := range words {
		if w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// targetTypes maps the box's rule types onto the ones the portal names.
var targetTypes = map[string]string{"dns": "domain", "domain": "domain", "country": "region"}

// Rules implements backends.RuleManager.
func (c *Client) Rules(ctx context.Context) ([]backends.Rule, error) {
	var raw struct {
		Policies []wirePolicy `json:"policies"`
	}
	if err := c.call(ctx, "get", "policies", "", nil, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]backends.Rule, 0, len(raw.Policies))
	for _, p := range raw.Policies {
		r := backends.Rule{
			ID: string(p.PID), Action: firstNonEmpty(p.Action, "block"), TargetType: p.Type, Target: p.Target,
			DNSOnly: p.DNSOnly.truthy(), Paused: p.Disabled.truthy(), Notes: firstNonEmpty(p.Notes, p.Description),
			Created: p.Timestamp.time(),
		}
		if t, ok := targetTypes[p.Type]; ok {
			r.TargetType = t
		}
		switch {
		case len(p.Scope) > 0:
			r.ScopeType, r.Scope = "device", p.Scope[0]
			if mac := routerusage.NormalizeMAC(p.Scope[0]); mac != "" {
				r.Scope = mac
			}
		case len(p.Tag) > 0:
			kind, value, _ := strings.Cut(p.Tag[0], ":")
			r.ScopeType, r.Scope = "group", value
			if kind == "intf" {
				r.ScopeType = "network"
			}
		}
		if p.CronTime != "" {
			r.Schedule = fmt.Sprintf("%s for %d min", p.CronTime, int(p.Duration.float()/60))
		}
		if r.Paused {
			r.ResumeAt = p.IdleTS.time()
		}
		out = append(out, r)
	}
	return out, nil
}

// ---- writing ----------------------------------------------------------------

// SetRulePaused implements backends.RuleManager.
func (c *Client) SetRulePaused(ctx context.Context, id string, paused bool) error {
	if err := c.writable(); err != nil {
		return err
	}
	if err := validID(id); err != nil {
		return err
	}
	item := "policy:enable"
	if paused {
		item = "policy:disable"
	}
	return c.call(ctx, "cmd", item, "", nil, map[string]string{"policyID": id}, nil)
}

// DeleteRule implements backends.RuleManager.
func (c *Client) DeleteRule(ctx context.Context, id string) error {
	if err := c.writable(); err != nil {
		return err
	}
	if err := validID(id); err != nil {
		return err
	}
	return c.call(ctx, "cmd", "policy:delete", "", nil, map[string]string{"policyID": id}, nil)
}

// RenameDevice implements backends.DeviceRenamer.
func (c *Client) RenameDevice(ctx context.Context, d backends.DeviceRef, name string) error {
	if err := c.writable(); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > MaxNameLen {
		return fmt.Errorf("%w: a device name is 1 to %d characters", backends.ErrInvalid, MaxNameLen)
	}
	mac := macWithColons(d.Native)
	if routerusage.NormalizeMAC(mac) == "" {
		return fmt.Errorf("%w: the device is not identified", backends.ErrInvalid)
	}
	return c.call(ctx, "set", "host", mac, nil, map[string]string{"name": name}, nil)
}

// MaxNameLen is the longest device name this sends. The box sets no limit
// of its own; this keeps a name within what its app shows.
const MaxNameLen = 64

// Groups implements backends.GroupManager. The box calls a device group a
// tag.
func (c *Client) Groups(ctx context.Context) ([]backends.Group, error) {
	var raw struct {
		Tags map[string]struct {
			UID  flex   `json:"uid"`
			Name string `json:"name"`
		} `json:"tags"`
	}
	if err := c.call(ctx, "get", "tags", "", nil, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]backends.Group, 0, len(raw.Tags))
	for id, t := range raw.Tags {
		out = append(out, backends.Group{ID: firstNonEmpty(string(t.UID), id), Name: t.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// MaxGroupNameLen is the longest group name this sends.
const MaxGroupNameLen = 64

// CreateGroup implements backends.GroupManager. The box returns the
// existing group when one already has the name.
func (c *Client) CreateGroup(ctx context.Context, name string) (backends.Group, error) {
	if err := c.writable(); err != nil {
		return backends.Group{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > MaxGroupNameLen {
		return backends.Group{}, fmt.Errorf("%w: a group name is 1 to %d characters", backends.ErrInvalid, MaxGroupNameLen)
	}
	var got struct {
		UID  flex   `json:"uid"`
		Name string `json:"name"`
	}
	if err := c.call(ctx, "cmd", "tag:create", "", nil, map[string]string{"name": name}, &got); err != nil {
		return backends.Group{}, err
	}
	if got.UID == "" {
		return backends.Group{}, fmt.Errorf("%w: the box did not say which group it made", backends.ErrRefused)
	}
	return backends.Group{ID: string(got.UID), Name: firstNonEmpty(got.Name, name)}, nil
}

// SetDeviceGroup implements backends.GroupManager.
func (c *Client) SetDeviceGroup(ctx context.Context, d backends.DeviceRef, groupID string) error {
	if err := c.writable(); err != nil {
		return err
	}
	mac := macWithColons(d.Native)
	if routerusage.NormalizeMAC(mac) == "" {
		return fmt.Errorf("%w: the device is not identified", backends.ErrInvalid)
	}
	tags := []string{}
	if groupID = strings.TrimSpace(groupID); groupID != "" {
		tags = append(tags, groupID)
	}
	return c.callBody(ctx, "set", "policy", mac, map[string]any{"tags": tags}, nil)
}

// DismissAlarm implements backends.AlarmDismisser.
func (c *Client) DismissAlarm(ctx context.Context, a backends.AlarmRef) error {
	if err := c.writable(); err != nil {
		return err
	}
	if strings.TrimSpace(a.ID) == "" {
		return fmt.Errorf("%w: the alarm is not identified", backends.ErrInvalid)
	}
	return c.call(ctx, "cmd", "alarm:delete", "", nil, map[string]string{"alarmID": a.ID}, nil)
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

// macWithColons writes a MAC the way the box does (AA:BB:...), and returns
// anything that is not one unchanged.
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
