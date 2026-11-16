// SPDX-License-Identifier: AGPL-3.0-or-later

package firewalla

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"shepherd/internal/backends"
)

// call is one request the fake MSP received.
type call struct {
	Method, Path, RawQuery, Auth, Body string
}

type fakeMSP struct {
	mu    sync.Mutex
	token string
	calls []call
	// answers maps "METHOD /path" to the body served; status overrides it.
	answers map[string]string
	status  int
}

func (f *fakeMSP) last() call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func (f *fakeMSP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newClient(t *testing.T, f *fakeMSP, mutate func(*Config)) *Client {
	t.Helper()
	if f.token == "" {
		f.token = "tok"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, call{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), string(b)})
		status, body := f.status, f.answers[r.Method+" "+r.URL.Path]
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Token "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	cfg := Config{BaseURL: "home.firewalla.net", Token: f.token, Transport: rt(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type rt func(*http.Request) (*http.Response, error)

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var ctx = context.Background()

func TestDevicesAreNormalizedAndCarryWhatARenameNeeds(t *testing.T) {
	f := &fakeMSP{answers: map[string]string{"GET /v2/devices": `[
	 {"id":"02:00:5E:00:00:01","gid":"box-1","name":"TV","ip":"192.0.2.5","macVendor":"Acme","online":true,
	  "network":{"id":"n","name":"Home"},"group":{"id":"1","name":"Kids"},"totalDownload":"90","totalUpload":10},
	 {"id":"vpn-1","gid":"box-1","name":"VPN"}]`}}
	c := newClient(t, f, func(c *Config) { c.Box = "box-1" })
	got, err := c.Devices(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v, %v", got, err)
	}
	tv := got[0]
	if tv.MAC != "02005e000001" || tv.Name != "TV" || tv.Group != "Kids" || tv.Network != "Home" ||
		!tv.Online || tv.Download != 90 || tv.Upload != 10 || tv.Vendor != "Acme" {
		t.Fatalf("tv = %+v", tv)
	}
	if tv.Ref() != (backends.DeviceRef{Box: "box-1", Native: "02:00:5E:00:00:01"}) {
		t.Fatalf("ref = %+v", tv.Ref())
	}
	if got[1].MAC != "" {
		t.Fatalf("a VPN profile has no MAC: %+v", got[1])
	}
	if l := f.last(); l.Auth != "Token tok" || l.RawQuery != "box=box-1" {
		t.Fatalf("request = %+v", l)
	}
}

func TestFlowsBecomeRequestsAndPageByCursor(t *testing.T) {
	f := &fakeMSP{answers: map[string]string{"GET /v2/flows": `{"count":2,"next_cursor":"c2","results":[
	 {"ts":1700000000.5,"gid":"box-1","protocol":"tcp","direction":"outbound","block":false,"download":1000,"upload":"500",
	  "category":"video","region":"US","device":{"id":"02:00:5E:00:00:01","ip":"192.0.2.5","name":"TV"},
	  "destination":{"id":"example.com","ip":"198.51.100.7","name":"Example.COM."}},
	 {"ts":1700000001,"block":true,"device":{"id":"02:00:5E:00:00:02"},"destination":{"ip":"203.0.113.9","name":"203.0.113.9"}}]}`}}
	c := newClient(t, f, nil)
	from := time.Unix(1699990000, 0)
	page, err := c.Flows(ctx, backends.FlowQuery{From: from, To: time.Unix(1700000100, 0), Limit: 9999, Cursor: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(f.last().RawQuery)
	if q.Get("query") != "ts:1699990000-1700000100" || q.Get("limit") != "500" || q.Get("cursor") != "c1" {
		t.Fatalf("query = %v", q)
	}
	if page.Next != "c2" || len(page.Flows) != 2 {
		t.Fatalf("page = %+v", page)
	}
	a, b := page.Flows[0], page.Flows[1]
	if a.DeviceMAC != "02005e000001" || a.Domain != "example.com" || a.RemoteIP != "198.51.100.7" ||
		!a.Outbound || a.Blocked || a.Download != 1000 || a.Upload != 500 || a.Category != "video" ||
		a.Country != "US" || a.Box != "box-1" || a.Time.Unix() != 1700000000 {
		t.Fatalf("a = %+v", a)
	}
	// A destination MSP names only by address has no domain.
	if b.Domain != "" || b.RemoteIP != "203.0.113.9" || !b.Blocked {
		t.Fatalf("b = %+v", b)
	}
}

func TestAlarmsReadAndActiveOnlyIsAskedFor(t *testing.T) {
	f := &fakeMSP{answers: map[string]string{"GET /v2/alarms": `{"count":1,"next_cursor":null,"results":[
	 {"aid":7,"type":5,"message":"Found a new device","ts":1664522841.9,"gid":"box-1",
	  "device":{"id":"02:00:5E:00:00:03","name":"Phone"}}]}`}}
	c := newClient(t, f, func(c *Config) { c.Box = "box-1" })
	page, err := c.Alarms(ctx, backends.AlarmQuery{ActiveOnly: true, Limit: 10})
	if err != nil || len(page.Alarms) != 1 || page.Next != "" {
		t.Fatalf("%+v, %v", page, err)
	}
	q, _ := url.ParseQuery(f.last().RawQuery)
	if q.Get("query") != "status:active box:box-1" || q.Get("limit") != "10" {
		t.Fatalf("query = %v", q)
	}
	al := page.Alarms[0]
	if al.ID != "7" || al.Type != "5" || al.DeviceMAC != "02005e000003" || al.Ref() != (backends.AlarmRef{Box: "box-1", ID: "7"}) {
		t.Fatalf("alarm = %+v", al)
	}
}

func TestRulesReadWithPausedState(t *testing.T) {
	f := &fakeMSP{answers: map[string]string{"GET /v2/rules": `{"count":2,"results":[
	 {"id":"r1","action":"block","gid":"box-1","status":"active","ts":1730447709.7,
	  "target":{"type":"domain","value":"example.com","dnsOnly":true},"scope":{"type":"device","value":"02:00:5E:00:00:01"}},
	 {"id":"r2","action":"allow","gid":"box-1","status":"paused","notes":"n","target":{"type":"ip","value":"198.51.100.1"}}]}`}}
	c := newClient(t, f, func(c *Config) { c.Box = "box-1" })
	rules, err := c.Rules(ctx)
	if err != nil || len(rules) != 2 {
		t.Fatalf("%+v, %v", rules, err)
	}
	if f.last().RawQuery != "query=box.id%3Abox-1" {
		t.Fatalf("query = %q", f.last().RawQuery)
	}
	r1, r2 := rules[0], rules[1]
	if r1.Paused || r1.ScopeType != "device" || r1.Scope != "02005e000001" || r1.Target != "example.com" {
		t.Fatalf("r1 = %+v", r1)
	}
	if !r2.Paused || r2.ScopeType != "" || r2.Notes != "n" {
		t.Fatalf("r2 = %+v", r2)
	}
}

func TestCreatingARuleSendsWhatMSPDocuments(t *testing.T) {
	f := &fakeMSP{answers: map[string]string{"POST /v2/rules": `{"id":"new","action":"block","gid":"box-1","status":"active","target":{"type":"domain","value":"example.com"}}`}}
	c := newClient(t, f, nil)
	rule, err := c.CreateRule(ctx, backends.RuleSpec{
		Action: "block", TargetType: "domain", Target: " example.com ", DNSOnly: true,
		ScopeType: "device", Scope: "02005e000001", Notes: "from Shepherd", Box: "box-1",
	})
	if err != nil || rule.ID != "new" {
		t.Fatalf("%+v, %v", rule, err)
	}
	l := f.last()
	if l.Method != "POST" || l.Path != "/v2/rules" {
		t.Fatalf("call = %+v", l)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(l.Body), &sent); err != nil {
		t.Fatal(err)
	}
	target := sent["target"].(map[string]any)
	scope := sent["scope"].(map[string]any)
	if sent["action"] != "block" || sent["gid"] != "box-1" || sent["direction"] != "bidirection" || sent["notes"] != "from Shepherd" ||
		target["type"] != "domain" || target["value"] != "example.com" || target["dnsOnly"] != true ||
		scope["type"] != "device" || scope["value"] != "02:00:5E:00:00:01" {
		t.Fatalf("body = %s", l.Body)
	}
}

func TestANetworkWideRuleHasNoScopeAndNeedsABox(t *testing.T) {
	f := &fakeMSP{answers: map[string]string{"POST /v2/rules": `{"id":"x"}`}}
	c := newClient(t, f, func(c *Config) { c.Box = "box-1" })
	if _, err := c.CreateRule(ctx, backends.RuleSpec{Action: "allow", TargetType: "ip", Target: "198.51.100.1"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.last().Body, `"scope"`) {
		t.Fatalf("a network-wide rule carried a scope: %s", f.last().Body)
	}
	// dnsOnly means nothing for an IP target and is not sent.
	if strings.Contains(f.last().Body, "dnsOnly") {
		t.Fatalf("body = %s", f.last().Body)
	}

	// With no box configured, one must be named: MSP cannot guess.
	c2 := newClient(t, &fakeMSP{}, nil)
	_, err := c2.CreateRule(ctx, backends.RuleSpec{Action: "block", TargetType: "domain", Target: "a.example"})
	if !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestPauseResumeAndDeleteHitTheDocumentedRoutes(t *testing.T) {
	f := &fakeMSP{}
	c := newClient(t, f, nil)
	if err := c.SetRulePaused(ctx, "r/1", true); err != nil {
		t.Fatal(err)
	}
	if l := f.last(); l.Method != "POST" || l.Path != "/v2/rules/r/1/pause" {
		t.Fatalf("pause = %+v", l)
	}
	if err := c.SetRulePaused(ctx, "r1", false); err != nil {
		t.Fatal(err)
	}
	if l := f.last(); l.Method != "POST" || l.Path != "/v2/rules/r1/resume" {
		t.Fatalf("resume = %+v", l)
	}
	if err := c.DeleteRule(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if l := f.last(); l.Method != "DELETE" || l.Path != "/v2/rules/r1" {
		t.Fatalf("delete = %+v", l)
	}
	if err := c.DeleteRule(ctx, " "); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("blank id: %v", err)
	}
}

func TestRenameAndDismissHitTheDocumentedRoutes(t *testing.T) {
	f := &fakeMSP{}
	c := newClient(t, f, nil)
	if err := c.RenameDevice(ctx, backends.DeviceRef{Box: "box-1", Native: "02:00:5E:00:00:01"}, " Living room TV "); err != nil {
		t.Fatal(err)
	}
	l := f.last()
	if l.Method != "PATCH" || l.Path != "/v2/boxes/box-1/devices/02:00:5E:00:00:01" || l.Body != `{"name":"Living room TV"}` {
		t.Fatalf("rename = %+v", l)
	}
	for name, n := range map[string]string{"empty": " ", "long": strings.Repeat("x", 33)} {
		if err := c.RenameDevice(ctx, backends.DeviceRef{Box: "b", Native: "d"}, n); !errors.Is(err, backends.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := c.RenameDevice(ctx, backends.DeviceRef{}, "x"); !errors.Is(err, backends.ErrInvalid) {
		t.Errorf("unidentified: %v", err)
	}
	if err := c.DismissAlarm(ctx, backends.AlarmRef{Box: "box-1", ID: "7"}); err != nil {
		t.Fatal(err)
	}
	if l := f.last(); l.Method != "DELETE" || l.Path != "/v2/alarms/box-1/7" {
		t.Fatalf("dismiss = %+v", l)
	}
	if err := c.DismissAlarm(ctx, backends.AlarmRef{}); !errors.Is(err, backends.ErrInvalid) {
		t.Errorf("unidentified alarm: %v", err)
	}
}

func TestAReadOnlyTokenNeverSendsAWrite(t *testing.T) {
	f := &fakeMSP{}
	c := newClient(t, f, func(c *Config) { c.ReadOnly = true; c.Box = "box-1" })
	spec := backends.RuleSpec{Action: "block", TargetType: "domain", Target: "example.com"}
	errs := []error{
		c.SetRulePaused(ctx, "r", true), c.DeleteRule(ctx, "r"),
		c.RenameDevice(ctx, backends.DeviceRef{Box: "b", Native: "d"}, "n"),
		c.DismissAlarm(ctx, backends.AlarmRef{Box: "b", ID: "1"}),
	}
	_, e := c.CreateRule(ctx, spec)
	errs = append(errs, e)
	for i, err := range errs {
		if !errors.Is(err, backends.ErrReadOnly) {
			t.Errorf("write %d: %v, want ErrReadOnly", i, err)
		}
	}
	if f.count() != 0 {
		t.Fatalf("%d requests left the machine for a read-only token", f.count())
	}
	for _, cap := range backends.Capabilities(c) {
		if cap == backends.CapRuleWrite || cap == backends.CapDeviceRename || cap == backends.CapAlarmDismiss {
			t.Fatalf("a read-only token advertises %s", cap)
		}
	}
}

func TestAFullAccessTokenAdvertisesEverything(t *testing.T) {
	c := newClient(t, &fakeMSP{}, nil)
	if got := backends.Capabilities(c); len(got) != 7 {
		t.Fatalf("capabilities = %v", got)
	}
}

func TestStatusCodesMapOntoBackendErrors(t *testing.T) {
	for status, want := range map[int]error{
		401: backends.ErrAuth, 403: backends.ErrAuth, 404: backends.ErrNotFound,
		429: backends.ErrRateLimited, 500: backends.ErrRefused,
	} {
		c := newClient(t, &fakeMSP{status: status}, nil)
		if _, err := c.Devices(ctx); !errors.Is(err, want) {
			t.Errorf("HTTP %d: %v, want %v", status, err, want)
		}
	}
	c := newClient(t, &fakeMSP{token: "good"}, func(c *Config) { c.Token = "bad" })
	if _, err := c.Devices(ctx); !errors.Is(err, backends.ErrAuth) {
		t.Errorf("bad token: %v", err)
	}
	c = newClient(t, &fakeMSP{answers: map[string]string{"GET /v2/devices": `{"not":"a list"}`}}, nil)
	if _, err := c.Devices(ctx); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Errorf("wrong shape: %v", err)
	}
}

func TestOnlyFirewallaNetIsEverContacted(t *testing.T) {
	for _, in := range []string{"https://evil.example.com", "http://home.firewalla.net", ""} {
		if _, err := New(Config{BaseURL: in, Token: "t"}); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
	if _, err := New(Config{BaseURL: "home.firewalla.net"}); err == nil {
		t.Error("a missing token was accepted")
	}
}

func TestNamesAndRefsAreStable(t *testing.T) {
	c := newClient(t, &fakeMSP{}, nil)
	if c.Name() != "firewalla" || c.ReadOnly() {
		t.Fatalf("%q read-only %v", c.Name(), c.ReadOnly())
	}
}

func TestUnreadableOrOutOfRangeFiguresAreZeroNotFailures(t *testing.T) {
	f := &fakeMSP{answers: map[string]string{"GET /v2/devices": `[
	 {"id":"02:00:5E:00:00:01","totalDownload":"lots","totalUpload":-5},
	 {"id":"02:00:5E:00:00:02","totalDownload":1e30,"totalUpload":null}]`}}
	got, err := newClient(t, f, nil).Devices(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v, %v", got, err)
	}
	for _, d := range got {
		if d.Download != 0 || d.Upload != 0 {
			t.Fatalf("%+v", d)
		}
	}
}

func TestFlowsWithoutARangeAskForTheProductDefaultAndTheBox(t *testing.T) {
	f := &fakeMSP{answers: map[string]string{"GET /v2/flows": `{"results":[]}`}}
	c := newClient(t, f, func(c *Config) { c.Box = "box-1" })
	if _, err := c.Flows(ctx, backends.FlowQuery{}); err != nil {
		t.Fatal(err)
	}
	if q, _ := url.ParseQuery(f.last().RawQuery); q.Get("query") != "box:box-1" || q.Get("limit") != "" {
		t.Fatalf("query = %v", q)
	}
	// An open-ended range runs to now.
	if _, err := newClient(t, f, nil).Flows(ctx, backends.FlowQuery{From: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if q, _ := url.ParseQuery(f.last().RawQuery); !strings.HasPrefix(q.Get("query"), "ts:") {
		t.Fatalf("query = %v", q)
	}
}

func TestReadFailuresAreReportedForEveryResource(t *testing.T) {
	c := newClient(t, &fakeMSP{status: 500}, nil)
	if _, err := c.Flows(ctx, backends.FlowQuery{}); !errors.Is(err, backends.ErrRefused) {
		t.Errorf("flows: %v", err)
	}
	if _, err := c.Alarms(ctx, backends.AlarmQuery{}); !errors.Is(err, backends.ErrRefused) {
		t.Errorf("alarms: %v", err)
	}
	if _, err := c.Rules(ctx); !errors.Is(err, backends.ErrRefused) {
		t.Errorf("rules: %v", err)
	}
	if _, err := c.CreateRule(ctx, backends.RuleSpec{Action: "block", TargetType: "domain", Target: "a.example", Box: "b"}); !errors.Is(err, backends.ErrRefused) {
		t.Errorf("create: %v", err)
	}
	if err := c.DeleteRule(ctx, "r"); !errors.Is(err, backends.ErrRefused) {
		t.Errorf("delete: %v", err)
	}
}

func TestAnInvalidRuleOrIDIsRefusedBeforeAnyRequest(t *testing.T) {
	f := &fakeMSP{}
	c := newClient(t, f, nil)
	if _, err := c.CreateRule(ctx, backends.RuleSpec{Action: "drop"}); !errors.Is(err, backends.ErrInvalid) {
		t.Errorf("create: %v", err)
	}
	if err := c.SetRulePaused(ctx, "", true); !errors.Is(err, backends.ErrInvalid) {
		t.Errorf("pause: %v", err)
	}
	if f.count() != 0 {
		t.Fatalf("%d requests were sent", f.count())
	}
}

func TestATransportFailureIsReadableAndAContextEndsIt(t *testing.T) {
	c, err := New(Config{BaseURL: "home.firewalla.net", Token: "t", Transport: rt(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Devices(ctx)
	if err == nil || !strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "Token") {
		t.Fatalf("err = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := newClient(t, &fakeMSP{}, nil).Devices(cancelled); err == nil {
		t.Fatal("a cancelled context must fail")
	}
}

func TestNewDefaultsAndRefusesRedirects(t *testing.T) {
	c, err := New(Config{BaseURL: "home.firewalla.net", Token: " t "})
	if err != nil || c.cfg.Token != "t" || c.cfg.Timeout <= 0 {
		t.Fatalf("%+v, %v", c, err)
	}
	if err := c.hc.CheckRedirect(nil, nil); err == nil {
		t.Fatal("redirects must be refused")
	}
}

func TestMACsAreWrittenTheWayMSPWritesThem(t *testing.T) {
	if got := macWithColons("02005e000001"); got != "02:00:5E:00:00:01" {
		t.Fatalf("got %q", got)
	}
	if got := macWithColons("not-a-mac"); got != "not-a-mac" {
		t.Fatalf("got %q", got)
	}
}
