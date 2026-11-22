// SPDX-License-Identifier: AGPL-3.0-or-later

package fwlocal

import (
	"context"
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

type call struct {
	Method, Command, Item, Target, Query, Body string
}

// fakeBox answers like a Firewalla's local API.
type fakeBox struct {
	mu      sync.Mutex
	calls   []call
	answers map[string]string // "command item" to the whole response body
	status  int
}

func (f *fakeBox) last() call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func (f *fakeBox) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

var testNow = time.Unix(1795300000, 0)

func newClient(t *testing.T, f *fakeBox, readOnly bool) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q := r.URL.Query()
		f.mu.Lock()
		f.calls = append(f.calls, call{r.Method, q.Get("command"), q.Get("item"), q.Get("target"), r.URL.RawQuery, string(b)})
		status, body := f.status, f.answers[q.Get("command")+" "+q.Get("item")]
		f.mu.Unlock()
		if r.URL.Path != "/v1/encipher/simple" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
		}
		if body == "" {
			body = `{"code":200,"data":{}}`
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, ReadOnly: readOnly, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ok(data string) string { return `{"code":200,"data":` + data + `}` }

func TestTheAddressMustBeLoopback(t *testing.T) {
	for raw, want := range map[string]string{
		"":                        DefaultURL,
		"  http://127.0.0.1:8834": "http://127.0.0.1:8834",
		"http://127.0.0.1:9000/":  "http://127.0.0.1:9000",
		"http://[::1]:8834":       "http://[::1]:8834",
	} {
		if got, err := NormalizeURL(raw); err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{
		"https://127.0.0.1:8834", "http://192.0.2.1:8834", "http://localhost:8834", "http://box.example:8834",
		"http://127.0.0.1", "http://127.0.0.1:8834/v1", "http://127.0.0.1:8834?x=1", "http://127.0.0.1:8834#x",
		"http://user@127.0.0.1:8834", "http://%zz", "127.0.0.1:8834",
	} {
		if _, err := NormalizeURL(raw); !errors.Is(err, ErrBadURL) {
			t.Errorf("NormalizeURL(%q) = %v, want ErrBadURL", raw, err)
		}
		if _, err := New(Config{BaseURL: raw}); !errors.Is(err, ErrBadURL) {
			t.Errorf("New(%q) = %v", raw, err)
		}
	}
	c, err := New(Config{})
	if err != nil || c.base != DefaultURL || c.Name() != "firewalla" || c.ReadOnly() {
		t.Fatalf("default client = %+v, %v", c, err)
	}
	c.SetReadOnly(true)
	if !c.ReadOnly() {
		t.Fatal("SetReadOnly did nothing")
	}
}

func TestDevicesKnowATypedNameFromALearnedOne(t *testing.T) {
	recent := testNow.Add(-time.Minute).Unix()
	f := &fakeBox{answers: map[string]string{"get hosts": ok(fmt.Sprintf(`{"hosts":[
	 {"mac":"02:00:5E:00:00:01","ip":"192.0.2.5","name":"Den TV","bname":"tv-1","macVendor":"ExampleCo","lastActive":%d},
	 {"mac":"02:00:5E:00:00:02","ip":"192.0.2.6","bname":"tablet-1","dhcpName":"tablet","lastActive":"%d.5"},
	 {"mac":"02:00:5E:00:00:03","bonjourName":"Printer","lastActive":null},
	 {"mac":"not-a-mac","dhcpName":"vpn"}]}`, recent, testNow.Add(-time.Hour).Unix()))}}
	c := newClient(t, f, true)
	devs, err := c.Devices(context.Background())
	if err != nil || len(devs) != 4 {
		t.Fatalf("devices = %+v, %v", devs, err)
	}
	a := devs[0]
	if a.MAC != "02005e000001" || a.Name != "Den TV" || a.NameFrom != backends.NameTyped || !a.Online ||
		a.Vendor != "ExampleCo" || a.IP != "192.0.2.5" || a.Ref() != (backends.DeviceRef{Native: "02:00:5E:00:00:01"}) {
		t.Errorf("typed = %+v", a)
	}
	if b := devs[1]; b.Name != "tablet-1" || b.NameFrom != backends.NameLearned || b.Online {
		t.Errorf("learned = %+v", b)
	}
	if devs[2].Name != "Printer" || devs[2].Online || devs[3].MAC != "" {
		t.Errorf("others = %+v", devs[2:])
	}
	if got := f.last(); got.Method != "GET" || got.Command != "get" || got.Item != "hosts" || got.Target != "" {
		t.Errorf("call = %+v", got)
	}
}

func TestFlowsArePagedByTimeAndNamedFromTheDeviceList(t *testing.T) {
	var many []string
	for i := 0; i < flowPage; i++ {
		many = append(many, fmt.Sprintf(`{"ts":%d.25,"fd":"in","count":2,"protocol":"tcp","ip":"198.51.100.7","deviceIP":"192.0.2.5",
		 "upload":"100","download":4000,"device":"02:00:5E:00:00:01","host":"Example.org.","country":"US","category":"av"}`, 1795299990-i))
	}
	f := &fakeBox{answers: map[string]string{
		"get hosts": ok(`{"hosts":[{"mac":"02:00:5E:00:00:01","name":"Den TV"}]}`),
		"get flows": ok(`{"flows":[` + strings.Join(many, ",") + `],"count":100,"nextTs":1795299891.25}`),
	}}
	c := newClient(t, f, true)
	ctx := context.Background()
	if _, err := c.Devices(ctx); err != nil {
		t.Fatal(err)
	}
	from, to := testNow.Add(-10*time.Minute), testNow
	page, err := c.Flows(ctx, backends.FlowQuery{From: from, To: to})
	if err != nil || len(page.Flows) != flowPage || page.Next != "1795299891.250" {
		t.Fatalf("page = %d flows, next %q, %v", len(page.Flows), page.Next, err)
	}
	fl := page.Flows[0]
	if fl.DeviceMAC != "02005e000001" || fl.Device != "Den TV" || fl.Domain != "example.org" || fl.RemoteIP != "198.51.100.7" ||
		!fl.Outbound || fl.Blocked || fl.Download != 4000 || fl.Upload != 100 || fl.Count != 2 || fl.Country != "US" ||
		fl.Category != "av" || fl.Protocol != "tcp" || fl.Time.Unix() != 1795299990 || fl.Time.Nanosecond() == 0 {
		t.Errorf("flow = %+v", fl)
	}
	q, _ := url.ParseQuery(f.last().Query)
	if q.Get("start") != fmt.Sprint(from.Unix()) || q.Get("end") != fmt.Sprint(to.Unix()) || f.last().Target != "" {
		t.Errorf("query = %v", q)
	}

	// The next page reads up to where this one stopped, for one device.
	if _, err := c.Flows(ctx, backends.FlowQuery{From: from, To: to, Cursor: page.Next, DeviceMAC: "02005e000001"}); err != nil {
		t.Fatal(err)
	}
	q, _ = url.ParseQuery(f.last().Query)
	if q.Get("end") != "1795299891" || f.last().Target != "02:00:5E:00:00:01" {
		t.Errorf("second page query = %v, target %q", q, f.last().Target)
	}

	// A short page, or one that has reached the start, is the last.
	f.answers["get flows"] = ok(`{"flows":[{"ts":1795299990,"fd":"out","ip":"198.51.100.7","host":"198.51.100.7","device":"02:00:5E:00:00:09","upload":-5,"download":"x"}],"nextTs":1795299980}`)
	last, err := c.Flows(ctx, backends.FlowQuery{})
	if err != nil || last.Next != "" || len(last.Flows) != 1 {
		t.Fatalf("last page = %+v, %v", last, err)
	}
	if g := last.Flows[0]; g.Outbound || g.Domain != "" || g.Device != "" || g.Upload != 0 || g.Download != 0 {
		t.Errorf("inbound flow = %+v", g)
	}
	if q, _ := url.ParseQuery(f.last().Query); q.Has("start") || q.Has("end") {
		t.Errorf("an unbounded query sent a range: %v", q)
	}
	f.answers["get flows"] = ok(`{"flows":[` + strings.Join(many, ",") + `],"nextTs":` + fmt.Sprint(from.Unix()-1) + `}`)
	if p, _ := c.Flows(ctx, backends.FlowQuery{From: from, To: to}); p.Next != "" {
		t.Errorf("paged past the start of the range: %q", p.Next)
	}

	n := f.count()
	for _, bad := range []backends.FlowQuery{{Cursor: "soon"}, {Cursor: "-1"}, {DeviceMAC: "nope"}} {
		if _, err := c.Flows(ctx, bad); !errors.Is(err, backends.ErrInvalid) {
			t.Errorf("Flows(%+v) = %v", bad, err)
		}
	}
	if f.count() != n {
		t.Fatal("an unusable query was sent")
	}
}

func TestAlarmsAreNamedAndTimed(t *testing.T) {
	f := &fakeBox{answers: map[string]string{"get alarms": ok(`{"alarms":[
	 {"aid":"81","type":"ALARM_NEW_DEVICE","message":"Found a device","alarmTimestamp":"1795299000.5","timestamp":"1","p.device.mac":"02:00:5E:00:00:01","p.device.name":"Den TV","p.intf.subnet6":["2001:db8::/64"],"p.x":{"a":1}},
	 {"aid":82,"type":"ALARM_LARGE_UPLOAD","message":"Uploaded a lot","timestamp":1795299100,"p.dest.name":"Example.org.","p.device.mac":null},
	 {"aid":"83","type":"","message":"odd","timestamp":"\ud800"}]}`)}}
	c := newClient(t, f, true)
	page, err := c.Alarms(context.Background(), backends.AlarmQuery{ActiveOnly: true})
	if err != nil || len(page.Alarms) != 3 {
		t.Fatalf("alarms = %+v, %v", page, err)
	}
	a := page.Alarms[0]
	if a.ID != "81" || a.Type != "New Device" || a.DeviceMAC != "02005e000001" || a.Device != "Den TV" || a.Time.Unix() != 1795299000 || a.Ref().ID != "81" {
		t.Errorf("alarm = %+v", a)
	}
	if b := page.Alarms[1]; b.ID != "82" || b.Type != "Large Upload" || b.Domain != "example.org" || b.Time.Unix() != 1795299100 || b.DeviceMAC != "" {
		t.Errorf("alarm = %+v", b)
	}
	if !page.Alarms[2].Time.IsZero() || page.Alarms[2].Type != "" {
		t.Errorf("alarm = %+v", page.Alarms[2])
	}
}

func TestRulesAreReadWithTheirScopeAndState(t *testing.T) {
	f := &fakeBox{answers: map[string]string{"get policies": ok(`{"policies":[
	 {"pid":"26","action":"block","type":"category","target":"games","dnsmasq_only":true,"disabled":"0","timestamp":"1795290000.3"},
	 {"pid":27,"type":"dns","target":"ads.example","disabled":"1","idleTs":"1795390000","scope":["02:00:5E:00:00:01"],"notes":"mine"},
	 {"pid":"28","action":"allow","type":"country","target":"CA","tag":["tag:3"],"cronTime":"0 21 * * *","duration":"3600","description":"evenings"},
	 {"pid":"29","action":"qos","type":"net","target":"203.0.113.0/24","tag":["intf:lan"],"scope":["office-vpn"],"dnsmasq_only":"false"}]}`)}}
	c := newClient(t, f, true)
	rules, err := c.Rules(context.Background())
	if err != nil || len(rules) != 4 {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	if r := rules[0]; r.ID != "26" || r.Action != "block" || r.TargetType != "category" || !r.DNSOnly || r.Paused || r.ScopeType != "" || r.Created.Unix() != 1795290000 {
		t.Errorf("rule = %+v", r)
	}
	if r := rules[1]; r.ID != "27" || r.Action != "block" || r.TargetType != "domain" || !r.Paused || r.ResumeAt.Unix() != 1795390000 ||
		r.ScopeType != "device" || r.Scope != "02005e000001" || r.Notes != "mine" {
		t.Errorf("rule = %+v", r)
	}
	if r := rules[2]; r.TargetType != "region" || r.ScopeType != "group" || r.Scope != "3" || r.Schedule != "0 21 * * * for 60 min" || r.Notes != "evenings" {
		t.Errorf("rule = %+v", r)
	}
	if r := rules[3]; r.Action != "qos" || r.TargetType != "net" || r.ScopeType != "device" || r.Scope != "office-vpn" || r.DNSOnly {
		t.Errorf("rule = %+v", r)
	}
	f.answers["get policies"] = ok(`{"policies":[{"pid":"30","type":"ip","target":"203.0.113.9","tag":["intf:lan"]}]}`)
	if rules, _ := c.Rules(context.Background()); rules[0].ScopeType != "network" || rules[0].Scope != "lan" {
		t.Errorf("network rule = %+v", rules[0])
	}
}

func TestWritesSendTheBoxesOwnCommands(t *testing.T) {
	f := &fakeBox{}
	c := newClient(t, f, false)
	ctx := context.Background()
	steps := []struct {
		do   func() error
		want call
	}{
		{func() error { return c.SetRulePaused(ctx, "26", true) }, call{Method: "POST", Command: "cmd", Item: "policy:disable", Body: `{"policyID":"26"}`}},
		{func() error { return c.SetRulePaused(ctx, "26", false) }, call{Method: "POST", Command: "cmd", Item: "policy:enable", Body: `{"policyID":"26"}`}},
		{func() error { return c.DeleteRule(ctx, "26") }, call{Method: "POST", Command: "cmd", Item: "policy:delete", Body: `{"policyID":"26"}`}},
		{func() error { return c.RenameDevice(ctx, backends.DeviceRef{Native: "02005e000001"}, "  Den TV ") },
			call{Method: "POST", Command: "set", Item: "host", Target: "02:00:5E:00:00:01", Body: `{"name":"Den TV"}`}},
		{func() error { return c.DismissAlarm(ctx, backends.AlarmRef{ID: "81"}) }, call{Method: "POST", Command: "cmd", Item: "alarm:delete", Body: `{"alarmID":"81"}`}},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			t.Fatalf("%s: %v", s.want.Item, err)
		}
		got := f.last()
		got.Query = ""
		if got != s.want {
			t.Errorf("sent %+v, want %+v", got, s.want)
		}
	}

	n := f.count()
	for name, err := range map[string]error{
		"pause no id":   c.SetRulePaused(ctx, " ", true),
		"delete no id":  c.DeleteRule(ctx, ""),
		"rename empty":  c.RenameDevice(ctx, backends.DeviceRef{Native: "02005e000001"}, " "),
		"rename long":   c.RenameDevice(ctx, backends.DeviceRef{Native: "02005e000001"}, strings.Repeat("x", MaxNameLen+1)),
		"rename no mac": c.RenameDevice(ctx, backends.DeviceRef{Native: "vpn"}, "Den TV"),
		"dismiss no id": c.DismissAlarm(ctx, backends.AlarmRef{}),
	} {
		if !errors.Is(err, backends.ErrInvalid) {
			t.Errorf("%s = %v", name, err)
		}
	}
	c.SetReadOnly(true)
	for name, err := range map[string]error{
		"pause":   c.SetRulePaused(ctx, "26", true),
		"delete":  c.DeleteRule(ctx, "26"),
		"rename":  c.RenameDevice(ctx, backends.DeviceRef{Native: "02005e000001"}, "Den TV"),
		"dismiss": c.DismissAlarm(ctx, backends.AlarmRef{ID: "81"}),
	} {
		if !errors.Is(err, backends.ErrReadOnly) {
			t.Errorf("%s while read-only = %v", name, err)
		}
	}
	if f.count() != n {
		t.Fatal("a refused write was sent")
	}
}

func TestFailuresAreMappedAndNeverHang(t *testing.T) {
	f := &fakeBox{}
	c := newClient(t, f, false)
	ctx := context.Background()

	f.answers = map[string]string{"get hosts": `{"code":500,"data":{},"message":"Error: Unsupported get action: hosts"}`}
	f.status = 500
	if _, err := c.Devices(ctx); !errors.Is(err, backends.ErrRefused) || !strings.HasSuffix(err.Error(), "Unsupported get action: hosts") {
		t.Fatalf("refused = %v", err)
	}
	f.answers = map[string]string{"cmd policy:delete": `{"code":404,"msg":"Policy not found"}`}
	f.status = 0
	if err := c.DeleteRule(ctx, "99"); !errors.Is(err, backends.ErrNotFound) {
		t.Fatalf("not found = %v", err)
	}
	f.answers = map[string]string{"get policies": `{"error":"boom","stack":"..."}`}
	f.status = 502
	if _, err := c.Rules(ctx); !errors.Is(err, backends.ErrRefused) || !strings.HasSuffix(err.Error(), "boom") {
		t.Fatalf("express error = %v", err)
	}
	f.answers = map[string]string{"get alarms": `<html>`}
	f.status = 503
	if _, err := c.Alarms(ctx, backends.AlarmQuery{}); !errors.Is(err, backends.ErrRefused) || !strings.HasSuffix(err.Error(), "HTTP 503") {
		t.Fatalf("not json, failed = %v", err)
	}
	f.status = 0
	if _, err := c.Alarms(ctx, backends.AlarmQuery{}); err == nil || !strings.Contains(err.Error(), "something unexpected") {
		t.Fatalf("not json, 200 = %v", err)
	}
	f.answers = map[string]string{"get flows": ok(`{"flows":"none"}`)}
	if _, err := c.Flows(ctx, backends.FlowQuery{}); err == nil || !strings.Contains(err.Error(), "something unexpected") {
		t.Fatalf("wrong shape = %v", err)
	}
	// An answer with no data is fine for a call that wants none back.
	f.answers = map[string]string{"cmd alarm:delete": `{"code":200}`}
	if err := c.DismissAlarm(ctx, backends.AlarmRef{ID: "81"}); err != nil {
		t.Fatal(err)
	}

	dead, _ := New(Config{BaseURL: "http://127.0.0.1:1", Timeout: time.Second})
	if _, err := dead.Devices(ctx); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("nothing listening = %v", err)
	}
	gone, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.Devices(gone); err == nil {
		t.Fatal("a cancelled call succeeded")
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.1/", http.StatusFound)
	}))
	defer redirect.Close()
	rc, _ := New(Config{BaseURL: redirect.URL})
	if _, err := rc.Devices(ctx); err == nil {
		t.Fatal("a redirect was followed")
	}
	bad, _ := New(Config{Transport: rtFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("plain") })})
	if _, err := bad.Devices(ctx); err == nil {
		t.Fatal("a transport failure was hidden")
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSmallHelpers(t *testing.T) {
	if alarmTypeName("ALARM_BRO_NOTICE") != "Bro Notice" || alarmTypeName("ALARM__X") != " X" {
		t.Errorf("alarmTypeName: %q %q", alarmTypeName("ALARM_BRO_NOTICE"), alarmTypeName("ALARM__X"))
	}
	if macWithColons("vpn") != "vpn" || macWithColons("02-00-5e-00-00-01") != "02:00:5E:00:00:01" {
		t.Error("macWithColons")
	}
	if flex("9e99").bytes() != 0 || flex("12").bytes() != 12 || !flex("true").truthy() || flex("0").truthy() {
		t.Error("flex")
	}
}

func TestGroupsAreListedCreatedAndAssigned(t *testing.T) {
	f := &fakeBox{answers: map[string]string{
		"get tags":       ok(`{"tags":{"18":{"uid":"18","name":"Smart Home"},"16":{"uid":16,"name":"Networking"},"20":{"name":"No uid"}}}`),
		"get hosts":      ok(`{"hosts":[{"mac":"02:00:5E:00:00:01","name":"Den TV","tags":["18"]},{"mac":"02:00:5E:00:00:02","bname":"tablet","tags":[]},{"mac":"02:00:5E:00:00:03","tags":[99]}]}`),
		"cmd tag:create": ok(`{"uid":"21","name":"Kids","createTs":1}`),
	}}
	c := newClient(t, f, false)
	ctx := context.Background()

	groups, err := c.Groups(ctx)
	if err != nil || len(groups) != 3 {
		t.Fatalf("groups = %+v, %v", groups, err)
	}
	want := []backends.Group{{ID: "16", Name: "Networking"}, {ID: "20", Name: "No uid"}, {ID: "18", Name: "Smart Home"}}
	for i := range want {
		if groups[i] != want[i] {
			t.Errorf("groups[%d] = %+v, want %+v", i, groups[i], want[i])
		}
	}

	devs, err := c.Devices(ctx)
	if err != nil || devs[0].Group != "Smart Home" || devs[1].Group != "" || devs[2].Group != "" {
		t.Fatalf("devices = %+v, %v", devs, err)
	}

	g, err := c.CreateGroup(ctx, "  Kids ")
	if err != nil || g != (backends.Group{ID: "21", Name: "Kids"}) {
		t.Fatalf("CreateGroup = %+v, %v", g, err)
	}
	if got := f.last(); got.Method != "POST" || got.Command != "cmd" || got.Item != "tag:create" || got.Body != `{"name":"Kids"}` {
		t.Errorf("create sent %+v", got)
	}

	ref := backends.DeviceRef{Native: "02005e000002"}
	if err := c.SetDeviceGroup(ctx, ref, " 21 "); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got.Command != "set" || got.Item != "policy" || got.Target != "02:00:5E:00:00:02" || got.Body != `{"tags":["21"]}` {
		t.Errorf("assign sent %+v", got)
	}
	if err := c.SetDeviceGroup(ctx, ref, ""); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got.Body != `{"tags":[]}` {
		t.Errorf("removal sent %+v", got)
	}

	n := f.count()
	for name, err := range map[string]error{
		"create empty":  second(c.CreateGroup(ctx, " ")),
		"create long":   second(c.CreateGroup(ctx, strings.Repeat("x", MaxGroupNameLen+1))),
		"assign no mac": c.SetDeviceGroup(ctx, backends.DeviceRef{Native: "vpn"}, "21"),
	} {
		if !errors.Is(err, backends.ErrInvalid) {
			t.Errorf("%s = %v", name, err)
		}
	}
	c.SetReadOnly(true)
	if _, err := c.CreateGroup(ctx, "Kids"); !errors.Is(err, backends.ErrReadOnly) {
		t.Errorf("create while read-only = %v", err)
	}
	if err := c.SetDeviceGroup(ctx, ref, "21"); !errors.Is(err, backends.ErrReadOnly) {
		t.Errorf("assign while read-only = %v", err)
	}
	if f.count() != n {
		t.Fatal("a refused group change was sent")
	}
	c.SetReadOnly(false)

	// A box that does not say which group it made, or refuses, is an error;
	// groups that cannot be read still leave the devices listed.
	f.answers["cmd tag:create"] = ok(`{}`)
	if _, err := c.CreateGroup(ctx, "Kids"); !errors.Is(err, backends.ErrRefused) {
		t.Errorf("no uid = %v", err)
	}
	f.answers["cmd tag:create"] = `{"code":400,"message":"'name' is not specified."}`
	if _, err := c.CreateGroup(ctx, "Kids"); !errors.Is(err, backends.ErrRefused) {
		t.Errorf("refused = %v", err)
	}
	f.answers["get tags"] = `{"code":500,"message":"boom"}`
	if _, err := c.Groups(ctx); !errors.Is(err, backends.ErrRefused) {
		t.Errorf("groups refused = %v", err)
	}
	if devs, err := c.Devices(ctx); err != nil || len(devs) != 3 || devs[0].Group != "" {
		t.Fatalf("devices without groups = %+v, %v", devs, err)
	}
}

func second[T any](_ T, err error) error { return err }
