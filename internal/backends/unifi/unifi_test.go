// SPDX-License-Identifier: AGPL-3.0-or-later

package unifi

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

	"shepherd/internal/backends"
)

var ctx = context.Background()

type call struct{ Method, Path, RawQuery, Body string }

// fakeConsole is a UniFi console: sites, clients, devices and policies,
// answered under the prefix a UniFi OS console or a self-hosted
// application would use.
type fakeConsole struct {
	mu      sync.Mutex
	prefix  string
	key     string
	calls   []call
	status  map[string]int // "METHOD /path" -> status override
	clients int            // how many client records to serve
	policy  string         // body served for a single policy
}

func (f *fakeConsole) last() call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func (f *fakeConsole) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.Method == method {
			n++
		}
	}
	return n
}

const siteID = "88f7af54-98f8-306a-a1c7-c9349722b1f6"

func (f *fakeConsole) client(t *testing.T, mutate func(*Config)) *Client {
	t.Helper()
	if f.prefix == "" {
		f.prefix = "/proxy/network/integration"
	}
	if f.key == "" {
		f.key = "key-1"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, call{r.Method, r.URL.Path, r.URL.RawQuery, string(b)})
		override := f.status[r.Method+" "+r.URL.Path]
		f.mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, f.prefix+"/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-API-KEY") != f.key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if override != 0 {
			w.WriteHeader(override)
			fmt.Fprint(w, `{"code":"X","message":"the console said no"}`)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, f.prefix)
		switch {
		case p == "/v1/info":
			fmt.Fprint(w, `{"applicationVersion":"9.1.0"}`)
		case p == "/v1/sites":
			fmt.Fprintf(w, `{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
			 {"id":"other","internalReference":"lab","name":"Lab"},
			 {"id":%q,"internalReference":"default","name":"Home"}]}`, siteID)
		case p == "/v1/sites/"+siteID+"/clients":
			f.serveClients(w, r)
		case p == "/v1/sites/"+siteID+"/devices":
			fmt.Fprint(w, `{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[
			 {"id":"d1","name":"Switch","model":"USW","state":"ONLINE","macAddress":"02:00:5e:00:00:aa","ipAddress":"192.0.2.2"}]}`)
		case p == "/v1/sites/"+siteID+"/firewall/policies" && r.Method == "GET":
			fmt.Fprint(w, `{"offset":0,"limit":200,"count":3,"totalCount":3,"data":[
			 {"id":"p1","enabled":true,"name":"Block IoT to LAN","description":"keep it apart","action":{"type":"BLOCK"},"metadata":{"origin":"USER_DEFINED"}},
			 {"id":"p2","enabled":false,"name":"Allow printer","action":{"type":"ALLOW"},"schedule":{"mode":"EVERY_WEEK"},"metadata":{"origin":"USER_DEFINED"}},
			 {"id":"sys","enabled":true,"name":"Allow Return Traffic","action":{"type":"ALLOW"},"metadata":{"origin":"SYSTEM_DEFINED"}}]}`)
		case strings.HasPrefix(p, "/v1/sites/"+siteID+"/firewall/policies/") && r.Method == "GET":
			body := f.policy
			if body == "" {
				body = `{"id":"p1","enabled":true,"name":"x","action":{"type":"BLOCK"},"metadata":{"origin":"USER_DEFINED"}}`
			}
			fmt.Fprint(w, body)
		default:
			fmt.Fprint(w, `{}`)
		}
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	cfg := Config{BaseURL: "https://192.0.2.10", APIKey: f.key, Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
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

func (f *fakeConsole) serveClients(w http.ResponseWriter, r *http.Request) {
	n := f.clients
	if n == 0 {
		n = 1
	}
	q := r.URL.Query()
	offset, limit := 0, 200
	fmt.Sscanf(q.Get("offset"), "%d", &offset)
	fmt.Sscanf(q.Get("limit"), "%d", &limit)
	var items []string
	for i := offset; i < n && i < offset+limit; i++ {
		items = append(items, fmt.Sprintf(`{"id":"c%d","name":"Client %d","type":"WIRELESS","ipAddress":"192.0.2.%d","macAddress":"02:00:5E:00:01:%02X"}`, i, i, i+10, i))
	}
	fmt.Fprintf(w, `{"offset":%d,"limit":%d,"count":%d,"totalCount":%d,"data":[%s]}`, offset, limit, len(items), n, strings.Join(items, ","))
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientsAndDevicesAreListedWithWhatABlockNeeds(t *testing.T) {
	f := &fakeConsole{}
	c := f.client(t, nil)
	devs, err := c.Devices(ctx)
	if err != nil || len(devs) != 2 {
		t.Fatalf("%+v, %v", devs, err)
	}
	cl, sw := devs[0], devs[1]
	if cl.MAC != "02005e000100" || cl.Name != "Client 0" || cl.IP != "192.0.2.10" || !cl.Online || cl.Network != "wireless" ||
		cl.Box != siteID || cl.Native != "c0" {
		t.Fatalf("client = %+v", cl)
	}
	// A UniFi device is listed but cannot be acted on.
	if sw.Name != "Switch" || sw.Native != "" || sw.Vendor != "Ubiquiti" || !sw.Online || sw.MAC != "02005e0000aa" {
		t.Fatalf("device = %+v", sw)
	}
}

func TestLongListsArePagedThrough(t *testing.T) {
	f := &fakeConsole{clients: 450}
	devs, err := f.client(t, nil).Devices(ctx)
	if err != nil || len(devs) != 451 {
		t.Fatalf("%d devices, %v", len(devs), err)
	}
}

func TestOnlyUserDefinedPoliciesAreListedAsRules(t *testing.T) {
	f := &fakeConsole{}
	rules, err := f.client(t, nil).Rules(ctx)
	if err != nil || len(rules) != 2 {
		t.Fatalf("%+v, %v", rules, err)
	}
	a, b := rules[0], rules[1]
	if a.ID != "p1" || a.Action != "block" || a.Paused || a.Name != "Block IoT to LAN" || a.TargetType != "policy" || a.Notes != "keep it apart" || a.Box != siteID {
		t.Fatalf("a = %+v", a)
	}
	if b.Action != "allow" || !b.Paused || b.Schedule != "every week" {
		t.Fatalf("b = %+v", b)
	}
}

func TestTheSiteIsFoundByNameReferenceOrIDAndTheDefaultIsUsedOtherwise(t *testing.T) {
	for _, site := range []string{"", "default", "Home", "HOME", siteID} {
		f := &fakeConsole{}
		c := f.client(t, func(c *Config) { c.Site = site })
		if _, err := c.Devices(ctx); err != nil {
			t.Fatalf("site %q: %v", site, err)
		}
	}
	f := &fakeConsole{}
	if _, err := f.client(t, func(c *Config) { c.Site = "nowhere" }).Devices(ctx); !errors.Is(err, ErrNoSite) {
		t.Fatalf("err = %v", err)
	}
	// The site is looked up once, not on every call.
	f = &fakeConsole{}
	c := f.client(t, nil)
	_, _ = c.Devices(ctx)
	_, _ = c.Rules(ctx)
	n := 0
	for _, cl := range f.calls {
		if cl.Path == f.prefix+"/v1/sites" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("sites listed %d times", n)
	}
}

func TestAStandaloneApplicationsPrefixIsDiscovered(t *testing.T) {
	f := &fakeConsole{prefix: "/integration"}
	c := f.client(t, nil)
	if _, err := c.Devices(ctx); err != nil {
		t.Fatal(err)
	}
	if c.prefix != "/integration" {
		t.Fatalf("prefix = %q", c.prefix)
	}
	// A console with neither has no Integration API.
	f = &fakeConsole{prefix: "/elsewhere"}
	if _, err := f.client(t, nil).Devices(ctx); !errors.Is(err, ErrNoAPI) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPolicyIsPausedByDisablingIt(t *testing.T) {
	f := &fakeConsole{}
	c := f.client(t, nil)
	if err := c.SetRulePaused(ctx, "p1", true); err != nil {
		t.Fatal(err)
	}
	if l := f.last(); l.Method != "PATCH" || l.Path != f.prefix+"/v1/sites/"+siteID+"/firewall/policies/p1" || l.Body != `{"enabled":false}` {
		t.Fatalf("pause = %+v", l)
	}
	if err := c.SetRulePaused(ctx, "p1", false); err != nil || f.last().Body != `{"enabled":true}` {
		t.Fatalf("resume: %v %+v", err, f.last())
	}
	if err := c.SetRulePaused(ctx, " ", true); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("blank id: %v", err)
	}
}

func TestDeletingAPolicyRefusesUniFisOwn(t *testing.T) {
	f := &fakeConsole{}
	c := f.client(t, nil)
	if err := c.DeleteRule(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if l := f.last(); l.Method != "DELETE" || !strings.HasSuffix(l.Path, "/firewall/policies/p1") {
		t.Fatalf("delete = %+v", l)
	}
	f.policy = `{"id":"sys","name":"Allow Return Traffic","metadata":{"origin":"SYSTEM_DEFINED"}}`
	before := f.count("DELETE")
	if err := c.DeleteRule(ctx, "sys"); !errors.Is(err, backends.ErrInvalid) || !strings.Contains(err.Error(), "built-in") {
		t.Fatalf("err = %v", err)
	}
	if f.count("DELETE") != before {
		t.Fatal("a built-in policy was deleted")
	}
	if err := c.DeleteRule(ctx, ""); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("blank id: %v", err)
	}
}

func TestBlockingAndUnblockingAClient(t *testing.T) {
	f := &fakeConsole{}
	c := f.client(t, nil)
	ref := backends.DeviceRef{Box: siteID, Native: "c0"}
	if err := c.BlockClient(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if l := f.last(); l.Method != "POST" || l.Path != f.prefix+"/v1/sites/"+siteID+"/clients/c0/actions" || l.Body != `{"action":"BLOCK"}` {
		t.Fatalf("block = %+v", l)
	}
	if err := c.UnblockClient(ctx, ref); err != nil || f.last().Body != `{"action":"UNBLOCK"}` {
		t.Fatalf("unblock: %v %+v", err, f.last())
	}
	// With no site on the reference, the configured one is used.
	if err := c.BlockClient(ctx, backends.DeviceRef{Native: "c1"}); err != nil || !strings.Contains(f.last().Path, siteID) {
		t.Fatalf("%v %+v", err, f.last())
	}
	if err := c.BlockClient(ctx, backends.DeviceRef{Box: siteID}); !errors.Is(err, backends.ErrInvalid) {
		t.Fatalf("a UniFi device itself cannot be blocked: %v", err)
	}
}

func TestAReadOnlyConnectionNeverSendsAWrite(t *testing.T) {
	f := &fakeConsole{}
	c := f.client(t, func(c *Config) { c.ReadOnly = true })
	for i, err := range []error{
		c.SetRulePaused(ctx, "p1", true), c.DeleteRule(ctx, "p1"),
		c.BlockClient(ctx, backends.DeviceRef{Native: "c"}), c.UnblockClient(ctx, backends.DeviceRef{Native: "c"}),
	} {
		if !errors.Is(err, backends.ErrReadOnly) {
			t.Errorf("write %d: %v", i, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("%d requests were sent", len(f.calls))
	}
	if caps := backends.Capabilities(c); len(caps) != 2 || caps[0] != backends.CapDevices || caps[1] != backends.CapRules {
		t.Fatalf("read-only capabilities = %v", caps)
	}
	c.SetReadOnly(false)
	want := []backends.Capability{backends.CapDevices, backends.CapRules, backends.CapRuleWrite, backends.CapDeviceBlock}
	got := backends.Capabilities(c)
	if len(got) != len(want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("capabilities = %v, want %v", got, want)
		}
	}
}

func TestStatusCodesMapOntoBackendErrors(t *testing.T) {
	for status, want := range map[int]error{
		403: backends.ErrAuth, 404: backends.ErrNotFound, 429: backends.ErrRateLimited, 500: backends.ErrRefused,
	} {
		f := &fakeConsole{status: map[string]int{}}
		c := f.client(t, nil)
		if _, err := c.Devices(ctx); err != nil { // discover the prefix and site first
			t.Fatal(err)
		}
		f.status["PATCH /proxy/network/integration/v1/sites/"+siteID+"/firewall/policies/p1"] = status
		err := c.SetRulePaused(ctx, "p1", true)
		if !errors.Is(err, want) {
			t.Errorf("HTTP %d: %v, want %v", status, err, want)
		}
		if status == 500 && !strings.Contains(err.Error(), "the console said no") {
			t.Errorf("the console's own message should reach the owner: %v", err)
		}
	}
	f := &fakeConsole{key: "good"}
	if _, err := f.client(t, func(c *Config) { c.APIKey = "bad" }).Devices(ctx); !errors.Is(err, backends.ErrAuth) {
		t.Errorf("bad key: %v", err)
	}
}

func TestTheConsoleAddressIsNormalizedAndRefusedWhenItCouldLeakTheKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.10":                 "https://192.0.2.10",
		"https://192.0.2.10/":        "https://192.0.2.10",
		"http://192.0.2.10:8443":     "http://192.0.2.10:8443",
		" https://unifi.example.org": "https://unifi.example.org",
	} {
		if got, err := NormalizeURL(in); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "  ", "ftp://192.0.2.10", "https://user:pw@192.0.2.10", "https://192.0.2.10/network",
		"https://192.0.2.10?x=1", "https://192.0.2.10#x", "https://",
	} {
		if got, err := NormalizeURL(in); !errors.Is(err, ErrBadURL) {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
	if _, err := New(Config{BaseURL: "192.0.2.10"}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := New(Config{BaseURL: "nonsense://", APIKey: "k"}); !errors.Is(err, ErrBadURL) {
		t.Fatalf("bad url: %v", err)
	}
}

func TestRedirectsAreRefusedAndErrorsNeverCarryTheKey(t *testing.T) {
	c, err := New(Config{BaseURL: "192.0.2.10", APIKey: "secret-key-value", AllowSelfSigned: true, Transport: rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.hc.CheckRedirect(nil, nil); err == nil {
		t.Fatal("redirects must be refused")
	}
	_, err = c.Devices(ctx)
	if err == nil || strings.Contains(err.Error(), "secret-key-value") {
		t.Fatalf("err = %v", err)
	}
	// With no transport given, a self-signed console is allowed only on request.
	for _, allow := range []bool{false, true} {
		c, _ := New(Config{BaseURL: "192.0.2.10", APIKey: "k", AllowSelfSigned: allow})
		tr := c.hc.Transport.(*http.Transport)
		if (tr.TLSClientConfig != nil) != allow {
			t.Fatalf("allow=%v but TLS config = %v", allow, tr.TLSClientConfig)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	f := &fakeConsole{}
	if _, err := f.client(t, nil).Devices(cancelled); err == nil {
		t.Fatal("a cancelled context must fail")
	}
}

func TestAnUnexpectedAnswerIsReportedPlainly(t *testing.T) {
	c, _ := New(Config{BaseURL: "192.0.2.10", APIKey: "k", Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		fmt.Fprint(rec, `<html>not json</html>`)
		return rec.Result(), nil
	})})
	_, err := c.Devices(ctx)
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("err = %v", err)
	}
	if c.Name() != "unifi" {
		t.Fatal(c.Name())
	}
}
