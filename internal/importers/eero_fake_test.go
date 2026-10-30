// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Synthetic credentials used by the tests. None is real.
const (
	testEmail   = "owner@example.com"
	testPhone   = "+15550100123"
	testCode    = "482913"
	testPending = "pending-token-abc"
	testSession = "session-token-xyz"
)

type recorded struct {
	Method, Path, RawQuery, Cookie, Body string
}

// fakeEero reproduces the response shapes of eero's user API as documented
// by public open-source clients, on loopback only.
type fakeEero struct {
	mu       sync.Mutex
	srv      *httptest.Server
	reqs     []recorded
	override func(w http.ResponseWriter, r *http.Request) bool // return true if handled

	devicesPages map[string]string // path+query -> body, for pagination tests
}

func envelopeOf(data string) string {
	return `{"meta":{"code":200,"server_time":"2026-03-01T12:00:00Z"},"data":` + data + `}`
}

func errBody(code int, msg string) string {
	return fmt.Sprintf(`{"meta":{"code":%d,"error":%q,"server_time":"2026-03-01T12:00:00Z"}}`, code, msg)
}

func newFakeEero(t *testing.T) *fakeEero {
	t.Helper()
	f := &fakeEero{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEero) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func (f *fakeEero) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ck := ""
	if c, err := r.Cookie("s"); err == nil {
		ck = c.Value
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.URL.RawQuery, ck, string(body)})
	ov := f.override
	f.mu.Unlock()
	if ov != nil && ov(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	write := func(code int, s string) { w.WriteHeader(code); _, _ = io.WriteString(w, s) }
	var in map[string]string
	_ = json.Unmarshal(body, &in)
	switch {
	case r.URL.Path == "/2.2/login" && r.Method == http.MethodPost:
		if in["login"] != testEmail && in["login"] != testPhone {
			write(422, errBody(422, "error.login.invalid"))
			return
		}
		write(200, envelopeOf(`{"user_token":"`+testPending+`"}`))
	case r.URL.Path == "/2.2/login/verify" && r.Method == http.MethodPost:
		if ck != testPending {
			write(401, errBody(401, "error.session.invalid"))
			return
		}
		switch in["code"] {
		case testCode:
			write(200, envelopeOf(`{}`))
		case "000000":
			write(401, errBody(401, "error.verification.expired"))
		default:
			write(401, errBody(401, "error.verification.invalid code "+in["code"]))
		}
	case ck != testPending:
		write(401, errBody(401, "error.session.refresh"))
	case r.URL.Path == "/2.2/account":
		write(200, envelopeOf(`{"name":"Owner","networks":{"count":2,"data":[{"url":"/2.2/networks/1001","name":"Home"},{"name":"no url"},{"url":"/2.2/networks/1002","name":"Cabin\u0007"}]}}`))
	case r.URL.Path == "/2.2/networks/1001/devices":
		write(200, envelopeOf(devicesJSON))
	case r.URL.Path == "/2.2/networks/1001/profiles":
		write(200, envelopeOf(profilesJSON))
	case r.URL.Path == "/2.2/networks/1001/eeros":
		write(200, envelopeOf(eerosJSON))
	default:
		write(404, errBody(404, "error.not-found"))
	}
}

// Fixture shapes follow the fields read by public eero clients.
const devicesJSON = `[
 {"url":"/2.2/networks/1001/devices/02:00:5e:00:00:11","mac":"02:00:5E:00:00:11","ip":"192.0.2.21","ips":["192.0.2.21","2001:db8::21"],
  "nickname":"Kids Tablet","hostname":"tablet-1","manufacturer":"ExampleCo","connection_type":"wireless","device_type":"tablet",
  "wireless":true,"paused":true,"is_guest":false,"connected":true,
  "source":{"location":"Living Room","url":"/2.2/eeros/501"},"profile":{"name":"Kids","url":"/2.2/networks/1001/profiles/9001"}},
 {"url":"/2.2/networks/1001/devices/00:00:5e:00:00:12","mac":"00:00:5e:00:00:12","ip":"192.0.2.22","nickname":"Living Room TV","hostname":"tv","manufacturer":"ExampleCo",
  "wireless":false,"device_type":"tv","source":{"location":"Living Room"}},
 {"url":"/2.2/networks/1001/devices/02:00:5e:00:00:13","mac":"02:00:5e:00:00:13","nickname":null,"hostname":"visitor-phone","is_guest":true,"wireless":true}
]`

const profilesJSON = `[
 {"url":"/2.2/networks/1001/profiles/9001","name":"Kids","paused":false,
  "devices":[{"url":"/2.2/networks/1001/devices/02:00:5e:00:00:11","mac":"02:00:5e:00:00:11"}]},
 {"url":"/2.2/networks/1001/profiles/9002","name":"Adults","devices":[]}
]`

const eerosJSON = `[
 {"url":"/2.2/eeros/501","location":"Living Room","model":"eero 6","mac_address":"00:00:5e:00:00:01","ip_address":"192.0.2.1","gateway":true,"serial":"SN-0001"},
 {"url":"/2.2/eeros/502","location":"Hallway","model":"eero Beacon","mac_address":"00:00:5e:00:00:02","gateway":false}
]`

// logCapture is an slog logger writing to a buffer, at debug level.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logCapture) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.d = append(s.d, d)
	s.mu.Unlock()
	return ctx.Err()
}

func (s *sleeps) list() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.d...)
}

func testClient(t *testing.T, f *fakeEero, mod func(*ClientOptions)) (*Client, *sleeps) {
	t.Helper()
	sl := &sleeps{}
	o := ClientOptions{MinInterval: -1, Sleep: sl.sleep}
	if mod != nil {
		mod(&o)
	}
	c, err := NewTestClient(f.srv.URL, o)
	if err != nil {
		t.Fatal(err)
	}
	return c, sl
}

func login(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	if err := c.StartLogin(ctx, testEmail); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, testCode); err != nil {
		t.Fatal(err)
	}
}

func contains(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
