// SPDX-License-Identifier: AGPL-3.0-or-later

package routerusage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeUniFi is enough of a controller to exercise both shapes: a UniFi OS
// console answering under /proxy/network, and a self-hosted Network
// Application answering directly.
type fakeUniFi struct {
	unifiOS  bool
	user     string
	pass     string
	clients  string // the JSON "data" array
	mu       sync.Mutex
	logins   int
	polls    int
	expire   bool // refuse the next stat/sta once, as a lapsed session does
	statCode int
}

func (f *fakeUniFi) start(t *testing.T) *httptest.Server {
	t.Helper()
	loginPath := "/api/login"
	statPath := "/api/s/default/stat/sta"
	if f.unifiOS {
		loginPath = "/api/auth/login"
		statPath = "/proxy/network/api/s/default/stat/sta"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case loginPath:
			f.logins++
			var in struct{ Username, Password string }
			_ = decodeJSON(r, &in)
			if in.Username != f.user || in.Password != f.pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if f.unifiOS {
				w.Header().Set("X-Csrf-Token", "csrf-1")
			}
			http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "s"})
			fmt.Fprint(w, `{"meta":{"rc":"ok"}}`)
		case statPath:
			f.polls++
			if f.expire {
				f.expire = false
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if f.statCode != 0 {
				w.WriteHeader(f.statCode)
				return
			}
			if f.unifiOS && r.Header.Get("X-Csrf-Token") != "csrf-1" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			fmt.Fprintf(w, `{"meta":{"rc":"ok"},"data":%s}`, f.clients)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func decodeJSON(r *http.Request, into any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(into)
}

func newUniFiFor(t *testing.T, f *fakeUniFi) *UniFi {
	t.Helper()
	srv := f.start(t)
	u, err := NewUniFi(UniFiConfig{BaseURL: srv.URL, Username: f.user, Password: f.pass})
	if err != nil {
		t.Fatal(err)
	}
	u.SetHTTPClient(srv.Client())
	return u
}

const twoClients = `[
 {"mac":"02:00:5e:00:00:31","name":"Living Room TV","tx_bytes":5000,"rx_bytes":400},
 {"mac":"02:00:5e:00:00:32","hostname":"nas","wired-tx_bytes":900,"wired-rx_bytes":8000}
]`

// The controller's directions are its own: tx_bytes is what it sent to
// the client, which is the device's download. Getting this backwards
// would be invisible until someone read a chart.
func TestUniFiReadsCountersAndKeepsTheDirectionsStraight(t *testing.T) {
	for _, unifiOS := range []bool{true, false} {
		f := &fakeUniFi{unifiOS: unifiOS, user: "ro", pass: "pw", clients: twoClients}
		u := newUniFiFor(t, f)
		if u.Name() != "unifi" || u.Kind() != KindCounters {
			t.Fatalf("source = %s/%s", u.Name(), u.Kind())
		}
		got, err := u.Poll(context.Background())
		if err != nil {
			t.Fatalf("unifiOS=%v: %v", unifiOS, err)
		}
		if len(got) != 2 {
			t.Fatalf("unifiOS=%v: samples = %+v", unifiOS, got)
		}
		if got[0].MAC != "02005e000031" || got[0].Name != "Living Room TV" || got[0].DownBytes != 5000 || got[0].UpBytes != 400 {
			t.Fatalf("unifiOS=%v: wireless client = %+v", unifiOS, got[0])
		}
		// A wired client reports under "wired-" keys.
		if got[1].Name != "nas" || got[1].DownBytes != 900 || got[1].UpBytes != 8000 {
			t.Fatalf("unifiOS=%v: wired client = %+v", unifiOS, got[1])
		}
		// The session is reused rather than logging in every poll.
		if _, err := u.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.logins != 1 {
			t.Fatalf("unifiOS=%v: logged in %d times for two polls", unifiOS, f.logins)
		}
	}
}

func TestUniFiLogsInAgainWhenTheSessionLapses(t *testing.T) {
	f := &fakeUniFi{unifiOS: true, user: "ro", pass: "pw", clients: twoClients}
	u := newUniFiFor(t, f)
	if _, err := u.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.expire = true
	f.mu.Unlock()
	if _, err := u.Poll(context.Background()); err != nil {
		t.Fatalf("a lapsed session was not recovered: %v", err)
	}
	if f.logins != 2 {
		t.Fatalf("logins = %d, want a second one after the session lapsed", f.logins)
	}
}

func TestUniFiReportsBadCredentialsAsSomethingToFix(t *testing.T) {
	f := &fakeUniFi{unifiOS: true, user: "ro", pass: "pw", clients: twoClients}
	srv := f.start(t)
	u, err := NewUniFi(UniFiConfig{BaseURL: srv.URL, Username: "ro", Password: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	u.SetHTTPClient(srv.Client())
	_, err = u.Poll(context.Background())
	if !errors.Is(err, ErrUniFiAuth) || !UniFiNeedsSignIn(err) {
		t.Fatalf("err = %v, want ErrUniFiAuth", err)
	}
	if UniFiNeedsSignIn(ErrUniFiRefused) {
		t.Error("a refused request is not a credentials problem")
	}
}

func TestUniFiSaysWhenItIsNotTalkingToAController(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	u, _ := NewUniFi(UniFiConfig{BaseURL: srv.URL, Username: "a", Password: "b"})
	u.SetHTTPClient(srv.Client())
	if _, err := u.Poll(context.Background()); !errors.Is(err, ErrUniFiRefused) {
		t.Fatalf("err = %v, want ErrUniFiRefused", err)
	}
}

func TestUniFiReportsAControllerThatIsUnwell(t *testing.T) {
	f := &fakeUniFi{unifiOS: true, user: "ro", pass: "pw", clients: twoClients, statCode: http.StatusInternalServerError}
	u := newUniFiFor(t, f)
	if _, err := u.Poll(context.Background()); !errors.Is(err, ErrUniFiRefused) {
		t.Fatalf("err = %v", err)
	}
}

func TestUniFiRefusesAnAddressItCannotUse(t *testing.T) {
	for name, in := range map[string]string{
		"empty":        "",
		"not a url":    "://nope",
		"no host":      "https://",
		"wrong scheme": "ftp://192.0.2.10",
		"credentials":  "https://user:pw@192.0.2.10",
	} {
		if _, err := NewUniFi(UniFiConfig{BaseURL: in}); !errors.Is(err, ErrUniFiBadURL) {
			t.Errorf("%s: err = %v, want ErrUniFiBadURL", name, err)
		}
	}
	// A path is ignored and the site defaults, so a pasted address works.
	u, err := NewUniFi(UniFiConfig{BaseURL: "https://192.0.2.10:8443/manage/site/default", Username: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if u.cfg.BaseURL != "https://192.0.2.10:8443" || u.cfg.Site != "default" {
		t.Fatalf("cfg = %+v", u.cfg)
	}
}

func TestUniFiSkipsRecordsItCannotUse(t *testing.T) {
	f := &fakeUniFi{unifiOS: true, user: "ro", pass: "pw", clients: `[
	 {"name":"no mac"},
	 {"mac":"nonsense","tx_bytes":1},
	 {"mac":"02:00:5e:00:00:33"},
	 {"mac":"02:00:5e:00:00:34","tx_bytes":-5,"rx_bytes":"2048"},
	 {"mac":"02:00:5e:00:00:35","tx_bytes":1e19}
	]`}
	u := newUniFiFor(t, f)
	got, err := u.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Only the one with a usable counter survives: a string counter is
	// read, a negative one ignored, an absurd one refused.
	if len(got) != 1 || got[0].MAC != "02005e000034" || got[0].UpBytes != 2048 || got[0].DownBytes != 0 {
		t.Fatalf("samples = %+v", got)
	}
}

// A self-signed controller is the normal case on a LAN, so the opt-in has
// to actually take effect.
func TestUniFiOnlySkipsCertificateChecksWhenAsked(t *testing.T) {
	f := &fakeUniFi{unifiOS: true, user: "ro", pass: "pw", clients: twoClients}
	srv := httptest.NewTLSServer(f.start(t).Config.Handler)
	t.Cleanup(srv.Close)

	strict, _ := NewUniFi(UniFiConfig{BaseURL: srv.URL, Username: "ro", Password: "pw"})
	if _, err := strict.Poll(context.Background()); err == nil {
		t.Fatal("an unverifiable certificate was accepted without being asked")
	}
	lax, _ := NewUniFi(UniFiConfig{BaseURL: srv.URL, Username: "ro", Password: "pw", AllowSelfSigned: true})
	if _, err := lax.Poll(context.Background()); err != nil {
		t.Fatalf("AllowSelfSigned did not take effect: %v", err)
	}
}

func TestUniFiReusesOneClientAndHonoursATimeout(t *testing.T) {
	u, err := NewUniFi(UniFiConfig{BaseURL: "https://192.0.2.10", Username: "a", Password: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if u.cfg.Timeout <= 0 {
		t.Fatal("no default timeout")
	}
	// The real client is built lazily and only once.
	if c := u.client(); c == nil || c != u.client() {
		t.Fatal("the client is rebuilt on every call")
	}
	// Replacing it forces a fresh login, since the cookies went with it.
	u.mu.Lock()
	u.loggedIn = true
	u.mu.Unlock()
	u.SetHTTPClient(&http.Client{})
	u.mu.Lock()
	still := u.loggedIn
	u.mu.Unlock()
	if still {
		t.Fatal("a new client kept the old session")
	}
}

func TestUniFiReportsAControllerItCannotReach(t *testing.T) {
	u, _ := NewUniFi(UniFiConfig{BaseURL: "http://127.0.0.1:1", Username: "a", Password: "b"})
	_, err := u.Poll(context.Background())
	if err == nil {
		t.Fatal("an unreachable controller reported success")
	}
	// The raw "Post \"http://.../api/auth/login\"" wrapper is replaced by
	// something readable; the cause underneath is kept.
	if strings.Contains(err.Error(), "/api/") || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error = %v", err)
	}
}

func TestUniFiRejectsAnAnswerThatIsNotJSONAndOneTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			fmt.Fprint(w, `{"meta":{"rc":"ok"}}`)
			return
		}
		fmt.Fprint(w, "<html>this is the login page, not the API</html>")
	}))
	t.Cleanup(srv.Close)
	u, _ := NewUniFi(UniFiConfig{BaseURL: srv.URL, Username: "a", Password: "b"})
	u.SetHTTPClient(srv.Client())
	if _, err := u.Poll(context.Background()); err == nil {
		t.Fatal("an HTML page was accepted as a client list")
	}
}

// scrubURLError leaves anything that is not a *url.Error alone.
func TestScrubURLErrorPassesThroughOtherErrors(t *testing.T) {
	want := errors.New("something else")
	if got := scrubURLError(want); !errors.Is(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestUniFiPollNeedsALoginThatWorked(t *testing.T) {
	f := &fakeUniFi{unifiOS: true, user: "ro", pass: "pw", clients: twoClients}
	srv := f.start(t)
	u, _ := NewUniFi(UniFiConfig{BaseURL: srv.URL, Username: "ro", Password: "nope"})
	u.SetHTTPClient(srv.Client())
	// Both attempts fail the same way, and it does not loop forever.
	if _, err := u.Poll(context.Background()); !errors.Is(err, ErrUniFiAuth) {
		t.Fatalf("err = %v", err)
	}
	if f.polls != 0 {
		t.Fatalf("it read clients %d times without logging in", f.polls)
	}
}
