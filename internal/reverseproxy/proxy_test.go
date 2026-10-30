// SPDX-License-Identifier: AGPL-3.0-or-later

package reverseproxy

import (
	"bufio"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingTransport answers every request itself, so routing can be
// checked without a single socket: it remembers which transport the proxy
// picked and the outbound request it built.
type recordingTransport struct {
	name string
	mu   sync.Mutex
	got  []*http.Request
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.got = append(rt.got, r)
	rt.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"X-Transport": {rt.name}},
		Body: io.NopCloser(strings.NewReader("from " + r.URL.String())), Request: r,
	}, nil
}

func newTestStore(t *testing.T, hosts ...Host) *Store {
	t.Helper()
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if _, err := s.Add(h); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestProxyRoutesByHostHeader(t *testing.T) {
	store := newTestStore(t,
		Host{Domain: "jellyfin.example.com", TargetScheme: "http", TargetHost: "127.0.0.1", TargetPort: 8096, Enabled: true},
		Host{Domain: "nas.example.com", TargetScheme: "https", TargetHost: "192.0.2.20", TargetPort: 5001, SkipTLSVerify: true, Enabled: true},
		Host{Domain: "git.example.com", TargetScheme: "https", TargetHost: "127.0.0.1", TargetPort: 3443, Enabled: true},
		Host{Domain: "off.example.com", TargetScheme: "http", TargetHost: "127.0.0.1", TargetPort: 9999, Enabled: false},
	)
	verify, insecure := &recordingTransport{name: "verify"}, &recordingTransport{name: "insecure"}
	p := New(Options{Hosts: store, Transport: verify, InsecureTransport: insecure})

	cases := []struct {
		host, path    string
		wantStatus    int
		wantTarget    string
		wantTransport string
	}{
		{"jellyfin.example.com", "/web/index.html?x=1", 200, "http://127.0.0.1:8096/web/index.html?x=1", "verify"},
		{"JELLYFIN.example.com:8443", "/", 200, "http://127.0.0.1:8096/", "verify"},
		{"nas.example.com", "/api", 200, "https://192.0.2.20:5001/api", "insecure"},
		{"git.example.com", "/a%2Fb", 200, "https://127.0.0.1:3443/a%2Fb", "verify"},
		{"off.example.com", "/", 404, "", ""},
		{"unknown.example.com", "/", 404, "", ""},
		{"192.0.2.1", "/", 404, "", ""},
		{"", "/", 404, "", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "http://placeholder"+c.path, nil)
		req.Host = c.host
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != c.wantStatus {
			t.Errorf("Host %q: status %d, want %d (%s)", c.host, rec.Code, c.wantStatus, rec.Body)
			continue
		}
		if c.wantStatus != 200 {
			if strings.Contains(strings.ToLower(rec.Body.String()), "<html") {
				t.Errorf("Host %q: a miss must be a plain 404, never a page: %q", c.host, rec.Body)
			}
			continue
		}
		if got := rec.Header().Get("X-Transport"); got != c.wantTransport {
			t.Errorf("Host %q: went through the %q transport, want %q", c.host, got, c.wantTransport)
		}
		if got := strings.TrimPrefix(rec.Body.String(), "from "); got != c.wantTarget {
			t.Errorf("Host %q: proxied to %q, want %q", c.host, got, c.wantTarget)
		}
	}
	if n := len(verify.got) + len(insecure.got); n != 4 {
		t.Errorf("%d requests reached a backend, want exactly the 4 that matched an enabled host", n)
	}
}

func TestProxyDetectsALoopBackIntoItself(t *testing.T) {
	store := newTestStore(t, Host{Domain: "loop.example.com", TargetHost: "127.0.0.1", TargetPort: 1, Enabled: true})
	rt := &recordingTransport{name: "verify"}
	p := New(Options{Hosts: store, Transport: rt})
	req := httptest.NewRequest("GET", "http://loop.example.com/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if len(rt.got) != 1 {
		t.Fatalf("first hop: %d backend requests", len(rt.got))
	}
	// Feed the request the proxy just sent back into it, as a host
	// pointed at the proxy's own listener would.
	again := httptest.NewRequest("GET", "http://loop.example.com/", nil)
	again.Header = rt.got[0].Header.Clone()
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, again)
	if rec.Code != http.StatusLoopDetected {
		t.Errorf("second hop status = %d, want 508", rec.Code)
	}
	if len(rt.got) != 1 {
		t.Errorf("a looped request must not be forwarded again")
	}
	// A different Shepherd's marker is not a loop: chaining two proxies works.
	other := httptest.NewRequest("GET", "http://loop.example.com/", nil)
	other.Header.Set(loopHeader, "someone-else")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, other)
	if rec.Code != http.StatusOK {
		t.Errorf("another proxy's marker: status %d, want 200", rec.Code)
	}
}

// backendRecord is what a fake backend saw of the one request it served.
type backendRecord struct {
	method, host, uri, body string
	header                  http.Header
}

func recordingBackend(t *testing.T, tlsBackend bool) (*httptest.Server, chan backendRecord) {
	t.Helper()
	seen := make(chan backendRecord, 4)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen <- backendRecord{method: r.Method, host: r.Host, uri: r.RequestURI, body: string(b), header: r.Header.Clone()}
		w.Header().Set("X-Backend", "yes")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "backend body")
	})
	var srv *httptest.Server
	if tlsBackend {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, seen
}

func hostFor(t *testing.T, domain string, backend *httptest.Server, scheme string, skip bool) Host {
	t.Helper()
	addr := backend.Listener.Addr().String()
	host, port := splitTestAddr(t, addr)
	return Host{Domain: domain, TargetScheme: scheme, TargetHost: host, TargetPort: port, SkipTLSVerify: skip, Enabled: true}
}

// frontDoor serves p over real TLS with HTTP/2 offered, the way
// cmd/shepherd's listener does, and returns a client that trusts it and
// dials it whatever Host header a request carries.
func frontDoor(t *testing.T, p http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	ts := httptest.NewUnstartedServer(p)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, ts.Client()
}

func TestProxyForwardsARealRequestWithTheRightHeaders(t *testing.T) {
	backend, seen := recordingBackend(t, false)
	store := newTestStore(t, hostFor(t, "jellyfin.example.com", backend, "http", false))
	front, client := frontDoor(t, New(Options{Hosts: store}))

	req, _ := http.NewRequest("POST", front.URL+"/emby/a%2Fb/items?x=1&y=two", strings.NewReader("upload-bytes"))
	req.Host = "jellyfin.example.com"
	req.Header.Set("X-Custom", "kept")
	req.Header.Set("Authorization", "MediaBrowser Token=t")
	req.Header.Set("X-Forwarded-For", "198.51.100.7") // a client cannot pick the address backends see
	req.Header.Set("X-Real-IP", "198.51.100.8")
	req.Header.Set("X-Forwarded-Proto", "gopher")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusCreated || string(body) != "backend body" || res.Header.Get("X-Backend") != "yes" {
		t.Fatalf("response = %d %q %v", res.StatusCode, body, res.Header)
	}
	if cookies := res.Header.Values("Set-Cookie"); len(cookies) != 2 {
		t.Errorf("Set-Cookie = %v, want both cookies passed through", cookies)
	}

	var got backendRecord
	select {
	case got = <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("the backend never saw the request")
	}
	if got.method != "POST" || got.body != "upload-bytes" {
		t.Errorf("backend saw %s with body %q", got.method, got.body)
	}
	if got.uri != "/emby/a%2Fb/items?x=1&y=two" {
		t.Errorf("backend saw URI %q, want the original path and query untouched", got.uri)
	}
	if got.host != "jellyfin.example.com" {
		t.Errorf("backend saw Host %q, want the public name (what NPM passes too)", got.host)
	}
	checks := map[string]string{
		"X-Custom":          "kept",
		"Authorization":     "MediaBrowser Token=t",
		"X-Forwarded-For":   "127.0.0.1",
		"X-Real-Ip":         "127.0.0.1",
		"X-Forwarded-Host":  "jellyfin.example.com",
		"X-Forwarded-Proto": "https",
	}
	for k, want := range checks {
		if v := got.header.Values(k); len(v) != 1 || v[0] != want {
			t.Errorf("backend header %s = %q, want exactly %q", k, v, want)
		}
	}
}

func TestProxyToAnHTTPSBackend(t *testing.T) {
	backend, seen := recordingBackend(t, true)
	pool := x509.NewCertPool()
	pool.AddCert(backend.Certificate())

	get := func(p *Proxy) int {
		front, client := frontDoor(t, p)
		req, _ := http.NewRequest("GET", front.URL+"/", nil)
		req.Host = "nas.example.com"
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}

	verified := newTestStore(t, hostFor(t, "nas.example.com", backend, "https", false))
	if code := get(New(Options{Hosts: verified, RootCAs: pool})); code != http.StatusCreated {
		t.Errorf("verified https backend: status %d, want 201", code)
	}
	<-seen
	if code := get(New(Options{Hosts: verified})); code != http.StatusBadGateway {
		t.Errorf("an untrusted backend certificate must fail closed: status %d, want 502", code)
	}
	skipped := newTestStore(t, hostFor(t, "nas.example.com", backend, "https", true))
	if code := get(New(Options{Hosts: skipped})); code != http.StatusCreated {
		t.Errorf("skip_tls_verify backend: status %d, want 201", code)
	}
}

func TestProxyAnswers502WhenTheBackendIsDown(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	h := hostFor(t, "down.example.com", dead, "http", false)
	dead.Close()
	var logged []error
	var mu sync.Mutex
	p := New(Options{Hosts: newTestStore(t, h), OnError: func(_ *http.Request, err error) {
		mu.Lock()
		logged = append(logged, err)
		mu.Unlock()
	}})
	req := httptest.NewRequest("GET", "http://down.example.com/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logged) != 1 {
		t.Errorf("OnError calls = %v, want one", logged)
	}
}

func TestProxyStaysQuietWhenTheClientGoesAway(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(backend.Close)
	defer close(release)
	var calls int
	var mu sync.Mutex
	p := New(Options{Hosts: newTestStore(t, hostFor(t, "slow.example.com", backend, "http", false)), OnError: func(*http.Request, error) {
		mu.Lock()
		calls++
		mu.Unlock()
	}})
	front, client := frontDoor(t, p)
	client.Timeout = 200 * time.Millisecond
	req, _ := http.NewRequest("GET", front.URL+"/", nil)
	req.Host = "slow.example.com"
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected the client to time out")
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Errorf("a client hanging up is not a backend failure worth logging: %d OnError calls", calls)
	}
}

// Home Assistant and friends stream (server-sent events, long polls): the
// first event must reach the client while the backend is still writing,
// not when it finally finishes.
func TestProxyStreamsWithoutBuffering(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
		io.WriteString(w, "data: last\n\n")
	}))
	t.Cleanup(backend.Close)
	front, client := frontDoor(t, New(Options{Hosts: newTestStore(t, hostFor(t, "ha.example.com", backend, "http", false))}))
	req, _ := http.NewRequest("GET", front.URL+"/api/stream", nil)
	req.Host = "ha.example.com"
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(res.Body).ReadString('\n')
		line <- l
	}()
	select {
	case l := <-line:
		if l != "data: first\n" {
			t.Errorf("first line = %q", l)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first event was held back until the backend finished")
	}
	close(release)
}

func TestNewDefaultsToRealTransportsThatNeverUseAnEnvironmentProxy(t *testing.T) {
	p := New(Options{Hosts: newTestStore(t)})
	for name, rt := range map[string]http.RoundTripper{"verify": p.verify.Transport, "insecure": p.insecure.Transport} {
		tr, ok := rt.(*http.Transport)
		if !ok {
			t.Fatalf("%s transport is %T", name, rt)
		}
		if tr.Proxy != nil {
			t.Errorf("%s transport honors HTTP_PROXY; backends are always dialed directly", name)
		}
		if tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
			t.Errorf("%s transport may negotiate HTTP/2 upstream, which cannot carry a WebSocket upgrade", name)
		}
	}
	if !p.insecure.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Error("the insecure transport must skip verification")
	}
	if p.verify.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Error("the default transport must verify backend certificates")
	}
}

func splitTestAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
