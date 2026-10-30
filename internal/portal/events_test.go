// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/dnsengine"
	"shepherd/internal/geo"
	"shepherd/internal/settings"
)

const tok = "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"

type fakeHistory struct {
	mode        string
	locked      bool
	initialized bool
	entries     []dnsengine.Entry
	err         error
	unlockErr   error
	gotQuery    dnsengine.HistoryQuery
}

func (f *fakeHistory) Mode() string      { return f.mode }
func (f *fakeHistory) Locked() bool      { return f.locked }
func (f *fakeHistory) Initialized() bool { return f.initialized }
func (f *fakeHistory) Query(q dnsengine.HistoryQuery) ([]dnsengine.Entry, dnsengine.Span, error) {
	f.gotQuery = q
	if f.locked {
		return nil, dnsengine.Span{}, dnsengine.ErrLocked
	}
	return f.entries, dnsengine.Span{Oldest: time.Unix(100, 0).UTC(), Newest: time.Unix(200, 0).UTC(), Skipped: 2}, f.err
}
func (f *fakeHistory) Unlock(p string) error {
	if f.unlockErr == nil && p == "right" {
		f.locked = false
	}
	if f.unlockErr == nil && p != "right" {
		return dnsengine.ErrWrongPassphrase
	}
	return f.unlockErr
}

type fakeGeoStatus struct{ st geo.Status }

func (g fakeGeoStatus) Status() geo.Status { return g.st }

func server(t *testing.T, mutate func(*Deps)) (*httptest.Server, *Server, *dnsengine.Engine) {
	t.Helper()
	dir := t.TempDir()
	filter := dnsengine.NewFilter()
	rules, err := dnsengine.LoadRules(filepath.Join(dir, "rules.json"), filter, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := dnsengine.NewPool([]string{"192.0.2.53"})
	engine := &dnsengine.Engine{Filter: filter, Pool: pool, Cache: dnsengine.NewCache(10), Log: dnsengine.NewQueryLog(50), Stats: dnsengine.NewStats()}
	d := Deps{Engine: engine, Lists: dnsengine.NewListManager(filter, dir, nil, nil), Rules: rules, Token: tok, Version: "test", Heartbeat: 20 * time.Millisecond}
	if mutate != nil {
		mutate(&d)
	}
	srv := New(d)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv, engine
}

func get(t *testing.T, url string, headers map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Shepherd", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// events reads SSE messages from res in the background.
type message struct{ id, event, data string }

func readEvents(res *http.Response) <-chan message {
	ch := make(chan message, 64)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(res.Body)
		var m message
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if m.event != "" {
					ch <- m
				}
				m = message{}
			case strings.HasPrefix(line, "id: "):
				m.id = line[4:]
			case strings.HasPrefix(line, "event: "):
				m.event = line[7:]
			case strings.HasPrefix(line, "data: "):
				m.data = line[6:]
			case strings.HasPrefix(line, ": keep-alive"):
				ch <- message{event: "keep-alive"}
			}
		}
	}()
	return ch
}

func next(t *testing.T, ch <-chan message, skipKeepAlive bool) message {
	t.Helper()
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				t.Fatal("stream ended")
			}
			if skipKeepAlive && m.event == "keep-alive" {
				continue
			}
			return m
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for a stream message")
		}
	}
}

func TestStreamDeliversLiveEntriesAsServerSentEvents(t *testing.T) {
	ts, _, engine := server(t, nil)
	res := get(t, ts.URL+"/api/stream", nil)
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream = %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	ch := readEvents(res)
	time.Sleep(50 * time.Millisecond) // the subscription is established before the headers flush
	engine.Log.Add(dnsengine.Entry{Name: "live.example.com", Client: "192.0.2.9", Action: "allowed",
		Dests: []dnsengine.Dest{{IP: "198.51.100.7", Lat: 48.8, Lon: 2.3, City: "Paris", Country: "FR"}}})

	m := next(t, ch, true)
	if m.event != "query" || m.id != "1" {
		t.Fatalf("message = %+v", m)
	}
	var e dnsengine.Entry
	if err := json.Unmarshal([]byte(m.data), &e); err != nil || e.Name != "live.example.com" || len(e.Dests) != 1 || e.Dests[0].City != "Paris" {
		t.Errorf("payload = %+v err %v", e, err)
	}
}

func TestStreamSendsHeartbeats(t *testing.T) {
	ts, _, _ := server(t, nil)
	ch := readEvents(get(t, ts.URL+"/api/stream", nil))
	if m := next(t, ch, false); m.event != "keep-alive" {
		t.Errorf("expected a keep-alive comment, got %+v", m)
	}
}

func TestStreamResumesWithoutGapsOrDuplicates(t *testing.T) {
	for _, c := range []struct {
		name string
		url  string
		hdr  map[string]string
	}{
		{"header", "/api/stream", map[string]string{"Last-Event-ID": "1"}},
		{"query", "/api/stream?after=1", nil},
	} {
		ts, _, engine := server(t, nil)
		for _, n := range []string{"one", "two", "three"} {
			engine.Log.Add(dnsengine.Entry{Name: n + ".example.com"})
		}
		ch := readEvents(get(t, ts.URL+c.url, c.hdr))
		a, b := next(t, ch, true), next(t, ch, true)
		if a.id != "2" || b.id != "3" {
			t.Errorf("%s: resumed with ids %s,%s, want 2,3", c.name, a.id, b.id)
		}
		engine.Log.Add(dnsengine.Entry{Name: "four.example.com"})
		if m := next(t, ch, true); m.id != "4" || !strings.Contains(m.data, "four.example.com") {
			t.Errorf("%s: the live entry after the replay is missing or duplicated: %+v", c.name, m)
		}
	}
}

// noFlush is a ResponseWriter that cannot stream.
type noFlush struct{ header http.Header }

func (n *noFlush) Header() http.Header         { return n.header }
func (n *noFlush) Write(b []byte) (int, error) { return len(b), nil }
func (n *noFlush) WriteHeader(int)             {}

// failingWriter flushes but every write fails, like a client that went away.
type failingWriter struct{ header http.Header }

func (f *failingWriter) Header() http.Header       { return f.header }
func (f *failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }
func (f *failingWriter) WriteHeader(int)           {}
func (f *failingWriter) Flush()                    {}

func TestStreamHandlesWritersThatCannotStreamOrHaveFailed(t *testing.T) {
	_, srv, engine := server(t, nil)
	req := httptest.NewRequest("GET", "/api/stream", nil)

	rec := &noFlush{header: http.Header{}}
	srv.stream(rec, req)
	if rec.header.Get("Content-Type") == "text/event-stream" {
		t.Error("a writer that cannot flush must be refused before streaming starts")
	}

	engine.Log.Add(dnsengine.Entry{Name: "backlog.example.com"})
	done := make(chan struct{})
	go func() {
		srv.stream(&failingWriter{header: http.Header{}}, httptest.NewRequest("GET", "/api/stream?after=0", nil))
		close(done)
	}()
	select {
	case <-done: // the very first write failed, so the handler must return
	case <-time.After(2 * time.Second):
		t.Fatal("the stream handler kept running after the client's connection failed")
	}

	// A failure while sending a replayed backlog also ends the stream.
	done2 := make(chan struct{})
	go func() {
		r := httptest.NewRequest("GET", "/api/stream", nil)
		r.Header.Set("Last-Event-ID", "0")
		srv.stream(&failingWriter{header: http.Header{}}, r)
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream handler kept running after a failed replay")
	}
}

func TestStreamRequiresAuthAndStopsWhenTheClientLeaves(t *testing.T) {
	ts, srv, engine := server(t, nil)
	res, _ := http.Get(ts.URL + "/api/stream")
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated stream = %d", res.StatusCode)
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/stream", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = srv
	cancel()
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	engine.Log.Add(dnsengine.Entry{Name: "after-disconnect.example.com"}) // must not block or panic
}

func TestHistoryEndpoint(t *testing.T) {
	fh := &fakeHistory{mode: "encrypted", initialized: true, entries: []dnsengine.Entry{{Name: "old.example.com", Client: "192.0.2.4"}}}
	ts, _, _ := server(t, func(d *Deps) { d.History = fh })

	res := get(t, ts.URL+"/api/history?from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z&client=192.0.2.4&q=old&action=allowed&limit=9999", nil)
	var body struct {
		Entries []dnsengine.Entry
		Source  string
		Locked  bool
		Skipped int
		Oldest  time.Time
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil || res.StatusCode != 200 {
		t.Fatalf("history = %d %v", res.StatusCode, err)
	}
	if len(body.Entries) != 1 || body.Source != "encrypted" || body.Locked || body.Skipped != 2 || body.Oldest.Unix() != 100 {
		t.Errorf("body = %+v", body)
	}
	q := fh.gotQuery
	if q.Client != "192.0.2.4" || q.Contains != "old" || q.Action != "allowed" || q.Limit != 5000 || q.From.Day() != 1 || q.To.Day() != 2 {
		t.Errorf("query passed to the store = %+v", q)
	}
	get(t, ts.URL+"/api/history?limit=abc", nil)
	if fh.gotQuery.Limit != 500 {
		t.Errorf("default limit = %d", fh.gotQuery.Limit)
	}
	if res := get(t, ts.URL+"/api/history?from=yesterday", nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad time = %d", res.StatusCode)
	}

	fh.entries = nil
	var empty struct{ Entries []dnsengine.Entry }
	json.NewDecoder(get(t, ts.URL+"/api/history", nil).Body).Decode(&empty)
	if empty.Entries == nil {
		t.Error("entries must be [] not null")
	}

	fh.err = errors.New("disk exploded")
	if res := get(t, ts.URL+"/api/history", nil); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("store failure = %d", res.StatusCode)
	}
	fh.err = nil
	fh.locked = true
	res = get(t, ts.URL+"/api/history", nil)
	if res.StatusCode != http.StatusLocked {
		t.Errorf("locked history = %d, want 423", res.StatusCode)
	}
	var lk struct {
		Locked  bool
		Entries []dnsengine.Entry
	}
	json.NewDecoder(res.Body).Decode(&lk)
	if !lk.Locked || lk.Entries == nil {
		t.Errorf("locked body = %+v", lk)
	}
}

func TestHistoryDefaultsToTheInMemoryRing(t *testing.T) {
	ts, _, engine := server(t, nil)
	engine.Log.Add(dnsengine.Entry{Time: time.Now(), Name: "ring.example.com", Client: "192.0.2.1", Action: "allowed"})
	var body struct {
		Entries []dnsengine.Entry
		Source  string
	}
	json.NewDecoder(get(t, ts.URL+"/api/history?q=ring", nil).Body).Decode(&body)
	if body.Source != "memory" || len(body.Entries) != 1 {
		t.Errorf("body = %+v", body)
	}
}

func TestHistoryUnlock(t *testing.T) {
	fh := &fakeHistory{mode: "encrypted", locked: true}
	ts, _, _ := server(t, func(d *Deps) { d.History = fh })
	if res := post(t, ts.URL+"/api/history/unlock", `{"passphrase":"wrong"}`); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong passphrase = %d", res.StatusCode)
	}
	if res := post(t, ts.URL+"/api/history/unlock", `{nope`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad json = %d", res.StatusCode)
	}
	res := post(t, ts.URL+"/api/history/unlock", `{"passphrase":"right"}`)
	var body struct{ OK, Locked bool }
	json.NewDecoder(res.Body).Decode(&body)
	if res.StatusCode != 200 || !body.OK || body.Locked {
		t.Errorf("unlock = %d %+v", res.StatusCode, body)
	}
	fh.unlockErr = errors.New("disk")
	if res := post(t, ts.URL+"/api/history/unlock", `{"passphrase":"x"}`); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("internal failure = %d", res.StatusCode)
	}
	fh.unlockErr = dnsengine.ErrNotSupported
	if res := post(t, ts.URL+"/api/history/unlock", `{"passphrase":"x"}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("memory mode = %d", res.StatusCode)
	}
	// Unlock needs the CSRF header like every state change.
	req, _ := http.NewRequest("POST", ts.URL+"/api/history/unlock", strings.NewReader(`{"passphrase":"right"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	r2, _ := http.DefaultClient.Do(req)
	r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden {
		t.Errorf("unlock without X-Shepherd = %d", r2.StatusCode)
	}
}

func TestSettingsAndHome(t *testing.T) {
	store, _ := settings.Open(filepath.Join(t.TempDir(), "s.json"))
	ts, _, _ := server(t, func(d *Deps) {
		d.Settings = store
		d.Geo = fakeGeoStatus{geo.Status{Ready: true, Attribution: geo.Attribution}}
		d.History = &fakeHistory{mode: "encrypted", initialized: true}
	})
	var s struct {
		Home    *settings.Home
		History map[string]any
		Geo     map[string]any
	}
	json.NewDecoder(get(t, ts.URL+"/api/settings", nil).Body).Decode(&s)
	if s.Home != nil || s.History["mode"] != "encrypted" || s.Geo["ready"] != true || s.Geo["enabled"] != true {
		t.Errorf("initial settings = %+v", s)
	}
	res := post(t, ts.URL+"/api/settings/home", `{"lat":48.5,"lon":-120.25,"label":"Test Town"}`)
	json.NewDecoder(res.Body).Decode(&s)
	if res.StatusCode != 200 || s.Home == nil || s.Home.Lat != 48.5 || store.Home() == nil {
		t.Errorf("set home = %d %+v", res.StatusCode, s.Home)
	}
	for _, body := range []string{`{"lat":91,"lon":0}`, `{nope`} {
		if r := post(t, ts.URL+"/api/settings/home", body); r.StatusCode != http.StatusBadRequest {
			t.Errorf("home %s = %d", body, r.StatusCode)
		}
	}
}

func TestSettingsWithoutStoreOrGeoStillWork(t *testing.T) {
	ts, _, _ := server(t, nil)
	res := post(t, ts.URL+"/api/settings/home", `{"lat":10,"lon":20}`)
	var s struct {
		Home *settings.Home
		Geo  map[string]any
	}
	json.NewDecoder(res.Body).Decode(&s)
	if res.StatusCode != 200 || s.Home == nil || s.Home.Lon != 20 || s.Geo["enabled"] != false {
		t.Errorf("in-memory settings = %d %+v", res.StatusCode, s)
	}
}

func del(t *testing.T, url string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Shepherd", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func TestHomeOverrideResetAndDetect(t *testing.T) {
	store, _ := settings.Open(filepath.Join(t.TempDir(), "s.json"))
	var detects int
	ts, _, _ := server(t, func(d *Deps) {
		d.Settings = store
		d.DetectHome = func(context.Context) error {
			detects++
			return store.SetAuto(settings.Home{Lat: 40.76, Lon: -111.89, Label: "Testville, ZZ"})
		}
	})
	type resp struct {
		Home     *settings.Home
		AutoHome bool `json:"auto_home"`
	}
	read := func(r *http.Response) resp {
		var v resp
		json.NewDecoder(r.Body).Decode(&v)
		return v
	}

	if v := read(post(t, ts.URL+"/api/settings/home/detect", "")); v.Home == nil || v.Home.Source != "auto" || v.Home.Label != "Testville, ZZ" || !v.AutoHome {
		t.Errorf("detect = %+v", v)
	}
	if v := read(post(t, ts.URL+"/api/settings/home", `{"lat":1,"lon":2,"label":"Mine"}`)); v.Home.Source != "user" {
		t.Errorf("an explicit home is the user's: %+v", v.Home)
	}
	post(t, ts.URL+"/api/settings/home/detect", "") // detection never overrides the user's choice
	if h := store.Home(); h.Source != "user" || h.Label != "Mine" {
		t.Errorf("detect clobbered the override: %+v", h)
	}
	v := read(del(t, ts.URL+"/api/settings/home"))
	if v.Home == nil || v.Home.Source != "auto" || v.Home.Label != "Testville, ZZ" {
		t.Errorf("reset must fall back to the detected home: %+v", v.Home)
	}
	if detects != 2 {
		t.Errorf("detections = %d", detects)
	}
}

func TestDetectHomeFailureAndDisabled(t *testing.T) {
	ts, _, _ := server(t, func(d *Deps) {
		d.DetectHome = func(context.Context) error { return errors.New("offline") }
	})
	if res := post(t, ts.URL+"/api/settings/home/detect", ""); res.StatusCode != http.StatusBadGateway {
		t.Errorf("detection failure = %d", res.StatusCode)
	}
	ts2, _, _ := server(t, nil)
	if res := post(t, ts2.URL+"/api/settings/home/detect", ""); res.StatusCode != http.StatusBadRequest {
		t.Errorf("detection when turned off = %d", res.StatusCode)
	}
	var v struct {
		AutoHome bool `json:"auto_home"`
	}
	json.NewDecoder(get(t, ts2.URL+"/api/settings", nil).Body).Decode(&v)
	if v.AutoHome {
		t.Error("auto_home must be false when detection is not configured")
	}
}

func TestResetHomeWithoutAStoreAndWithAFailingStore(t *testing.T) {
	ts, _, _ := server(t, nil)
	post(t, ts.URL+"/api/settings/home", `{"lat":10,"lon":20}`)
	var v struct{ Home *settings.Home }
	json.NewDecoder(del(t, ts.URL+"/api/settings/home").Body).Decode(&v)
	if v.Home != nil {
		t.Errorf("an in-memory reset must clear home: %+v", v.Home)
	}
	dir := t.TempDir()
	store, _ := settings.Open(filepath.Join(dir, "gone", "s.json")) // saving can never work
	ts2, _, _ := server(t, func(d *Deps) { d.Settings = store })
	if res := del(t, ts2.URL+"/api/settings/home"); res.StatusCode != http.StatusInternalServerError {
		t.Errorf("reset with an unwritable store = %d", res.StatusCode)
	}
}
