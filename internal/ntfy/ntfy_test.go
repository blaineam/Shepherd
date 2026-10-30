// SPDX-License-Identifier: AGPL-3.0-or-later

package ntfy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type capture struct {
	method string
	path   string
	hdr    http.Header
	body   string
}

func server(t *testing.T, status int, reply string, extra func(http.ResponseWriter)) (*httptest.Server, *atomic.Pointer[capture]) {
	t.Helper()
	var last atomic.Pointer[capture]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		last.Store(&capture{method: r.Method, path: r.URL.Path, hdr: r.Header.Clone(), body: string(b)})
		if extra != nil {
			extra(w)
		}
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, &last
}

func TestPublishShape(t *testing.T) {
	srv, last := server(t, 200, `{"id":"abc123","time":1}`, nil)
	c := &Client{Server: srv.URL + "/", Token: "tk_example"}
	res, err := c.Publish(context.Background(), Message{
		Topic: "shepherd-alarms", Title: "New device", Body: "A device joined.", Priority: PriorityHigh,
		Tags: []string{"rotating_light", "skull"}, Click: "https://portal.example.com/alarms/a1",
		Actions: []Action{{Kind: "view", Label: "Open portal", URL: "https://portal.example.com/alarms/a1", Clear: true}},
	})
	if err != nil || res.Status != 200 || res.ID != "abc123" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	got := last.Load()
	if got.method != "POST" || got.path != "/shepherd-alarms" || got.body != "A device joined." {
		t.Fatalf("request = %+v", got)
	}
	h := got.hdr
	want := map[string]string{
		"Title": "New device", "Priority": "4", "Tags": "rotating_light,skull",
		"Click":         "https://portal.example.com/alarms/a1",
		"Actions":       "view, Open portal, https://portal.example.com/alarms/a1, clear=true",
		"Authorization": "Bearer tk_example",
		"Content-Type":  "text/plain; charset=utf-8",
	}
	for k, v := range want {
		if h.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, h.Get(k), v)
		}
	}
}

func TestPublishSubpathServerAndBasicAuth(t *testing.T) {
	srv, last := server(t, 200, "ok", nil)
	c := &Client{Server: srv.URL + "/ntfy//", Username: "shepherd", Password: "s3cret:pw"}
	if _, err := c.Publish(context.Background(), Message{Topic: "t1", Body: "hi"}); err != nil {
		t.Fatal(err)
	}
	got := last.Load()
	if got.path != "/ntfy/t1" {
		t.Fatalf("path = %q", got.path)
	}
	enc := strings.TrimPrefix(got.hdr.Get("Authorization"), "Basic ")
	dec, _ := base64.StdEncoding.DecodeString(enc)
	if string(dec) != "shepherd:s3cret:pw" {
		t.Fatalf("basic = %q", dec)
	}
	if got.hdr.Get("Priority") != "3" || got.hdr.Get("Title") != "" || got.hdr.Get("Tags") != "" {
		t.Fatalf("defaults: %v", got.hdr)
	}
	// A token wins over basic credentials; no credentials means no header.
	c.Token = "tk"
	c.Publish(context.Background(), Message{Topic: "t1", Body: "hi"})
	if last.Load().hdr.Get("Authorization") != "Bearer tk" {
		t.Fatal("token precedence")
	}
	anon := &Client{Server: srv.URL}
	anon.Publish(context.Background(), Message{Topic: "t1", Body: "hi"})
	if last.Load().hdr.Get("Authorization") != "" {
		t.Fatal("anonymous request carried credentials")
	}
}

func TestUTF8TitleAndActionsAreEncoded(t *testing.T) {
	srv, last := server(t, 200, "ok", nil)
	c := &Client{Server: srv.URL}
	title := "Nouvel appareil réseau – caméra"
	_, err := c.Publish(context.Background(), Message{Topic: "t", Title: title, Body: "b",
		Actions: []Action{{Kind: "http", Label: "Bloquer, vite", URL: "https://portal.example.com/a?x=1,2"}}})
	if err != nil {
		t.Fatal(err)
	}
	h := last.Load().hdr
	for _, v := range h {
		for _, s := range v {
			for i := 0; i < len(s); i++ {
				if s[i] >= 0x80 {
					t.Fatalf("raw non-ASCII header value %q", s)
				}
			}
		}
	}
	dec, err := new(mime.WordDecoder).DecodeHeader(h.Get("Title"))
	if err != nil || dec != title {
		t.Fatalf("title decodes to %q (%v)", dec, err)
	}
	if got := h.Get("Actions"); got != "http, 'Bloquer, vite', 'https://portal.example.com/a?x=1,2'" {
		t.Fatalf("actions = %q", got)
	}
}

func TestBodyStandsInForTitleAndIsTruncated(t *testing.T) {
	srv, last := server(t, 200, "ok", nil)
	c := &Client{Server: srv.URL}
	c.Publish(context.Background(), Message{Topic: "t", Title: "Only a title"})
	if got := last.Load(); got.body != "Only a title" {
		t.Fatalf("body = %q", got.body)
	}
	long := strings.Repeat("é", 3000) // 6000 bytes
	c.Publish(context.Background(), Message{Topic: "t", Body: long})
	if b := last.Load().body; len(b) > MaxBody || !strings.HasPrefix(long, b) {
		t.Fatalf("body len %d", len(b))
	}
	c.Publish(context.Background(), Message{Topic: "t", Title: strings.Repeat("T", 600), Body: "b"})
	if got := last.Load().hdr.Get("Title"); len(got) != maxTitle {
		t.Fatalf("title len %d", len(got))
	}
}

func TestInputValidation(t *testing.T) {
	srv, last := server(t, 200, "ok", nil)
	good := Client{Server: srv.URL}
	ctx := context.Background()
	msg := func(f func(*Message)) Message {
		m := Message{Topic: "topic", Title: "T", Body: "B"}
		f(&m)
		return m
	}
	cases := map[string]Message{
		"topic empty":       msg(func(m *Message) { m.Topic = "" }),
		"topic slash":       msg(func(m *Message) { m.Topic = "a/b" }),
		"topic space":       msg(func(m *Message) { m.Topic = "a b" }),
		"topic traversal":   msg(func(m *Message) { m.Topic = ".." }),
		"topic too long":    msg(func(m *Message) { m.Topic = strings.Repeat("a", 65) }),
		"empty":             msg(func(m *Message) { m.Title, m.Body = " ", "\n" }),
		"title CRLF":        msg(func(m *Message) { m.Title = "x\r\nX-Evil: 1" }),
		"title LF":          msg(func(m *Message) { m.Title = "x\ny" }),
		"title NUL":         msg(func(m *Message) { m.Title = "x\x00y" }),
		"title DEL":         msg(func(m *Message) { m.Title = "x\x7fy" }),
		"title huge":        msg(func(m *Message) { m.Title = strings.Repeat("a", 2000) }),
		"tag CRLF":          msg(func(m *Message) { m.Tags = []string{"a\r\nB: c"} }),
		"tag comma":         msg(func(m *Message) { m.Tags = []string{"a,b"} }),
		"tag empty":         msg(func(m *Message) { m.Tags = []string{""} }),
		"too many tags":     msg(func(m *Message) { m.Tags = strings.Split("a b c d e f g h i j k", " ") }),
		"click CRLF":        msg(func(m *Message) { m.Click = "https://portal.example.com/\r\nX: y" }),
		"click scheme":      msg(func(m *Message) { m.Click = "javascript:alert(1)" }),
		"click no host":     msg(func(m *Message) { m.Click = "https:///x" }),
		"priority high":     msg(func(m *Message) { m.Priority = 6 }),
		"priority negative": msg(func(m *Message) { m.Priority = -1 }),
		"action kind":       msg(func(m *Message) { m.Actions = []Action{{Kind: "broadcast", Label: "x", URL: "https://a.example.com"}} }),
		"action label":      msg(func(m *Message) { m.Actions = []Action{{Kind: "view", Label: "", URL: "https://a.example.com"}} }),
		"action semicolon":  msg(func(m *Message) { m.Actions = []Action{{Kind: "view", Label: "a;b", URL: "https://a.example.com"}} }),
		"action url":        msg(func(m *Message) { m.Actions = []Action{{Kind: "view", Label: "a", URL: "ftp://a.example.com"}} }),
		"action url quote":  msg(func(m *Message) { m.Actions = []Action{{Kind: "view", Label: "a", URL: "https://a.example.com/'x"}} }),
		"action CRLF label": msg(func(m *Message) { m.Actions = []Action{{Kind: "view", Label: "a\r\nb", URL: "https://a.example.com"}} }),
		"too many actions": msg(func(m *Message) {
			a := Action{Kind: "view", Label: "a", URL: "https://a.example.com"}
			m.Actions = []Action{a, a, a, a}
		}),
	}
	for name, m := range cases {
		_, err := good.Publish(ctx, m)
		if err == nil || KindOf(err) != KindInvalid || IsRetryable(err) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	bad := map[string]Client{
		"token CRLF":    {Server: srv.URL, Token: "a\r\nb"},
		"user CRLF":     {Server: srv.URL, Username: "a\nb", Password: "x"},
		"pass CRLF":     {Server: srv.URL, Username: "a", Password: "x\ry"},
		"no server":     {},
		"ftp server":    {Server: "ftp://ntfy.example.com"},
		"creds in url":  {Server: "https://u:p" + "@ntfy.example.com"},
		"query in url":  {Server: "https://ntfy.example.com/?x=1"},
		"no host":       {Server: "https://"},
		"unparseable":   {Server: "http://[::1"},
		"fragment":      {Server: "https://ntfy.example.com/#x"},
		"relative path": {Server: "/just/a/path"},
	}
	for name, c := range bad {
		c := c
		if _, err := c.Publish(ctx, Message{Topic: "t", Body: "b"}); err == nil || KindOf(err) != KindInvalid {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if last.Load() != nil {
		t.Fatalf("an invalid message reached the server: %+v", last.Load())
	}
	if KindOf(errors.New("other")) != KindInvalid || IsRetryable(errors.New("other")) {
		t.Fatal("non-ntfy errors")
	}
}

func TestErrorClassification(t *testing.T) {
	cases := []struct {
		status    int
		reply     string
		kind      ErrorKind
		retryable bool
		retry     time.Duration
		msg       string
	}{
		{401, `{"code":40101,"error":"unauthorized"}`, KindAuth, false, 0, "unauthorized"},
		{403, `{"error":"forbidden"}`, KindAuth, false, 0, "forbidden"},
		{404, `page not found`, KindNotFound, false, 0, "Not Found"},
		{413, `{"error":"too large"}`, KindTooLarge, false, 0, "too large"},
		{429, `{"error":"limit reached"}`, KindRateLimited, true, 30 * time.Second, "limit reached"},
		{500, `oops`, KindServer, true, 30 * time.Second, "Internal Server Error"},
		{502, `{"error":"bad\r\ngateway"}`, KindServer, true, 30 * time.Second, "bad  gateway"},
		{400, `{"error":"invalid priority"}`, KindRejected, false, 0, "invalid priority"},
		{302, ``, KindRejected, false, 0, "Found"},
	}
	for _, c := range cases {
		srv, _ := server(t, c.status, c.reply, func(w http.ResponseWriter) {
			if c.retry > 0 {
				w.Header().Set("Retry-After", "30")
			}
		})
		cl := &Client{Server: srv.URL, HTTP: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
		res, err := cl.Publish(context.Background(), Message{Topic: "t", Body: "b"})
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("%d: err = %v", c.status, err)
		}
		if e.Kind != c.kind || e.Status != c.status || res.Status != c.status || IsRetryable(err) != c.retryable || e.RetryAfter != c.retry {
			t.Errorf("%d: %+v", c.status, e)
		}
		if !strings.Contains(e.Error(), c.msg) || !strings.Contains(e.Error(), c.kind.String()) {
			t.Errorf("%d: message %q lacks %q", c.status, e.Error(), c.msg)
		}
		if errors.Unwrap(e) == nil {
			t.Error("no cause")
		}
	}
}

func TestRetryAfterParsing(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "x": 0, "-3": 0, " 7 ": 7 * time.Second, "999999": 24 * time.Hour} {
		if got := retryAfter(in); got != want {
			t.Errorf("%q = %v", in, got)
		}
	}
}

func TestNetworkErrorsAndTimeouts(t *testing.T) {
	srv, _ := server(t, 200, "ok", nil)
	url := srv.URL
	srv.Close()
	c := &Client{Server: url}
	_, err := c.Publish(context.Background(), Message{Topic: "t", Body: "b"})
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindNetwork || !e.Retryable() || e.Status != 0 {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(e.Error(), url) {
		t.Fatalf("network error leaks the URL: %v", e)
	}
	if !strings.Contains(e.Error(), "network") {
		t.Fatalf("message = %v", e)
	}
	// A server that never answers is cut off by Timeout.
	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer slow.Close()
	defer close(block)
	start := time.Now()
	c = &Client{Server: slow.URL, Timeout: 50 * time.Millisecond}
	if _, err := c.Publish(context.Background(), Message{Topic: "t", Body: "b"}); KindOf(err) != KindNetwork {
		t.Fatalf("timeout err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not honored")
	}
	// A non-url transport error passes through unchanged.
	if got := scrub(errors.New("plain")); got != "plain" {
		t.Fatal(got)
	}
}

func TestSeverityMapping(t *testing.T) {
	want := map[string]struct {
		p    Priority
		name string
		tags []string
	}{
		"info":     {PriorityMin, "min", []string{"information_source"}},
		"low":      {PriorityLow, "low", []string{"white_check_mark"}},
		"medium":   {PriorityDefault, "default", []string{"warning"}},
		"high":     {PriorityHigh, "high", []string{"rotating_light"}},
		"CRITICAL": {PriorityUrgent, "urgent", []string{"rotating_light", "skull"}},
		"bogus":    {PriorityDefault, "default", nil},
	}
	for sev, w := range want {
		if got := PriorityFor(sev); got != w.p || got.String() != w.name {
			t.Errorf("%s: %v", sev, got)
		}
		tags := TagsFor(sev)
		if strings.Join(tags, ",") != strings.Join(w.tags, ",") {
			t.Errorf("%s tags: %v", sev, tags)
		}
	}
	if Priority(0).String() != "default" {
		t.Fatal("zero priority name")
	}
	if !ValidTopic("a_B-9") || ValidTopic("a.b") {
		t.Fatal("ValidTopic")
	}
	if b, err := BaseURL(" https://ntfy.example.com/ "); err != nil || b != "https://ntfy.example.com" {
		t.Fatalf("%q %v", b, err)
	}
}
