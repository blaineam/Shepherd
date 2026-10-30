// SPDX-License-Identifier: AGPL-3.0-or-later

package ntfy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Priority is an ntfy message priority, 1 (min) to 5 (urgent).
type Priority int

// ntfy priorities.
const (
	PriorityMin     Priority = 1
	PriorityLow     Priority = 2
	PriorityDefault Priority = 3
	PriorityHigh    Priority = 4
	PriorityUrgent  Priority = 5
)

func (p Priority) String() string {
	switch p {
	case PriorityMin:
		return "min"
	case PriorityLow:
		return "low"
	case PriorityDefault:
		return "default"
	case PriorityHigh:
		return "high"
	case PriorityUrgent:
		return "urgent"
	}
	return "default"
}

// PriorityFor maps an alarm severity (info, low, medium, high, critical) to
// an ntfy priority. Unknown severities get the default priority.
func PriorityFor(severity string) Priority {
	switch strings.ToLower(severity) {
	case "info":
		return PriorityMin
	case "low":
		return PriorityLow
	case "medium":
		return PriorityDefault
	case "high":
		return PriorityHigh
	case "critical":
		return PriorityUrgent
	}
	return PriorityDefault
}

// TagsFor maps an alarm severity to ntfy tags. ntfy turns tags that are emoji
// short codes into emoji in front of the title. Unknown severities get none.
func TagsFor(severity string) []string {
	switch strings.ToLower(severity) {
	case "info":
		return []string{"information_source"}
	case "low":
		return []string{"white_check_mark"}
	case "medium":
		return []string{"warning"}
	case "high":
		return []string{"rotating_light"}
	case "critical":
		return []string{"rotating_light", "skull"}
	}
	return nil
}

// Action is an ntfy action button.
// Only the "view" and "http" kinds are supported.
type Action struct {
	Kind  string // "view" or "http"
	Label string
	URL   string
	Clear bool // dismiss the notification after the action
}

// Message is one notification to publish.
type Message struct {
	Topic    string
	Title    string
	Body     string
	Priority Priority // zero means default
	Tags     []string
	Click    string // URL opened when the notification is tapped
	Actions  []Action
}

// ErrorKind classifies a publish failure.
type ErrorKind int

// Error kinds.
const (
	// KindInvalid: the message or configuration was rejected locally; nothing
	// was sent.
	KindInvalid ErrorKind = iota
	// KindAuth: 401 or 403. Wrong or missing credentials, or no write access
	// to the topic. Retrying will not help.
	KindAuth
	// KindNotFound: 404. The server path or topic does not exist.
	KindNotFound
	// KindTooLarge: 413. The message is over the server's limit.
	KindTooLarge
	// KindRateLimited: 429. Retry after Error.RetryAfter.
	KindRateLimited
	// KindServer: 5xx. Retry later.
	KindServer
	// KindNetwork: the server could not be reached or timed out. Retry later.
	KindNetwork
	// KindRejected: any other non-2xx answer.
	KindRejected
)

func (k ErrorKind) String() string {
	return [...]string{"invalid", "auth", "not-found", "too-large", "rate-limited", "server", "network", "rejected"}[k]
}

// Error is a classified publish failure.
type Error struct {
	Kind       ErrorKind
	Status     int
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("ntfy: %s (HTTP %d): %v", e.Kind, e.Status, e.Err)
	}
	return fmt.Sprintf("ntfy: %s: %v", e.Kind, e.Err)
}

// Unwrap exposes the cause.
func (e *Error) Unwrap() error { return e.Err }

// Retryable reports whether trying again later can succeed.
func (e *Error) Retryable() bool {
	return e.Kind == KindRateLimited || e.Kind == KindServer || e.Kind == KindNetwork
}

// IsRetryable reports whether err is a retryable publish failure.
func IsRetryable(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Retryable()
}

// KindOf returns the kind of a publish error (KindInvalid for other errors).
func KindOf(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInvalid
}

func invalid(format string, a ...any) error {
	return &Error{Kind: KindInvalid, Err: fmt.Errorf(format, a...)}
}

// Limits.
const (
	MaxBody        = 4096 // ntfy's message size limit
	maxTitle       = 250
	maxTags        = 10
	maxActions     = 3
	maxHeaderLen   = 1024
	DefaultTimeout = 10 * time.Second
)

var topicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidTopic reports whether s is an acceptable topic name.
func ValidTopic(s string) bool { return topicRE.MatchString(s) }

// Client publishes to one ntfy server. The zero value is not usable: set
// Server, and optionally Token or Username and Password. Fields must not be
// changed while Publish is running.
type Client struct {
	// Server is the base URL, e.g. https://ntfy.example.com or
	// http://ntfy.example.net:8080/prefix. Trailing slashes are ignored.
	Server string
	// Token authenticates with "Authorization: Bearer <token>". It wins over
	// Username and Password.
	Token string
	// Username and Password authenticate with basic auth.
	Username, Password string
	// HTTP is the client to use; nil means a default with Timeout.
	HTTP *http.Client
	// Timeout bounds one publish; zero means DefaultTimeout.
	Timeout time.Duration
}

// Result is the server's acknowledgement.
type Result struct {
	Status int
	ID     string // message ID assigned by the server, when it answered JSON
}

// BaseURL validates and normalizes the server URL.
func BaseURL(server string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(server))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", invalid("server must be an http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", invalid("server URL must not carry credentials, a query or a fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// checkHeader rejects any control character, which covers CR and LF.
func checkHeader(name, v string) error {
	if len(v) > maxHeaderLen {
		return invalid("%s is too long", name)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return invalid("%s contains a control character", name)
		}
	}
	return nil
}

// encodeHeader returns v unchanged when it is printable ASCII, else RFC 2047
// encoded (which ntfy decodes) so UTF-8 titles survive HTTP header rules.
func encodeHeader(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] >= 0x80 {
			return mime.BEncoding.Encode("utf-8", v)
		}
	}
	return v
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func checkURL(name, v string) error {
	if err := checkHeader(name, v); err != nil {
		return err
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return invalid("%s must be an http(s) URL", name)
	}
	return nil
}

func formatActions(as []Action) (string, error) {
	if len(as) > maxActions {
		return "", invalid("at most %d actions", maxActions)
	}
	parts := make([]string, 0, len(as))
	for _, a := range as {
		if a.Kind != "view" && a.Kind != "http" {
			return "", invalid("unsupported action kind %q", a.Kind)
		}
		if a.Label == "" || strings.ContainsAny(a.Label, ";'\"") {
			return "", invalid("bad action label")
		}
		if err := checkURL("action URL", a.URL); err != nil {
			return "", err
		}
		if strings.ContainsAny(a.URL, ";'\"") {
			return "", invalid("action URL contains a reserved character")
		}
		if err := checkHeader("action label", a.Label); err != nil {
			return "", err
		}
		p := a.Kind + ", " + quoteIfComma(a.Label) + ", " + quoteIfComma(a.URL)
		if a.Clear {
			p += ", clear=true"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; "), nil
}

func quoteIfComma(s string) string {
	if strings.Contains(s, ",") {
		return "'" + s + "'"
	}
	return s
}

// request validates m and builds the HTTP request.
func (c *Client) request(ctx context.Context, m Message) (*http.Request, error) {
	base, err := BaseURL(c.Server)
	if err != nil {
		return nil, err
	}
	if !ValidTopic(m.Topic) {
		return nil, invalid("topic must be 1 to 64 letters, digits, - or _")
	}
	if strings.TrimSpace(m.Body) == "" && strings.TrimSpace(m.Title) == "" {
		return nil, invalid("empty message")
	}
	body := m.Body
	if strings.TrimSpace(body) == "" {
		body = m.Title // ntfy needs a body; the title stands in
	}
	body = truncate(body, MaxBody)
	if err := checkHeader("title", m.Title); err != nil {
		return nil, err
	}
	if len(m.Tags) > maxTags {
		return nil, invalid("at most %d tags", maxTags)
	}
	for _, t := range m.Tags {
		if t == "" || strings.ContainsAny(t, ", ") || checkHeader("tag", t) != nil {
			return nil, invalid("bad tag %q", t)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/"+m.Topic, strings.NewReader(body))
	if err != nil {
		return nil, invalid("%v", err)
	}
	h := req.Header
	h.Set("Content-Type", "text/plain; charset=utf-8")
	if m.Title != "" {
		h.Set("Title", encodeHeader(truncate(m.Title, maxTitle)))
	}
	p := m.Priority
	if p == 0 {
		p = PriorityDefault
	}
	if p < PriorityMin || p > PriorityUrgent {
		return nil, invalid("priority %d out of range", int(p))
	}
	h.Set("Priority", strconv.Itoa(int(p)))
	if len(m.Tags) > 0 {
		h.Set("Tags", strings.Join(m.Tags, ","))
	}
	if m.Click != "" {
		if err := checkURL("click URL", m.Click); err != nil {
			return nil, err
		}
		h.Set("Click", m.Click)
	}
	if len(m.Actions) > 0 {
		a, err := formatActions(m.Actions)
		if err != nil {
			return nil, err
		}
		h.Set("Actions", encodeHeader(a))
	}
	switch {
	case c.Token != "":
		if err := checkHeader("token", c.Token); err != nil {
			return nil, err
		}
		h.Set("Authorization", "Bearer "+c.Token)
	case c.Username != "" || c.Password != "":
		if err := checkHeader("username", c.Username); err != nil {
			return nil, err
		}
		if err := checkHeader("password", c.Password); err != nil {
			return nil, err
		}
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	}
	return req, nil
}

// Publish sends m. Errors are *Error values: use KindOf and IsRetryable.
func (c *Client) Publish(ctx context.Context, m Message) (Result, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := c.request(ctx, m)
	if err != nil {
		return Result{}, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Result{}, &Error{Kind: KindNetwork, Err: errors.New(scrub(err))}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res := Result{Status: resp.StatusCode}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var ack struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(bytes.TrimSpace(data), &ack) == nil {
			res.ID = ack.ID
		}
		return res, nil
	}
	e := &Error{Status: resp.StatusCode, Err: errors.New(serverMessage(data, resp.StatusCode))}
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		e.Kind = KindAuth
	case resp.StatusCode == 404:
		e.Kind = KindNotFound
	case resp.StatusCode == 413:
		e.Kind = KindTooLarge
	case resp.StatusCode == 429:
		e.Kind = KindRateLimited
		e.RetryAfter = retryAfter(resp.Header.Get("Retry-After"))
	case resp.StatusCode >= 500:
		e.Kind = KindServer
		e.RetryAfter = retryAfter(resp.Header.Get("Retry-After"))
	default:
		e.Kind = KindRejected
	}
	return res, e
}

// scrub turns a transport error into text without the credentials-bearing URL
// details (net/http errors include the URL, never the headers).
func scrub(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// serverMessage extracts ntfy's JSON error text, falling back to the status.
func serverMessage(data []byte, status int) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(bytes.TrimSpace(data), &e) == nil && e.Error != "" {
		return truncate(strings.Map(func(r rune) rune {
			if r < 0x20 {
				return ' '
			}
			return r
		}, e.Error), 200)
	}
	return http.StatusText(status)
}

func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	if n > 86400 {
		n = 86400
	}
	return time.Duration(n) * time.Second
}
