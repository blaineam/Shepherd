// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	dohMediaType   = "application/dns-message"
	dohUserAgent   = "shepherd-dns/1 (+DNS-over-HTTPS client)"
	maxDoHResponse = 64 << 10 // a DNS message never exceeds 64 KiB
)

type dohClient struct {
	hc *http.Client
	tr *http.Transport
}

func (u *Upstream) dohClient() *dohClient {
	u.clientOnce.Do(func() {
		tr := &http.Transport{
			Proxy:                 nil, // never route resolver traffic through a proxy
			DialContext:           u.dialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: u.env.roots},
			ForceAttemptHTTP2:     true,
			DisableCompression:    true,
			MaxIdleConns:          4,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			// A half-dead HTTP/2 connection is detected by ping instead of
			// hanging every query until its own timeout.
			HTTP2: &http.HTTP2Config{SendPingTimeout: 10 * time.Second, PingTimeout: 4 * time.Second},
		}
		u.client = &dohClient{
			tr: tr,
			hc: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects are not followed")
			}},
		}
	})
	return u.client
}

// closeIdle drops pooled connections (a connection that went silent must not
// be reused). In-flight requests are unaffected.
func (u *Upstream) closeIdle() {
	if u.network == "https" {
		u.dohClient().tr.CloseIdleConnections()
	}
}

// dialContext resolves the URL host through the bootstrap resolvers (never the
// system resolver) and dials the resulting IPs. TLS verification still uses
// the hostname from the URL, because net/http derives ServerName from it.
func (u *Upstream) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := u.env.boot.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(ips, func(i, j int) bool { return ips[i].Is4() && !ips[j].Is4() })
	var lastErr error
	for i, ip := range ips {
		if i == 4 || ctx.Err() != nil {
			break
		}
		d := net.Dialer{}
		if i < len(ips)-1 {
			d.Timeout = 1500 * time.Millisecond // do not spend the whole budget on one dead address
		}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, lastErr
}

func (u *Upstream) exchangeDoH(ctx context.Context, m *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	q := m.Copy() // never mutate the caller's message
	id := q.Id
	q.Id = 0 // RFC 8484 section 4.1: the ID is redundant over HTTP and hurts caching
	wire, err := q.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("doh: pack query: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.dohURL, bytes.NewReader(wire))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)
	req.Header.Set("User-Agent", dohUserAgent)

	c := u.dohClient()
	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		c.tr.CloseIdleConnections()
		return nil, 0, fmt.Errorf("doh: %w", unwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("doh: HTTP status %s", resp.Status)
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mt, dohMediaType) {
		return nil, 0, fmt.Errorf("doh: unexpected Content-Type %q", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponse+1))
	if err != nil {
		c.tr.CloseIdleConnections()
		return nil, 0, fmt.Errorf("doh: read response: %w", err)
	}
	if len(body) > maxDoHResponse {
		return nil, 0, fmt.Errorf("doh: response larger than %d bytes", maxDoHResponse)
	}
	rtt := time.Since(start)
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("doh: malformed DNS response: %w", err)
	}
	if !out.Response {
		return nil, 0, errors.New("doh: reply is not a DNS response")
	}
	if len(m.Question) > 0 && (len(out.Question) != 1 || out.Question[0].Qtype != m.Question[0].Qtype ||
		!strings.EqualFold(out.Question[0].Name, m.Question[0].Name)) {
		return nil, 0, errors.New("doh: response question does not match the query")
	}
	out.Id = id
	return out, rtt, nil
}

// unwrapURLError drops the repeated `Post "https://..."` prefix net/http adds.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
