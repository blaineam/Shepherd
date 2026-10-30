// SPDX-License-Identifier: AGPL-3.0-or-later

package geo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"shepherd/internal/dnsengine"
)

// Method is one way to ask the internet which public address we appear from.
type Method struct {
	Name  string
	Query func(ctx context.Context) (net.IP, error)
}

// WANDetector finds this network's public IP address with DNS "who am I"
// queries. They go to well-known public resolvers over plain DNS, the same
// kind of traffic your resolver already sends, with no web service involved.
// The answer is used only to place home on the globe; it is never stored or logged.
type WANDetector struct {
	Methods []Method      // default: Cloudflare, Google, OpenDNS
	Timeout time.Duration // per method (default 4s)
}

// NewWANDetector returns a detector using the built-in methods.
func NewWANDetector() *WANDetector {
	return &WANDetector{Methods: whoamiMethods("1.1.1.1:53", "216.239.32.10:53", "208.67.222.222:53")}
}

func whoamiMethods(cloudflare, google, opendns string) []Method {
	return []Method{
		{"cloudflare", func(ctx context.Context) (net.IP, error) {
			return queryIP(ctx, cloudflare, "whoami.cloudflare.", dns.TypeTXT, dns.ClassCHAOS)
		}},
		{"google", func(ctx context.Context) (net.IP, error) {
			return queryIP(ctx, google, "o-o.myaddr.l.google.com.", dns.TypeTXT, dns.ClassINET)
		}},
		{"opendns", func(ctx context.Context) (net.IP, error) {
			return queryIP(ctx, opendns, "myip.opendns.com.", dns.TypeA, dns.ClassINET)
		}},
	}
}

func queryIP(ctx context.Context, server, name string, qtype, class uint16) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Question[0].Qclass = class
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 4 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, err
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			return v.A, nil
		case *dns.TXT:
			for _, txt := range v.Txt {
				if ip := net.ParseIP(strings.TrimSpace(txt)); ip != nil {
					return ip, nil
				}
			}
		}
	}
	return nil, errors.New("no address in the answer")
}

// Detect tries each method in order and returns the first public address.
func (d *WANDetector) Detect(ctx context.Context) (net.IP, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	var errs []error
	for _, m := range d.Methods {
		mctx, cancel := context.WithTimeout(ctx, timeout)
		ip, err := m.Query(mctx)
		cancel()
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", m.Name, err))
		case !dnsengine.PublicIP(ip):
			errs = append(errs, fmt.Errorf("%s: answered with a non-public address", m.Name))
		default:
			return ip, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("no detection methods configured"))
	}
	return nil, fmt.Errorf("could not determine the public address: %w", errors.Join(errs...))
}
