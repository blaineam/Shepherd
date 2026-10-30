// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"shepherd/internal/config"
	"shepherd/internal/reverseproxy"
	"shepherd/internal/tlscert"
)

// Test seams, the same set tls.go has and for the same reason: production
// leaves them nil/zero (the real ACME client, the real Cloudflare provider,
// the real propagation wait, tlscert.DefaultCheckInterval), so no test ever
// reaches Let's Encrypt or Cloudflare.
var (
	rproxyEvery            time.Duration
	rproxyACMEClient       tlscert.ACMEClient
	rproxyDNS01            tlscert.DNS01Provider
	rproxyPropagationCheck func(ctx context.Context, fqdn, value string) error
)

// reverseProxyServer is the running [reverseproxy] listener.
type reverseProxyServer struct {
	addr net.Addr
	cert *tlscert.Manager
	ln   net.Listener
	srv  *http.Server
}

// startReverseProxy serves store's hosts over HTTPS on reverseproxy.listen
// behind one wildcard certificate (docs/REVERSEPROXY.md). The certificate
// comes from the same DNS-01 machinery as [tls] but lives in its own
// directory, <data_dir>/reverseproxy/tls, so the two never overwrite each
// other's certificate or account. Binding happens here, synchronously, so
// a port that is already taken (say, by the reverse proxy this is meant to
// replace) stops startup with a clear error instead of failing later in a
// goroutine; obtaining the certificate never blocks, exactly as for [tls].
// onFail hears about the listener dying after startup. Returns (nil, nil)
// when [reverseproxy] is off, which is the default.
func startReverseProxy(ctx context.Context, cfg config.Config, store *reverseproxy.Store, onFail func(error)) (*reverseProxyServer, error) {
	rp := cfg.ReverseProxy
	if !rp.Enabled {
		return nil, nil
	}
	mgr, err := startCertManager(ctx, certSpec{
		logPrefix: "reverseproxy",
		dir:       filepath.Join(cfg.DataDir, "reverseproxy", "tls"),
		hostname:  rp.Wildcard(),
		email:     rp.Email,
		token: func() (string, error) {
			return tokenFrom(rp.CloudflareAPIToken, rp.CloudflareAPITokenFile, "reverseproxy.cloudflare_api_token_file")
		},
		bootstrap: cfg.DNS.Bootstrap,
		acme:      rproxyACMEClient,
		dns01:     rproxyDNS01,
		propagate: rproxyPropagationCheck,
		every:     rproxyEvery,
	})
	if err != nil {
		return nil, fmt.Errorf("reverseproxy: %w", err)
	}

	ln, err := net.Listen("tcp", rp.Listen)
	if err != nil {
		return nil, fmt.Errorf("reverseproxy: %w", err)
	}
	proxy := reverseproxy.New(reverseproxy.Options{
		Hosts: store,
		// Only the name, never the path or query: those can carry tokens.
		OnError: func(r *http.Request, err error) { log.Printf("reverseproxy: %s: %v", r.Host, err) },
	})
	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		// No read or write timeout: uploads, video streams and WebSockets
		// legitimately last for hours. Idle keep-alives are still reaped.
		IdleTimeout: 2 * time.Minute,
		TLSConfig:   &tls.Config{GetCertificate: mgr.GetCertificate, MinVersion: tls.VersionTLS12},
	}
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && onFail != nil {
			onFail(fmt.Errorf("reverseproxy: %w", err))
		}
	}()

	base := rp.BaseDomain()
	for _, h := range store.List() {
		if !reverseproxy.Covers(base, h.Domain) {
			log.Printf("reverseproxy: %s is not covered by the %s certificate; browsers will refuse it", h.Domain, rp.Wildcard())
		}
	}
	return &reverseProxyServer{addr: ln.Addr(), cert: mgr, ln: ln, srv: srv}, nil
}

// Close stops accepting connections and gives in-flight requests a few
// seconds to finish. Upgraded connections (WebSockets) are not waited for:
// net/http hands them off entirely once hijacked.
func (s *reverseProxyServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx) // in-flight requests get up to five seconds
	s.srv.Close()           // then whatever is left is cut off
}

// stopOnFailure is how a listener started after run's portal tells run to
// stop: the first reason is kept for run to return, later ones are
// dropped rather than blocking a goroutine forever, and everything is
// cancelled either way.
func stopOnFailure(errs chan<- error, cancel context.CancelFunc) func(error) {
	return func(err error) {
		select {
		case errs <- err:
		default:
		}
		cancel()
	}
}
