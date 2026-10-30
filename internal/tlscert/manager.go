// SPDX-License-Identifier: AGPL-3.0-or-later

package tlscert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// CertObtainer is the one method Manager needs from Obtainer. Tests inject
// a fake so Manager's scheduling, persistence and hot-swap logic can be
// exercised without running the real ACME/Cloudflare flow at all.
type CertObtainer interface {
	Obtain(ctx context.Context) (tls.Certificate, error)
}

// DefaultRenewBefore is how far ahead of a Let's Encrypt certificate's real
// 90-day expiry Manager renews it. 30 days leaves a wide, deliberately
// generous retry window: if Cloudflare or Let's Encrypt are unreachable for
// a while (an outage, a misconfigured token, a changed DNS record), Manager
// keeps retrying on every scheduled check with the still-valid certificate
// staying in service the whole time, and there is still a full 30 days of
// headroom before that certificate would actually expire and HTTPS would
// stop working.
const DefaultRenewBefore = 30 * 24 * time.Hour

// DefaultCheckInterval is how often Manager.Run reconsiders whether the
// current certificate still needs renewing. Hours, not seconds: like
// internal/portscan and internal/vulnscan's own scheduling, there is no
// reason to check more often than this for something that only matters on
// the scale of weeks.
const DefaultCheckInterval = 12 * time.Hour

// DefaultObtainTimeout bounds one renewal attempt, so an unreachable
// Cloudflare or Let's Encrypt can never hang Manager.Run forever; the next
// scheduled check simply tries again.
const DefaultObtainTimeout = 2 * time.Minute

// Options configures a Manager. Hostname, Dir and Obtainer are required;
// every duration defaults to the constants above when left zero.
type Options struct {
	Hostname      string
	Dir           string // where the certificate and key are persisted (see SaveCertificate)
	Obtainer      CertObtainer
	RenewBefore   time.Duration
	ObtainTimeout time.Duration
	// OnError, when set, is called whenever a renewal attempt fails. Never
	// fatal: the previous certificate (if any) keeps serving.
	OnError func(error)
	// OnObtained, when set, is called after a certificate is obtained or
	// renewed, with its expiry.
	OnObtained func(notAfter time.Time)
}

// Manager holds Shepherd portal's current TLS certificate, obtained and
// renewed via Options.Obtainer, and makes it available to a
// crypto/tls.Config through GetCertificate so a renewal takes effect
// without restarting the process (the standard hot-swap pattern for this,
// via atomic.Pointer).
type Manager struct {
	hostname      string
	dir           string
	obtainer      CertObtainer
	renewBefore   time.Duration
	obtainTimeout time.Duration
	onError       func(error)
	onObtained    func(time.Time)

	cert atomic.Pointer[tls.Certificate]
}

// New validates opts and returns a Manager with no certificate loaded yet;
// call LoadCached (cheap, local disk only) before Run to pick up a
// certificate obtained by an earlier process, and start Run in a goroutine
// so the first renewal attempt, if one turns out to be needed, never blocks
// startup.
func New(opts Options) (*Manager, error) {
	if opts.Hostname == "" {
		return nil, errors.New("tlscert: hostname must not be empty")
	}
	if opts.Dir == "" {
		return nil, errors.New("tlscert: dir must not be empty")
	}
	if opts.Obtainer == nil {
		return nil, errors.New("tlscert: obtainer must not be nil")
	}
	m := &Manager{
		hostname:      opts.Hostname,
		dir:           opts.Dir,
		obtainer:      opts.Obtainer,
		renewBefore:   opts.RenewBefore,
		obtainTimeout: opts.ObtainTimeout,
		onError:       opts.OnError,
		onObtained:    opts.OnObtained,
	}
	if m.renewBefore <= 0 {
		m.renewBefore = DefaultRenewBefore
	}
	if m.obtainTimeout <= 0 {
		m.obtainTimeout = DefaultObtainTimeout
	}
	return m, nil
}

// LoadCached loads whatever certificate is already saved in Dir, if any, so
// a still-valid certificate from an earlier run survives a restart without
// touching the network at all. A missing cache is not an error — Run's
// first check will simply obtain one.
func (m *Manager) LoadCached() error {
	cert, err := LoadCertificate(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	m.cert.Store(&cert)
	return nil
}

// GetCertificate implements the crypto/tls.Config.GetCertificate callback.
// It returns an error until a certificate has been obtained at least once
// (there is nothing to serve yet; the HTTPS listener simply fails its
// handshake until the background renewal loop succeeds).
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := m.cert.Load()
	if cert == nil {
		return nil, fmt.Errorf("tlscert: no certificate obtained yet for %s", m.hostname)
	}
	return cert, nil
}

// Certificate returns the currently active certificate, or nil if none has
// been obtained yet.
func (m *Manager) Certificate() *tls.Certificate { return m.cert.Load() }

// EnsureFresh obtains a new certificate if none is loaded yet or the
// current one expires within RenewBefore, and persists it to Dir on
// success. It returns nil without doing anything (and without any network
// access) when the current certificate is still comfortably valid.
func (m *Manager) EnsureFresh(ctx context.Context) error {
	cur := m.cert.Load()
	if cur != nil && time.Until(cur.Leaf.NotAfter) > m.renewBefore {
		return nil
	}
	cert, err := m.obtainer.Obtain(ctx)
	if err != nil {
		if cur != nil {
			return fmt.Errorf("renewing the certificate for %s (keeping the current one, valid until %s): %w", m.hostname, cur.Leaf.NotAfter.Format(time.RFC3339), err)
		}
		return fmt.Errorf("obtaining a certificate for %s: %w", m.hostname, err)
	}
	if err := SaveCertificate(m.dir, cert); err != nil {
		return fmt.Errorf("persisting the certificate for %s: %w", m.hostname, err)
	}
	m.cert.Store(&cert)
	if m.onObtained != nil {
		m.onObtained(cert.Leaf.NotAfter)
	}
	return nil
}

// Run checks immediately, then again every `every` on a ticker, until ctx
// ends. A failed attempt is reported through OnError and never stops the
// loop or disturbs whatever certificate is already in service; the next
// scheduled check simply tries again. every <= 0 checks once and returns
// (used by tests; production always passes DefaultCheckInterval or a
// configured override). This mirrors internal/portscan.Scanner.Run's own
// shape exactly.
func (m *Manager) Run(ctx context.Context, every time.Duration) {
	m.attempt(ctx)
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ctx.Err() != nil {
				return
			}
			m.attempt(ctx)
		}
	}
}

func (m *Manager) attempt(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, m.obtainTimeout)
	defer cancel()
	if err := m.EnsureFresh(cctx); err != nil && m.onError != nil {
		m.onError(err)
	}
}
