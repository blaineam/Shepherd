// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/webpush"
)

// pushService is Web Push as cmd/shepherd runs it: the VAPID key pair
// under <data_dir>/alarms/vapid.json, the subscription store under
// <data_dir>/alarms/push.json, and the sender the alarm Router delivers
// through. It is also what the portal's /api/alarms/push endpoints drive
// (portal.PushService): a browser subscribes, the store is saved, and the
// next alarm reaches it.
type pushService struct {
	keys   webpush.VAPIDKeys
	store  *webpush.Store
	path   string
	sender *webpush.Sender

	mu sync.Mutex // serialises mutate-then-save
}

// defaultPushContact is the RFC 8292 contact used when the configuration
// names none and the portal has no HTTPS hostname: a page a push service
// operator could reach the project through.
const defaultPushContact = "https://github.com/blaineam/shepherd"

// pushContact turns the configured contact into the mailto: or https: URL
// RFC 8292 wants, or picks one.
func pushContact(cfg config.Config) string {
	c := strings.TrimSpace(cfg.Alarms.Push.Contact)
	switch {
	case c == "" && cfg.TLS.Enabled && cfg.TLS.Hostname != "":
		return "https://" + cfg.TLS.Hostname
	case c == "":
		return defaultPushContact
	case strings.HasPrefix(c, "mailto:") || strings.HasPrefix(c, "https://"):
		return c
	case strings.Contains(c, "@"):
		return "mailto:" + c
	}
	return "https://" + c
}

// startPush loads or creates the VAPID keys and the subscription store and
// builds the Router's Pusher. It never fails Shepherd's startup for a
// subscription file it cannot read: that file is moved aside and the
// store starts empty, since a lost subscription costs one re-subscribe and
// a refused start costs everything. Returns (nil, nil, nil) when Web Push
// is off.
func startPush(cfg config.Config) (*pushService, alarms.Pusher, error) {
	if !cfg.Alarms.Push.Enabled {
		return nil, nil, nil
	}
	dir := filepath.Join(cfg.DataDir, "alarms")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	keys, created, err := webpush.LoadOrCreateVAPIDKeys(filepath.Join(dir, "vapid.json"))
	if err != nil {
		return nil, nil, err
	}
	if created {
		log.Print("alarms: generated a Web Push (VAPID) key pair; browsers subscribe against it, so keep the data directory")
	}
	sender, err := webpush.NewSender(keys, pushContact(cfg))
	if err != nil {
		return nil, nil, err
	}
	store := webpush.NewStore(webpush.StoreOptions{NodeID: "local"})
	path := filepath.Join(dir, "push.json")
	if err := store.Load(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		aside := path + ".unreadable"
		log.Printf("alarms: cannot read Web Push subscriptions %s (%v); moved aside to %s, browsers will need to subscribe again", path, err, aside)
		_ = os.Rename(path, aside)
	}
	ps := &pushService{keys: keys, store: store, path: path, sender: sender}
	return ps, alarms.NewWebPushPusher(&webpush.Broadcaster{Store: store, Sender: sender}), nil
}

// PublicKey is the browser's applicationServerKey.
func (p *pushService) PublicKey() string { return p.keys.Public }

// Devices lists the subscribed browsers, without endpoints or keys.
func (p *pushService) Devices() []webpush.Device { return p.store.List() }

// Subscribe records a browser's subscription (or revives and updates one
// for the same endpoint) and saves the store.
func (p *pushService) Subscribe(sub webpush.BrowserSubscription, name, userAgent string) (webpush.Device, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, err := p.store.Add(sub, name, userAgent)
	if err != nil {
		return webpush.Device{}, err
	}
	return d, p.store.Save(p.path)
}

// Rename names a subscribed browser and saves.
func (p *pushService) Rename(id, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.store.Rename(id, name); err != nil {
		return err
	}
	return p.store.Save(p.path)
}

// Remove drops a subscription and saves.
func (p *pushService) Remove(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.store.Remove(id); err != nil {
		return err
	}
	return p.store.Save(p.path)
}
