// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"net/http"
	"strings"

	"shepherd/internal/alarms"
	"shepherd/internal/webpush"
)

// PushService is what the portal needs from cmd/shepherd's Web Push wiring
// (docs/ALARMS.md): the VAPID public key a browser subscribes against,
// and the subscription store. Nil Deps.Push means Web Push is off, and the
// API says so rather than failing.
type PushService interface {
	PublicKey() string
	Devices() []webpush.Device
	Subscribe(sub webpush.BrowserSubscription, name, userAgent string) (webpush.Device, error)
	Rename(id, name string) error
	Remove(id string) error
}

const maxPushName = 60

// NtfyStatus says whether ntfy delivery is on and where it publishes, so the
// Alarms screen can walk the owner through setting it up. It never carries
// a token or password.
type NtfyStatus struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"`
	Topic   string `json:"topic,omitempty"`
}

// getPush reports whether Web Push is on, the public key, every
// subscribed browser (never an endpoint or a key) and the ntfy status.
func (s *Server) getPush(w http.ResponseWriter, r *http.Request) {
	if s.Push == nil {
		writeJSON(w, map[string]any{"enabled": false, "devices": []webpush.Device{}, "ntfy": s.Ntfy})
		return
	}
	devs := s.Push.Devices()
	if devs == nil {
		devs = []webpush.Device{}
	}
	writeJSON(w, map[string]any{"enabled": true, "public_key": s.Push.PublicKey(), "devices": devs, "ntfy": s.Ntfy})
}

type pushSubscribeBody struct {
	Subscription webpush.BrowserSubscription `json:"subscription"`
	Name         string                      `json:"name"`
}

// subscribePush records this browser's PushSubscription. The name is the
// owner's label for the browser ("Blaine's phone"); the user agent is kept
// so an unnamed one is still recognisable.
func (s *Server) subscribePush(w http.ResponseWriter, r *http.Request) {
	if s.Push == nil {
		notFound(w, "Web Push is turned off in the configuration")
		return
	}
	var b pushSubscribeBody
	if !decode(w, r, &b, smallBody) {
		return
	}
	if strings.TrimSpace(b.Subscription.Endpoint) == "" {
		bad(w, "subscription.endpoint is required")
		return
	}
	name := strings.TrimSpace(b.Name)
	if len(name) > maxPushName {
		name = name[:maxPushName]
	}
	d, err := s.Push.Subscribe(b.Subscription, name, r.UserAgent())
	if err != nil {
		bad(w, err.Error())
		return
	}
	writeJSON(w, d)
}

func (s *Server) renamePush(w http.ResponseWriter, r *http.Request) {
	if s.Push == nil {
		notFound(w, "Web Push is turned off in the configuration")
		return
	}
	var b struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	name := strings.TrimSpace(b.Name)
	if name == "" || len(name) > maxPushName {
		bad(w, "name must be 1 to 60 characters")
		return
	}
	if err := s.Push.Rename(r.PathValue("id"), name); err != nil {
		pushError(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) removePush(w http.ResponseWriter, r *http.Request) {
	if s.Push == nil {
		notFound(w, "Web Push is turned off in the configuration")
		return
	}
	if err := s.Push.Remove(r.PathValue("id")); err != nil {
		pushError(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func pushError(w http.ResponseWriter, err error) {
	if errors.Is(err, webpush.ErrNotFound) {
		notFound(w, err.Error())
		return
	}
	bad(w, err.Error())
}

// testPush raises the bypassing test alarm, which the Router delivers over
// every configured channel: the way to find out whether this browser's
// subscription, or ntfy, actually reaches a phone.
func (s *Server) testPush(w http.ResponseWriter, r *http.Request) {
	a, err := s.Alarms.RaiseSync(alarms.Event{
		Type:   alarms.TypeTest,
		Source: "portal",
		Title:  "Test notification from Shepherd",
		Body:   "If you can read this, alarms reach this device.",
		Key:    "test|" + r.RemoteAddr + "|",
	})
	if err != nil {
		serverFault(w, "could not raise the test alarm")
		return
	}
	writeJSON(w, map[string]any{"alarm_id": a.ID})
}
