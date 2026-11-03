// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"context"
	"net/http"
	"time"

	"shepherd/internal/secrets"
)

// ntfy delivery, set up here rather than in shepherd.toml (docs/ALARMS.md).
// It is the same shape as the mail relay in api_secrets.go, for the same
// reason: the server is one only the owner can name, and no feature of
// Shepherd should need a text editor. shepherd.toml's [alarms.ntfy] is still
// read once, to import an install that predates this, and ignored afterwards.
//
// Like every other secret here the token and password are write-only: the
// document below says whether one is set, never what it is.
//
// The check before saving is a real publish, because ntfy has no way to ask
// "would this work" without sending something — and the owner is setting up
// a notification channel, so one notification arriving is the clearest
// possible confirmation. The same call is behind the explicit "send a test
// notification" action, so a test and a save prove exactly the same path.

// SecretNtfy is the kind passed to Deps.OnSecretsChanged for ntfy.
const SecretNtfy = "ntfy"

const defaultNtfyTopic = "shepherd-alarms"

type ntfyJSON struct {
	// Available is false when the alarm engine itself is off, in which
	// case nothing here is delivered whatever is stored.
	Available bool `json:"available"`
	// Configured is whether a server is stored; Enabled is the owner's
	// switch, which can be off with a server still stored.
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
	Server     string `json:"server,omitempty"`
	Topic      string `json:"topic"`
	Username   string `json:"username,omitempty"`
	HasToken   bool   `json:"has_token"`
	HasAuth    bool   `json:"has_password"`
	// Source and UpdatedAt say whether this came from the portal or was
	// imported from shepherd.toml, and when it last changed.
	Source    string     `json:"source,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func (s *Server) ntfyDoc() ntfyJSON {
	n, ok := s.Secrets.Ntfy()
	out := ntfyJSON{Available: s.Alarms != nil, Configured: ok, Topic: defaultNtfyTopic}
	if ok {
		out.Enabled = n.Enabled
		out.Server, out.Topic, out.Username = n.Server, n.Topic, n.Username
		out.HasToken, out.HasAuth = n.Token != "", n.Password != ""
	}
	if s.Secrets.NtfyManaged() {
		out.Source = n.Source
		t := n.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

// ntfyStatus is what the Alarms screen's push document carries, so a client
// that only reads /api/alarms/push still learns whether ntfy is delivering.
func (s *Server) ntfyStatus() NtfyStatus {
	n, ok := s.Secrets.Ntfy()
	if !ok {
		return NtfyStatus{}
	}
	return NtfyStatus{Enabled: n.Enabled, Server: n.Server, Topic: n.Topic}
}

func (s *Server) getNtfy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.ntfyDoc())
}

func (s *Server) putNtfy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Server string `json:"server"`
		Topic  string `json:"topic"`
		// Token and Password left empty keep the saved ones, but only for
		// the same server: a stored credential must never be sendable to
		// a server the owner did not enter it for, which would be a way
		// to read it back.
		Token         string `json:"token"`
		ClearToken    bool   `json:"clear_token"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		ClearPassword bool   `json:"clear_password"`
		// Enabled defaults to on: someone filling this in wants
		// notifications, and the switch is one PATCH away.
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	if b.Topic == "" {
		b.Topic = defaultNtfyTopic
	}
	enabled := true
	if b.Enabled != nil {
		enabled = *b.Enabled
	}
	n := secrets.Ntfy{Server: b.Server, Topic: b.Topic, Token: b.Token,
		Username: b.Username, Password: b.Password, Enabled: enabled}
	cur, have := s.Secrets.Ntfy()
	sameServer := have && cur.Server == n.Server
	if n.Token == "" && !b.ClearToken && sameServer {
		n.Token = cur.Token
	}
	if n.Password == "" && !b.ClearPassword && sameServer && n.Username == cur.Username {
		n.Password = cur.Password
	}
	// A kept token together with a newly typed username would fail
	// validation with a message about both being set, which is not what
	// happened: the owner switched from a token to a username, so the
	// token goes.
	if n.Token != "" && b.Token == "" && n.Username != "" {
		n.Token = ""
	}
	n, err := n.Normalize()
	if err != nil {
		bad(w, err.Error())
		return
	}
	if s.VerifyNtfy != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		err := s.VerifyNtfy(ctx, n)
		cancel()
		if err != nil {
			refused(w, err)
			return
		}
	}
	if _, err := s.Secrets.SetNtfy(n); err != nil {
		secretError(w, err)
		return
	}
	s.secretsChanged(SecretNtfy)
	writeJSON(w, s.ntfyDoc())
}

// patchNtfy flips the switch without touching the server or its
// credentials, so delivery can be paused and resumed with one click.
func (s *Server) patchNtfy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &b, smallBody) {
		return
	}
	ok, err := s.Secrets.SetNtfyEnabled(b.Enabled)
	if err != nil {
		secretError(w, err)
		return
	}
	if !ok {
		bad(w, "there is no ntfy server to switch on; add one first")
		return
	}
	s.secretsChanged(SecretNtfy)
	writeJSON(w, s.ntfyDoc())
}

// testNtfy publishes one notification to the stored server now. It works
// while the switch is off, which is the point: you can prove the server
// works before you let alarms go to it.
func (s *Server) testNtfy(w http.ResponseWriter, r *http.Request) {
	n, ok := s.Secrets.Ntfy()
	if !ok {
		bad(w, "no ntfy server is set")
		return
	}
	if s.VerifyNtfy == nil {
		notFound(w, "this build cannot publish to ntfy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.VerifyNtfy(ctx, n); err != nil {
		refused(w, err)
		return
	}
	writeJSON(w, map[string]any{"sent": true})
}

func (s *Server) deleteNtfy(w http.ResponseWriter, r *http.Request) {
	if err := s.Secrets.ClearNtfy(); err != nil {
		secretError(w, err)
		return
	}
	s.secretsChanged(SecretNtfy)
	writeJSON(w, s.ntfyDoc())
}
