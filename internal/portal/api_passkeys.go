// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"shepherd/internal/passkeys"
)

// Passkey unlock (docs/PASSKEYS.md). It is additive: nothing here touches
// the token or the PIN, and a passkey login ends in exactly the session a
// token or PIN login does (s.sessions, the shepherd_session cookie), with
// the same idle and age limits. Passkeys can only be registered from an
// already-unlocked session, so they are never how first access is gained.

// passkeyCookieName carries the id of a ceremony in progress between its
// begin and finish requests. The challenge itself stays on the server.
const passkeyCookieName = "shepherd_passkey"

// initPasskeys opens passkeys.json and, when [tls] names a hostname, the
// ceremony service. The store opens whether or not [tls] is on, so the
// owner can still see and revoke passkeys from the plain-HTTP portal. A
// store that cannot be read disables passkeys only (every passkey route
// answers 503 and the file is never overwritten); the token and PIN are
// unaffected.
func (s *Server) initPasskeys(d Deps) {
	path := ""
	if d.DataDir != "" {
		path = filepath.Join(d.DataDir, "passkeys.json")
	}
	store, err := passkeys.Open(path, tokenHash(d.Token))
	if err != nil {
		s.passkeyBroken = "passkeys are unavailable: " + err.Error() + " (fix or remove passkeys.json and restart; the token and PIN still work)"
		return
	}
	s.passkeyStore = store
	rp, err := passkeys.NewRelyingParty(d.TLSHostname, d.TLSListen)
	if err != nil {
		s.passkeyProblem = err.Error()
		return
	}
	svc, err := passkeys.NewService(rp, store, func() time.Time { return s.clock() })
	if err != nil {
		s.passkeyProblem = err.Error()
		return
	}
	s.passkeySvc = svc
}

// passkeyHere returns the service when r can run a ceremony: [tls] is
// configured and r reached the portal over HTTPS at its hostname. problem
// says why not, naming both where the request is and where passkeys work;
// it is only ever shown to an unlocked owner.
func (s *Server) passkeyHere(r *http.Request) (svc *passkeys.Service, problem string) {
	if s.passkeySvc == nil {
		return nil, s.passkeyProblem
	}
	rp := s.passkeySvc.RP()
	if !rp.Serves(r) {
		return nil, "passkeys only work at " + rp.Origin + ", the portal's own HTTPS address; this page is " +
			passkeys.RequestOrigin(r) + ". Open the portal at " + rp.Origin + " to add or use a passkey."
	}
	return s.passkeySvc, ""
}

// passkeyStoreOK answers 503 and returns false when passkeys.json could
// not be read at startup.
func (s *Server) passkeyStoreOK(w http.ResponseWriter) bool {
	if s.passkeyStore == nil {
		http.Error(w, s.passkeyBroken, http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (s *Server) setPasskeyCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: passkeyCookieName, Value: id, Path: "/api/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(passkeys.CeremonyTTL / time.Second),
	})
}

func clearPasskeyCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: passkeyCookieName, Value: "", Path: "/api/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func passkeyCeremonyID(r *http.Request) string {
	if c, err := r.Cookie(passkeyCookieName); err == nil {
		return c.Value
	}
	return ""
}

// readCeremonyBody reads the browser's raw WebAuthn response.
func readCeremonyBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, smallBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return b, true
}

type passkeyView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`
	// Synced is the backup-state flag: a passkey kept in a synced keychain
	// (iCloud Keychain, Google Password Manager, a password manager) rather
	// than bound to one device.
	Synced bool `json:"synced"`
}

func viewPasskey(p passkeys.Passkey) passkeyView {
	return passkeyView{ID: p.ID, Name: p.Name, Created: p.Created, LastUsed: p.LastUsed, Synced: p.Credential.Flags.BackupState}
}

// listPasskeys is the Locking screen's passkey card: whether passkeys can
// work at all, whether they can work from this page, and the list.
func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.passkeyStoreOK(w) {
		return
	}
	_, problem := s.passkeyHere(r)
	out := map[string]any{"configured": s.passkeySvc != nil, "here": problem == "", "problem": problem, "max": passkeys.MaxPasskeys}
	if s.passkeySvc != nil {
		out["rp_id"], out["origin"] = s.passkeySvc.RP().ID, s.passkeySvc.RP().Origin
	}
	list := s.passkeyStore.List()
	views := make([]passkeyView, 0, len(list))
	for _, p := range list {
		views = append(views, viewPasskey(p))
	}
	out["passkeys"] = views
	writeJSON(w, out)
}

// beginPasskeyRegistration starts adding a passkey. It refuses, before any
// ceremony exists, whenever the browser could not complete one: [tls] not
// configured, or this page is not the portal's own HTTPS address.
func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if !s.passkeyStoreOK(w) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body, smallBody) {
		return
	}
	svc, problem := s.passkeyHere(r)
	if svc == nil {
		conflict(w, problem)
		return
	}
	id, opts, err := svc.BeginRegistration(body.Name)
	switch {
	case errors.Is(err, passkeys.ErrInvalid):
		bad(w, err.Error())
		return
	case errors.Is(err, passkeys.ErrTooMany):
		conflict(w, err.Error())
		return
	case err != nil:
		serverFault(w, "could not start adding a passkey")
		return
	}
	s.setPasskeyCookie(w, id)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(opts)
}

func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	if !s.passkeyStoreOK(w) {
		return
	}
	body, ok := readCeremonyBody(w, r)
	if !ok {
		return
	}
	svc, problem := s.passkeyHere(r)
	if svc == nil {
		conflict(w, problem)
		return
	}
	clearPasskeyCookie(w)
	pk, err := svc.FinishRegistration(passkeyCeremonyID(r), body)
	switch {
	case errors.Is(err, passkeys.ErrNoCeremony), errors.Is(err, passkeys.ErrRejected):
		// The owner is signed in, so the library's reason is theirs to see.
		bad(w, err.Error())
		return
	case errors.Is(err, passkeys.ErrDuplicate), errors.Is(err, passkeys.ErrTooMany):
		conflict(w, err.Error())
		return
	case err != nil:
		serverFault(w, "could not save the passkey")
		return
	}
	writeJSON(w, viewPasskey(pk))
}

func (s *Server) renamePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.passkeyStoreOK(w) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body, smallBody) {
		return
	}
	pk, err := s.passkeyStore.Rename(r.PathValue("id"), body.Name)
	switch {
	case errors.Is(err, passkeys.ErrNotFound):
		notFound(w, err.Error())
		return
	case errors.Is(err, passkeys.ErrInvalid):
		bad(w, err.Error())
		return
	case err != nil:
		serverFault(w, "could not rename the passkey")
		return
	}
	writeJSON(w, viewPasskey(pk))
}

// revokePasskey removes a passkey and ends every session it opened, the
// same as revoking a trusted browser.
func (s *Server) revokePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.passkeyStoreOK(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.passkeyStore.Remove(id); err != nil {
		if errors.Is(err, passkeys.ErrNotFound) {
			notFound(w, err.Error())
		} else {
			serverFault(w, "could not remove the passkey")
		}
		return
	}
	s.sessions.deleteByPasskey(id)
	writeJSON(w, map[string]bool{"ok": true})
}

// passkeyAvailable tells the lock screen whether to offer "Sign in with a
// passkey". It is unauthenticated, so it says only yes or no: never the
// hostname (a visitor on the plain-HTTP address learns nothing) and never
// how many passkeys exist.
func (s *Server) passkeyAvailable(w http.ResponseWriter, r *http.Request) {
	svc, _ := s.passkeyHere(r)
	writeJSON(w, map[string]bool{"available": svc != nil && s.passkeyStore != nil && s.passkeyStore.Len() > 0})
}

// notHere is the unauthenticated refusal: no hostname, no reason beyond
// "not here".
const notHere = "passkey sign-in is not available at this address"

func (s *Server) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.passkeyStoreOK(w) {
		return
	}
	svc, _ := s.passkeyHere(r)
	if svc == nil {
		conflict(w, notHere)
		return
	}
	id, opts, err := svc.BeginLogin()
	switch {
	case errors.Is(err, passkeys.ErrNoPasskeys):
		conflict(w, notHere)
		return
	case err != nil:
		serverFault(w, "could not start a passkey sign-in")
		return
	}
	s.setPasskeyCookie(w, id)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(opts)
}

// finishPasskeyLogin verifies the assertion and, on success, opens an
// ordinary portal session (createForPasskey only records which passkey, so
// revoking it can end the session).
func (s *Server) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.passkeyStoreOK(w) {
		return
	}
	body, ok := readCeremonyBody(w, r)
	if !ok {
		return
	}
	svc, _ := s.passkeyHere(r)
	if svc == nil {
		conflict(w, notHere)
		return
	}
	clearPasskeyCookie(w)
	pk, err := svc.FinishLogin(passkeyCeremonyID(r), body)
	if err != nil {
		s.sleep(400 * time.Millisecond)
		switch {
		case errors.Is(err, passkeys.ErrNoCeremony):
			http.Error(w, "the passkey sign-in expired or was already used; try again", http.StatusUnauthorized)
		case errors.Is(err, passkeys.ErrCloned):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case errors.Is(err, passkeys.ErrRejected):
			http.Error(w, "that passkey was not accepted", http.StatusUnauthorized)
		default:
			serverFault(w, "could not record the passkey sign-in")
		}
		return
	}
	sess := s.sessions.createForPasskey(pk.ID, s.clock())
	s.setSessionCookie(w, sess.id)
	writeJSON(w, map[string]bool{"ok": true})
}
