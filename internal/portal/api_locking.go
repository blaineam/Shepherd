// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const trustedCookieName = "shepherd_trusted"

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func encodeTrustedCookie(id string, secret []byte) string {
	return id + "." + hex.EncodeToString(secret)
}

func parseTrustedCookie(v string) (id string, secret []byte, ok bool) {
	i := strings.IndexByte(v, '.')
	if i < 0 {
		return "", nil, false
	}
	secret, err := hex.DecodeString(v[i+1:])
	if err != nil || len(secret) == 0 {
		return "", nil, false
	}
	return v[:i], secret, true
}

func browserName(r *http.Request) string {
	ua := strings.TrimSpace(r.UserAgent())
	if ua == "" {
		return "Unknown browser"
	}
	if len(ua) > 120 {
		ua = ua[:120]
	}
	return ua
}

// pinParams is the Argon2id cost for hashing PINs, matching the convention
// internal/history uses for passphrases (time=3, memory=64 MiB, threads=1).
// Zero fields (the production default) use that strong cost; tests lower it
// for speed the same way history_test.go's fastPass does.
func (s *Server) pinParams() (t, m uint32) {
	t, m = s.pinArgonTime, s.pinArgonMem
	if t == 0 {
		t = 3
	}
	if m == 0 {
		m = 64 * 1024
	}
	return
}

// currentTrustedDeviceID returns the id of the trusted device this request's
// cookie proves, or "" if there is none or it does not check out.
func (s *Server) currentTrustedDeviceID(r *http.Request) string {
	c, err := r.Cookie(trustedCookieName)
	if err != nil {
		return ""
	}
	id, secret, ok := parseTrustedCookie(c.Value)
	if !ok {
		return ""
	}
	dev, ok := s.lockStore.findTrustedDevice(id)
	if !ok || subtle.ConstantTimeCompare(sha256Sum(secret), dev.SecretHash) != 1 {
		return ""
	}
	return id
}

func (s *Server) setTrustedCookie(w http.ResponseWriter, id string, secret []byte) {
	http.SetCookie(w, &http.Cookie{
		Name: trustedCookieName, Value: encodeTrustedCookie(id, secret), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: trustedCookieMaxAge,
	})
}

// loginPIN unlocks with a PIN, which only works together with a trusted-
// browser cookie: either alone is useless to an attacker.
func (s *Server) loginPIN(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PIN string `json:"pin"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	now := s.clock()
	id := s.currentTrustedDeviceID(r)
	if id == "" {
		s.sleep(400 * time.Millisecond)
		http.Error(w, "this browser is not trusted; sign in with the token", http.StatusUnauthorized)
		return
	}
	if locked, until := s.lockStore.lockedUntil(id, now); locked {
		// Still count this attempt (and keep slowing it down), so a browser
		// that keeps guessing through the lockout still runs into the
		// outright revoke at pinFailsRevoke instead of being able to sit at
		// the lockout forever. The PIN itself is never even checked while
		// locked out, right or wrong.
		fails, revoked, err := s.lockStore.recordPINFailure(id, now)
		if err == nil {
			s.sleep(time.Duration(min(fails, pinFailsLockout)*300) * time.Millisecond)
		}
		if revoked {
			s.sessions.deleteByTrustedDevice(id)
			http.Error(w, "too many wrong PINs; this browser's trust was revoked, sign in with the token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(until.Sub(now).Seconds())))
		http.Error(w, "too many wrong PINs; try again later", http.StatusLocked)
		return
	}
	pin, ok := s.lockStore.pin()
	if !ok {
		http.Error(w, "no PIN is set", http.StatusUnauthorized)
		return
	}
	hash := argon2.IDKey([]byte(body.PIN), pin.Salt, pin.ArgonTime, pin.ArgonMem, 1, uint32(len(pin.Hash)))
	if subtle.ConstantTimeCompare(hash, pin.Hash) != 1 {
		fails, revoked, err := s.lockStore.recordPINFailure(id, now)
		if err == nil {
			s.sleep(time.Duration(min(fails, pinFailsLockout)*300) * time.Millisecond)
		}
		if revoked {
			s.sessions.deleteByTrustedDevice(id)
			http.Error(w, "too many wrong PINs; this browser's trust was revoked, sign in with the token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "wrong PIN", http.StatusUnauthorized)
		return
	}
	_ = s.lockStore.recordPINSuccess(id, now)
	sess := s.sessions.create(id, now)
	s.setSessionCookie(w, sess.id)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: 30 * 24 * 3600,
	})
}

// lockSession ends the caller's session (the explicit Lock button). It sits
// behind s.auth like any other endpoint, so calling it without a live
// session (nothing to lock) is simply unauthorized, like any other endpoint.
func (s *Server) lockSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, map[string]bool{"ok": true})
}

// setPIN creates or changes the PIN. The first time it is called for a given
// browser it also registers that browser as trusted; a browser that already
// holds a valid trusted cookie keeps it (changing the PIN does not need a new
// trusted device, since the PIN is shared across every trusted browser).
func (s *Server) setPIN(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PIN string `json:"pin"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := validatePIN(body.PIN); err != nil {
		bad(w, err.Error())
		return
	}
	now := s.clock()
	devID := s.currentTrustedDeviceID(r)
	var secret []byte
	if devID == "" {
		id, sec, err := s.lockStore.addTrustedDevice(browserName(r), now)
		if err != nil {
			conflict(w, err.Error())
			return
		}
		devID, secret = id, sec
	}
	t, m := s.pinParams()
	salt := randBytes(16)
	hash := argon2.IDKey([]byte(body.PIN), salt, t, m, 1, 32)
	if err := s.lockStore.setPIN(pinRecord{Salt: salt, Hash: hash, ArgonTime: t, ArgonMem: m}); err != nil {
		serverFault(w, "saving the PIN")
		return
	}
	if secret != nil {
		s.setTrustedCookie(w, devID, secret)
	}
	writeJSON(w, map[string]any{"ok": true, "device_id": devID})
}

// clearPIN turns the PIN off, which also revokes every trusted browser (a
// trusted-browser cookie alone, with no PIN, cannot unlock anything).
func (s *Server) clearPIN(w http.ResponseWriter, r *http.Request) {
	ids, err := s.lockStore.clearPIN()
	if err != nil {
		serverFault(w, "clearing the PIN")
		return
	}
	for _, id := range ids {
		s.sessions.deleteByTrustedDevice(id)
	}
	writeJSON(w, map[string]bool{"ok": true})
}

type trustedDeviceView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used"`
}

func (s *Server) listTrustedDevices(w http.ResponseWriter, r *http.Request) {
	devs := s.lockStore.trustedDevices()
	out := make([]trustedDeviceView, 0, len(devs))
	for _, d := range devs {
		out = append(out, trustedDeviceView{ID: d.ID, Name: d.Name, Created: d.Created, LastUsed: d.LastUsed})
	}
	writeJSON(w, map[string]any{"devices": out})
}

func (s *Server) revokeTrustedDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.lockStore.revokeTrustedDevice(id); err != nil {
		notFound(w, "trusted browser not found")
		return
	}
	s.sessions.deleteByTrustedDevice(id)
	writeJSON(w, map[string]bool{"ok": true})
}

// idleLockMinutes is the effective idle-lock setting: the portal settings
// override if one was ever saved, otherwise the configuration file's value.
func (s *Server) idleLockMinutes() int {
	return s.lockStore.idleLockMinutes(s.IdleLockMinutes)
}

func (s *Server) setLockingSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IdleLockMinutes int `json:"idle_lock_minutes"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := s.lockStore.setIdleLockMinutes(body.IdleLockMinutes); err != nil {
		bad(w, err.Error())
		return
	}
	s.getSettings(w, r)
}
