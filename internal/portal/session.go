// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"encoding/hex"
	"sync"
	"time"
)

// portalSession is a server-side session created by a successful token, PIN
// or passkey unlock. All three are the same kind of session, with the same
// idle and age limits; they differ only in which credential's revocation
// ends them. The cookie only ever carries its random id, never the token,
// the PIN or anything from the passkey.
type portalSession struct {
	id              string
	trustedDeviceID string // the PIN-trusted browser that opened it, or ""
	passkeyID       string // the passkey that opened it, or ""
	created         time.Time
	lastActivity    time.Time
}

// sessionStore holds sessions in memory only: nothing here is persisted, so
// every session ends when the process restarts, matching docs/LOCKING.md.
type sessionStore struct {
	mu   sync.Mutex
	byID map[string]*portalSession
}

func newSessionStore() *sessionStore { return &sessionStore{byID: map[string]*portalSession{}} }

func randomID() string { return hex.EncodeToString(randBytes(32)) }

// create starts a new session and returns it. trustedDeviceID is "" for a
// session created by a plain token login.
func (s *sessionStore) create(trustedDeviceID string, now time.Time) *portalSession {
	sess := &portalSession{id: randomID(), trustedDeviceID: trustedDeviceID, created: now, lastActivity: now}
	s.mu.Lock()
	s.byID[sess.id] = sess
	s.mu.Unlock()
	return sess
}

// createForPasskey starts a session opened by a passkey login, so revoking
// that passkey can end it (deleteByPasskey).
func (s *sessionStore) createForPasskey(passkeyID string, now time.Time) *portalSession {
	sess := &portalSession{id: randomID(), passkeyID: passkeyID, created: now, lastActivity: now}
	s.mu.Lock()
	s.byID[sess.id] = sess
	s.mu.Unlock()
	return sess
}

// valid reports whether id names a session that has not hit the absolute
// session-age cap and has not gone idle for longer than idleMinutes (0 means
// idle locking is off). It deliberately does not extend the session: routine
// polling (status tiles, the live feed) must not itself count as activity, or
// idle locking would never trigger while a tab merely sits open. Only touch
// extends it; see the comment on auth/authPassive in portal.go for which
// endpoints call which.
func (s *sessionStore) valid(id string, idleMinutes int, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return false
	}
	if now.Sub(sess.created) > maxSessionAge {
		delete(s.byID, id)
		return false
	}
	if idleMinutes > 0 && now.Sub(sess.lastActivity) > time.Duration(idleMinutes)*time.Minute {
		delete(s.byID, id)
		return false
	}
	return true
}

// touch records real activity on a session, sliding its idle window forward.
func (s *sessionStore) touch(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return false
	}
	sess.lastActivity = now
	return true
}

// delete ends one session (explicit lock, or logging out).
func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	delete(s.byID, id)
	s.mu.Unlock()
}

// deleteByTrustedDevice ends every session that was opened with a given
// trusted browser's PIN, used when that browser is revoked.
func (s *sessionStore) deleteByTrustedDevice(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	for k, v := range s.byID {
		if v.trustedDeviceID == id {
			delete(s.byID, k)
		}
	}
	s.mu.Unlock()
}

// deleteByPasskey ends every session opened with a given passkey, used when
// that passkey is revoked.
func (s *sessionStore) deleteByPasskey(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	for k, v := range s.byID {
		if v.passkeyID == id {
			delete(s.byID, k)
		}
	}
	s.mu.Unlock()
}

// count reports how many sessions are currently live (tests only).
func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}
