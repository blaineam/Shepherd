// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

import (
	"errors"
	"strings"
	"time"
)

var (
	// ErrLocked means the history is encrypted and not unlocked yet.
	ErrLocked = errors.New("history is locked")
	// ErrNotSupported means the operation does not apply to this history mode.
	ErrNotSupported = errors.New("not supported in this history mode")
	// ErrWrongPassphrase means the passphrase did not unlock the history.
	ErrWrongPassphrase = errors.New("wrong passphrase")
)

// HistoryQuery selects past entries. Zero values mean "no limit" on that field.
type HistoryQuery struct {
	From, To time.Time
	Client   string // exact device address
	Action   string // allowed, cached, blocked or error
	Contains string // case-insensitive substring of the domain or reason
	Limit    int    // keep only the newest Limit matches
}

// Match reports whether e satisfies the query (Limit excluded).
func (q HistoryQuery) Match(e Entry) bool {
	if !q.From.IsZero() && e.Time.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && e.Time.After(q.To) {
		return false
	}
	if q.Client != "" && e.Client != q.Client {
		return false
	}
	if q.Action != "" && e.Action != q.Action {
		return false
	}
	if q.Contains != "" {
		needle := strings.ToLower(q.Contains)
		if !strings.Contains(strings.ToLower(e.Name), needle) && !strings.Contains(strings.ToLower(e.Reason), needle) {
			return false
		}
	}
	return true
}

// Span is the time range a history currently holds.
type Span struct {
	Oldest  time.Time `json:"oldest"`
	Newest  time.Time `json:"newest"`
	Skipped int       `json:"skipped,omitempty"` // unreadable or tampered frames left out of a result
}

// HistorySource is what the portal reads past entries from.
type HistorySource interface {
	// Mode is "memory" or "encrypted".
	Mode() string
	// Locked reports whether the history needs a passphrase before it can be read.
	Locked() bool
	// Initialized reports whether a passphrase (or key) already exists.
	Initialized() bool
	Query(HistoryQuery) ([]Entry, Span, error)
	// Unlock supplies the passphrase. On first use it creates the passphrase.
	Unlock(passphrase string) error
}

// Newest returns the last n entries of es (all of them when n <= 0).
func Newest(es []Entry, n int) []Entry {
	if n > 0 && len(es) > n {
		return es[len(es)-n:]
	}
	return es
}

// MemoryHistory serves queries from the in-memory ring. It is the default and
// stores nothing on disk.
type MemoryHistory struct{ Log *QueryLog }

func (MemoryHistory) Mode() string        { return "memory" }
func (MemoryHistory) Locked() bool        { return false }
func (MemoryHistory) Initialized() bool   { return true }
func (MemoryHistory) Unlock(string) error { return ErrNotSupported }

func (m MemoryHistory) Query(q HistoryQuery) ([]Entry, Span, error) {
	all := m.Log.All()
	var span Span
	var out []Entry
	if len(all) > 0 {
		span = Span{Oldest: all[0].Time, Newest: all[len(all)-1].Time}
	}
	for _, e := range all {
		if q.Match(e) {
			out = append(out, e)
		}
	}
	return Newest(out, q.Limit), span, nil
}
