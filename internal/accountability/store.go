// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import "sort"

const storeVersion = 1

// storeDoc is the on-disk shape of ContactsFile.
type storeDoc struct {
	Version       int            `json:"version"`
	Contacts      []Contact      `json:"contacts"`
	Subscriptions []Subscription `json:"subscriptions"`
}

// pendingDoc is the on-disk shape of PendingFile.
type pendingDoc struct {
	Version int                       `json:"version"`
	Pending map[string]*pendingDigest `json:"pending"`
}

func (e *Engine) exportStoreLocked() storeDoc {
	doc := storeDoc{Version: storeVersion}
	for _, c := range e.contacts {
		doc.Contacts = append(doc.Contacts, c)
	}
	for _, s := range e.subs {
		doc.Subscriptions = append(doc.Subscriptions, s)
	}
	sort.Slice(doc.Contacts, func(i, j int) bool { return doc.Contacts[i].ID < doc.Contacts[j].ID })
	sort.Slice(doc.Subscriptions, func(i, j int) bool { return doc.Subscriptions[i].ID < doc.Subscriptions[j].ID })
	return doc
}

func (e *Engine) importStoreLocked(doc storeDoc) {
	e.contacts = make(map[string]Contact, len(doc.Contacts))
	for _, c := range doc.Contacts {
		e.contacts[c.ID] = c
	}
	e.subs = make(map[string]Subscription, len(doc.Subscriptions))
	for _, s := range doc.Subscriptions {
		e.subs[s.ID] = s
	}
}

func (e *Engine) exportPendingLocked() pendingDoc {
	doc := pendingDoc{Version: storeVersion, Pending: make(map[string]*pendingDigest, len(e.pending))}
	for id, p := range e.pending {
		doc.Pending[id] = p
	}
	return doc
}

func (e *Engine) importPendingLocked(doc pendingDoc) {
	e.pending = make(map[string]*pendingDigest, len(doc.Pending))
	for id, p := range doc.Pending {
		if p != nil {
			e.pending[id] = p
		}
	}
}

// saveStoreLocked and savePendingLocked are no-ops when Dir is unset
// (memory-only engines, used freely in tests that do not exercise restart
// recovery).
func (e *Engine) saveStoreLocked() error {
	if e.dir == "" {
		return nil
	}
	return saveJSON(e.codec, e.contactsPath(), e.exportStoreLocked())
}

func (e *Engine) savePendingLocked() error {
	if e.dir == "" {
		return nil
	}
	return saveJSON(e.codec, e.pendingPath(), e.exportPendingLocked())
}
