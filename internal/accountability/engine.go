// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Options configures an Engine. Sender is required; everything else has a
// sensible default.
type Options struct {
	// Dir, when set, is where ContactsFile and PendingFile persist. It is
	// created (mode 0700) and loaded on New.
	Dir   string
	Clock Clock // default SystemClock
	Codec Codec // default PlainCodec
	// NewID produces contact and subscription IDs; default random.
	NewID func() string

	// Sender delivers composed emails. Required.
	Sender Sender
	// From is the Message.From handed to Sender with every email. Optional:
	// SMTPSender (and so RelaySender) always uses its own relay's
	// SMTPConfig.From for both the envelope and the header, which is what
	// lets a relay changed in the portal change the From address too
	// without rebuilding the engine. It only matters to a custom Sender.
	From string

	// ImmediateWindow is the dedupe window applied to immediate-mode
	// subscriptions (design rule 2); default 5 minutes.
	ImmediateWindow time.Duration
	// TickEvery is how often the background loop checks for digests
	// whose window has closed; default 30 seconds. It has no effect on
	// when a window closes, only on how promptly a closed one is noticed.
	TickEvery time.Duration
	// MaxDomains caps how many distinct domains a detailed email lists
	// per item; default 5. Extra occurrences still count toward Count.
	MaxDomains int

	// ScopeLabel turns a Scope into the phrase an email uses for "roughly
	// which device/group" (design rule 1). When unset, emails use a
	// generic phrase that names neither the group nor the device.
	ScopeLabel func(Scope) string
	// ItemLabel turns a catalog, list or app ID into a display name.
	// When unset, defaultLabel title-cases the ID.
	ItemLabel func(string) string
}

// Engine is the accountability-partner engine: it stores contacts and
// subscriptions, implements Intake, accumulates matching accesses per
// subscription, and sends the resulting emails on a digest or immediate
// schedule. It is safe for concurrent use.
type Engine struct {
	mu sync.Mutex

	dir   string
	clock Clock
	codec Codec
	newID func() string

	sender          Sender
	from            string
	immediateWindow time.Duration
	tickEvery       time.Duration
	maxDomains      int
	scopeLabel      func(Scope) string
	itemLabel       func(string) string

	contacts map[string]Contact
	subs     map[string]Subscription
	pending  map[string]*pendingDigest

	sendLog []SendRecord

	quit chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

// SendRecord is one past send attempt, kept for observability and tests.
type SendRecord struct {
	SubscriptionID string
	ContactID      string
	To             string
	Time           time.Time
	Result         Result
}

const maxSendLog = 50

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// New creates an engine, loading any saved state from Options.Dir, and
// starts its background digest loop. Call Close to stop it and flush state.
func New(o Options) (*Engine, error) {
	if o.Sender == nil {
		return nil, fmt.Errorf("%w: a Sender is required", ErrInvalid)
	}
	e := &Engine{
		dir: o.Dir, clock: o.Clock, codec: o.Codec, newID: o.NewID,
		sender: o.Sender, from: o.From,
		immediateWindow: o.ImmediateWindow, tickEvery: o.TickEvery, maxDomains: o.MaxDomains,
		scopeLabel: o.ScopeLabel, itemLabel: o.ItemLabel,
		contacts: map[string]Contact{}, subs: map[string]Subscription{}, pending: map[string]*pendingDigest{},
		quit: make(chan struct{}),
	}
	if e.clock == nil {
		e.clock = SystemClock{}
	}
	if e.codec == nil {
		e.codec = PlainCodec{}
	}
	if e.newID == nil {
		e.newID = randomID
	}
	if e.immediateWindow <= 0 {
		e.immediateWindow = defaultImmediateWindow
	}
	if e.tickEvery <= 0 {
		e.tickEvery = 30 * time.Second
	}
	if e.maxDomains <= 0 {
		e.maxDomains = 5
	}
	if e.scopeLabel == nil {
		e.scopeLabel = defaultScopeLabel
	}
	if e.itemLabel == nil {
		e.itemLabel = defaultLabel
	}
	if e.dir != "" {
		if err := os.MkdirAll(e.dir, 0o700); err != nil {
			return nil, err
		}
		if err := e.load(); err != nil {
			return nil, err
		}
	}
	e.wg.Add(1)
	go e.run()
	return e, nil
}

func (e *Engine) contactsPath() string { return filepath.Join(e.dir, ContactsFile) }
func (e *Engine) pendingPath() string  { return filepath.Join(e.dir, PendingFile) }

func (e *Engine) load() error {
	var store storeDoc
	if err := loadJSON(e.codec, e.contactsPath(), &store); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		e.importStoreLocked(store)
	}
	var pend pendingDoc
	if err := loadJSON(e.codec, e.pendingPath(), &pend); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		e.importPendingLocked(pend)
	}
	return nil
}

// Save flushes contacts, subscriptions and in-progress digests to disk. New
// and Close call it automatically; call it yourself after a batch of changes
// made with Options.Dir unset in earlier tests is never necessary, since
// every mutating method already saves.
func (e *Engine) Save() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.saveLocked()
}

func (e *Engine) saveLocked() error {
	if err := e.saveStoreLocked(); err != nil {
		return err
	}
	return e.savePendingLocked()
}

// Close stops the background loop and saves final state.
func (e *Engine) Close() error {
	var err error
	e.once.Do(func() {
		close(e.quit)
		e.wg.Wait()
		e.mu.Lock()
		err = e.saveLocked()
		e.mu.Unlock()
	})
	return err
}

func (e *Engine) run() {
	defer e.wg.Done()
	tk := e.clock.NewTicker(e.tickEvery)
	defer tk.Stop()
	for {
		select {
		case <-tk.C():
			e.Tick()
		case <-e.quit:
			return
		}
	}
}

// --- Contacts ---

// AddContact creates a contact. name and email are trimmed; email must
// parse as an RFC 5322 address.
func (e *Engine) AddContact(name, email string) (Contact, error) {
	c := Contact{ID: e.newID(), Name: strings.TrimSpace(name), Email: strings.TrimSpace(email)}
	e.mu.Lock()
	defer e.mu.Unlock()
	c.CreatedAt = e.clock.Now()
	if err := c.validate(); err != nil {
		return Contact{}, err
	}
	e.contacts[c.ID] = c
	if err := e.saveStoreLocked(); err != nil {
		return Contact{}, err
	}
	return c, nil
}

// Contact returns one contact by ID.
func (e *Engine) Contact(id string) (Contact, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.contacts[id]
	if !ok {
		return Contact{}, ErrNotFound
	}
	return c, nil
}

// Contacts returns every contact, sorted by ID.
func (e *Engine) Contacts() []Contact {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Contact, 0, len(e.contacts))
	for _, c := range e.contacts {
		out = append(out, c.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RemoveContact deletes a contact and every subscription of theirs (design
// rule 4: a subscription never outlives the contact it emails).
func (e *Engine) RemoveContact(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.contacts[id]; !ok {
		return ErrNotFound
	}
	delete(e.contacts, id)
	for subID, s := range e.subs {
		if s.ContactID == id {
			delete(e.subs, subID)
			delete(e.pending, subID)
		}
	}
	return e.saveLocked()
}

// --- Subscriptions ---

// AddSubscription creates a subscription. Its ID is assigned by the engine;
// any ID on sub is ignored. ContactID must name an existing contact.
func (e *Engine) AddSubscription(sub Subscription) (Subscription, error) {
	sub = sub.clone()
	sub.ID = e.newID()
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.contacts[sub.ContactID]; !ok {
		return Subscription{}, fmt.Errorf("%w: contact %q", ErrNotFound, sub.ContactID)
	}
	sub.CreatedAt = e.clock.Now()
	if err := sub.validate(); err != nil {
		return Subscription{}, err
	}
	e.subs[sub.ID] = sub
	if err := e.saveStoreLocked(); err != nil {
		return Subscription{}, err
	}
	return sub, nil
}

// Subscription returns one subscription by ID.
func (e *Engine) Subscription(id string) (Subscription, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.subs[id]
	if !ok {
		return Subscription{}, ErrNotFound
	}
	return s, nil
}

// Subscriptions returns every subscription, sorted by ID.
func (e *Engine) Subscriptions() []Subscription {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Subscription, 0, len(e.subs))
	for _, s := range e.subs {
		out = append(out, s.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SubscriptionsFor returns contactID's subscriptions, sorted by ID.
func (e *Engine) SubscriptionsFor(contactID string) []Subscription {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Subscription
	for _, s := range e.subs {
		if s.ContactID == contactID {
			out = append(out, s.clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RemoveSubscription deletes a subscription and discards any digest in
// progress for it.
func (e *Engine) RemoveSubscription(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.subs[id]; !ok {
		return ErrNotFound
	}
	delete(e.subs, id)
	delete(e.pending, id)
	return e.saveLocked()
}

// --- Intake ---

// Record implements Intake: it files ev against every subscription whose
// scope, watched items and trigger mode match, accumulating it into that
// subscription's pending digest. An event missing its required Item field is
// dropped. Record never blocks on sending mail; it only ever writes to its
// own pending state.
func (e *Engine) Record(ev AccessEvent) {
	if err := ev.validate(); err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ev.Time.IsZero() {
		ev.Time = e.clock.Now()
	}
	now := e.clock.Now()
	changed := false
	for _, sub := range e.subs {
		if !sub.Matches(ev) {
			continue
		}
		p := e.pending[sub.ID]
		if p == nil {
			p = newPendingDigest(sub.ID, now, now.Add(windowFor(sub, e.immediateWindow)))
			e.pending[sub.ID] = p
		}
		p.add(ev)
		changed = true
	}
	if changed {
		_ = e.savePendingLocked()
	}
}

var _ Intake = (*Engine)(nil)

// --- Digest delivery ---

// Tick sends every digest whose window has closed. It is called by the
// background loop on Options.TickEvery, and can be called directly by tests
// using a FakeClock instead of waiting on the loop.
func (e *Engine) Tick() {
	e.mu.Lock()
	now := e.clock.Now()
	var due []string
	for id, p := range e.pending {
		if !p.FlushAt.After(now) {
			due = append(due, id)
		}
	}
	sort.Strings(due) // deterministic order for tests and logs
	type job struct {
		sub Subscription
		p   *pendingDigest
	}
	jobs := make([]job, 0, len(due))
	for _, id := range due {
		sub, ok := e.subs[id]
		p := e.pending[id]
		delete(e.pending, id)
		if !ok {
			continue // subscription removed while its digest was pending
		}
		jobs = append(jobs, job{sub, p})
	}
	if len(due) > 0 {
		_ = e.savePendingLocked()
	}
	e.mu.Unlock()

	for _, j := range jobs {
		e.deliver(j.sub, j.p)
	}
}

func (e *Engine) deliver(sub Subscription, p *pendingDigest) {
	e.mu.Lock()
	contact, ok := e.contacts[sub.ContactID]
	from := e.from
	scopeLabel := e.scopeLabel(sub.Scope)
	itemLabel := e.itemLabel
	maxDomains := e.maxDomains
	e.mu.Unlock()
	if !ok {
		return // contact removed while the digest was pending
	}

	data := emailData{
		ContactName: contact.Name,
		ScopeLabel:  scopeLabel,
		Mode:        sub.Mode,
		Detail:      sub.Detail,
		WindowStart: p.Opened,
		WindowEnd:   lastSeen(p),
		Total:       p.Total,
		Items:       sortedItemLines(p, itemLabel, sub.Detail == DetailDetailed, maxDomains),
	}
	subject, body, err := renderEmail(data)
	result := Result{Outcome: OutcomeInvalid, Err: err}
	if err == nil {
		msg := Message{From: from, To: contact.Email, Subject: subject, Body: body}
		result = e.sender.Send(context.Background(), msg)
	}

	e.mu.Lock()
	e.sendLog = append(e.sendLog, SendRecord{
		SubscriptionID: sub.ID, ContactID: sub.ContactID, To: contact.Email,
		Time: e.clock.Now(), Result: result,
	})
	if len(e.sendLog) > maxSendLog {
		e.sendLog = e.sendLog[len(e.sendLog)-maxSendLog:]
	}
	e.mu.Unlock()
}

func lastSeen(p *pendingDigest) time.Time {
	last := p.Opened
	for _, it := range p.Items {
		if it.Last.After(last) {
			last = it.Last
		}
	}
	return last
}

// SendLog returns the most recent send attempts (oldest first), for
// observability and tests. At most maxSendLog (50) are kept.
func (e *Engine) SendLog() []SendRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]SendRecord(nil), e.sendLog...)
}

// Pending reports how many subscriptions currently have an accumulating
// digest, for observability and tests.
func (e *Engine) Pending() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.pending)
}
