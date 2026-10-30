// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import "time"

// EventKind classifies a registry change.
type EventKind string

const (
	EventNewDevice    EventKind = "new-device"
	EventRenamed      EventKind = "renamed"
	EventUpdated      EventKind = "updated" // excluded, tags, type, notes
	EventMerged       EventKind = "merged"
	EventSplit        EventKind = "split"
	EventDeleted      EventKind = "deleted"
	EventGroupCreated EventKind = "group-created"
	EventGroupUpdated EventKind = "group-updated"
	EventGroupDeleted EventKind = "group-deleted"
	EventGroupMembers EventKind = "group-members" // membership changed
)

// Event describes one change. Events are emitted for local changes only;
// records arriving through Import or Load are silent so a synced replica
// does not re-announce devices its peers already know.
type Event struct {
	Kind      EventKind
	Time      time.Time
	DeviceID  string
	DeviceIDs []string // bulk and group-membership changes
	GroupID   string
	OldName   string
	NewName   string
	Device    *Device // snapshot for new-device
}

// Subscribe registers fn to be called for every event. Callbacks run on the
// goroutine that made the change, after the registry lock is released, so
// they may call back into the registry. It returns an unsubscribe function.
func (r *Registry) Subscribe(fn func(Event)) (unsubscribe func()) {
	r.subMu.Lock()
	r.subSeq++
	id := r.subSeq
	r.subs[id] = fn
	r.subMu.Unlock()
	return func() {
		r.subMu.Lock()
		delete(r.subs, id)
		r.subMu.Unlock()
	}
}

// Events returns a buffered channel of events. When the buffer is full new
// events are dropped rather than blocking the registry. Call cancel to stop;
// the channel is closed.
func (r *Registry) Events(buffer int) (<-chan Event, func()) {
	if buffer < 1 {
		buffer = 1
	}
	ch := make(chan Event, buffer)
	var closed bool
	var mu = make(chan struct{}, 1)
	unsub := r.Subscribe(func(e Event) {
		mu <- struct{}{}
		defer func() { <-mu }()
		if closed {
			return
		}
		select {
		case ch <- e:
		default:
		}
	})
	return ch, func() {
		unsub()
		mu <- struct{}{}
		if !closed {
			closed = true
			close(ch)
		}
		<-mu
	}
}

func (r *Registry) emit(evs []Event) {
	if len(evs) == 0 {
		return
	}
	r.subMu.RLock()
	fns := make([]func(Event), 0, len(r.subs))
	for _, f := range r.subs {
		fns = append(fns, f)
	}
	r.subMu.RUnlock()
	for _, e := range evs {
		for _, f := range fns {
			f(e)
		}
	}
}
