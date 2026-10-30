// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"fmt"
	"sync"
	"time"
)

// Frame is a raw outbound Ethernet frame: whatever bytes go on the wire.
// The Spoofer builds one by marshaling an internal/arp.Frame; the Relay
// builds one by copying and lightly rewriting an inbound frame it did not
// build itself.
type Frame []byte

// Sender transmits a raw frame on an interface. It is the mirror image of
// internal/arp's Source.Next: Next takes nothing and returns a Frame,
// Send takes a Frame and returns only an error. Nothing in this package
// calls a real Sender's Send outside this package's own tests; the only
// concrete implementation that touches a socket is open_linux.go, which
// needs CAP_NET_RAW.
type Sender interface {
	Send(Frame) error
}

// FakeSender is an in-memory Sender for tests. It records every sent
// frame and can be told to fail or to block, so tests can prove the
// Controller's bounded send timeout actually bounds a wedged Sender.
type FakeSender struct {
	mu       sync.Mutex
	frames   []Frame
	err      error
	blockCh  chan struct{}
	watchers []chan Frame
}

// NewFakeSender returns an empty FakeSender.
func NewFakeSender() *FakeSender { return &FakeSender{} }

// Send implements Sender.
func (s *FakeSender) Send(f Frame) error {
	s.mu.Lock()
	block := s.blockCh
	err := s.err
	s.mu.Unlock()

	if block != nil {
		<-block
	}
	if err != nil {
		return err
	}

	cp := append(Frame(nil), f...)
	s.mu.Lock()
	s.frames = append(s.frames, cp)
	watchers := append([]chan Frame(nil), s.watchers...)
	s.mu.Unlock()

	for _, w := range watchers {
		select {
		case w <- cp:
		default:
		}
	}
	return nil
}

// Frames returns a snapshot of every frame sent so far, in order.
func (s *FakeSender) Frames() []Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Frame(nil), s.frames...)
}

// SetError makes every subsequent Send fail with err. Pass nil to clear it.
func (s *FakeSender) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Block makes every subsequent Send call hang until the returned release
// function is called, to simulate a wedged Sender. Safe to call release
// more than once.
func (s *FakeSender) Block() (release func()) {
	ch := make(chan struct{})
	s.mu.Lock()
	s.blockCh = ch
	s.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// Watch returns a channel that receives a copy of every frame sent from
// now on, and a stop function that unregisters it. The channel is
// generously buffered; a test that does not keep up loses notifications,
// not correctness (Frames still has everything).
func (s *FakeSender) Watch() (<-chan Frame, func()) {
	ch := make(chan Frame, 64)
	s.mu.Lock()
	s.watchers = append(s.watchers, ch)
	s.mu.Unlock()
	stop := func() {
		s.mu.Lock()
		for i, w := range s.watchers {
			if w == ch {
				s.watchers = append(s.watchers[:i], s.watchers[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}
	return ch, stop
}

var _ Sender = (*FakeSender)(nil)

// selfBounded is implemented by a Sender whose own Send call already
// cannot block past some bound it enforces itself — rawSender's socket
// carries a kernel-level SO_SNDTIMEO, set once at Open time, so a single
// Sendto can never hang. sendWithTimeout checks for this and, when
// present, skips its own goroutine and timer: wrapping an already-bounded
// call in another one only adds a goroutine spawn and a timer allocation
// to every single packet, for no further protection. At the relay's real
// packet rate (tens of thousands of frames per second during a sustained
// transfer) that per-packet overhead was measured to matter far more than
// the raw syscalls underneath it. FakeSender does not implement this, so
// every existing safety test (Block(), a deliberately wedged Sender) goes
// on exercising the slow, fully defensive path unchanged.
type selfBounded interface{ selfBounded() }

// sendWithTimeout calls sender.Send(f) but never blocks the caller longer
// than timeout, even if Send never returns and even if Send panics. This
// is what keeps a wedged or broken Sender out of the Controller's safety
// path (PanicStop, the health loop, Unsteer's corrective revert): none of
// them ever makes an unbounded blocking call.
//
// A genuinely wedged Send leaves its goroutine running after the timeout;
// that goroutine finishes (or leaks forever) on its own, unobserved. There
// is no way to cancel it from here, because Sender.Send intentionally
// takes no context — it is a one-method mirror of internal/arp's
// Source.Next.
func sendWithTimeout(sender Sender, f Frame, timeout time.Duration) error {
	if sender == nil {
		return fmt.Errorf("intercept: no Sender configured")
	}
	if timeout <= 0 {
		timeout = DefaultSendTimeout
	}
	if _, ok := sender.(selfBounded); ok {
		return sendRecovered(sender, f)
	}
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("intercept: Send panicked: %v", r)
			}
		}()
		done <- sender.Send(f)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("intercept: Send timed out after %s", timeout)
	}
}

// sendRecovered calls sender.Send(f) directly (no goroutine, no timer),
// recovering a panic the same way the defensive path does. Only ever used
// for a Sender that reports selfBounded — see its doc comment.
func sendRecovered(sender Sender, f Frame) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("intercept: Send panicked: %v", r)
		}
	}()
	return sender.Send(f)
}
