// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"context"
	"errors"
	"sync"
)

// Source delivers ARP frames. It is read-only by construction: there is no
// way to send through it.
type Source interface {
	// Next blocks for the next frame. It returns ctx.Err() when ctx ends,
	// ErrClosed after Close, an error wrapping ErrMalformed or ErrNotARP for
	// a frame that could not be decoded (the caller should carry on), and
	// any other error for a failed capture.
	Next(ctx context.Context) (Frame, error)
	Close() error
}

// packetReader is the raw layer under a byteSource: whole Ethernet frames.
type packetReader interface {
	ReadPacket(ctx context.Context) ([]byte, error)
	Close() error
}

// byteSource decodes raw packets from a packetReader into Frames. The
// platform files only supply the packetReader.
type byteSource struct {
	r packetReader
}

func newByteSource(r packetReader) *byteSource { return &byteSource{r: r} }

func (s *byteSource) Next(ctx context.Context) (Frame, error) {
	b, err := s.r.ReadPacket(ctx)
	if err != nil {
		return Frame{}, err
	}
	return ParseFrame(b)
}

func (s *byteSource) Close() error { return s.r.Close() }

// FakeSource is an in-memory Source for tests and for replaying captures.
type FakeSource struct {
	mu       sync.Mutex
	queue    []fakeItem
	wake     chan struct{}
	finished bool
	closed   bool
}

type fakeItem struct {
	frame Frame
	raw   []byte
	err   error
	isRaw bool
}

// NewFakeSource returns an empty FakeSource.
func NewFakeSource() *FakeSource { return &FakeSource{wake: make(chan struct{}, 1)} }

func (s *FakeSource) push(it fakeItem) {
	s.mu.Lock()
	s.queue = append(s.queue, it)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Push queues a decoded frame.
func (s *FakeSource) Push(f Frame) { s.push(fakeItem{frame: f}) }

// PushRaw queues raw bytes, decoded with ParseFrame when read.
func (s *FakeSource) PushRaw(b []byte) { s.push(fakeItem{raw: b, isRaw: true}) }

// PushErr queues an error to be returned by Next.
func (s *FakeSource) PushErr(err error) { s.push(fakeItem{err: err}) }

// Finish makes Next return ErrClosed once the queue is drained.
func (s *FakeSource) Finish() {
	s.mu.Lock()
	s.finished = true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Next implements Source.
func (s *FakeSource) Next(ctx context.Context) (Frame, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return Frame{}, ErrClosed
		}
		if len(s.queue) > 0 {
			it := s.queue[0]
			s.queue = s.queue[1:]
			s.mu.Unlock()
			switch {
			case it.err != nil:
				return Frame{}, it.err
			case it.isRaw:
				return ParseFrame(it.raw)
			}
			return it.frame, nil
		}
		fin := s.finished
		s.mu.Unlock()
		if fin {
			return Frame{}, ErrClosed
		}
		select {
		case <-ctx.Done():
			return Frame{}, ctx.Err()
		case <-s.wake:
		}
	}
}

// Close implements Source. It is idempotent.
func (s *FakeSource) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Closed reports whether Close was called.
func (s *FakeSource) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

var _ Source = (*FakeSource)(nil)

func isRecoverable(err error) bool {
	return errors.Is(err, ErrMalformed) || errors.Is(err, ErrNotARP)
}
