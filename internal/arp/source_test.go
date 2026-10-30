// SPDX-License-Identifier: AGPL-3.0-or-later

package arp

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFakeSourceOrderAndFinish(t *testing.T) {
	s := NewFakeSource()
	f := NewAnnounce(stable(1), ip(10))
	raw, _ := f.Marshal()
	s.Push(f)
	s.PushRaw(raw)
	s.PushRaw([]byte{1, 2})
	boom := errors.New("boom")
	s.PushErr(boom)
	s.Finish()
	ctx := context.Background()
	if got, err := s.Next(ctx); err != nil || got != f {
		t.Fatalf("first: %+v %v", got, err)
	}
	if got, err := s.Next(ctx); err != nil || got != f {
		t.Fatalf("raw: %+v %v", got, err)
	}
	if _, err := s.Next(ctx); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad raw: %v", err)
	}
	if _, err := s.Next(ctx); !errors.Is(err, boom) {
		t.Fatalf("pushed err: %v", err)
	}
	if _, err := s.Next(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("drained: %v", err)
	}
}

func TestFakeSourceBlocksUntilPushOrCancel(t *testing.T) {
	s := NewFakeSource()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Next(ctx); done <- err }()
	time.Sleep(20 * time.Millisecond)
	s.Push(NewAnnounce(stable(1), ip(10)))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := s.Next(ctx); done <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestFakeSourceClose(t *testing.T) {
	s := NewFakeSource()
	done := make(chan error, 1)
	go func() { _, err := s.Next(context.Background()); done <- err }()
	time.Sleep(20 * time.Millisecond)
	if s.Closed() {
		t.Fatal("closed early")
	}
	s.Close()
	s.Close()
	if err := <-done; !errors.Is(err, ErrClosed) || !s.Closed() {
		t.Fatalf("got %v", err)
	}
}

type fakeReader struct {
	pkts   [][]byte
	err    error
	closed bool
}

func (r *fakeReader) ReadPacket(ctx context.Context) ([]byte, error) {
	if len(r.pkts) == 0 {
		return nil, r.err
	}
	p := r.pkts[0]
	r.pkts = r.pkts[1:]
	return p, nil
}
func (r *fakeReader) Close() error { r.closed = true; return nil }

func TestByteSourceDecodes(t *testing.T) {
	good, _ := NewAnnounce(stable(1), ip(10)).Marshal()
	r := &fakeReader{pkts: [][]byte{good, {0, 1}}, err: ErrClosed}
	s := newByteSource(r)
	if f, err := s.Next(context.Background()); err != nil || f.SenderIP != ip(10) {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("%v", err)
	}
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
	s.Close()
	if !r.closed {
		t.Fatal("reader not closed")
	}
}

func TestOpenReportsAnError(t *testing.T) {
	// Unprivileged and without a real interface this must fail cleanly on
	// every platform: ErrUnsupported off Linux, a lookup error on Linux.
	if _, _, err := Open("shepherd-no-such-iface0"); err == nil {
		t.Fatal("Open succeeded")
	}
}
