// SPDX-License-Identifier: AGPL-3.0-or-later

package intercept

import (
	"errors"
	"testing"
	"time"
)

func TestFakeSenderRecordsFrames(t *testing.T) {
	s := NewFakeSender()
	if err := s.Send(Frame{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(Frame{4, 5}); err != nil {
		t.Fatal(err)
	}
	got := s.Frames()
	if len(got) != 2 || string(got[0]) != "\x01\x02\x03" || string(got[1]) != "\x04\x05" {
		t.Fatalf("Frames() = %v", got)
	}
	// Mutating the input after Send must not retroactively change what
	// was recorded: FakeSender copies.
	f := Frame{9, 9, 9}
	s.Send(f)
	f[0] = 0
	if s.Frames()[2][0] != 9 {
		t.Fatal("FakeSender aliased the caller's slice")
	}
}

func TestFakeSenderError(t *testing.T) {
	s := NewFakeSender()
	boom := errors.New("boom")
	s.SetError(boom)
	if err := s.Send(Frame{1}); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if len(s.Frames()) != 0 {
		t.Fatal("a failed send should not be recorded")
	}
	s.SetError(nil)
	if err := s.Send(Frame{1}); err != nil {
		t.Fatal(err)
	}
}

func TestFakeSenderBlockReleases(t *testing.T) {
	s := NewFakeSender()
	release := s.Block()
	done := make(chan error, 1)
	go func() { done <- s.Send(Frame{1}) }()
	select {
	case <-done:
		t.Fatal("Send returned before release")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	release() // idempotent
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Send never returned after release")
	}
}

func TestFakeSenderWatch(t *testing.T) {
	s := NewFakeSender()
	ch, stop := s.Watch()
	s.Send(Frame{1})
	got := waitForFrame(t, ch, time.Second)
	if string(got) != "\x01" {
		t.Fatalf("got %v", got)
	}
	stop()
	s.Send(Frame{2})
	select {
	case f := <-ch:
		t.Fatalf("watcher still receiving after stop: %v", f)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestSendWithTimeoutBoundsAWedgedSender(t *testing.T) {
	s := NewFakeSender()
	s.Block()
	start := time.Now()
	err := sendWithTimeout(s, Frame{1}, 30*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("sendWithTimeout did not bound the wait: %s", elapsed)
	}
}

type panickingSender struct{}

func (panickingSender) Send(Frame) error { panic("boom") }

func TestSendWithTimeoutRecoversAPanickingSender(t *testing.T) {
	err := sendWithTimeout(panickingSender{}, Frame{1}, time.Second)
	if err == nil {
		t.Fatal("expected an error from the panic")
	}
}

func TestSendWithTimeoutNilSender(t *testing.T) {
	if err := sendWithTimeout(nil, Frame{1}, time.Second); err == nil {
		t.Fatal("expected an error for a nil Sender")
	}
}

func TestSendWithTimeoutDefaultsNonPositiveTimeout(t *testing.T) {
	s := NewFakeSender()
	if err := sendWithTimeout(s, Frame{1}, 0); err != nil {
		t.Fatal(err)
	}
	if len(s.Frames()) != 1 {
		t.Fatal("frame not sent")
	}
}

// selfBoundedFakeSender is a FakeSender that also claims to be
// selfBounded, so sendWithTimeout takes the direct, no-goroutine path for
// it exactly as it would for a real rawSender.
type selfBoundedFakeSender struct{ *FakeSender }

func (selfBoundedFakeSender) selfBounded() {}

func TestSendWithTimeoutTakesTheDirectPathForASelfBoundedSender(t *testing.T) {
	s := selfBoundedFakeSender{NewFakeSender()}
	if err := sendWithTimeout(s, Frame{1, 2, 3}, time.Second); err != nil {
		t.Fatal(err)
	}
	got := s.FakeSender.Frames()
	if len(got) != 1 || !bytesEqual(got[0], Frame{1, 2, 3}) {
		t.Fatalf("Frames() = %v, want one frame {1,2,3}", got)
	}
}

func TestSendWithTimeoutDirectPathStillRecoversAPanic(t *testing.T) {
	err := sendWithTimeout(struct {
		panickingSender
		selfBounded
	}{}, Frame{1}, time.Second)
	if err == nil {
		t.Fatal("expected an error from the panic")
	}
}

func TestSendWithTimeoutDirectPathStillReportsAnError(t *testing.T) {
	s := selfBoundedFakeSender{NewFakeSender()}
	s.SetError(errors.New("send failed"))
	if err := sendWithTimeout(s, Frame{1}, time.Second); err == nil {
		t.Fatal("expected the Sender's own error")
	}
}

func bytesEqual(a, b Frame) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
