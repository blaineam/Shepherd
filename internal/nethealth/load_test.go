// SPDX-License-Identifier: AGPL-3.0-or-later

package nethealth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultLoadFuncReadsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
	}))
	defer srv.Close()

	fn := DefaultLoadFunc(srv.URL + "/?bytes=%d")
	if err := fn(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultLoadFuncPropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	fn := DefaultLoadFunc(srv.URL + "/?bytes=%d")
	if err := fn(context.Background()); err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
}

func TestDefaultLoadFuncRespectsContextCancellation(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 1000; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
			_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
			if flusher != nil {
				flusher.Flush()
			}
		}
		close(block)
	}))
	defer srv.Close()

	fn := DefaultLoadFunc(srv.URL + "/?bytes=%d")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_ = fn(ctx) // either a context error or nil if the tiny body finished first; must not hang

	select {
	case <-block:
		t.Fatal("server handler ran to completion: DefaultLoadFunc did not stop reading on cancellation")
	case <-time.After(200 * time.Millisecond):
		// the handler's own loop should have exited (client gone) well before this
	}
}
