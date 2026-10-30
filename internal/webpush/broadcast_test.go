// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBroadcastDeliversRetiresAndRecords(t *testing.T) {
	statusFor := func(path string) int {
		switch {
		case strings.HasSuffix(path, "/ok"):
			return 201
		case strings.HasSuffix(path, "/gone"):
			return 410
		case strings.HasSuffix(path, "/slow"):
			return 503
		}
		return 400
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(statusFor(r.URL.Path))
	}))
	defer srv.Close()
	keys, _ := GenerateVAPIDKeys()
	sender, _ := NewSender(keys, "mailto:ops@example.com")
	sender.Client = srv.Client()
	sender.Validate = AllowAnyEndpoint
	store := NewStore(StoreOptions{Validate: AllowAnyEndpoint})
	d := newDevice(t)
	ids := map[string]string{}
	for _, p := range []string{"ok", "gone", "slow", "bad"} {
		dev, err := store.Add(d.browserSub(srv.URL+"/"+p), p, "")
		if err != nil {
			t.Fatal(err)
		}
		ids[p] = dev.ID
	}
	b := &Broadcaster{Store: store, Sender: sender, Parallel: 2}
	rep := b.Broadcast(context.Background(), []byte("hello"), Options{Topic: "k"})
	if rep.Subscribed != 4 || rep.Delivered != 1 || rep.Gone != 1 || rep.Failed != 2 || len(rep.Results) != 4 {
		t.Fatalf("report = %+v", rep)
	}
	if store.Count() != 3 {
		t.Fatalf("the gone subscription must be retired, %d live", store.Count())
	}
	ok, _ := store.Get(ids["ok"])
	slow, _ := store.Get(ids["slow"])
	if ok.LastOK.IsZero() || slow.LastError == "" || slow.Failures != 1 {
		t.Fatalf("bookkeeping: ok=%+v slow=%+v", ok, slow)
	}
	for _, r := range rep.Results {
		if r.ID == "" || r.Name == "" || (r.Outcome != OutcomeOK && r.Err == "") {
			t.Fatalf("result = %+v", r)
		}
	}
	// With no subscriptions a broadcast is empty and calls nothing.
	empty := &Broadcaster{Store: NewStore(StoreOptions{}), Sender: sender}
	if rep := empty.Broadcast(context.Background(), []byte("x"), Options{}); rep.Subscribed != 0 || rep.Delivered != 0 {
		t.Fatalf("empty: %+v", rep)
	}
}
