// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fixture ULA address
const ula = "fd7a:115c:a1e0::2" // leakcheck:allow fixture

type tsSink struct{ obs []Observation }

func (s *tsSink) Observe(o Observation) string { s.obs = append(s.obs, o); return "" }

func TestTailscaleSourceObservesOnlineNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/localapi/v0/status" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"Self":{"HostName":"nas","TailscaleIPs":["100.64.0.1"],"Online":true},
		"Peer":{"a":{"HostName":"","DNSName":"pixel-8.example.ts.net.","TailscaleIPs":["100.64.0.2","` + ula + `"],"Online":true},
		"b":{"HostName":"gone","TailscaleIPs":["100.64.0.3"],"Online":false}}}`))
	}))
	defer srv.Close()
	sink := &tsSink{}
	src := &TailscaleSource{Sink: sink, Client: srv.Client(), BaseURL: srv.URL}
	n, err := src.Poll(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	got := map[string]string{}
	for _, o := range sink.obs {
		if o.Source != SourceTailscale {
			t.Fatalf("source = %s", o.Source)
		}
		got[o.IP] = o.Hostname
	}
	want := map[string]string{"100.64.0.1": "nas", "100.64.0.2": "pixel-8", ula: "pixel-8"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestTailscaleSourceNamesAnIPOnlyDevice(t *testing.T) {
	reg := New(Options{})
	reg.Observe(Observation{Source: SourceDNS, IP: "100.64.0.2"})
	reg.Observe(Observation{Source: SourceTailscale, IP: "100.64.0.2", Hostname: "pixel-8"})
	var found bool
	for _, d := range reg.List() {
		if d.Hostname == "pixel-8" {
			found = true
		}
	}
	if !found {
		t.Fatal("the tailnet name was not applied to the device that queried from that address")
	}
}

func TestTailscaleSourceReportsHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer srv.Close()
	src := &TailscaleSource{Sink: &tsSink{}, Client: srv.Client(), BaseURL: srv.URL}
	if _, err := src.Poll(context.Background()); err == nil {
		t.Fatal("a 403 must be an error")
	}
}
