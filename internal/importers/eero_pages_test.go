// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func dev(mac string) string {
	return `{"url":"/2.2/networks/1001/devices/` + mac + `","mac":"` + mac + `","nickname":"n-` + mac + `"}`
}

func pagedClient(t *testing.T, pages map[string]string) (*Client, *fakeEero) {
	t.Helper()
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	login(t, c)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/devices") {
			return false
		}
		key := r.URL.RawQuery
		body, ok := pages[key]
		if !ok {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, errBody(404, "no such page"))
			return true
		}
		body = strings.ReplaceAll(body, "{{BASE}}", "http://"+r.Host)
		_, _ = io.WriteString(w, body)
		return true
	}
	return c, f
}

func macsOf(ds []EeroDevice) string {
	var out []string
	for _, d := range ds {
		out = append(out, d.MAC)
	}
	return strings.Join(out, ",")
}

func TestPaginationShapes(t *testing.T) {
	cases := map[string]map[string]string{
		"top-level pagination absolute URL": {
			"":       `{"meta":{"code":200},"pagination":{"next":"{{BASE}}/2.2/networks/1001/devices?page=2"},"data":[` + dev("02:00:5e:00:00:01") + `]}`,
			"page=2": `{"meta":{"code":200},"data":[` + dev("02:00:5e:00:00:02") + `]}`,
		},
		"meta pagination relative path": {
			"":       `{"meta":{"code":200,"pagination":{"next":"/2.2/networks/1001/devices?page=2"}},"data":[` + dev("02:00:5e:00:00:01") + `]}`,
			"page=2": `{"meta":{"code":200},"data":[` + dev("02:00:5e:00:00:02") + `]}`,
		},
		"meta next": {
			"":       `{"meta":{"code":200,"next":"/2.2/networks/1001/devices?page=2"},"data":[` + dev("02:00:5e:00:00:01") + `]}`,
			"page=2": `{"meta":{"code":200},"data":[` + dev("02:00:5e:00:00:02") + `]}`,
		},
		"data object with next": {
			"":       `{"meta":{"code":200},"data":{"data":[` + dev("02:00:5e:00:00:01") + `],"next":"/2.2/networks/1001/devices?page=2"}}`,
			"page=2": `{"meta":{"code":200},"data":{"devices":[` + dev("02:00:5e:00:00:02") + `]}}`,
		},
		"cursor": {
			"":             `{"meta":{"code":200},"pagination":{"next_cursor":"abc 1"},"data":[` + dev("02:00:5e:00:00:01") + `]}`,
			"cursor=abc+1": `{"meta":{"code":200},"data":[` + dev("02:00:5e:00:00:02") + `]}`,
		},
	}
	for name, pages := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := pagedClient(t, pages)
			ds, err := c.Devices(context.Background(), "1001")
			if err != nil || macsOf(ds) != "02:00:5e:00:00:01,02:00:5e:00:00:02" {
				t.Fatalf("%v %s", err, macsOf(ds))
			}
		})
	}
}

func TestPaginationNeverLeavesTheHost(t *testing.T) {
	c, _ := pagedClient(t, map[string]string{
		"": `{"meta":{"code":200},"pagination":{"next":"https://elsewhere.example.com/2.2/networks/1001/devices?page=2"},"data":[` + dev("02:00:5e:00:00:01") + `]}`,
	})
	if _, err := c.Devices(context.Background(), "1001"); !errors.Is(err, ErrEeroBadResponse) {
		t.Fatalf("%v", err)
	}
	c, _ = pagedClient(t, map[string]string{
		"": `{"meta":{"code":200},"pagination":{"next":"http://[::bad"},"data":[]}`,
	})
	if _, err := c.Devices(context.Background(), "1001"); !errors.Is(err, ErrEeroBadResponse) {
		t.Fatalf("bad link: %v", err)
	}
}

func TestPaginationLoopAndCaps(t *testing.T) {
	c, f := pagedClient(t, map[string]string{
		"": `{"meta":{"code":200},"pagination":{"next":"/2.2/networks/1001/devices"},"data":[` + dev("02:00:5e:00:00:01") + `]}`,
	})
	ds, err := c.Devices(context.Background(), "1001")
	if err != nil || len(ds) != 1 {
		t.Fatalf("%v %d", err, len(ds))
	}
	// An endless chain of distinct pages stops at maxPages.
	n := 0
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/devices") {
			return false
		}
		n++
		_, _ = io.WriteString(w, `{"meta":{"code":200},"pagination":{"next":"/2.2/networks/1001/devices?page=`+strings.Repeat("x", n)+`"},"data":[`+dev("02:00:5e:00:00:01")+`]}`)
		return true
	}
	ds, err = c.Devices(context.Background(), "1001")
	if err != nil || n != maxPages || len(ds) != maxPages {
		t.Fatalf("%v pages=%d items=%d", err, n, len(ds))
	}
	// An error on page two is an error.
	c, _ = pagedClient(t, map[string]string{
		"": `{"meta":{"code":200},"pagination":{"next":"/2.2/networks/1001/devices?page=9"},"data":[` + dev("02:00:5e:00:00:01") + `]}`,
	})
	if _, err := c.Devices(context.Background(), "1001"); err == nil {
		t.Fatal("expected an error from page two")
	}
	// Too many items overall.
	big := make([]map[string]any, 30000)
	for i := range big {
		big[i] = map[string]any{"mac": "02:00:5e:00:00:01"}
	}
	raw, _ := json.Marshal(big)
	c, _ = pagedClient(t, map[string]string{
		"":       `{"meta":{"code":200},"pagination":{"next":"/2.2/networks/1001/devices?page=2"},"data":` + string(raw) + `}`,
		"page=2": `{"meta":{"code":200},"data":` + string(raw) + `}`,
	})
	if _, err := c.Devices(context.Background(), "1001"); !errors.Is(err, ErrEeroTooLarge) {
		t.Fatalf("%v", err)
	}
}

func TestParserToleratesOddShapes(t *testing.T) {
	c, _ := pagedClient(t, map[string]string{
		"": `{"data":{"devices":[
 {"mac_address":"02:00:5e:00:00:21","ip_address":"192.0.2.31","ip_addresses":["192.0.2.31","2001:db8::31"],"name":"Renamed Field","host_name":"h","vendor":"V","type":"camera","connectionType":"Wired","paused":"true","guest":true,"source":"/2.2/eeros/9","profile":"/2.2/networks/1001/profiles/9001"},
 {"url":"/2.2/networks/1001/devices/02:00:5e:00:00:22","nickname":7,"wireless":"false","extra":{"deep":[1,2,3]},"ips":"192.0.2.32","paused":"maybe"},
 {"nothing":"useful"}
]}}`,
	})
	ds, err := c.Devices(context.Background(), "1001")
	if err != nil || len(ds) != 3 {
		t.Fatalf("%v %d", err, len(ds))
	}
	a, b := ds[0], ds[1]
	if a.MAC != "02:00:5e:00:00:21" || a.Nickname != "Renamed Field" || a.Hostname != "h" || a.Manufacturer != "V" || a.DeviceType != "camera" ||
		a.Connection != "wired" || !a.Paused || !a.Guest || a.NodeURL != "/2.2/eeros/9" || a.ProfileURL != "/2.2/networks/1001/profiles/9001" || len(a.IPs) != 3 {
		t.Fatalf("%+v", a)
	}
	if b.MAC != "02:00:5e:00:00:22" || b.Nickname != "7" || b.Connection != "wired" || len(b.IPs) != 1 || b.Paused {
		t.Fatalf("%+v", b)
	}
	if ds[2].MAC != "" || ds[2].Nickname != "" {
		t.Fatalf("%+v", ds[2])
	}
}

func TestProfileAndNodeParsingVariants(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	login(t, c)
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case strings.HasSuffix(r.URL.Path, "/profiles"):
			_, _ = io.WriteString(w, envelopeOf(`[
 {"url":"/p/1","display_name":"A","devices":{"data":[{"url":"/d/02:00:5e:00:00:31"},"/d/02:00:5e:00:00:32"]}},
 {"url":"/p/2","name":"B","devices":"nonsense"},
 {"url":"/p/3","name":"C"}]`))
		case strings.HasSuffix(r.URL.Path, "/eeros"):
			_, _ = io.WriteString(w, envelopeOf(`{"eeros":[{"name":"Den","model_number":"M1","mac":"00:00:5e:00:00:41","ip":"192.0.2.41","is_gateway":true}]}`))
		default:
			return false
		}
		return true
	}
	ps, err := c.Profiles(context.Background(), "1001")
	if err != nil || len(ps) != 3 || ps[0].Name != "A" || len(ps[0].DeviceURLs) != 2 || len(ps[1].DeviceURLs) != 0 {
		t.Fatalf("%v %+v", err, ps)
	}
	ns, err := c.Nodes(context.Background(), "1001")
	if err != nil || len(ns) != 1 || ns[0].Location != "Den" || ns[0].Model != "M1" || !ns[0].Gateway || ns[0].IP != "192.0.2.41" {
		t.Fatalf("%v %+v", err, ns)
	}
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(500)
		return true
	}
	if _, err := c.Profiles(context.Background(), "1001"); err == nil {
		t.Fatal("profiles error swallowed")
	}
	if _, err := c.Nodes(context.Background(), "1001"); err == nil {
		t.Fatal("nodes error swallowed")
	}
}

func TestListOfEdgeCases(t *testing.T) {
	if listOf(nil) != nil || listOf([]byte(`"x"`)) != nil || listOf([]byte(`{"other":1}`)) != nil {
		t.Fatal("expected nil")
	}
	if got := listOf([]byte(`{"items":[{"a":1}]}`)); len(got) != 1 {
		t.Fatal(got)
	}
	if idFromURL("/2.2/networks/77/") != "77" || idFromURL("88") != "88" || idFromURL("") != "" {
		t.Fatal("idFromURL")
	}
}
