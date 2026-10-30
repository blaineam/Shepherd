// SPDX-License-Identifier: AGPL-3.0-or-later

package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shepherd/internal/reverseproxy"
)

// withReverseProxy swaps a persisted store into the harness, the way
// cmd/shepherd opens <data_dir>/reverseproxy.json.
func (h *harness) withReverseProxy() *reverseproxy.Store {
	h.t.Helper()
	s, err := reverseproxy.Open(filepath.Join(h.dir, "reverseproxy.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	h.srv.ReverseProxy = s
	return s
}

func TestReverseProxyHostsCRUD(t *testing.T) {
	h := newHarness(t)
	store := h.withReverseProxy()

	list := h.ok("GET", "/api/reverseproxy/hosts", "", 200)
	if hosts, _ := list["hosts"].([]any); hosts == nil || len(hosts) != 0 {
		t.Fatalf("empty list = %+v, want hosts: []", list)
	}

	created := h.ok("POST", "/api/reverseproxy/hosts", `{"domain":"Jellyfin.Example.com","target_scheme":"http","target_host":"127.0.0.1","target_port":8096}`, 200)
	id, _ := created["id"].(string)
	if id == "" || created["domain"] != "jellyfin.example.com" || created["enabled"] != true || created["skip_tls_verify"] != false {
		t.Fatalf("created = %+v, want an id, a normalized domain and enabled by default", created)
	}
	if _, ok := store.Lookup("jellyfin.example.com"); !ok {
		t.Error("a host added in the portal must route at once")
	}

	h.ok("POST", "/api/reverseproxy/hosts", `{"domain":"git.example.com","target_scheme":"https","target_host":"127.0.0.1","target_port":3443,"skip_tls_verify":true,"enabled":false}`, 200)
	list = h.ok("GET", "/api/reverseproxy/hosts", "", 200)
	hosts, _ := list["hosts"].([]any)
	if len(hosts) != 2 || hosts[0].(map[string]any)["domain"] != "git.example.com" {
		t.Fatalf("list = %+v, want two hosts sorted by domain", list)
	}
	if g := hosts[0].(map[string]any); g["enabled"] != false || g["skip_tls_verify"] != true {
		t.Errorf("explicit enabled/skip_tls_verify were not honored: %+v", g)
	}

	// PUT replaces every field it is given; leaving enabled out keeps it.
	upd := h.ok("PUT", "/api/reverseproxy/hosts/"+id, `{"domain":"jellyfin.example.com","target_scheme":"https","target_host":"192.0.2.30","target_port":8920,"skip_tls_verify":true}`, 200)
	if upd["id"] != id || upd["target_host"] != "192.0.2.30" || upd["target_port"] != float64(8920) || upd["enabled"] != true {
		t.Errorf("updated = %+v", upd)
	}
	off := h.ok("PUT", "/api/reverseproxy/hosts/"+id, `{"domain":"jellyfin.example.com","target_scheme":"https","target_host":"192.0.2.30","target_port":8920,"skip_tls_verify":true,"enabled":false}`, 200)
	if off["enabled"] != false {
		t.Errorf("toggle off = %+v", off)
	}

	b, err := os.ReadFile(filepath.Join(h.dir, "reverseproxy.json"))
	if err != nil || !strings.Contains(string(b), "192.0.2.30") {
		t.Errorf("edits must persist to reverseproxy.json: %v %s", err, b)
	}

	h.expect("DELETE", "/api/reverseproxy/hosts/"+id, "", 200)
	h.expect("DELETE", "/api/reverseproxy/hosts/"+id, "", 404)
	if _, ok := store.Lookup("jellyfin.example.com"); ok {
		t.Error("a deleted host must stop routing")
	}
}

func TestReverseProxyHostsRejectBadInput(t *testing.T) {
	h := newHarness(t)
	h.withReverseProxy()
	created := h.ok("POST", "/api/reverseproxy/hosts", `{"domain":"immich.example.com","target_host":"127.0.0.1","target_port":2283}`, 200)
	id := created["id"].(string)

	h.expect("POST", "/api/reverseproxy/hosts", `{"domain":"nope","target_host":"127.0.0.1","target_port":80}`, 400)
	h.expect("POST", "/api/reverseproxy/hosts", `{"domain":"a.example.com","target_scheme":"ftp","target_host":"127.0.0.1","target_port":21}`, 400)
	h.expect("POST", "/api/reverseproxy/hosts", `{"domain":"a.example.com","target_host":"127.0.0.1","target_port":0}`, 400)
	h.expect("POST", "/api/reverseproxy/hosts", `{"domain":"a.example.com","target_host":"127.0.0.1","target_port":80,"surprise":1}`, 400)
	h.expect("POST", "/api/reverseproxy/hosts", `{"id":"chosen","domain":"a.example.com","target_host":"127.0.0.1","target_port":80}`, 400)
	h.expect("POST", "/api/reverseproxy/hosts", `{"domain":"IMMICH.example.com","target_host":"192.0.2.1","target_port":80}`, 409)
	h.expect("PUT", "/api/reverseproxy/hosts/nope", `{"domain":"x.example.com","target_host":"127.0.0.1","target_port":80}`, 404)
	h.expect("PUT", "/api/reverseproxy/hosts/"+id, `{"domain":"bad","target_host":"127.0.0.1","target_port":80}`, 400)
	h.expect("PUT", "/api/reverseproxy/hosts/"+id, `not json`, 400)

	// Without the CSRF header nothing changes.
	req, _ := http.NewRequest("POST", h.ts.URL+"/api/reverseproxy/hosts", strings.NewReader(`{"domain":"csrf.example.com","target_host":"127.0.0.1","target_port":80}`))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 64))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Errorf("POST without X-Shepherd = %d, want 403", res.StatusCode)
	}
}

func TestReverseProxyHostsReportAFailedSaveAs500(t *testing.T) {
	h := newHarness(t)
	h.withReverseProxy()
	// Occupy the temporary file's name so the atomic write cannot happen.
	if err := os.Mkdir(filepath.Join(h.dir, "reverseproxy.json.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.expect("POST", "/api/reverseproxy/hosts", `{"domain":"a.example.com","target_host":"127.0.0.1","target_port":80}`, 500)
}

func TestReverseProxyWorksWithoutAWiredStore(t *testing.T) {
	h := newHarness(t) // New() gives a memory-only store when Deps.ReverseProxy is nil
	h.ok("POST", "/api/reverseproxy/hosts", `{"domain":"a.example.com","target_host":"127.0.0.1","target_port":80}`, 200)
	list := h.ok("GET", "/api/reverseproxy/hosts", "", 200)
	if hosts, _ := list["hosts"].([]any); len(hosts) != 1 {
		t.Errorf("list = %+v", list)
	}
}

func TestReverseProxyStatusWhenOff(t *testing.T) {
	h := newHarness(t)
	st := h.ok("GET", "/api/reverseproxy", "", 200)
	if st["enabled"] != false || st["certificate"] != nil || st["wildcard"] != "" {
		t.Errorf("status with the listener off = %+v", st)
	}
}

func TestReverseProxyStatusReportsTheListenerAndCertificate(t *testing.T) {
	h := newHarness(t)
	notAfter := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	cert := selfSignedForTest(t, "*.example.com", notAfter)
	var current *tls.Certificate
	h.srv.ReverseProxyStatus = ReverseProxyStatus{Enabled: true, Listen: ":8443", Wildcard: "*.example.com", Certificate: func() *tls.Certificate { return current }}

	st := h.ok("GET", "/api/reverseproxy", "", 200)
	if st["enabled"] != true || st["listen"] != ":8443" || st["wildcard"] != "*.example.com" || st["certificate"] != nil {
		t.Errorf("status before the first issuance = %+v", st)
	}

	current = &cert
	st = h.ok("GET", "/api/reverseproxy", "", 200)
	c, _ := st["certificate"].(map[string]any)
	if c == nil {
		t.Fatalf("status = %+v, want a certificate", st)
	}
	if names, _ := c["names"].([]any); len(names) != 1 || names[0] != "*.example.com" {
		t.Errorf("certificate names = %v", c["names"])
	}
	if c["not_after"] != notAfter.Format(time.RFC3339) {
		t.Errorf("not_after = %v, want %s", c["not_after"], notAfter.Format(time.RFC3339))
	}
}

func selfSignedForTest(t *testing.T, name string, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
