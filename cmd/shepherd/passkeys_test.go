// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// With [tls] on, the portal's passkeys take [tls]'s hostname as their
// relying party and its listen port for their origin, and only the HTTPS
// listener at that name counts as somewhere a ceremony can run.
func TestRunConfiguresPasskeysFromTLS(t *testing.T) {
	resetTLSSeams(t)
	hostname := "shepherd.example.com"
	tlsEvery = 10 * time.Millisecond
	tlsACMEClient = newFakeTLSACME(hostname)
	tlsDNS01 = &fakeTLSDNS01{}
	tlsPropagationCheck = func(context.Context, string, string) error { return nil }

	tlsPort := freePort(t)
	// Two spaces before "=" keep start()'s portal-port scan off this line.
	extra := fmt.Sprintf("[tls]\nenabled = true\nhostname = %q\nlisten  = \"127.0.0.1:%d\"\ncloudflare_api_token = \"unused-fake\"\n", hostname, tlsPort)
	r := start(t, writeConfig(t, freePort(t), freePort(t), extra))
	defer r.stop()

	origin := fmt.Sprintf("https://%s:%d", hostname, tlsPort)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: time.Second}
	var status map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%d/api/passkeys", tlsPort), nil)
		req.Host = fmt.Sprintf("%s:%d", hostname, tlsPort)
		req.Header.Set("Authorization", "Bearer "+r.token)
		res, err := client.Do(req)
		if err == nil {
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				json.Unmarshal(b, &status)
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status == nil {
		t.Fatal("the HTTPS portal never answered /api/passkeys")
	}
	if status["configured"] != true || status["here"] != true || status["rp_id"] != hostname || status["origin"] != origin {
		t.Errorf("passkeys over the HTTPS listener = %v", status)
	}

	code, body := r.api("GET", "/api/passkeys", "")
	if code != http.StatusOK || !strings.Contains(body, `"here":false`) || !strings.Contains(body, origin) {
		t.Errorf("passkeys over plain HTTP = %d %s, want here=false and a pointer to %s", code, body, origin)
	}
}

func TestRunWithoutTLSLeavesPasskeysUnconfigured(t *testing.T) {
	r := start(t, writeConfig(t, freePort(t), freePort(t), ""))
	defer r.stop()
	code, body := r.api("GET", "/api/passkeys", "")
	if code != http.StatusOK || !strings.Contains(body, `"configured":false`) || !strings.Contains(body, "[tls]") {
		t.Errorf("passkeys without [tls] = %d %s", code, body)
	}
}
