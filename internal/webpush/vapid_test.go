// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateAndValidateKeys(t *testing.T) {
	k, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := decodeB64(k.Public); len(raw) != 65 || raw[0] != 4 {
		t.Fatalf("public key is %d bytes", len(raw))
	}
	if raw, _ := decodeB64(k.Private); len(raw) != 32 {
		t.Fatalf("private key is %d bytes", len(raw))
	}
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	other, _ := GenerateVAPIDKeys()
	bad := []VAPIDKeys{
		{Public: k.Public, Private: other.Private}, // mismatched halves
		{Public: k.Public, Private: "AAAA"},
		{Public: k.Public, Private: "%%%"},
		{Public: "AAAA", Private: k.Private},
		{Public: k.Public, Private: b64(make([]byte, 32))}, // zero scalar
		{},
	}
	for i, b := range bad {
		if err := b.Validate(); !errors.Is(err, ErrBadKey) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

func TestJWTStructureAndSignature(t *testing.T) {
	k, _ := GenerateVAPIDKeys()
	now := time.Unix(1_700_000_000, 0)
	jwt, err := k.JWT("https://push.example.com/send/abc123", "mailto:ops@example.com", now, 0)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	hdr, _ := decodeB64(parts[0])
	if string(hdr) != `{"typ":"JWT","alg":"ES256"}` {
		t.Fatalf("header = %s", hdr)
	}
	body, _ := decodeB64(parts[1])
	var c map[string]any
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	if c["aud"] != "https://push.example.com" || c["sub"] != "mailto:ops@example.com" {
		t.Fatalf("claims = %v", c)
	}
	if exp := int64(c["exp"].(float64)); exp != now.Add(DefaultJWTLifetime).Unix() {
		t.Fatalf("exp = %d", exp)
	}
	if sig, _ := decodeB64(parts[2]); len(sig) != 64 {
		t.Fatalf("signature must be raw r||s (64 bytes), got %d", len(sig))
	}
	aud, sub, exp, err := VerifyJWT(k.Public, jwt)
	if err != nil || aud != "https://push.example.com" || sub != "mailto:ops@example.com" || !exp.Equal(now.Add(DefaultJWTLifetime)) {
		t.Fatalf("verify: %q %q %v %v", aud, sub, exp, err)
	}
	// Another key does not verify it, and neither does a tampered token.
	other, _ := GenerateVAPIDKeys()
	if _, _, _, err := VerifyJWT(other.Public, jwt); err == nil {
		t.Fatal("wrong key verified")
	}
	forged := parts[0] + "." + b64([]byte(`{"aud":"https://evil.example.com","exp":9999999999,"sub":"x"}`)) + "." + parts[2]
	if _, _, _, err := VerifyJWT(k.Public, forged); err == nil {
		t.Fatal("tampered claims verified")
	}
}

func TestJWTLifetimeNeverExceeds24Hours(t *testing.T) {
	k, _ := GenerateVAPIDKeys()
	now := time.Unix(1_700_000_000, 0)
	for _, lt := range []time.Duration{48 * time.Hour, 1000 * time.Hour, MaxJWTLifetime} {
		jwt, err := k.JWT("https://push.example.com/x", "mailto:ops@example.com", now, lt)
		if err != nil {
			t.Fatal(err)
		}
		_, _, exp, _ := VerifyJWT(k.Public, jwt)
		if exp.Sub(now) > 24*time.Hour {
			t.Fatalf("lifetime %v signed %v", lt, exp.Sub(now))
		}
	}
	jwt, _ := k.JWT("https://push.example.com/x", "mailto:ops@example.com", now, time.Hour)
	if _, _, exp, _ := VerifyJWT(k.Public, jwt); exp.Sub(now) != time.Hour {
		t.Fatalf("explicit lifetime ignored: %v", exp.Sub(now))
	}
}

func TestJWTErrors(t *testing.T) {
	k, _ := GenerateVAPIDKeys()
	now := time.Now()
	for _, ep := range []string{"", "not a url", "/relative"} {
		if _, err := k.JWT(ep, "mailto:ops@example.com", now, 0); err == nil {
			t.Errorf("endpoint %q accepted", ep)
		}
	}
	if _, err := (VAPIDKeys{}).JWT("https://push.example.com/x", "s", now, 0); !errors.Is(err, ErrBadKey) {
		t.Fatal(err)
	}
	if _, err := (VAPIDKeys{}).Authorization("https://push.example.com/x", "s", now, 0); !errors.Is(err, ErrBadKey) {
		t.Fatal(err)
	}
	auth, err := k.Authorization("https://push.example.com/x", "mailto:ops@example.com", now, 0)
	if err != nil || !strings.HasPrefix(auth, "vapid t=") || !strings.HasSuffix(auth, ", k="+k.Public) {
		t.Fatalf("auth = %q %v", auth, err)
	}
}

func TestVerifyJWTRejectsMalformed(t *testing.T) {
	k, _ := GenerateVAPIDKeys()
	good, _ := k.JWT("https://push.example.com/x", "mailto:ops@example.com", time.Now(), 0)
	p := strings.Split(good, ".")
	if _, _, _, err := VerifyJWT(k.Public, "a.b"); err == nil {
		t.Error("two parts")
	}
	if _, _, _, err := VerifyJWT("%%%", good); !errors.Is(err, ErrBadKey) {
		t.Error("bad key b64")
	}
	if _, _, _, err := VerifyJWT("AAAA", good); !errors.Is(err, ErrBadKey) {
		t.Error("bad key point")
	}
	if _, _, _, err := VerifyJWT(k.Public, p[0]+"."+p[1]+".AAAA"); err == nil {
		t.Error("short signature")
	}
	if _, _, _, err := VerifyJWT(k.Public, p[0]+"."+p[1]+".%%%"); err == nil {
		t.Error("bad signature b64")
	}
	// Properly signed but with a non-ES256 header, bad base64, or bad JSON.
	sign := func(h, c string) string {
		signed := h + "." + c
		return signed + "." + signRaw(t, k, signed)
	}
	if _, _, _, err := VerifyJWT(k.Public, sign(b64([]byte(`{"alg":"none"}`)), p[1])); err == nil {
		t.Error("alg none")
	}
	if _, _, _, err := VerifyJWT(k.Public, sign("%%%", p[1])); err == nil {
		t.Error("bad header b64")
	}
	if _, _, _, err := VerifyJWT(k.Public, sign(p[0], "%%%")); err == nil {
		t.Error("bad claims b64")
	}
	if _, _, _, err := VerifyJWT(k.Public, sign(p[0], b64([]byte("not json")))); err == nil {
		t.Error("bad claims json")
	}
	if _, _, _, err := VerifyJWT(k.Public, sign(b64([]byte("not json")), p[1])); err == nil {
		t.Error("bad header json")
	}
}

func TestVAPIDPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vapid.json")
	k1, created, err := LoadOrCreateVAPIDKeys(path)
	if err != nil || !created {
		t.Fatalf("first: %v %v", created, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
	k2, created, err := LoadOrCreateVAPIDKeys(path)
	if err != nil || created || k2 != k1 {
		t.Fatalf("second: %v %v %v", created, err, k2 == k1)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".webpush-*")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	// A corrupt or mismatched file is an error, never silently replaced.
	os.WriteFile(path, []byte("{nope"), 0o600)
	if _, _, err := LoadOrCreateVAPIDKeys(path); !errors.Is(err, ErrBadKey) {
		t.Fatalf("corrupt: %v", err)
	}
	other, _ := GenerateVAPIDKeys()
	mismatch, _ := json.Marshal(VAPIDKeys{Public: k1.Public, Private: other.Private})
	os.WriteFile(path, mismatch, 0o600)
	if _, err := LoadVAPIDKeys(path); !errors.Is(err, ErrBadKey) {
		t.Fatalf("mismatch: %v", err)
	}
	if err := SaveVAPIDKeys(path, VAPIDKeys{}); !errors.Is(err, ErrBadKey) {
		t.Fatalf("save invalid: %v", err)
	}
	if _, err := LoadVAPIDKeys(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	// An unwritable directory surfaces the error.
	if _, _, err := LoadOrCreateVAPIDKeys(filepath.Join(dir, "no", "such", "dir", "k.json")); err == nil {
		t.Fatal("expected error")
	}
}
