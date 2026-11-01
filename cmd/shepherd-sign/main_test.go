// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "release.key")
	var out, errb bytes.Buffer
	if code := realMain([]string{"-generate", "-out", key}, &out, &errb, os.Getenv); code != 0 {
		t.Fatalf("generate exit %d: %s", code, errb.String())
	}
	line := ""
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "public key: ") {
			line = strings.TrimPrefix(l, "public key: ")
		}
	}
	if line == "" {
		t.Fatalf("no public key printed: %s", out.String())
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key file: %v %v", fi, err)
	}
	sums := filepath.Join(dir, "SHA256SUMS")
	os.WriteFile(sums, []byte("abc  shepherd_1.0.0_linux_amd64.tar.gz\n"), 0o600)
	out.Reset()
	if code := realMain([]string{"-sign", sums, "-key", key}, &out, &errb, os.Getenv); code != 0 {
		t.Fatalf("sign exit %d: %s", code, errb.String())
	}
	if _, err := os.Stat(sums + ".sig"); err != nil {
		t.Fatal("no signature written")
	}
	if code := realMain([]string{"-verify", sums, "-pub", line}, &out, &errb, os.Getenv); code != 0 {
		t.Fatalf("verify exit %d: %s", code, errb.String())
	}
	// The key from the environment, as CI passes it.
	priv, _ := os.ReadFile(key)
	env := func(k string) string {
		if k == "KEY" {
			return string(priv)
		}
		return ""
	}
	if code := realMain([]string{"-sign", sums, "-key-env", "KEY"}, &out, &errb, env); code != 0 {
		t.Fatalf("sign from env exit %d: %s", code, errb.String())
	}
	// Tampering fails verification.
	os.WriteFile(sums, []byte("def  shepherd_1.0.0_linux_amd64.tar.gz\n"), 0o600)
	if code := realMain([]string{"-verify", sums, "-pub", line}, &out, &errb, os.Getenv); code == 0 {
		t.Fatal("a tampered file verified")
	}
	// Errors are reported, not panics.
	for _, args := range [][]string{
		{},
		{"-sign", sums},
		{"-sign", sums, "-key", filepath.Join(dir, "missing")},
		{"-sign", filepath.Join(dir, "missing"), "-key", key},
		{"-sign", sums, "-key-env", "EMPTY"},
		{"-verify", sums, "-pub", "%%%"},
		{"-verify", filepath.Join(dir, "missing"), "-pub", line},
		{"-generate", "-out", filepath.Join(dir, "no", "dir", "k")},
		{"-bogus"},
	} {
		if code := realMain(args, &out, &errb, os.Getenv); code == 0 {
			t.Errorf("%v should fail", args)
		}
	}
	os.Remove(sums + ".sig")
	if code := realMain([]string{"-verify", sums, "-pub", line}, &out, &errb, os.Getenv); code == 0 {
		t.Fatal("verify without a signature file should fail")
	}
}
