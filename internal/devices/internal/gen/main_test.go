// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "oui.txt")
	os.WriteFile(in, []byte("00-03-93   (hex)\t\tApple, Inc.\n"), 0o600)
	out := filepath.Join(dir, "o.gz")
	if err := run(in, out); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(out); err != nil || st.Size() == 0 {
		t.Fatalf("no output: %v", err)
	}
	if run(filepath.Join(dir, "missing"), out) == nil {
		t.Fatal("want error for missing input")
	}
	if run(in, filepath.Join(dir, "no", "such", "dir")) == nil {
		t.Fatal("want error for bad output")
	}
}
