// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"encoding/csv"
	"errors"
	"strings"
	"testing"
)

type failWriter struct{ after int }

func (f failWriter) Write(p []byte) (int, error) {
	if len(p) > f.after {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func rawRecords(t *testing.T, s string) [][]string {
	t.Helper()
	r := csv.NewReader(strings.NewReader(s))
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}
