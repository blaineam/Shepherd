// SPDX-License-Identifier: AGPL-3.0-or-later

package importers

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
)

// parseDevice must take eero's usage object when it is there and carry on
// without it when it is not, because whether it appears at all depends on
// the account and the firmware.
func TestParseDeviceReadsUsageWhenEeroSendsIt(t *testing.T) {
	cases := map[string]struct {
		body     string
		want     bool
		down, up float64
	}{
		"numbers":   {`{"usage":{"down_mbps":12.5,"up_mbps":0.25}}`, true, 12.5, 0.25},
		"camel":     {`{"usage":{"downMbps":3,"upMbps":4}}`, true, 3, 4},
		"strings":   {`{"usage":{"down_mbps":"7.5","up_mbps":" 1 "}}`, true, 7.5, 1},
		"down only": {`{"usage":{"down_mbps":2}}`, true, 2, 0},
		// Negative, absurd and unusable readings must not become traffic.
		"negative":      {`{"usage":{"down_mbps":-5,"up_mbps":2}}`, true, 0, 2},
		"no usage":      {`{"nickname":"x"}`, false, 0, 0},
		"empty":         {`{"usage":{}}`, false, 0, 0},
		"null":          {`{"usage":null}`, false, 0, 0},
		"not an object": {`{"usage":"12 Mbps"}`, false, 0, 0},
		"unparseable":   {`{"usage":{"down_mbps":"fast"}}`, false, 0, 0},
	}
	for name, c := range cases {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.body), &m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		d := parseDevice(m)
		if d.HasUsage != c.want || d.DownMbps != c.down || d.UpMbps != c.up {
			t.Errorf("%s: HasUsage=%v down=%v up=%v, want %v/%v/%v", name, d.HasUsage, d.DownMbps, d.UpMbps, c.want, c.down, c.up)
		}
	}
}

func TestNumberRefusesWhatCannotBeARate(t *testing.T) {
	for name, m := range map[string]map[string]any{
		"missing":  {},
		"nan":      {"v": math.NaN()},
		"infinite": {"v": math.Inf(1)},
		"text":     {"v": "not a number"},
		"bool":     {"v": true},
	} {
		if got, ok := number(m, "v"); ok {
			t.Errorf("%s: number = %v, want refused", name, got)
		}
	}
	if got, ok := number(map[string]any{"a": "nope", "b": 2.0}, "a", "b"); !ok || got != 2 {
		t.Errorf("number should fall through to the next key, got %v %v", got, ok)
	}
	if nonNegative(-1) != 0 || nonNegative(3) != 3 {
		t.Error("nonNegative")
	}
}

// PersistTo is how a one-time sign-in becomes a lasting connection: the
// token goes straight from the client into the store, never through the
// caller.
func TestPersistToHandsTheTokenToAStoreWithoutReturningIt(t *testing.T) {
	f := newFakeEero(t)
	c, _ := testClient(t, f, nil)
	st := &memStore{}

	// Nothing to persist before the code is verified.
	if err := c.PersistTo(st); !errors.Is(err, ErrEeroNoSession) {
		t.Fatalf("err = %v, want ErrEeroNoSession", err)
	}
	ctx := context.Background()
	if err := c.StartLogin(ctx, testEmail); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, testCode); err != nil {
		t.Fatal(err)
	}
	if err := c.PersistTo(nil); err == nil {
		t.Fatal("PersistTo accepted a nil store")
	}
	if err := c.PersistTo(st); err != nil {
		t.Fatal(err)
	}
	if st.tok != testPending {
		t.Fatalf("stored %q", st.tok)
	}
}
