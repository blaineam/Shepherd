// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"errors"
	"testing"
	"time"
)

func TestContactValidate(t *testing.T) {
	cases := []struct {
		name string
		c    Contact
		ok   bool
	}{
		{"valid", Contact{Name: "Jordan", Email: "jordan@example.com"}, true},
		{"blank name", Contact{Name: "  ", Email: "jordan@example.com"}, false},
		{"bad email", Contact{Name: "Jordan", Email: "not-an-address"}, false},
		{"email with display name rejected", Contact{Name: "Jordan", Email: "Jordan <jordan@example.com>"}, false},
		{"name too long", Contact{Name: string(make([]byte, 201)), Email: "jordan@example.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.validate()
			if tc.ok && err != nil {
				t.Fatalf("validate() = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("validate() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSubscriptionValidate(t *testing.T) {
	base := Subscription{
		ContactID: "c1", Scope: GroupScope("g1"), Items: []string{"gaming"},
		Detail: DetailSummary, Mode: ModeDigest, Trigger: TriggerAny,
	}
	cases := []struct {
		name string
		mod  func(Subscription) Subscription
		ok   bool
	}{
		{"valid", func(s Subscription) Subscription { return s }, true},
		{"no contact", func(s Subscription) Subscription { s.ContactID = ""; return s }, false},
		{"bad scope kind", func(s Subscription) Subscription { s.Scope.Kind = "network"; return s }, false},
		{"empty scope id", func(s Subscription) Subscription { s.Scope.ID = ""; return s }, false},
		{"no items", func(s Subscription) Subscription { s.Items = nil; return s }, false},
		{"blank item", func(s Subscription) Subscription { s.Items = []string{" "}; return s }, false},
		{"wildcard items ok", func(s Subscription) Subscription { s.Items = []string{Wildcard}; return s }, true},
		{"bad detail", func(s Subscription) Subscription { s.Detail = "partial"; return s }, false},
		{"bad mode", func(s Subscription) Subscription { s.Mode = "sometimes"; return s }, false},
		{"bad trigger", func(s Subscription) Subscription { s.Trigger = "always"; return s }, false},
		{"negative interval", func(s Subscription) Subscription { s.DigestInterval = -time.Hour; return s }, false},
		{"device scope ok", func(s Subscription) Subscription { s.Scope = DeviceScope("d1"); return s }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mod(base).validate()
			if tc.ok && err != nil {
				t.Fatalf("validate() = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("validate() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestScopeString(t *testing.T) {
	if got := GroupScope("kids").String(); got != "group:kids" {
		t.Errorf("GroupScope.String() = %q", got)
	}
	if got := DeviceScope("tv1").String(); got != "device:tv1" {
		t.Errorf("DeviceScope.String() = %q", got)
	}
}

func TestSubscriptionMatches(t *testing.T) {
	groupSub := Subscription{Scope: GroupScope("tommy"), Items: []string{"gaming"}, Trigger: TriggerAny}
	deviceSub := Subscription{Scope: DeviceScope("console-1"), Items: []string{"gaming"}, Trigger: TriggerAny}
	wildcardSub := Subscription{Scope: GroupScope("tommy"), Items: []string{Wildcard}, Trigger: TriggerAny}
	blockedOnlySub := Subscription{Scope: GroupScope("tommy"), Items: []string{"gaming"}, Trigger: TriggerBlockedOnly}

	cases := []struct {
		name string
		sub  Subscription
		ev   AccessEvent
		want bool
	}{
		{"group match, any trigger, allowed", groupSub,
			AccessEvent{GroupIDs: []string{"tommy"}, Item: "gaming", Action: "allowed"}, true},
		{"group match, any trigger, blocked", groupSub,
			AccessEvent{GroupIDs: []string{"tommy"}, Item: "gaming", Action: "blocked"}, true},
		{"group no match", groupSub,
			AccessEvent{GroupIDs: []string{"other"}, Item: "gaming", Action: "allowed"}, false},
		{"item no match", groupSub,
			AccessEvent{GroupIDs: []string{"tommy"}, Item: "streaming", Action: "allowed"}, false},
		{"device scope matches by client id", deviceSub,
			AccessEvent{ClientID: "console-1", Item: "gaming", Action: "allowed"}, true},
		{"device scope ignores group ids", deviceSub,
			AccessEvent{GroupIDs: []string{"console-1"}, Item: "gaming", Action: "allowed"}, false},
		{"wildcard matches any item in scope", wildcardSub,
			AccessEvent{GroupIDs: []string{"tommy"}, Item: "whatever-id", Action: "allowed"}, true},
		{"blocked_only rejects allowed", blockedOnlySub,
			AccessEvent{GroupIDs: []string{"tommy"}, Item: "gaming", Action: "allowed"}, false},
		{"blocked_only accepts blocked", blockedOnlySub,
			AccessEvent{GroupIDs: []string{"tommy"}, Item: "gaming", Action: "blocked"}, true},
		{"blocked_only is case-insensitive", blockedOnlySub,
			AccessEvent{GroupIDs: []string{"tommy"}, Item: "gaming", Action: "Blocked"}, true},
		{"empty group ids never match a group scope", groupSub,
			AccessEvent{Item: "gaming", Action: "allowed"}, false},
		{"unknown scope kind never matches", Subscription{Scope: Scope{Kind: "network"}, Items: []string{"gaming"}, Trigger: TriggerAny},
			AccessEvent{ClientID: "x", GroupIDs: []string{"x"}, Item: "gaming", Action: "allowed"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sub.Matches(tc.ev); got != tc.want {
				t.Errorf("Matches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAccessEventValidate(t *testing.T) {
	if err := (AccessEvent{Item: "gaming"}).validate(); err != nil {
		t.Errorf("validate() = %v, want nil", err)
	}
	if err := (AccessEvent{}).validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("validate() = %v, want ErrInvalid", err)
	}
}
