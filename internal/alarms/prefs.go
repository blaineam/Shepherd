// SPDX-License-Identifier: AGPL-3.0-or-later

package alarms

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that serializes as a string such as "6h".
type Duration time.Duration

// D converts back to a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON writes the duration as "1h30m".
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// UnmarshalJSON accepts "1h30m" or a number of seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		p, err := time.ParseDuration(x)
		if err != nil {
			return err
		}
		*d = Duration(p)
	case float64:
		*d = Duration(time.Duration(x * float64(time.Second)))
	default:
		return errors.New("alarms: duration must be a string or seconds")
	}
	return nil
}

// ChannelPref configures one outbound channel.
type ChannelPref struct {
	Enabled bool `json:"enabled"`
	// MinSeverity is the lowest severity the channel carries.
	MinSeverity Severity `json:"min_severity"`
}

// DigestPref configures the digest that carries alarms below ImmediateMin.
type DigestPref struct {
	Enabled bool `json:"enabled"`
	// Every sends the digest this long after its first alarm was queued
	// (interval mode). Ignored when At is set.
	Every Duration `json:"every"`
	// At, as "HH:MM" in Preferences.Timezone, sends the digest at a set time
	// of day instead.
	At string `json:"at,omitempty"`
}

// QuietWindow is one span of quiet hours. Start and End are "HH:MM" in
// Preferences.Timezone; End before Start wraps past midnight (22:00 to 07:00).
// Days lists the weekdays (0 = Sunday) on which the window starts; empty means
// every day.
type QuietWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
	Days  []int  `json:"days,omitempty"`
	// Allow is the lowest severity that still notifies during this window.
	// Empty means nothing gets through (critical alarms included).
	Allow Severity `json:"allow,omitempty"`
}

// QuietPref is the global quiet-hours setting.
type QuietPref struct {
	Enabled bool          `json:"enabled"`
	Windows []QuietWindow `json:"windows"`
}

// LearningPref configures learning mode.
type LearningPref struct {
	Enabled bool `json:"enabled"`
	// Period is how long after install learning-flagged types are recorded as
	// info without notifying.
	Period Duration `json:"period"`
	// DevicePeriod is the same for a device after it was first seen, for
	// types flagged DeviceLearning.
	DevicePeriod Duration `json:"device_period"`
}

// TypePref overrides one alarm type. The zero value changes nothing.
type TypePref struct {
	// Off silences notifications for the type everywhere (alarms are still
	// recorded).
	Off bool `json:"off,omitempty"`
	// OffForClasses silences it for these device classes ("camera", "tv").
	OffForClasses []string `json:"off_for_classes,omitempty"`
	// Channels replaces the type's default channels when non-empty.
	Channels []string `json:"channels,omitempty"`
}

// Preferences is everything a household can tune about alarms.
type Preferences struct {
	// Channels maps ChannelPush and ChannelNtfy to their settings.
	Channels map[string]ChannelPref `json:"channels"`
	// NtfyAlways sends through ntfy in addition to Web Push, not only as the
	// fallback when push could not deliver.
	NtfyAlways bool `json:"ntfy_always"`
	// ImmediateMin is the lowest severity delivered at once; lower ones wait
	// for the digest (when enabled).
	ImmediateMin Severity     `json:"immediate_min"`
	Digest       DigestPref   `json:"digest"`
	Quiet        QuietPref    `json:"quiet"`
	Learning     LearningPref `json:"learning"`
	// Types holds per-type switches, keyed by alarm type ID.
	Types map[string]TypePref `json:"types,omitempty"`
	// Timezone is an IANA name ("America/Chicago"), "UTC", or empty for the
	// server's local zone. Quiet hours, digest times and "tomorrow morning"
	// use it.
	Timezone string `json:"timezone,omitempty"`
	// MorningHour is the hour (0 to 23) "until tomorrow morning" ends.
	MorningHour int `json:"morning_hour"`
	// PortalURL is the portal's base URL, used to build absolute links for
	// ntfy. Empty means ntfy gets no Click link.
	PortalURL string `json:"portal_url,omitempty"`
}

// DefaultPreferences returns the shipped defaults: push and ntfy carry
// everything low and above, high and above is immediate, the rest goes in a
// digest every 6 hours, quiet hours are off, and learning mode lasts 72 hours.
func DefaultPreferences() Preferences {
	return Preferences{
		Channels: map[string]ChannelPref{
			ChannelPush: {Enabled: true, MinSeverity: SeverityLow},
			ChannelNtfy: {Enabled: true, MinSeverity: SeverityLow},
		},
		ImmediateMin: SeverityHigh,
		Digest:       DigestPref{Enabled: true, Every: Duration(6 * time.Hour)},
		Quiet: QuietPref{Windows: []QuietWindow{
			{Start: "22:00", End: "07:00", Allow: SeverityCritical},
		}},
		Learning:    LearningPref{Enabled: true, Period: Duration(72 * time.Hour), DevicePeriod: Duration(24 * time.Hour)},
		MorningHour: 8,
	}
}

// Clone returns a deep copy.
func (p Preferences) Clone() Preferences {
	c := p
	c.Channels = make(map[string]ChannelPref, len(p.Channels))
	for k, v := range p.Channels {
		c.Channels[k] = v
	}
	if p.Types != nil {
		c.Types = make(map[string]TypePref, len(p.Types))
		for k, v := range p.Types {
			v.OffForClasses = append([]string(nil), v.OffForClasses...)
			v.Channels = append([]string(nil), v.Channels...)
			c.Types[k] = v
		}
	}
	c.Quiet.Windows = make([]QuietWindow, len(p.Quiet.Windows))
	for i, w := range p.Quiet.Windows {
		w.Days = append([]int(nil), w.Days...)
		c.Quiet.Windows[i] = w
	}
	return c
}

// ErrBadPreferences wraps a validation failure.
var ErrBadPreferences = errors.New("alarms: invalid preferences")

var hhmmRE = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):([0-5][0-9])$`)

// parseHHMM returns minutes after midnight.
func parseHHMM(s string) (int, bool) {
	m := hhmmRE.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	h, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return h*60 + min, true
}

// Location resolves the Timezone setting.
func (p Preferences) Location() (*time.Location, error) {
	switch p.Timezone {
	case "", "Local":
		return time.Local, nil
	case "UTC":
		return time.UTC, nil
	}
	return time.LoadLocation(p.Timezone)
}

// Validate checks every field.
func (p Preferences) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadPreferences, fmt.Sprintf(format, a...))
	}
	if _, err := p.Location(); err != nil {
		return bad("timezone %q", p.Timezone)
	}
	for name, c := range p.Channels {
		if name != ChannelPush && name != ChannelNtfy {
			return bad("unknown channel %q", name)
		}
		if !c.MinSeverity.Valid() {
			return bad("channel %s: min severity %q", name, c.MinSeverity)
		}
	}
	if !p.ImmediateMin.Valid() {
		return bad("immediate_min %q", p.ImmediateMin)
	}
	if p.Digest.At != "" {
		if _, ok := parseHHMM(p.Digest.At); !ok {
			return bad("digest time %q", p.Digest.At)
		}
	} else if p.Digest.Enabled && p.Digest.Every.D() < time.Minute {
		return bad("digest interval must be at least one minute")
	}
	for i, w := range p.Quiet.Windows {
		if _, ok := parseHHMM(w.Start); !ok {
			return bad("quiet window %d start %q", i, w.Start)
		}
		if _, ok := parseHHMM(w.End); !ok {
			return bad("quiet window %d end %q", i, w.End)
		}
		if w.Allow != "" && !w.Allow.Valid() {
			return bad("quiet window %d allow %q", i, w.Allow)
		}
		for _, d := range w.Days {
			if d < 0 || d > 6 {
				return bad("quiet window %d day %d", i, d)
			}
		}
	}
	if p.Learning.Period < 0 || p.Learning.DevicePeriod < 0 {
		return bad("learning periods must not be negative")
	}
	if p.MorningHour < 0 || p.MorningHour > 23 {
		return bad("morning_hour %d", p.MorningHour)
	}
	for id, t := range p.Types {
		for _, c := range t.Channels {
			if c != ChannelPortal && c != ChannelPush && c != ChannelNtfy {
				return bad("type %s: channel %q", id, c)
			}
		}
	}
	if p.PortalURL != "" {
		if !strings.HasPrefix(p.PortalURL, "https://") && !strings.HasPrefix(p.PortalURL, "http://") {
			return bad("portal_url must be http(s)")
		}
	}
	return nil
}

// channelsFor returns the channels a type uses under these preferences.
func (p Preferences) channelsFor(t AlarmType) []string {
	if tp, ok := p.Types[t.ID]; ok && len(tp.Channels) > 0 {
		return tp.Channels
	}
	return t.Channels
}

// typeOn reports whether notifications for the type and device class are on.
func (p Preferences) typeOn(typ, class string) bool {
	tp, ok := p.Types[typ]
	if !ok {
		return true
	}
	if tp.Off {
		return false
	}
	for _, c := range tp.OffForClasses {
		if class != "" && strings.EqualFold(c, class) {
			return false
		}
	}
	return true
}

// ---- time helpers ------------------------------------------------------------

// QuietUntil reports whether t falls inside a quiet window that holds an
// alarm of severity sev. When it does, it returns the end of that window; the
// zero time means no hold. Alarms at or above a window's Allow severity are
// not held by it. Overlapping windows hold until the latest end.
func (p Preferences) QuietUntil(t time.Time, sev Severity, loc *time.Location) time.Time {
	if !p.Quiet.Enabled {
		return time.Time{}
	}
	t = t.In(loc)
	var end time.Time
	for _, w := range p.Quiet.Windows {
		if w.Allow != "" && sev.AtLeast(w.Allow) {
			continue
		}
		if e, ok := windowEnd(w, t); ok && e.After(end) {
			end = e
		}
	}
	return end
}

func dayAllowed(days []int, wd time.Weekday) bool {
	if len(days) == 0 {
		return true
	}
	for _, d := range days {
		if time.Weekday(d) == wd {
			return true
		}
	}
	return false
}

// windowEnd reports whether t (already in the window's zone) is inside w and
// when that occurrence ends.
func windowEnd(w QuietWindow, t time.Time) (time.Time, bool) {
	start, _ := parseHHMM(w.Start)
	end, _ := parseHHMM(w.End)
	m := t.Hour()*60 + t.Minute()
	at := func(day time.Time, mins int) time.Time {
		return time.Date(day.Year(), day.Month(), day.Day(), mins/60, mins%60, 0, 0, t.Location())
	}
	switch {
	case start == end: // a full day
		if dayAllowed(w.Days, t.Weekday()) {
			return at(t, 0).AddDate(0, 0, 1), true
		}
	case start < end:
		if m >= start && m < end && dayAllowed(w.Days, t.Weekday()) {
			return at(t, end), true
		}
	default: // wraps midnight
		if m >= start && dayAllowed(w.Days, t.Weekday()) {
			return at(t.AddDate(0, 0, 1), end), true
		}
		if m < end && dayAllowed(w.Days, t.AddDate(0, 0, -1).Weekday()) {
			return at(t, end), true
		}
	}
	return time.Time{}, false
}

// NextAt returns the first moment after t at which the wall clock reads
// "HH:MM" in loc. It is used for digest times.
func NextAt(t time.Time, hhmm string, loc *time.Location) time.Time {
	mins, _ := parseHHMM(hhmm)
	t = t.In(loc)
	c := time.Date(t.Year(), t.Month(), t.Day(), mins/60, mins%60, 0, 0, loc)
	if !c.After(t) {
		c = time.Date(t.Year(), t.Month(), t.Day()+1, mins/60, mins%60, 0, 0, loc)
	}
	return c
}

// MutePreset names a mute duration.
type MutePreset string

// Mute presets.
const (
	MuteHour     MutePreset = "1h"
	MuteTomorrow MutePreset = "tomorrow" // until the next morning (Preferences.MorningHour)
	MuteDays     MutePreset = "days"     // MuteSpec.Days days
	MuteForever  MutePreset = "forever"
	MuteUntil    MutePreset = "until" // MuteSpec.Until
)

// MuteSpec says how long a mute lasts.
type MuteSpec struct {
	Preset MutePreset `json:"preset"`
	Days   int        `json:"days,omitempty"`
	Until  time.Time  `json:"until,omitzero"`
}

// ErrBadMuteSpec reports an unusable mute duration.
var ErrBadMuteSpec = errors.New("alarms: invalid mute duration")

// Resolve returns the moment the mute ends; the zero time means forever.
func (s MuteSpec) Resolve(now time.Time, loc *time.Location, morningHour int) (time.Time, error) {
	switch s.Preset {
	case MuteHour:
		return now.Add(time.Hour), nil
	case MuteTomorrow:
		return NextAt(now, fmt.Sprintf("%02d:00", morningHour), loc), nil
	case MuteDays:
		if s.Days < 1 || s.Days > 3650 {
			return time.Time{}, fmt.Errorf("%w: days must be 1 to 3650", ErrBadMuteSpec)
		}
		return now.In(loc).AddDate(0, 0, s.Days), nil
	case MuteForever:
		return time.Time{}, nil
	case MuteUntil:
		if !s.Until.After(now) {
			return time.Time{}, fmt.Errorf("%w: until is in the past", ErrBadMuteSpec)
		}
		return s.Until, nil
	}
	return time.Time{}, fmt.Errorf("%w: preset %q", ErrBadMuteSpec, s.Preset)
}
