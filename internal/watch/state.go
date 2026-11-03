// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"shepherd/internal/intercept"
)

// persisted is what survives a restart: only the kill switch. An owner who
// pressed it because something was wrong must not find steering silently
// back on after a reboot; it stays off until they re-arm it.
type persisted struct {
	Killed bool `json:"killed"`
	// FlappyDrivers names kernel drivers that were seen to drop the link
	// when a native XDP attach rebuilt their receive rings. Learned by
	// watching the kernel's carrier counter either side of an attach, and
	// remembered so the cost is paid once ever rather than once per
	// start. A driver listed here gets generic XDP instead, which runs in
	// the kernel just the same and never reinitialises the interface.
	FlappyDrivers []string `json:"flappy_drivers,omitempty"`
	// LoopingRelays names relays whose self-test found that a frame they
	// transmit comes back to the interface it left (intercept's
	// ErrRelayLoops), as "<interface>/<relay>", e.g. "eth0/xdp-generic".
	// Remembered because the test costs a brief burst of looping frames to
	// run, so it is run once rather than on every restart, and because a
	// relay that loops on this hardware will loop again.
	LoopingRelays []string `json:"looping_relays,omitempty"`
	// LastLoopStop is what the loop brake measured the last time it
	// stopped steering, kept because a container rebuild takes the logs
	// with it. That has now happened twice to this investigation: the
	// brake logs exactly the evidence the cause needs, a redeploy discards
	// the container, and the evidence is gone. The kill switch survives a
	// restart, so the reason for it should too.
	LastLoopStop *LoopStop `json:"last_loop_stop,omitempty"`
}

// LoopStop is one loop-brake trip, as measured.
type LoopStop struct {
	At time.Time `json:"at"`
	// RxPackets and TxPackets are the interface's counts in the second
	// that tripped it, and ApartPercent how far apart they were.
	RxPackets    float64 `json:"rx_packets"`
	TxPackets    float64 `json:"tx_packets"`
	ApartPercent float64 `json:"apart_percent"`
	// RelayedPPS is what the relay itself reported, and SharePercent that
	// as a share of received. Both are evidence rather than triggers: the
	// relay's counter lags a storm by seconds.
	RelayedPPS   float64 `json:"relayed_pps"`
	SharePercent float64 `json:"share_percent"`
	// Suppressed is the duplicate brake's count at the moment of the trip.
	// A high figure with a trip anyway means a loop the duplicate brake
	// could not break; a zero means the mirrored traffic was not duplicate
	// frames at all, which points somewhere else entirely.
	Suppressed uint64 `json:"duplicates_suppressed"`
	// Devices names what was relaying most, and Flows the sampled-frame
	// digest: the lines that say whether the frames were circulating.
	Devices []string `json:"devices,omitempty"`
	Flows   []string `json:"flows,omitempty"`
	// StreakRelayed, StreakDuplicates and StreakReturned are the relay's
	// counts over the mirrored seconds alone: frames relayed, copies the
	// duplicate brake refused, and Shepherd's own frames that came back.
	StreakRelayed    uint64 `json:"streak_relayed"`
	StreakDuplicates uint64 `json:"streak_duplicates"`
	StreakReturned   uint64 `json:"streak_returned"`
	// Echo is how long echoed frames took to return, bucketed: microseconds
	// means local, hundreds of microseconds a switch, milliseconds wireless.
	Echo *intercept.EchoDelays `json:"echo_delays,omitempty"`
	// Frames are the sampled frames as hex (first 60 bytes each), for
	// opening in a packet tool.
	Frames []string `json:"frames,omitempty"`
}

// echoDelays reads the relay's echo histogram, nil when it has none.
func echoDelays(ctrl *intercept.Controller) *intercept.EchoDelays {
	d := ctrl.EchoDelays()
	if d.Total() == 0 {
		return nil
	}
	return &d
}

// sampleHex renders up to 64 sampled frames, newest last, as
// "len=N <hex>" lines.
func sampleHex(samples []intercept.FrameSample) []string {
	if len(samples) > 64 {
		samples = samples[len(samples)-64:]
	}
	out := make([]string, 0, len(samples))
	for _, s := range samples {
		out = append(out, fmt.Sprintf("len=%d %x", s.Len, s.Bytes))
	}
	return out
}

// appendStopHistory appends the trip to watch-stops.jsonl beside the state
// file. last_loop_stop keeps only the latest trip, so without this each
// new one erases the evidence of the one before; failure to write it is
// not worth failing the trip over.
func appendStopHistory(statePath string, stop *LoopStop) {
	b, err := json.Marshal(stop)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(statePath), "watch-stops.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// hasLoopingRelay reports whether the relay named "<iface>/<relay>" is
// already known to loop here.
func (p persisted) hasLoopingRelay(key string) bool {
	for _, x := range p.LoopingRelays {
		if x == key {
			return true
		}
	}
	return false
}

// hasDriver reports whether d is already known to flap.
func (p persisted) hasDriver(d string) bool {
	for _, x := range p.FlappyDrivers {
		if x == d {
			return true
		}
	}
	return false
}

func loadState(path string) (persisted, error) {
	var st persisted
	if path == "" {
		return st, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return persisted{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return st, nil
}

func saveState(path string, st persisted) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
