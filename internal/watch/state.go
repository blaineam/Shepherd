// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
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
