// SPDX-License-Identifier: AGPL-3.0-or-later

package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
