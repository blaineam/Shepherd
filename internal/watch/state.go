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
