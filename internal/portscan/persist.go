// SPDX-License-Identifier: AGPL-3.0-or-later

package portscan

import (
	"encoding/json"
	"os"
)

type persistedFile struct {
	Devices map[string]*DeviceScan `json:"devices"`
}

// Save writes the scan history to path (mode 0600), atomically.
func (s *Scanner) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(persistedFile{Devices: s.history}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load replaces the scan history with what is saved at path. A missing file
// is reported through the usual os.IsNotExist error; callers that want to
// start empty in that case check for it, as with every other store here.
func (s *Scanner) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f persistedFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.Devices == nil {
		f.Devices = map[string]*DeviceScan{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = f.Devices
	return nil
}
