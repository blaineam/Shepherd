// SPDX-License-Identifier: AGPL-3.0-or-later

package accountability

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Codec transforms the serialized files on their way to and from disk, so a
// caller can plug in encryption later (same shape as the Codec in
// internal/devices and internal/alarms, so one implementation can serve all
// three).
type Codec interface {
	Encode(plain []byte) ([]byte, error)
	Decode(stored []byte) ([]byte, error)
}

// PlainCodec stores bytes unchanged. It is the default: see
// docs/ACCOUNTABILITY.md for the SMTP-password-at-rest gap this leaves, which
// matches the rest of the project today.
type PlainCodec struct{}

// Encode returns b unchanged.
func (PlainCodec) Encode(b []byte) ([]byte, error) { return b, nil }

// Decode returns b unchanged.
func (PlainCodec) Decode(b []byte) ([]byte, error) { return b, nil }

// File names inside Options.Dir.
const (
	// ContactsFile holds contacts and subscriptions.
	ContactsFile = "accountability.json"
	// PendingFile holds digest and immediate-mode accumulation in
	// progress, so a restart does not lose or double-count a digest.
	PendingFile = "accountability-pending.json"
)

// ErrBadSnapshot is returned by load for an unreadable or unsupported file.
var ErrBadSnapshot = errors.New("accountability: unreadable snapshot")

// writeFileAtomic writes data to path through a temp file in the same
// directory (mode 0600, fsync, rename) so a crash never leaves half a file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".accountability-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	err = errors.Join(tmp.Chmod(0o600), werr, tmp.Sync(), tmp.Close())
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// saveJSON encodes v through the codec and writes it atomically.
func saveJSON(codec Codec, path string, v any) error {
	plain, _ := json.MarshalIndent(v, "", " ") // plain structs: cannot fail
	data, err := codec.Encode(plain)
	if err != nil {
		return fmt.Errorf("accountability: encode: %w", err)
	}
	return writeFileAtomic(path, data)
}

// loadJSON reads path through the codec into v. A missing file returns an
// error satisfying errors.Is(err, os.ErrNotExist).
func loadJSON(codec Codec, path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plain, err := codec.Decode(data)
	if err != nil {
		return fmt.Errorf("accountability: decode: %w", err)
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSnapshot, err)
	}
	return nil
}
