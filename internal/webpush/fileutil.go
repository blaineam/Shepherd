// SPDX-License-Identifier: AGPL-3.0-or-later

package webpush

import (
	"errors"
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to path through a temp file in the same
// directory (mode 0600, fsync, rename) so a crash never leaves half a file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".webpush-*.tmp")
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
