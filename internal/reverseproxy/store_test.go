// SPDX-License-Identifier: AGPL-3.0-or-later

package reverseproxy

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func jellyfin() Host {
	return Host{Domain: "jellyfin.example.com", TargetScheme: "http", TargetHost: "127.0.0.1", TargetPort: 8096, Enabled: true}
}

func TestOpenMissingFileStartsEmptyAndWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reverseproxy.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if hs := s.List(); len(hs) != 0 {
		t.Errorf("List() = %+v, want none", hs)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("opening must not create %s until the first edit: %v", path, err)
	}
}

func TestStoreCRUDPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reverseproxy.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	added, err := s.Add(Host{Domain: "Jellyfin.Example.com", TargetHost: "127.0.0.1", TargetPort: 8096, Enabled: true})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if added.ID == "" || added.Domain != "jellyfin.example.com" || added.TargetScheme != "http" {
		t.Fatalf("Add returned %+v, want an id and normalized fields", added)
	}
	if _, err := s.Add(Host{Domain: "git.example.com", TargetScheme: "https", TargetHost: "127.0.0.1", TargetPort: 3443, SkipTLSVerify: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the first edit must write %s: %v", path, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s mode = %v, want 0600", path, info.Mode().Perm())
	}

	upd := added
	upd.TargetPort = 8920
	upd.TargetScheme = "https"
	upd.Enabled = false
	got, err := s.Update(added.ID, upd)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got.ID != added.ID || got.TargetPort != 8920 || got.Enabled {
		t.Errorf("Update returned %+v", got)
	}

	re, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	list := re.List()
	if len(list) != 2 || list[0].Domain != "git.example.com" || list[1].Domain != "jellyfin.example.com" {
		t.Fatalf("reopened List() = %+v, want both hosts sorted by domain", list)
	}
	if list[1].TargetPort != 8920 || list[1].Enabled || list[1].ID != added.ID {
		t.Errorf("reopened jellyfin = %+v, want the update to have persisted", list[1])
	}
	if g, ok := re.Get(added.ID); !ok || g.Domain != "jellyfin.example.com" {
		t.Errorf("Get(%q) = %+v, %v", added.ID, g, ok)
	}

	if err := re.Remove(added.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := re.Lookup("jellyfin.example.com"); ok {
		t.Error("a removed host must stop routing")
	}
	again, _ := Open(path)
	if len(again.List()) != 1 {
		t.Errorf("after Remove and reopen: %+v", again.List())
	}
}

func TestStoreRejectsDuplicatesUnknownIDsAndInvalidHosts(t *testing.T) {
	s, _ := Open("")
	h, err := s.Add(jellyfin())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(Host{Domain: "JELLYFIN.example.com", TargetHost: "192.0.2.10", TargetPort: 80}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("a second host for the same domain: err = %v, want ErrDuplicate", err)
	}
	other, err := s.Add(Host{Domain: "immich.example.com", TargetHost: "127.0.0.1", TargetPort: 2283})
	if err != nil {
		t.Fatal(err)
	}
	renamed := other
	renamed.Domain = h.Domain
	if _, err := s.Update(other.ID, renamed); !errors.Is(err, ErrDuplicate) {
		t.Errorf("renaming onto another host's domain: err = %v, want ErrDuplicate", err)
	}
	same := h
	same.TargetPort = 9000
	if _, err := s.Update(h.ID, same); err != nil {
		t.Errorf("updating a host without changing its domain must not count as a duplicate: %v", err)
	}
	if _, ok := s.Get("nope"); ok {
		t.Error("Get(unknown) found something")
	}
	if _, err := s.Update("nope", jellyfin()); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.Remove("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.Add(Host{Domain: "bad", TargetHost: "app", TargetPort: 80}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Add(invalid) = %v, want ErrInvalid", err)
	}
	if _, err := s.Update(h.ID, Host{Domain: "bad"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Update(invalid) = %v, want ErrInvalid", err)
	}
	if len(s.List()) != 2 {
		t.Errorf("rejected edits must change nothing: %+v", s.List())
	}
}

func TestLookupMatchesTheWayRequestsSpellTheHost(t *testing.T) {
	s, _ := Open("")
	if _, err := s.Add(jellyfin()); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"jellyfin.example.com", "JELLYFIN.example.com", "jellyfin.example.com.", "jellyfin.example.com:8443", "jellyfin.example.com.:443"} {
		if _, ok := s.Lookup(in); !ok {
			t.Errorf("Lookup(%q) found nothing", in)
		}
	}
	for _, in := range []string{"", "example.com", "x.jellyfin.example.com", "192.0.2.1", "[2001:db8::1]:443"} {
		if h, ok := s.Lookup(in); ok {
			t.Errorf("Lookup(%q) = %+v, want no match", in, h)
		}
	}
}

func TestOpenRejectsACorruptOrForeignFile(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"garbage":     "{not json",
		"version":     `{"version":99,"hosts":[]}`,
		"invalid":     `{"version":1,"hosts":[{"id":"a","domain":"nope","target_scheme":"http","target_host":"app","target_port":80}]}`,
		"duplicate":   `{"version":1,"hosts":[{"id":"a","domain":"a.example.com","target_scheme":"http","target_host":"app","target_port":80},{"id":"b","domain":"a.example.com","target_scheme":"http","target_host":"app","target_port":81}]}`,
		"missing id":  `{"version":1,"hosts":[{"domain":"a.example.com","target_scheme":"http","target_host":"app","target_port":80}]}`,
		"repeated id": `{"version":1,"hosts":[{"id":"a","domain":"a.example.com","target_scheme":"http","target_host":"app","target_port":80},{"id":"a","domain":"b.example.com","target_scheme":"http","target_host":"app","target_port":81}]}`,
	}
	for name, body := range cases {
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); err == nil {
			t.Errorf("%s: Open succeeded, want an error so a later edit cannot overwrite the owner's hosts", name)
		}
	}
	if _, err := Open(dir); err == nil {
		t.Error("Open(a directory) succeeded")
	}
}

func TestFailedSaveChangesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "reverseproxy.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Add(jellyfin())
	if err != nil {
		t.Fatal(err)
	}
	// Replace the directory with a file so every later write fails.
	if err := os.RemoveAll(filepath.Join(dir, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(Host{Domain: "immich.example.com", TargetHost: "127.0.0.1", TargetPort: 2283}); err == nil {
		t.Error("Add succeeded although saving failed")
	}
	upd := h
	upd.TargetPort = 1
	if _, err := s.Update(h.ID, upd); err == nil {
		t.Error("Update succeeded although saving failed")
	}
	if err := s.Remove(h.ID); err == nil {
		t.Error("Remove succeeded although saving failed")
	}
	if list := s.List(); len(list) != 1 || list[0].TargetPort != 8096 {
		t.Errorf("after failed saves List() = %+v, want the original host untouched", list)
	}
	if _, ok := s.Lookup("immich.example.com"); ok {
		t.Error("a host whose save failed must not route")
	}
}

func TestSaveFailuresAtEachStepChangeNothing(t *testing.T) {
	t.Run("temporary file cannot be written", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "reverseproxy.json")
		s, _ := Open(path)
		if err := os.Mkdir(path+".tmp", 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Add(jellyfin()); err == nil {
			t.Error("Add succeeded although the temporary file could not be written")
		}
		if len(s.List()) != 0 {
			t.Errorf("List() = %+v after a failed save", s.List())
		}
	})
	t.Run("rename over the real file fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "reverseproxy.json")
		s, _ := Open(path)
		if err := os.MkdirAll(filepath.Join(path, "occupied"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Add(jellyfin()); err == nil {
			t.Error("Add succeeded although the rename could not happen")
		}
		if _, err := os.Stat(path + ".tmp"); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a failed rename must not leave %s.tmp behind: %v", path, err)
		}
		if len(s.List()) != 0 {
			t.Errorf("List() = %+v after a failed save", s.List())
		}
	})
}
