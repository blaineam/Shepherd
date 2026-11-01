// SPDX-License-Identifier: AGPL-3.0-or-later

// Package update checks GitHub releases for a newer Shepherd, verifies a
// release against its checksums and an Ed25519 signature, swaps the
// running binary for it while keeping the previous one, and rolls back on
// the next start if the new one does not stay up. See docs/UPDATE.md.
//
// It is deliberately small and infrequent: one HTTPS request a day to
// find the latest release, and nothing at all is downloaded until the
// owner (or the configuration) asks for an update to be applied.
package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultRepo is the GitHub repository releases are read from.
const DefaultRepo = "blaineam/shepherd"

// MaxArchiveBytes caps one release archive download.
const MaxArchiveBytes = 128 << 20

// Channel is which releases count: stable only, or betas too.
type Channel string

const (
	ChannelStable Channel = "stable"
	ChannelBeta   Channel = "beta"
)

// Version is a parsed semantic version: X.Y.Z with an optional
// prerelease such as "beta.17", where numeric prerelease parts compare as
// numbers (beta.10 is newer than beta.9) and any prerelease is older than
// the release it precedes.
type Version struct {
	Major, Minor, Patch int
	Pre                 []string
	raw                 string
}

var versionRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// ParseVersion reads "1.2.3", "v1.2.3", "1.2.3-beta.4" and a build
// suffix; String gives it back without the "v", which is how releases
// name their files. A development build ("dev", or anything else) is not
// a version.
func ParseVersion(s string) (Version, bool) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, false
	}
	v := Version{raw: strings.TrimPrefix(strings.TrimSpace(s), "v")}
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	if m[4] != "" {
		v.Pre = strings.Split(m[4], ".")
	}
	return v, true
}

func (v Version) String() string { return v.raw }

// Prerelease reports whether v has a prerelease part.
func (v Version) Prerelease() bool { return len(v.Pre) > 0 }

// Compare orders versions: -1 when v is older than o, 0 equal, 1 newer.
func (v Version) Compare(o Version) int {
	for _, d := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(v.Pre) == 0 && len(o.Pre) == 0:
		return 0
	case len(v.Pre) == 0:
		return 1 // a release is newer than its prereleases
	case len(o.Pre) == 0:
		return -1
	}
	for i := 0; i < len(v.Pre) && i < len(o.Pre); i++ {
		a, b := v.Pre[i], o.Pre[i]
		an, aerr := strconv.Atoi(a)
		bn, berr := strconv.Atoi(b)
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case aerr == nil:
			return -1 // numeric parts sort before alphanumeric ones
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(a, b); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(v.Pre) < len(o.Pre):
		return -1
	case len(v.Pre) > len(o.Pre):
		return 1
	}
	return 0
}

// Release is one published release.
type Release struct {
	Version     Version           `json:"-"`
	Tag         string            `json:"tag"`
	Name        string            `json:"name"`
	Prerelease  bool              `json:"prerelease"`
	PublishedAt time.Time         `json:"published_at"`
	URL         string            `json:"url"`    // the release page
	Assets      map[string]string `json:"assets"` // file name -> download URL
}

// VersionString is Release.Version as text, for JSON.
func (r Release) VersionString() string { return r.Version.String() }

// Checker finds the latest release on a channel.
type Checker struct {
	// Repo is "owner/name"; empty uses DefaultRepo.
	Repo string
	// Client makes the request; nil uses a client with a 30-second timeout.
	Client *http.Client
	// API is the GitHub API base; empty uses https://api.github.com. Tests
	// point it at a local server.
	API string
}

func (c Checker) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c Checker) repo() string {
	if c.Repo != "" {
		return c.Repo
	}
	return DefaultRepo
}

func (c Checker) api() string {
	if c.API != "" {
		return strings.TrimSuffix(c.API, "/")
	}
	return "https://api.github.com"
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// ErrNoRelease says the channel has no release yet: a repository that
// has only published betas has no "latest" stable release, and GitHub
// answers 404. It is a state, not a failure.
var ErrNoRelease = errors.New("update: no release has been published on this channel yet")

func (c Checker) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "shepherd")
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNoRelease
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update: GitHub answered HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

func toRelease(g ghRelease) (Release, bool) {
	v, ok := ParseVersion(g.TagName)
	if !ok || g.Draft {
		return Release{}, false
	}
	r := Release{Version: v, Tag: g.TagName, Name: g.Name, Prerelease: g.Prerelease, PublishedAt: g.PublishedAt, URL: g.HTMLURL, Assets: map[string]string{}}
	for _, a := range g.Assets {
		r.Assets[a.Name] = a.URL
	}
	return r, true
}

// Latest returns the newest release on the channel: the one GitHub marks
// latest for stable, else the newest of the recent releases including
// prereleases.
func (c Checker) Latest(ctx context.Context, ch Channel) (Release, error) {
	if ch != ChannelBeta {
		var g ghRelease
		if err := c.get(ctx, "/repos/"+c.repo()+"/releases/latest", &g); err != nil {
			return Release{}, err
		}
		r, ok := toRelease(g)
		if !ok {
			return Release{}, errors.New("update: the latest release has no version tag")
		}
		return r, nil
	}
	var list []ghRelease
	if err := c.get(ctx, "/repos/"+c.repo()+"/releases?per_page=20", &list); err != nil {
		return Release{}, err
	}
	var best Release
	found := false
	for _, g := range list {
		r, ok := toRelease(g)
		if !ok {
			continue
		}
		if !found || r.Version.Compare(best.Version) > 0 {
			best, found = r, true
		}
	}
	if !found {
		return Release{}, ErrNoRelease
	}
	return best, nil
}

// AssetName is the archive for goos/goarch at version, as build-release
// names it.
func AssetName(version, goos, goarch string) string {
	if goos == "windows" {
		return "shepherd_" + version + "_" + goos + "_" + goarch + ".zip"
	}
	return "shepherd_" + version + "_" + goos + "_" + goarch + ".tar.gz"
}

// Sums is a parsed SHA256SUMS: file name to hex digest.
type Sums map[string]string

// ParseSums reads shasum -a 256 output.
func ParseSums(b []byte) Sums {
	out := Sums{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || len(f[0]) != 64 {
			continue
		}
		out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
	}
	return out
}

// VerifySignature checks sig (base64, as shepherd-sign writes it) over
// sums with pub. An empty key never verifies: apply refuses without one.
func VerifySignature(pub ed25519.PublicKey, sums, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("update: no release signing key is built into this Shepherd, so releases cannot be verified; see docs/UPDATE.md")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil {
		return fmt.Errorf("update: the signature is not readable: %w", err)
	}
	if !ed25519.Verify(pub, sums, raw) {
		return errors.New("update: the release's checksums are not signed by Shepherd's release key")
	}
	return nil
}

// Sign produces the signature VerifySignature checks.
func Sign(priv ed25519.PrivateKey, sums []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n")
}

// Fetcher downloads release files. Nil uses a plain client; tests fake it.
type Fetcher func(ctx context.Context, url string, max int64) ([]byte, error)

// HTTPFetcher downloads with client, refusing anything over max bytes.
func HTTPFetcher(client *http.Client) Fetcher {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	return func(ctx context.Context, url string, max int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "shepherd")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > max {
			return nil, fmt.Errorf("download is larger than the %d MiB cap", max>>20)
		}
		return b, nil
	}
}

// Download fetches the archive for goos/goarch, checks it against the
// release's SHA256SUMS, and checks that file's signature with pub, then
// returns the shepherd binary from inside it. Nothing is written to disk.
func Download(ctx context.Context, fetch Fetcher, rel Release, goos, goarch string, pub ed25519.PublicKey) ([]byte, error) {
	if fetch == nil {
		fetch = HTTPFetcher(nil)
	}
	name := AssetName(rel.Version.String(), goos, goarch)
	archiveURL, ok := rel.Assets[name]
	if !ok {
		return nil, fmt.Errorf("update: release %s has no build for %s/%s", rel.Version, goos, goarch)
	}
	sumsURL, ok := rel.Assets["SHA256SUMS"]
	if !ok {
		return nil, fmt.Errorf("update: release %s has no SHA256SUMS", rel.Version)
	}
	sigURL, ok := rel.Assets["SHA256SUMS.sig"]
	if !ok {
		return nil, fmt.Errorf("update: release %s is not signed (no SHA256SUMS.sig), so it cannot be applied automatically", rel.Version)
	}
	sums, err := fetch(ctx, sumsURL, 1<<20)
	if err != nil {
		return nil, err
	}
	sig, err := fetch(ctx, sigURL, 4096)
	if err != nil {
		return nil, err
	}
	if err := VerifySignature(pub, sums, sig); err != nil {
		return nil, err
	}
	want, ok := ParseSums(sums)[name]
	if !ok {
		return nil, fmt.Errorf("update: SHA256SUMS has no entry for %s", name)
	}
	archive, err := fetch(ctx, archiveURL, MaxArchiveBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != want {
		return nil, errors.New("update: the downloaded archive does not match its checksum")
	}
	if goos == "windows" {
		return nil, errors.New("update: applying an update on Windows is not supported yet; download the release by hand")
	}
	return extractBinary(archive)
}

// extractBinary finds the shepherd binary inside a release tar.gz.
func extractBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("update: the archive is not gzip: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("update: reading the archive: %w", err)
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == "shepherd" {
			b, err := io.ReadAll(io.LimitReader(tr, MaxArchiveBytes))
			if err != nil {
				return nil, err
			}
			if len(b) == 0 {
				return nil, errors.New("update: the archive's shepherd binary is empty")
			}
			return b, nil
		}
	}
	return nil, errors.New("update: the archive holds no shepherd binary")
}

// State is what update.json in the data directory records: the update
// applied last, and whether the binary that followed it stayed up.
type State struct {
	// Applied is the version swapped in, At when; Prev is the previous
	// binary kept beside it for rollback.
	Applied string    `json:"applied,omitempty"`
	At      time.Time `json:"at,omitzero"`
	Prev    string    `json:"prev,omitempty"`
	// Starts counts starts since the swap that did not reach Confirmed;
	// RolledBack records that the previous binary was put back, and why.
	Starts     int       `json:"starts,omitempty"`
	Confirmed  bool      `json:"confirmed,omitempty"`
	RolledBack string    `json:"rolled_back,omitempty"`
	RolledAt   time.Time `json:"rolled_at,omitzero"`
}

// StatePath is where State lives.
func StatePath(dataDir string) string { return filepath.Join(dataDir, "update.json") }

// LoadState reads the state; a missing file is the zero State.
func LoadState(dataDir string) (State, error) {
	b, err := os.ReadFile(StatePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, err
	}
	return s, nil
}

// SaveState writes the state atomically, mode 0600.
func SaveState(dataDir string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := StatePath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, StatePath(dataDir))
}

// Writable reports whether the running binary can be replaced: its
// directory must accept a new file. A read-only container (the usual
// Docker deployment) cannot, and the portal says so instead of trying.
func Writable(exe string) error {
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, ".shepherd-update-*")
	if err != nil {
		return fmt.Errorf("update: %s cannot be replaced in place (%v); update by installing the release or rebuilding the container", exe, err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// Apply writes bin beside exe, keeps the current binary as exe+".prev",
// and swaps the new one in with two renames, so at every moment there is
// a complete binary at exe. It records the swap in the data directory's
// State; the caller then re-executes itself.
func Apply(exe, dataDir string, bin []byte, version string, now time.Time) error {
	if err := Writable(exe); err != nil {
		return err
	}
	info, err := os.Stat(exe)
	if err != nil {
		return err
	}
	next := exe + ".new"
	if err := os.WriteFile(next, bin, info.Mode().Perm()|0o100); err != nil {
		return err
	}
	prev := exe + ".prev"
	_ = os.Remove(prev)
	if err := os.Rename(exe, prev); err != nil {
		os.Remove(next)
		return err
	}
	if err := os.Rename(next, exe); err != nil {
		_ = os.Rename(prev, exe) // put the old one back; nothing is lost
		return err
	}
	return SaveState(dataDir, State{Applied: version, At: now, Prev: prev})
}

// RollbackReason is why Startup rolled back.
const (
	ReasonAsked   = "asked"
	ReasonCrashed = "the updated binary did not stay up"
)

// Rollback swaps exe+".prev" back into place and records why. The caller
// re-executes itself afterwards.
func Rollback(exe, dataDir, reason string, now time.Time) error {
	st, err := LoadState(dataDir)
	if err != nil {
		return err
	}
	prev := st.Prev
	if prev == "" {
		prev = exe + ".prev"
	}
	if _, err := os.Stat(prev); err != nil {
		return fmt.Errorf("update: nothing to roll back to: %w", err)
	}
	bad := exe + ".bad"
	_ = os.Remove(bad)
	if err := os.Rename(exe, bad); err != nil {
		return err
	}
	if err := os.Rename(prev, exe); err != nil {
		_ = os.Rename(bad, exe)
		return err
	}
	_ = os.Remove(bad)
	return SaveState(dataDir, State{RolledBack: reason, RolledAt: now})
}

// MaxUnconfirmedStarts is how many times an updated binary may start
// without being confirmed healthy before Startup rolls it back.
const MaxUnconfirmedStarts = 3

// Startup is called first thing by an updated binary: it counts the start
// and, when the previous starts never reached Confirm, puts the previous
// binary back. It reports true when a rollback happened, in which case the
// caller must re-execute itself. A binary whose version is not the one
// applied (a manual install since) clears the record instead.
func Startup(exe, dataDir, version string, now time.Time) (rolledBack bool, err error) {
	st, err := LoadState(dataDir)
	if err != nil || st.Applied == "" || st.Confirmed {
		return false, err
	}
	if st.Applied != version {
		return false, SaveState(dataDir, State{})
	}
	st.Starts++
	if st.Starts >= MaxUnconfirmedStarts {
		if err := Rollback(exe, dataDir, ReasonCrashed, now); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, SaveState(dataDir, st)
}

// Confirm records that the updated binary stayed up, so later starts are
// ordinary ones.
func Confirm(dataDir string) error {
	st, err := LoadState(dataDir)
	if err != nil || st.Applied == "" || st.Confirmed {
		return err
	}
	st.Confirmed = true
	return SaveState(dataDir, st)
}

// DirSize sums the bytes under dir, grouped by top-level entry, for the
// portal's data-directory budget. Errors inside are ignored: a file that
// vanished mid-walk is not a failure.
func DirSize(dir string) (total int64, parts map[string]int64) {
	parts = map[string]int64{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, parts
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		var n int64
		if e.IsDir() {
			filepath.WalkDir(p, func(_ string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					if fi, err := d.Info(); err == nil {
						n += fi.Size()
					}
				}
				return nil
			})
		} else if fi, err := e.Info(); err == nil {
			n = fi.Size()
		}
		parts[e.Name()] = n
		total += n
	}
	return total, parts
}
