// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"shepherd/internal/alarms"
	"shepherd/internal/config"
	"shepherd/internal/update"
)

// Test seams. Production leaves them at their defaults.
var (
	updateEvery   time.Duration
	updateChecker update.Checker
	updateFetcher update.Fetcher
	updateExec    = reexec
	updateExePath = os.Executable
	// updateConfirmAfter is how long an updated binary must stay up before
	// its update counts as good (docs/UPDATE.md).
	updateConfirmAfter = 2 * time.Minute
)

// updater is the running update service: the daily check, the latest
// release it found, and the apply path. It is also the portal's handle
// (portal.Updater).
type updater struct {
	cfg     config.Config
	current string // the running version's text
	version update.Version
	exe     string
	eng     *alarms.Engine
	checker update.Checker
	fetch   update.Fetcher

	mu          sync.Mutex
	latest      *update.Release
	lastChecked time.Time
	lastError   string
	applying    bool
	applied     string
	noRelease   bool // the channel has no release yet (update.ErrNoRelease)
}

// startUpdate wires the update checker: a read of the release list on the
// configured interval, an alarm when a newer release exists, and the
// state the portal reads. It also confirms an update that was applied on
// the previous start once this binary has stayed up for a while.
func startUpdate(ctx context.Context, cfg config.Config, eng *alarms.Engine) (*updater, error) {
	if !cfg.Update.Enabled {
		return nil, nil
	}
	exe, err := updateExePath()
	if err != nil {
		return nil, err
	}
	u := &updater{cfg: cfg, current: version, exe: exe, eng: eng, checker: updateChecker, fetch: updateFetcher}
	u.version, _ = update.ParseVersion(version)
	every := time.Duration(cfg.Update.CheckHours) * time.Hour
	if updateEvery > 0 {
		every = updateEvery
	}
	go func() {
		t := time.NewTimer(updateConfirmAfter)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := update.Confirm(cfg.DataDir); err != nil {
				log.Printf("update: recording that this version stayed up: %v", err)
			}
		}
	}()
	go func() {
		u.Check(ctx)
		tk := time.NewTicker(every)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				u.Check(ctx)
			}
		}
	}()
	return u, nil
}

func (u *updater) channel() update.Channel {
	if u.cfg.Update.Channel == string(update.ChannelBeta) {
		return update.ChannelBeta
	}
	return update.ChannelStable
}

// Check reads the latest release and raises the update alarm when it is
// newer than this binary. A development build ("dev") compares as older
// than everything, so it always reports the latest release as available
// without ever applying it (Writable and the version check refuse).
func (u *updater) Check(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rel, err := u.checker.Latest(cctx, u.channel())
	u.mu.Lock()
	u.lastChecked = time.Now()
	if errors.Is(err, update.ErrNoRelease) {
		u.lastError, u.noRelease, u.latest = "", true, nil
		u.mu.Unlock()
		return
	}
	if err != nil {
		u.lastError = err.Error()
		u.mu.Unlock()
		log.Printf("update: checking for a newer release: %v", err)
		return
	}
	u.lastError, u.noRelease = "", false
	u.latest = &rel
	newer := u.newer(rel)
	u.mu.Unlock()
	if newer && u.eng != nil {
		u.eng.Raise(alarms.Event{
			Type:   alarms.TypeSelfUpdate,
			Source: "update",
			Title:  "Shepherd " + rel.Version.String() + " is available",
			Body:   "This Shepherd is " + u.current + ". Apply the update from the Overview screen, or install the release by hand.",
			Key:    "self-update|" + rel.Tag + "|",
			URL:    rel.URL,
		})
	}
}

// newer reports whether rel is newer than the running binary. A binary
// whose version does not parse (a dev build) sees every release as newer.
func (u *updater) newer(rel update.Release) bool {
	if u.version.String() == "" {
		return true
	}
	return rel.Version.Compare(u.version) > 0
}

// Status is what the portal shows.
type updateStatus struct {
	Current       string           `json:"current"`
	Channel       string           `json:"channel"`
	Latest        *update.Release  `json:"latest,omitempty"`
	LatestVersion string           `json:"latest_version,omitempty"`
	Available     bool             `json:"available"`
	CanApply      bool             `json:"can_apply"`
	Reason        string           `json:"reason,omitempty"`
	Applying      bool             `json:"applying"`
	Applied       string           `json:"applied,omitempty"`
	LastChecked   time.Time        `json:"last_checked,omitzero"`
	LastError     string           `json:"last_error,omitempty"`
	State         update.State     `json:"state"`
	DataDirBytes  int64            `json:"data_dir_bytes"`
	DataDirParts  map[string]int64 `json:"data_dir_parts"`
	// BudgetBytes is [retention] max_mb in bytes; 0 means no budget.
	BudgetBytes int64 `json:"budget_bytes,omitempty"`
}

// Status implements portal.Updater.
func (u *updater) Status() any {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := updateStatus{Current: u.current, Channel: string(u.channel()), Applying: u.applying, Applied: u.applied, LastChecked: u.lastChecked, LastError: u.lastError}
	if u.latest != nil {
		st.Latest = u.latest
		st.LatestVersion = u.latest.Version.String()
		st.Available = u.newer(*u.latest)
	}
	st.CanApply, st.Reason = u.canApply()
	st.State, _ = update.LoadState(u.cfg.DataDir)
	st.DataDirBytes, st.DataDirParts = update.DirSize(u.cfg.DataDir)
	st.BudgetBytes = int64(u.cfg.Retention.MaxMB) << 20
	return st
}

// canApply says whether "update now" would work here, and why not.
func (u *updater) canApply() (bool, string) {
	switch {
	case u.latest == nil && u.noRelease:
		return false, "no release has been published on the " + string(u.channel()) + " channel yet"
	case u.latest == nil:
		return false, "no release has been checked yet"
	case !u.newer(*u.latest):
		return false, "this Shepherd is up to date"
	case u.version.String() == "":
		return false, "this is a development build; install a release by hand"
	case update.ReleasePublicKey() == nil:
		return false, "no release signing key is built into this Shepherd, so a download could not be verified (docs/UPDATE.md)"
	case runtime.GOOS == "windows":
		return false, "updating in place is not supported on Windows yet"
	}
	if err := update.Writable(u.exe); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// CheckNow implements portal.Updater.
func (u *updater) CheckNow(ctx context.Context) any {
	u.Check(ctx)
	return u.Status()
}

// Apply implements portal.Updater: download, verify, swap, then restart
// into the new binary shortly after answering, so the portal gets its
// reply. Refused with a reason when canApply says no.
func (u *updater) Apply(ctx context.Context) error {
	u.mu.Lock()
	if u.applying {
		u.mu.Unlock()
		return errors.New("an update is already being applied")
	}
	ok, why := u.canApply()
	if !ok {
		u.mu.Unlock()
		return errors.New(why)
	}
	rel := *u.latest
	u.applying = true
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.applying = false; u.mu.Unlock() }()

	bin, err := update.Download(ctx, u.fetch, rel, runtime.GOOS, runtime.GOARCH, update.ReleasePublicKey())
	if err != nil {
		return err
	}
	if err := update.Apply(u.exe, u.cfg.DataDir, bin, rel.Version.String(), time.Now()); err != nil {
		return err
	}
	u.mu.Lock()
	u.applied = rel.Version.String()
	u.mu.Unlock()
	log.Printf("update: %s installed at %s, previous kept as %s.prev; restarting", rel.Version, u.exe, u.exe)
	go func() {
		time.Sleep(time.Second)
		if err := updateExec(u.exe); err != nil {
			log.Printf("update: restart failed (%v); the new binary runs on the next start", err)
		}
	}()
	return nil
}

// rollbackNow is the -rollback flag: put the previous binary back and
// exit, for an owner whose updated Shepherd is misbehaving but running.
func rollbackNow(cfg config.Config) error {
	exe, err := updateExePath()
	if err != nil {
		return err
	}
	if err := update.Rollback(exe, cfg.DataDir, update.ReasonAsked, time.Now()); err != nil {
		return err
	}
	log.Printf("update: the previous binary is back at %s; start Shepherd again", exe)
	return nil
}

// startupRollback is the first thing run does: an updated binary that
// never stayed up long enough to be confirmed is replaced by the previous
// one, and this process re-executes into it.
func startupRollback(cfg config.Config) error {
	exe, err := updateExePath()
	if err != nil {
		return nil // nothing to do without knowing the binary
	}
	rolled, err := update.Startup(exe, cfg.DataDir, version, time.Now())
	if err != nil {
		log.Printf("update: reading the update record: %v", err)
		return nil
	}
	if !rolled {
		return nil
	}
	log.Printf("update: %s did not stay up after %d starts, so the previous binary is back; restarting into it", version, update.MaxUnconfirmedStarts)
	return updateExec(exe)
}
