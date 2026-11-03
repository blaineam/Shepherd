// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRulesetIsReadableBeforeItIsApplied(t *testing.T) {
	got := Ruleset("eth0", []netip.Addr{poolStart, poolEnd})

	// The table is deleted and recreated in one batch, so there is never a
	// moment with half a rule set loaded.
	if !strings.Contains(got, "add table ip "+TableName) || !strings.Contains(got, "delete table ip "+TableName) {
		t.Errorf("the ruleset should replace the whole table atomically:\n%s", got)
	}
	// Masquerade is the whole unlock: it removes the foreign source address
	// the gateway reflects.
	if !strings.Contains(got, "ip saddr @routed oifname \"eth0\" masquerade") {
		t.Errorf("the ruleset must masquerade the routed set out of the LAN interface:\n%s", got)
	}
	if !strings.Contains(got, "elements = { 192.0.2.100, 192.0.2.110 }") {
		t.Errorf("the routed set should hold the addresses:\n%s", got)
	}
	if !strings.Contains(got, "ct state established,related accept") {
		t.Errorf("the return path has to be accepted, which is what makes downloads measurable:\n%s", got)
	}

	// An empty set is a valid rule set that translates nothing, which is
	// what "routing off" looks like in the kernel.
	empty := Ruleset("eth0", nil)
	if strings.Contains(empty, "elements") {
		t.Errorf("an empty routed set has no elements:\n%s", empty)
	}
	if !strings.Contains(empty, "masquerade") {
		t.Error("the rules are still loaded; the set is simply empty")
	}
}

func newReconciler(t *testing.T) (*Reconciler, *fakeNFT, *fakeSysctl) {
	t.Helper()
	nft := &fakeNFT{}
	sc := newSysctl()
	return &Reconciler{LAN: "eth0", Run: nft.run, Sysctl: sc, NFT: "nft-test"}, nft, sc
}

func TestApplyTurnsOnForwardingAndLoadsTheRules(t *testing.T) {
	r, nft, sc := newReconciler(t)
	changed, err := r.Apply(context.Background(), []netip.Addr{poolStart})
	if err != nil || !changed {
		t.Fatalf("Apply = %v, %v", changed, err)
	}
	wrote := sc.wrote()
	for _, want := range []string{
		"net.ipv4.ip_forward=1",
		"net.ipv4.conf.all.send_redirects=0",
		"net.ipv4.conf.eth0.send_redirects=0",
		"net.netfilter.nf_conntrack_acct=1",
	} {
		if !slices.Contains(wrote, want) {
			t.Errorf("sysctl %s was not set; wrote %v", want, wrote)
		}
	}
	calls := nft.all()
	if len(calls) != 1 {
		t.Fatalf("nft was called %d times, want once", len(calls))
	}
	if calls[0].name != "nft-test" || !slices.Equal(calls[0].args, []string{"-f", "-"}) {
		t.Errorf("nft call = %+v", calls[0])
	}
	if !strings.Contains(calls[0].stdin, "192.0.2.100") {
		t.Errorf("the rule set did not reach nft:\n%s", calls[0].stdin)
	}
	if got := r.Applied(); len(got) != 1 || got[0] != poolStart {
		t.Errorf("Applied = %v", got)
	}
}

// Apply runs on every lease change, so an unchanged set must cost nothing.
func TestApplyIsIdempotentAndIgnoresOrdering(t *testing.T) {
	r, nft, _ := newReconciler(t)
	ctx := context.Background()
	if _, err := r.Apply(ctx, []netip.Addr{poolEnd, poolStart}); err != nil {
		t.Fatal(err)
	}
	changed, err := r.Apply(ctx, []netip.Addr{poolStart, poolEnd})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("the same set in a different order is not a change")
	}
	if len(nft.all()) != 1 {
		t.Errorf("nft was called %d times, want once", len(nft.all()))
	}
	if changed, err := r.Apply(ctx, []netip.Addr{poolStart}); err != nil || !changed {
		t.Errorf("dropping an address is a change: %v, %v", changed, err)
	}
}

// The deployment runs read-only with a reduced capability set, where
// /proc/sys is not writable. A value the operator already set on the host or
// through the container's own sysctls must be accepted rather than rewritten.
func TestApplyAcceptsASysctlThatIsAlreadyRightInAReadOnlyContainer(t *testing.T) {
	r, _, sc := newReconciler(t)
	sc.values["net.ipv4.ip_forward"] = "1"
	sc.values["net.ipv4.conf.all.send_redirects"] = "0"
	sc.values["net.ipv4.conf.eth0.send_redirects"] = "0"
	sc.values["net.netfilter.nf_conntrack_acct"] = "1"
	for k := range sc.values {
		sc.setErr[k] = os.ErrPermission
	}
	if _, err := r.Apply(context.Background(), []netip.Addr{poolStart}); err != nil {
		t.Fatalf("Apply = %v; a value that is already correct needs no write", err)
	}
	if len(sc.wrote()) != 0 {
		t.Errorf("nothing should have been written, got %v", sc.wrote())
	}
}

func TestApplyExplainsASysctlItCannotSet(t *testing.T) {
	r, _, sc := newReconciler(t)
	sc.setErr["net.ipv4.ip_forward"] = os.ErrPermission
	_, err := r.Apply(context.Background(), []netip.Addr{poolStart})
	if err == nil {
		t.Fatal("Apply must fail when forwarding cannot be turned on")
	}
	if !strings.Contains(err.Error(), "sysctls:") {
		t.Errorf("error %q should say how to fix it in the container's configuration", err)
	}
}

// Connection accounting is groundwork for a later change, so it is
// deliberately not fatal: the mode works without it.
func TestConnectionAccountingFailureIsRecordedButNotFatal(t *testing.T) {
	r, _, sc := newReconciler(t)
	sc.setErr["net.netfilter.nf_conntrack_acct"] = os.ErrPermission
	if _, err := r.Apply(context.Background(), []netip.Addr{poolStart}); err != nil {
		t.Fatalf("Apply = %v; accounting is not needed for DHCP mode to work", err)
	}
	if r.AccountingError() == nil {
		t.Error("but it should be recorded, so the portal can say the groundwork is missing")
	}
}

func TestApplyWithNoInterfaceIsRefused(t *testing.T) {
	r, _, _ := newReconciler(t)
	r.LAN = ""
	if _, err := r.Apply(context.Background(), []netip.Addr{poolStart}); err == nil {
		t.Fatal("there is nothing to masquerade out of")
	}
}

func TestApplyReportsWhatNftSaid(t *testing.T) {
	r, nft, _ := newReconciler(t)
	nft.fail(errors.New("exit status 1"))
	_, err := r.Apply(context.Background(), []netip.Addr{poolStart})
	if err == nil {
		t.Fatal("a kernel that will not take the rules is a failure")
	}
	if !strings.Contains(err.Error(), "nft: refused") {
		t.Errorf("error %q should carry nft's own output, which is the only thing that says why", err)
	}
	if len(r.Applied()) != 0 {
		t.Error("a failed apply leaves nothing recorded as applied")
	}
}

func TestClearRemovesTheTableWhetherOrNotAnythingWasApplied(t *testing.T) {
	r, nft, _ := newReconciler(t)
	ctx := context.Background()
	// Called at startup, before anything was applied, to clear a table a
	// previous run may have left behind.
	if err := r.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(nft.all()) != 1 || !strings.Contains(nft.all()[0].stdin, "delete table ip "+TableName) {
		t.Fatalf("Clear should delete the table, got %+v", nft.all())
	}

	if _, err := r.Apply(ctx, []netip.Addr{poolStart}); err != nil {
		t.Fatal(err)
	}
	if err := r.Clear(ctx); err != nil {
		t.Fatalf("Clear after Apply: %v", err)
	}
	if len(r.Applied()) != 0 {
		t.Error("after Clear nothing is translated")
	}
	// Clearing is how routing stops, so the next Apply must reload.
	if changed, err := r.Apply(ctx, []netip.Addr{poolStart}); err != nil || !changed {
		t.Errorf("Apply after Clear = %v, %v; the kernel has nothing loaded", changed, err)
	}
}

func TestAvailableWrapsErrNoNFT(t *testing.T) {
	r, nft, _ := newReconciler(t)
	if err := r.Available(context.Background()); err != nil {
		t.Fatalf("Available = %v", err)
	}
	nft.fail(errors.New("executable file not found"))
	err := r.Available(context.Background())
	if !errors.Is(err, ErrNoNFT) {
		t.Fatalf("error = %v, want one wrapping ErrNoNFT", err)
	}
}

func TestReconcilerDefaultsAreTheRealThings(t *testing.T) {
	// Not run, only inspected: the real runner would call nft, and the real
	// sysctl would write /proc/sys. What is checked is that the defaults
	// exist at all, so a zero-valued Reconciler is not a nil dereference.
	r := &Reconciler{LAN: "eth0"}
	if r.Timeout != 0 {
		t.Error("the zero value has no timeout of its own")
	}
	var _ Runner = ExecRunner
	var _ Sysctl = ProcSysctl{}
	if got := sysctlPath("net.ipv4.ip_forward"); got != "/proc/sys/net/ipv4/ip_forward" {
		t.Errorf("sysctlPath = %q", got)
	}
	if _, err := (ProcSysctl{}).Get("net.this.does.not.exist"); err == nil {
		t.Error("reading a parameter that does not exist is an error")
	}
}

func TestRunHonoursItsTimeout(t *testing.T) {
	r := &Reconciler{LAN: "eth0", Timeout: 5 * time.Millisecond, Run: func(ctx context.Context, _ []byte, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	if _, err := r.run(context.Background(), nil, "list", "tables"); err == nil {
		t.Fatal("a command that never returns must be cut off")
	}
}

func TestExecRunnerRunsACommandAndCarriesItsInput(t *testing.T) {
	out, err := ExecRunner(context.Background(), nil, "echo", "hello")
	if err != nil {
		t.Fatalf("ExecRunner: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("output = %q", out)
	}
	// Standard input is how the rule set reaches nft, so it has to arrive.
	out, err = ExecRunner(context.Background(), []byte("piped"), "cat")
	if err != nil {
		t.Fatalf("ExecRunner with input: %v", err)
	}
	if strings.TrimSpace(string(out)) != "piped" {
		t.Errorf("output = %q, want the input back", out)
	}
	if _, err := ExecRunner(context.Background(), nil, "this-command-does-not-exist-shepherd"); err == nil {
		t.Error("a missing command is an error, which is how a missing nft is reported")
	}
}

func TestProcSysctlReportsAWriteItCannotMake(t *testing.T) {
	// Nothing here is allowed to change the host, so this is the failure
	// path: a parameter that does not exist cannot be written.
	if err := (ProcSysctl{}).Set("net.this.does.not.exist.shepherd", "1"); err == nil {
		t.Error("writing a parameter that does not exist must be an error")
	}
}

func TestEnsureWritesWhenTheValueIsWrongOrUnreadable(t *testing.T) {
	r, _, sc := newReconciler(t)
	// Unreadable: the only safe thing is to write it.
	sc.readErr["net.ipv4.ip_forward"] = os.ErrPermission
	if err := r.ensure("net.ipv4.ip_forward", "1"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if !slices.Contains(sc.wrote(), "net.ipv4.ip_forward=1") {
		t.Errorf("writes = %v", sc.wrote())
	}

	// Readable but wrong: also written.
	sc.values["net.ipv4.conf.eth0.send_redirects"] = "1"
	if err := r.ensure("net.ipv4.conf.eth0.send_redirects", "0"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if got, _ := sc.Get("net.ipv4.conf.eth0.send_redirects"); got != "0" {
		t.Errorf("value = %q", got)
	}
}

func TestEnsureWithNoSysctlUsesTheRealOne(t *testing.T) {
	r := &Reconciler{LAN: "eth0"}
	// A parameter that cannot exist, so nothing on this host is touched and
	// the default Sysctl is still exercised.
	if err := r.ensure("net.this.does.not.exist.shepherd", "1"); err == nil {
		t.Error("ensure must report a parameter it can neither read nor write")
	}
}

func TestVerifyIsANoOpUntilSomethingHasBeenApplied(t *testing.T) {
	r, nft, _ := newReconciler(t)
	if err := r.Verify(context.Background()); err != nil {
		t.Fatalf("Verify with nothing applied = %v", err)
	}
	if len(nft.all()) != 0 {
		t.Error("and it should not have asked the kernel anything")
	}
}
