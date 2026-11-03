// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"
)

// Runner runs one external command with optional standard input and returns
// its combined output. It is the seam the NAT reconciler is tested through —
// the same shape internal/devices/neighbor.go already uses for the neighbour
// table — so every rule Shepherd would install can be asserted without
// touching a kernel.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// ExecRunner is the real one.
func ExecRunner(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(stdin) > 0 {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	return cmd.CombinedOutput()
}

// Sysctl reads and writes one kernel parameter. Separate from Runner because
// it is a file access rather than a command, and because the test for "did
// Shepherd turn forwarding on" should not have to parse a command line.
//
// Reading matters as much as writing here. Shepherd's own deployment runs in
// a container with `read_only: true` and a reduced capability set
// (deploy/docker/compose.yaml), where /proc/sys is not writable even with
// CAP_NET_ADMIN. The right behaviour there is to notice that the value is
// already what it needs to be — because the operator set it on the host or
// through compose's own `sysctls:` — rather than to refuse to work.
type Sysctl interface {
	Get(key string) (string, error)
	Set(key, value string) error
}

// ProcSysctl is the real one: /proc/sys, with dots as path separators.
type ProcSysctl struct{}

func sysctlPath(key string) string { return "/proc/sys/" + strings.ReplaceAll(key, ".", "/") }

// Get reads one parameter.
func (ProcSysctl) Get(key string) (string, error) {
	b, err := os.ReadFile(sysctlPath(key))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Set writes one parameter.
func (ProcSysctl) Set(key, value string) error {
	return os.WriteFile(sysctlPath(key), []byte(value+"\n"), 0o644)
}

// TableName is the nftables table Shepherd owns. It owns the whole table, so
// the rule set can be replaced atomically and deleted completely, and nothing
// Shepherd writes can disturb another tenant's rules.
const TableName = "shepherd_dhcp"

// ErrNoNFT means the nft binary is not available, which is a configuration
// problem rather than a runtime one: the Docker image needs `apk add
// nftables` and a host install needs the package.
var ErrNoNFT = errors.New("dhcp: the nft command is not available")

// Reconciler keeps the kernel's forwarding and NAT configuration in step with
// the set of routed addresses.
//
// Shepherd configures the kernel; it is not the datapath. That line is from
// docs/GATEWAY.md and it holds here without change: the kernel already
// forwards, translates and accounts at line rate, and no Shepherd code is on
// a per-packet path.
type Reconciler struct {
	// LAN is the interface the routed devices are on, which is both the
	// input and the output interface — this is a one-armed router, and the
	// hairpin is the point.
	LAN string
	// Run and Sysctl default to the real ones.
	Run    Runner
	Sysctl Sysctl
	// NFT is the command name, for the test that asserts the path rather
	// than running it.
	NFT string
	// Timeout bounds one nft invocation.
	Timeout time.Duration

	mu      sync.Mutex
	applied []netip.Addr
	active  bool
	acctErr error
}

func (r *Reconciler) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	run := r.Run
	if run == nil {
		run = ExecRunner
	}
	name := r.NFT
	if name == "" {
		name = "nft"
	}
	to := r.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	out, err := run(ctx, stdin, name, args...)
	if err != nil {
		return out, fmt.Errorf("dhcp: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Available reports whether the kernel can be configured at all: nft runs and
// can list its tables. It is called at startup so a missing binary is a
// message in the portal rather than a surprise at the moment a device is
// routed.
func (r *Reconciler) Available(ctx context.Context) error {
	if _, err := r.run(ctx, nil, "list", "tables"); err != nil {
		return fmt.Errorf("%w: %v", ErrNoNFT, err)
	}
	return nil
}

// Ruleset is the nft script for a set of routed addresses. It is a pure
// function of its input and is what the tests assert on, because a rule set
// that can be read before it is applied is most of the reason for driving nft
// rather than speaking netlink.
func Ruleset(lan string, routed []netip.Addr) string {
	var b strings.Builder
	// Deleting and recreating the table in one batch makes the change
	// atomic: there is never a moment with half a rule set loaded. The
	// `add` before the `delete` is the standard idiom for making the
	// delete succeed when the table does not exist yet.
	fmt.Fprintf(&b, "add table ip %s\n", TableName)
	fmt.Fprintf(&b, "delete table ip %s\n", TableName)
	fmt.Fprintf(&b, "table ip %s {\n", TableName)
	b.WriteString("\tset routed {\n\t\ttype ipv4_addr\n")
	if len(routed) > 0 {
		parts := make([]string, 0, len(routed))
		for _, a := range routed {
			parts = append(parts, a.String())
		}
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(parts, ", "))
	}
	b.WriteString("\t}\n")
	// Masquerade is the whole unlock (docs/DHCP.md): forwarding a frame
	// back out the interface it arrived on is only a hairpin hazard while
	// it carries a foreign source address, and source NAT removes exactly
	// that. It is also what brings the return traffic back through
	// Shepherd, which is what makes downloads measured rather than
	// estimated.
	fmt.Fprintf(&b, "\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\tip saddr @routed oifname %q masquerade\n\t}\n", lan)
	fmt.Fprintf(&b, "\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tip saddr @routed oifname %q accept\n\t\tip daddr @routed ct state established,related accept\n\t}\n", lan)
	b.WriteString("}\n")
	return b.String()
}

// Verify checks that the rule set Shepherd believes it installed is still
// there. It exists because Apply is idempotent, and an idempotent Apply would
// otherwise never notice that the kernel stopped cooperating: something else
// flushed the table, nft stopped working, the host's own firewall was
// reloaded. In a design that fails open by stopping to claim to be the
// gateway, noticing is the whole mechanism, so it is checked on every
// housekeeping tick rather than assumed from the last success.
func (r *Reconciler) Verify(ctx context.Context) error {
	r.mu.Lock()
	active := r.active
	r.mu.Unlock()
	if !active {
		return nil
	}
	if _, err := r.run(ctx, nil, "list", "table", "ip", TableName); err != nil {
		r.mu.Lock()
		r.active = false
		r.mu.Unlock()
		return err
	}
	return nil
}

// Apply makes the kernel route and translate exactly the given addresses. It
// is idempotent: an unchanged set does nothing, so this can be called on
// every lease change. Verify is what notices a kernel that stopped
// cooperating while the set did not change.
func (r *Reconciler) Apply(ctx context.Context, routed []netip.Addr) (changed bool, err error) {
	want := slices.Clone(routed)
	slices.SortFunc(want, func(a, b netip.Addr) int { return a.Compare(b) })
	r.mu.Lock()
	same := r.active && slices.Equal(want, r.applied)
	r.mu.Unlock()
	if same {
		return false, nil
	}
	if r.LAN == "" {
		return false, fmt.Errorf("dhcp: no LAN interface configured for NAT")
	}
	if err := r.sysctls(); err != nil {
		return false, err
	}
	if _, err := r.run(ctx, []byte(Ruleset(r.LAN, want)), "-f", "-"); err != nil {
		return false, err
	}
	r.mu.Lock()
	r.applied, r.active = want, true
	r.mu.Unlock()
	return true, nil
}

// ensure makes one kernel parameter hold want, and says what to do when it
// cannot. A parameter that already holds want is not written at all, which is
// what makes this work in a read-only container.
func (r *Reconciler) ensure(key, want string) error {
	sc := r.Sysctl
	if sc == nil {
		sc = ProcSysctl{}
	}
	if got, err := sc.Get(key); err == nil && strings.TrimSpace(got) == want {
		return nil
	}
	if err := sc.Set(key, want); err != nil {
		return fmt.Errorf("dhcp: %s must be %s and could not be set (%w). Set it on the host, or add it to the container's `sysctls:` list", key, want, err)
	}
	return nil
}

func (r *Reconciler) sysctls() error {
	// Forwarding first. Without it the rule set loads and nothing moves,
	// which looks like a Shepherd bug and is not one.
	if err := r.ensure("net.ipv4.ip_forward", "1"); err != nil {
		return err
	}
	// An ICMP redirect is the kernel politely undoing this whole mode, and
	// on a one-armed gateway it is not an edge case but the default. Asked
	// to forward a packet back out the interface it arrived on, the kernel
	// tells the client "go direct to the router next time" — which is
	// correct ICMP, and the exact opposite of what is wanted here. A device
	// that takes the redirect silently stops being measured.
	for _, key := range []string{"net.ipv4.conf.all.send_redirects", "net.ipv4.conf." + r.LAN + ".send_redirects"} {
		if err := r.ensure(key, "0"); err != nil {
			return err
		}
	}
	// Per-flow byte counters in both directions, which is what the
	// accounting work in docs/GATEWAY.md will read. Enabling it costs
	// nothing and means the data is already being collected when that
	// lands. A kernel without the knob is not a failure: the mode works
	// and only the future accounting would be missing, so this one is
	// deliberately not an error.
	if err := r.ensure("net.netfilter.nf_conntrack_acct", "1"); err != nil {
		r.noteAcct(err)
	}
	return nil
}

// noteAcct records that connection accounting could not be turned on. It is
// kept rather than returned because it does not stop DHCP mode working.
func (r *Reconciler) noteAcct(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.acctErr = err
}

// AccountingError reports why per-flow byte counters are not enabled, if they
// are not. Nothing in this change reads those counters; it is here so the
// portal can say the groundwork is missing before the accounting work lands.
func (r *Reconciler) AccountingError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.acctErr
}

// Clear removes Shepherd's table entirely, so nothing is routed and no rule
// of Shepherd's is left behind. It does not turn forwarding back off: the
// host may be forwarding for something else (a Tailscale subnet router, for
// one, which this NAS runs), and turning off a global switch Shepherd did not
// own is how one feature breaks another.
func (r *Reconciler) Clear(ctx context.Context) error {
	r.mu.Lock()
	wasActive := r.active
	r.applied, r.active = nil, false
	r.mu.Unlock()
	if !wasActive {
		// Still worth one delete at startup, in case a previous run left
		// a table behind; the caller decides by calling Clear before it
		// ever calls Apply.
		_, err := r.run(ctx, []byte(fmt.Sprintf("add table ip %s\ndelete table ip %s\n", TableName, TableName)), "-f", "-")
		return err
	}
	_, err := r.run(ctx, []byte(fmt.Sprintf("add table ip %s\ndelete table ip %s\n", TableName, TableName)), "-f", "-")
	return err
}

// Applied returns the addresses the kernel is currently translating, as
// Shepherd last left it.
func (r *Reconciler) Applied() []netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.applied)
}
