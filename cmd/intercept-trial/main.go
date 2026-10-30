// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

// Command intercept-trial is a throwaway, one-off tool for running a single
// controlled trial of internal/intercept's Watch-mode ARP steering against a
// real device on a real network, per docs/INTERCEPT.md's "How a future
// trial would use this". It is deliberately not part of cmd/shepherd: it is
// built, deployed and run by hand, once, with the maintainer at the keyboard
// watching Status(), never wired into any startup path or the portal.
//
// Safety is layered on top of what Controller already enforces (gateway and
// Shepherd-MAC exclusion, health-verified fail-open, PanicStop):
//   - the target device must be named twice (-target-mac and -confirm, which
//     must match byte for byte) so a typo can't steer the wrong device;
//   - Trial mode is mandatory and capped at 5 minutes;
//   - Ctrl-C (or any termination signal) calls PanicStop then Close before
//     exiting, so the corrective ARP reply goes out even on a hard stop;
//   - GRO is disabled on the interface for the life of the trial (needs
//     CAP_NET_ADMIN as well as CAP_NET_RAW) and always restored on exit, so
//     a real captured frame is never a kernel-coalesced super-frame larger
//     than the wire allows — see the comment above the GRO handling below.
//
// Capture and relay run across -workers parallel goroutines via
// Controller.ParallelRelay (internal/intercept/capture_linux.go), not one:
// a real, sustained transfer through a single capture/relay goroutine was
// observed to cut a steered device's throughput to roughly a third, and
// PACKET_FANOUT-based parallelism is the fix. See docs/INTERCEPT.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"shepherd/internal/arp"
	"shepherd/internal/intercept"
)

const maxTrialDuration = 5 * time.Minute

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	iface := flag.String("iface", "eth0", "network interface to steer on")
	gatewayIPFlag := flag.String("gateway-ip", "", "the real gateway's IPv4 address (required)")
	gatewayMACFlag := flag.String("gateway-mac", "", "the real gateway's MAC address (required)")
	targetMACFlag := flag.String("target-mac", "", "MAC address of the one device to steer (required)")
	targetIPFlag := flag.String("target-ip", "", "IPv4 address of the one device to steer (required)")
	confirmFlag := flag.String("confirm", "", "must exactly repeat -target-mac, as a typo guard")
	duration := flag.Duration("duration", 45*time.Second, "trial duration; auto-reverts on its own, capped at 5m")
	workers := flag.Int("workers", intercept.DefaultParallelism, "parallel capture/relay workers (PACKET_FANOUT); more cores, more throughput")
	flag.Parse()

	if *gatewayIPFlag == "" || *gatewayMACFlag == "" || *targetMACFlag == "" || *targetIPFlag == "" {
		return errors.New("intercept-trial: -gateway-ip, -gateway-mac, -target-mac and -target-ip are all required")
	}
	if *confirmFlag != *targetMACFlag {
		return fmt.Errorf("intercept-trial: -confirm %q does not match -target-mac %q; refusing to guess", *confirmFlag, *targetMACFlag)
	}
	if *duration <= 0 || *duration > maxTrialDuration {
		return fmt.Errorf("intercept-trial: -duration must be positive and at most %s", maxTrialDuration)
	}

	gatewayIP, err := netip.ParseAddr(*gatewayIPFlag)
	if err != nil {
		return fmt.Errorf("intercept-trial: -gateway-ip: %w", err)
	}
	gatewayMAC, err := arp.ParseMAC(*gatewayMACFlag)
	if err != nil {
		return fmt.Errorf("intercept-trial: -gateway-mac: %w", err)
	}
	targetMAC, err := arp.ParseMAC(*targetMACFlag)
	if err != nil {
		return fmt.Errorf("intercept-trial: -target-mac: %w", err)
	}
	targetIP, err := netip.ParseAddr(*targetIPFlag)
	if err != nil {
		return fmt.Errorf("intercept-trial: -target-ip: %w", err)
	}

	ifc, err := net.InterfaceByName(*iface)
	if err != nil {
		return fmt.Errorf("intercept-trial: interface %q: %w", *iface, err)
	}
	var shepherdMAC arp.MAC
	copy(shepherdMAC[:], ifc.HardwareAddr)
	if shepherdMAC.IsZero() {
		return fmt.Errorf("intercept-trial: interface %q has no usable MAC", *iface)
	}

	sender, err := intercept.Open(*iface)
	if err != nil {
		return fmt.Errorf("intercept-trial: %w", err)
	}
	if closer, ok := sender.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	// GRO (Generic Receive Offload) coalesces several inbound TCP segments
	// into one oversized frame before any socket, raw ones included, ever
	// sees them. The Relay retransmits whatever it captures unchanged, and
	// a coalesced super-frame can be larger than a real Ethernet frame is
	// allowed to be, which fails the raw send with EMSGSIZE and (correctly,
	// by design) fails that device open at once. Disabling GRO on the
	// interface for the life of this trial — and restoring it on every
	// exit path, including a signal — avoids that without leaving the NIC
	// permanently detuned.
	groWasOn, groFixed, err := ethtoolGRO(*iface)
	if err != nil {
		return fmt.Errorf("intercept-trial: checking GRO on %q: %w", *iface, err)
	}
	if groFixed {
		return fmt.Errorf("intercept-trial: %q reports generic-receive-offload as fixed (cannot be toggled); refusing to start, since an oversized GRO frame would abort the trial the same way it did before", *iface)
	}
	if groWasOn {
		if err := setEthtoolGRO(*iface, false); err != nil {
			return fmt.Errorf("intercept-trial: disabling GRO on %q: %w", *iface, err)
		}
		log.Printf("disabled GRO on %s for this trial", *iface)
		defer func() {
			if err := setEthtoolGRO(*iface, true); err != nil {
				log.Printf("WARNING: failed to restore GRO on %s: %v (run `ethtool -K %s gro on` by hand)", *iface, err, *iface)
				return
			}
			log.Printf("restored GRO on %s", *iface)
		}()
	} else {
		log.Printf("GRO already off on %s", *iface)
	}

	ctrl, err := intercept.NewController(intercept.ControllerConfig{
		Sender:      sender,
		ShepherdMAC: shepherdMAC,
		GatewayIP:   gatewayIP,
		GatewayMAC:  gatewayMAC,
		OnUnsteer: func(r intercept.UnsteerRecord) {
			log.Printf("unsteered %s: %s", r.MAC, r.Reason)
		},
	})
	if err != nil {
		return fmt.Errorf("intercept-trial: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ParallelRelay opens its own n capture sockets and n Senders (a
	// PACKET_FANOUT group, one goroutine each), independent of the single
	// sender above (which only ever carries the Spoofer's low-volume
	// periodic ARP claims). This is what makes the relay path itself use
	// more than one core; see internal/intercept/capture_linux.go.
	go func() {
		if err := ctrl.ParallelRelay(ctx, *iface, *workers); err != nil && ctx.Err() == nil {
			log.Printf("ParallelRelay: %v", err)
		}
	}()

	log.Printf("shepherd: %s (%s)  gateway: %s (%s)", shepherdMAC, *iface, gatewayMAC, gatewayIP)
	log.Printf("relaying across %d parallel workers", *workers)
	log.Printf("steering %s (%s) for %s, trial mode (auto-revert)", targetMAC, targetIP, *duration)

	if err := ctrl.Steer(intercept.DeviceRef{MAC: targetMAC, IP: targetIP}, intercept.SteerOptions{
		Trial:    true,
		Duration: *duration,
	}); err != nil {
		ctrl.Close()
		return fmt.Errorf("intercept-trial: Steer: %w", err)
	}

	reportStatus(ctx, ctrl)

	log.Println("shutting down: panic-stop, then close")
	ctrl.PanicStop()
	ctrl.Close()

	for _, r := range ctrl.History() {
		log.Printf("history: %s %s at %s", r.MAC, r.Reason, r.Time.Format(time.RFC3339))
	}
	return nil
}

// reportStatus prints Status() and the packet-rate line every 2s until ctx
// is done or nothing is steered anymore (the trial expired or was
// unsteered some other way). The rate line is the diagnostic the last live
// trial did not have: packets and bytes per second, live, is exactly what
// would have shown a retransmission storm (or a self-capture overhead
// problem — see not_for_shepherd below) growing in real time, instead of
// needing a separate packet capture afterward to notice it.
func reportStatus(ctx context.Context, ctrl *intercept.Controller) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	prevStats := ctrl.Stats()
	prevTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			st := ctrl.Status()
			if len(st) == 0 {
				log.Println("nothing steered anymore; trial is over")
				return
			}
			for _, d := range st {
				log.Printf("status: %s healthy=%v bytes_relayed=%d packets_relayed=%d last_verified=%s",
					d.MAC, d.Healthy, d.BytesRelayed, d.PacketsRelayed, formatSince(d.LastVerified))
			}
			curStats := ctrl.Stats()
			log.Printf("rate: %s", statsRate(prevStats, curStats, now.Sub(prevTime)))
			prevStats, prevTime = curStats, now
		}
	}
}

// statsRate turns two ControllerStats samples, taken elapsed apart, into a
// one-line summary: packets and bytes per second actually relayed, the
// examined rate (everything the capture sockets handed to a Relay, matched
// or not), and not_for_shepherd — the count of frames in that window whose
// destination was not Shepherd's own MAC. The capture sockets now carry a
// kernel-side BPF filter that only admits IPv4 frames addressed to
// Shepherd (capture_filter.go), so this should read zero or nearly so;
// anything else means the filter did not attach (an old kernel) and the
// Relay is paying in userspace for frames the kernel should have dropped.
// Before that filter existed, a burst here that tracked a transfer was
// the clue that pointed at the source-MAC problem in docs/INTERCEPT.md.
func statsRate(prev, cur intercept.ControllerStats, elapsed time.Duration) string {
	if elapsed <= 0 {
		return "n/a (no time elapsed)"
	}
	secs := elapsed.Seconds()
	examinedPPS := float64(cur.FramesExamined-prev.FramesExamined) / secs
	relayedPPS := float64(cur.FramesRelayed-prev.FramesRelayed) / secs
	relayedBPS := float64(cur.BytesRelayed-prev.BytesRelayed) / secs
	notForShepherd := cur.FramesNotForShepherd - prev.FramesNotForShepherd
	return fmt.Sprintf("examined=%.0f pkt/s relayed=%.0f pkt/s (%.0f B/s) not_for_shepherd=%d",
		examinedPPS, relayedPPS, relayedBPS, notForShepherd)
}

// ethtoolGRO reports whether generic-receive-offload is currently on for
// iface, and whether it is reported as [fixed] (not configurable).
func ethtoolGRO(iface string) (on bool, fixed bool, err error) {
	out, err := exec.Command("ethtool", "-k", iface).Output()
	if err != nil {
		return false, false, fmt.Errorf("ethtool -k %s: %w", iface, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "generic-receive-offload:")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		return strings.HasPrefix(rest, "on"), strings.Contains(rest, "[fixed]"), nil
	}
	return false, false, fmt.Errorf("ethtool -k %s: generic-receive-offload not reported", iface)
}

// setEthtoolGRO turns generic-receive-offload on iface on or off.
func setEthtoolGRO(iface string, on bool) error {
	val := "off"
	if on {
		val = "on"
	}
	out, err := exec.Command("ethtool", "-K", iface, "gro", val).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ethtool -K %s gro %s: %w: %s", iface, val, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func formatSince(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return time.Since(t).Round(time.Millisecond).String() + " ago"
}
