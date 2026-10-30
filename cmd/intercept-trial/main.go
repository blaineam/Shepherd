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
//     exiting, so the corrective ARP reply goes out even on a hard stop.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
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

	rawCap, err := openCapture(*iface)
	if err != nil {
		return fmt.Errorf("intercept-trial: capture: %w", err)
	}
	defer rawCap.Close()

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

	go pumpCapture(ctx, rawCap, ctrl)

	log.Printf("shepherd: %s (%s)  gateway: %s (%s)", shepherdMAC, *iface, gatewayMAC, gatewayIP)
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

// reportStatus prints Status() every 2s until ctx is done or nothing is
// steered anymore (the trial expired or was unsteered some other way).
func reportStatus(ctx context.Context, ctrl *intercept.Controller) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st := ctrl.Status()
			if len(st) == 0 {
				log.Println("nothing steered anymore; trial is over")
				return
			}
			for _, d := range st {
				log.Printf("status: %s healthy=%v bytes_relayed=%d last_verified=%s",
					d.MAC, d.Healthy, d.BytesRelayed, formatSince(d.LastVerified))
			}
		}
	}
}

func formatSince(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return time.Since(t).Round(time.Millisecond).String() + " ago"
}

// capture is a read-only AF_PACKET SOCK_RAW socket bound to one interface
// with EtherType ETH_P_ALL, used only to feed Controller.HandleFrame. It
// never sends anything; sending is Sender's job, opened separately above.
type capture struct {
	fd int
}

const ethPAll = 0x0003

func openCapture(iface string) (*capture, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("raw socket (needs CAP_NET_RAW): %w", err)
	}
	addr := &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifc.Index}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind %q: %w", iface, err)
	}
	return &capture{fd: fd}, nil
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.LittleEndian.Uint16(b)
}

func (c *capture) Close() error { return syscall.Close(c.fd) }

// pumpCapture reads frames off the wire and feeds every one to the
// Controller until ctx is done. HandleFrame itself ignores anything that
// isn't addressed to Shepherd's MAC from a currently steered device, so
// feeding it unfiltered traffic (including our own ARP and relayed frames
// looping back) is safe and cheap.
func pumpCapture(ctx context.Context, rawCap *capture, ctrl *intercept.Controller) {
	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return
		}
		tv := syscall.Timeval{Sec: 0, Usec: 250000}
		_ = syscall.SetsockoptTimeval(rawCap.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		n, _, err := syscall.Recvfrom(rawCap.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if _, err := ctrl.HandleFrame(buf[:n]); err != nil {
			log.Printf("relay error: %v", err)
		}
	}
}
