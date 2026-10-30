// SPDX-License-Identifier: AGPL-3.0-or-later

// Command gen builds internal/devices/oui_data.gz from the IEEE MA-L registry
// (https://standards-oui.ieee.org/oui/oui.txt):
//
//	go run ./internal/devices/internal/gen -in oui.txt -out internal/devices/oui_data.gz
package main

import (
	"flag"
	"fmt"
	"os"

	"shepherd/internal/devices"
)

func main() {
	in := flag.String("in", "oui.txt", "IEEE oui.txt input")
	out := flag.String("out", "oui_data.gz", "compressed table output")
	flag.Parse()
	if err := run(*in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := devices.ParseIEEEOUI(f)
	if err != nil {
		return err
	}
	w, err := os.Create(out)
	if err != nil {
		return err
	}
	if err := devices.EncodeOUITable(entries, w); err != nil {
		w.Close()
		return err
	}
	fmt.Printf("%d prefixes\n", len(entries))
	return w.Close()
}
