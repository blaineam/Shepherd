// SPDX-License-Identifier: AGPL-3.0-or-later

// shepherd-sign makes and uses the Ed25519 key that signs releases
// (docs/UPDATE.md).
//
//	shepherd-sign -generate -out release.key   writes the private key (base64, mode 0600) and prints the public key
//	shepherd-sign -sign dist/SHA256SUMS -key release.key   writes dist/SHA256SUMS.sig
//	shepherd-sign -sign dist/SHA256SUMS -key-env SHEPHERD_SIGNING_KEY   the same, key from the environment (CI)
//	shepherd-sign -verify dist/SHA256SUMS -pub <base64>   checks dist/SHA256SUMS.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"shepherd/internal/update"
)

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr, os.Getenv)) }

func realMain(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("shepherd-sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	generate := fs.Bool("generate", false, "generate a key pair")
	out := fs.String("out", "release.key", "where -generate writes the private key")
	sign := fs.String("sign", "", "the SHA256SUMS file to sign; writes <file>.sig")
	keyFile := fs.String("key", "", "the private key file for -sign")
	keyEnv := fs.String("key-env", "", "the environment variable holding the private key for -sign")
	verify := fs.String("verify", "", "the SHA256SUMS file to verify against <file>.sig")
	pub := fs.String("pub", "", "the base64 public key for -verify")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	err := func() error {
		switch {
		case *generate:
			pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "private key written to %s (keep it secret; put it in the SHEPHERD_SIGNING_KEY repository secret)\n", *out)
			fmt.Fprintf(stdout, "public key: %s\n", base64.StdEncoding.EncodeToString(pubKey))
			fmt.Fprintln(stdout, "set that as update.ReleasePublicKeyB64 in internal/update/pubkey.go and commit it")
			return nil
		case *sign != "":
			var raw string
			switch {
			case *keyEnv != "":
				raw = getenv(*keyEnv)
			case *keyFile != "":
				b, err := os.ReadFile(*keyFile)
				if err != nil {
					return err
				}
				raw = string(b)
			default:
				return errors.New("-sign needs -key or -key-env")
			}
			priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
			if err != nil || len(priv) != ed25519.PrivateKeySize {
				return errors.New("the private key is not a base64 Ed25519 key")
			}
			sums, err := os.ReadFile(*sign)
			if err != nil {
				return err
			}
			sig := update.Sign(ed25519.PrivateKey(priv), sums)
			if err := os.WriteFile(*sign+".sig", sig, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "signed %s -> %s.sig\n", *sign, *sign)
			return nil
		case *verify != "":
			pubKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*pub))
			if err != nil {
				return errors.New("the public key is not base64")
			}
			sums, err := os.ReadFile(*verify)
			if err != nil {
				return err
			}
			sig, err := os.ReadFile(*verify + ".sig")
			if err != nil {
				return err
			}
			if err := update.VerifySignature(ed25519.PublicKey(pubKey), sums, sig); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "%s is signed by that key\n", *verify)
			return nil
		}
		return errors.New("one of -generate, -sign or -verify is required")
	}()
	if err != nil {
		fmt.Fprintf(stderr, "shepherd-sign: %v\n", err)
		return 1
	}
	return 0
}
