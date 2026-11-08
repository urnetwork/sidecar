// The edge's setup ceremony over every production shape (SPEC.md 10.3, SMTP-M9-27). It writes a KeySet
// directory, each shape's transcript and the keys it fixes, and prints keyset.json's SHA-256, which a
// release pins. Run it on the controlled host the owner names: at production size it takes hours and
// tens of gigabytes, and its secrets live and die inside gnark's Contribute.
//
//	setup -out <directory> -beacon <hex>
//
// The beacon is a public value fixed only after the contributions are made, such as a named round of a
// public randomness beacon, so that no contributor can grind the result.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/urnetwork/sidecar/smtpproof"
)

func main() {
	out := flag.String("out", "", "the KeySet directory to write, which must not exist")
	beacon := flag.String("beacon", "", "the public beacon, in hex")
	flag.Parse()
	beaconBytes, err := hex.DecodeString(*beacon)
	if *out == "" || err != nil || len(beaconBytes) == 0 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: setup -out <directory> -beacon <hex>")
		os.Exit(64)
	}
	// a KeySet is written once: another run's files beside this one's would mix two ceremonies
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintf(os.Stderr, "setup: %s exists\n", *out)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	pin, err := smtpproof.RunSetup(ctx, *out, beaconBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%x\n", pin)
}
