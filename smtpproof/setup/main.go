// The edge's setup ceremony over every production shape (SPEC.md 10.3; DESIGN-DETAILS 3.2.7). It writes a
// key set's directory, one phase 1 and each shape's phase 2, circuit digest and keys, and prints
// keyset.json's SHA-256, the set's id, which a release pins. Run it on the controlled host the owner
// names: at production size it takes hours and gigabytes, and its secrets live and die inside gnark's
// Contribute.
//
//	setup -out <directory> -beacon <hex>    a new key set
//	setup -extend <directory>               the catalog shapes a key set lacks, on its phase 1
//	setup -digests <file>                   shape_digests.go, each catalog shape's circuit digest
//
// The beacon is a public value fixed only after the contributions are made, such as a named round of a
// public randomness beacon, so that no contributor can grind the result. -extend leaves every entry the
// set has as it is and prints the new id, which a release pins ahead of the old one. -digests runs first
// after any change to a circuit: a ceremony refuses a shape whose circuit is not the one the table names.
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
	out := flag.String("out", "", "the key set directory to write, which must not exist")
	beacon := flag.String("beacon", "", "the public beacon, in hex")
	extend := flag.String("extend", "", "a key set directory to add the catalog shapes it lacks to")
	digests := flag.String("digests", "", "the shape_digests.go to write")
	flag.Parse()
	usage := func() {
		fmt.Fprintln(os.Stderr, "usage: setup -out <directory> -beacon <hex> | setup -extend <directory> | setup -digests <file>")
		os.Exit(64)
	}
	modes := 0
	for _, mode := range []string{*out, *extend, *digests} {
		if mode != "" {
			modes += 1
		}
	}
	if modes != 1 || flag.NArg() != 0 {
		usage()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	switch {
	case *digests != "":
		if *beacon != "" {
			usage()
		}
		file, err := os.Create(*digests)
		if err != nil {
			fmt.Fprintf(os.Stderr, "setup: %v\n", err)
			os.Exit(1)
		}
		if err := smtpproof.WriteShapeDigests(file); err != nil {
			file.Close()
			fmt.Fprintf(os.Stderr, "setup: %v\n", err)
			os.Exit(1)
		}
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "setup: %v\n", err)
			os.Exit(1)
		}
	case *extend != "":
		if *beacon != "" {
			usage()
		}
		id, err := smtpproof.ExtendSetup(ctx, *extend)
		if err != nil {
			fmt.Fprintf(os.Stderr, "setup: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%x\n", id)
	default:
		beaconBytes, err := hex.DecodeString(*beacon)
		if err != nil || len(beaconBytes) == 0 {
			usage()
		}
		// a key set is written once: another run's files beside this one's would mix two ceremonies
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintf(os.Stderr, "setup: %s exists\n", *out)
			os.Exit(1)
		}
		id, err := smtpproof.RunSetup(ctx, *out, beaconBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "setup: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%x\n", id)
	}
}
