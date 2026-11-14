package main

import (
	"context"
	"crypto/sha256"
	"testing"
)

func TestNoProverIsInjectedWithoutAPinnedKeySet(t *testing.T) {
	// what this release does: no production setup, no pin, no prover, and a host that queues
	if prover := newSmtpProver(t.TempDir(), ""); prover != nil {
		t.Errorf("prover %v", prover)
	}
}

func TestAPinnedKeySetThatIsNotThereNamesNoKeySet(t *testing.T) {
	pin := sha256.Sum256([]byte("a release's keyset.json"))
	smtpKeySetPins = [][]byte{pin[:]}
	defer func() { smtpKeySetPins = nil }()
	// with no base url nothing is fetched, so a set whose files are not on the host never becomes ready:
	// the check has nothing left to do, and the host names no key set and queues its mail
	prover := newSmtpProver(t.TempDir(), "")
	if prover == nil {
		t.Fatal("no prover over a pinned set")
	}
	readiness, err := prover.PrepareKeys(context.Background())
	if err != nil || !readiness.Done || len(readiness.KeySets) != 0 {
		t.Errorf("readiness %+v, %v", readiness, err)
	}
	if keySet := prover.KeySet(); len(keySet) != 0 {
		t.Errorf("KeySet %x", keySet)
	}
}
