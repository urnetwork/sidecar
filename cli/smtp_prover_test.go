package main

import (
	"context"
	"crypto/sha256"
	"testing"
)

func TestNoProverIsInjectedWithoutAPinnedKeySet(t *testing.T) {
	// what this release does: no production setup, no pin, no prover, and a host that queues
	prover, err := newSmtpProver(t.TempDir(), t.TempDir())
	if prover != nil || err != nil {
		t.Errorf("prover %v, %v", prover, err)
	}
	if err := verifySmtpProverKeys(context.Background(), t.TempDir(), t.TempDir()); err != nil {
		t.Error(err)
	}
}

func TestAPinnedKeySetThatIsNotThereInjectsNothing(t *testing.T) {
	pin := sha256.Sum256([]byte("a release's keyset.json"))
	smtpKeySetPin = pin[:]
	defer func() { smtpKeySetPin = nil }()
	prover, err := newSmtpProver(t.TempDir(), t.TempDir())
	if prover != nil || err == nil {
		t.Errorf("prover %v, %v", prover, err)
	}
	if err := verifySmtpProverKeys(context.Background(), t.TempDir(), t.TempDir()); err == nil {
		t.Error("verified a KeySet that is not there")
	}
}
