package main

import (
	"context"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpproof"
)

// The prover ur injects on desktop builds (§14.9, D-SMTP-18): smtpproof's, over the KeySet this release
// pins. No production setup has run, so no release pins one yet, and ur injects no prover: a host then
// queues its mail for one that has, as a phone does. Nothing calls these until ur daemon and
// SmtpSender exist (SMTP-M9-07 to M9-09), which start the check at idle and inject the prover.

// keyset.json's SHA-256 for this release, or nil before the first production setup. The release sets
// it beside the KeySet it ships or names (SPEC.md 10.3).
var smtpKeySetPin []byte

// The prover a host runs: nil, with no error, when the release pins no KeySet. keyDirectory holds the
// KeySet and cacheDirectory the proving keys this host has verified.
func newSmtpProver(keyDirectory string, cacheDirectory string) (sidecar.SmtpProver, error) {
	if smtpKeySetPin == nil {
		return nil, nil
	}
	keySet, err := smtpproof.OpenKeySet(keyDirectory, smtpKeySetPin)
	if err != nil {
		return nil, err
	}
	return smtpproof.NewProver(smtpproof.DefaultProverSettings(), keySet, cacheDirectory), nil
}

// Checks the pinned KeySet's transcripts against this build's circuits and caches the keys they fix,
// once per release, at idle (SPEC.md 10.2). Until it has passed for a shape, the prover refuses that
// shape's parts.
func verifySmtpProverKeys(ctx context.Context, keyDirectory string, cacheDirectory string) error {
	if smtpKeySetPin == nil {
		return nil
	}
	keySet, err := smtpproof.OpenKeySet(keyDirectory, smtpKeySetPin)
	if err != nil {
		return err
	}
	return keySet.VerifyProvingKeys(ctx, cacheDirectory)
}
