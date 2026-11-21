package main

import (
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpproof"
)

// The prover ur injects on desktop builds (§14.9, D-SMTP-18): smtpproof's, over the key sets this release
// pins. No production setup has run, so no release pins one yet, and ur injects no prover: a host then
// queues its mail for one that has, as a phone does. The daemon installs the prover at startup. Its mail component
// calls PrepareKeys at idle only after mail has been enabled on this device, since that check fetches the sets'
// transcripts (§2.8 smtp-7).

// keyset.json's SHA-256 of each key set this release pins, newest first (DESIGN-DETAILS 3.2.7). The newest
// is the set this build's circuits were set up for; an older one stays listed only while this build
// compiles the same circuits for it, which a host checks by digest. The release sets them beside
// smtpproof's smtpShapeDigests; none before the first production setup.
var smtpKeySetPins [][]byte

// The prover a host runs, or nil when the release pins no key set. directory holds the sets' fetched files
// and this host's cache of its checks. keysUrl comes from §18.9's service host table. An empty URL restricts the
// host to the sets already in its directory.
func newSmtpProver(directory string, keysUrl string) sidecar.SmtpProver {
	if len(smtpKeySetPins) == 0 {
		return nil
	}
	keySettings := smtpproof.DefaultKeySettings()
	keySettings.BaseUrl = keysUrl
	return smtpproof.NewProver(smtpproof.DefaultProverSettings(), keySettings, smtpKeySetPins, directory)
}
