//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// M9-out's mail rows of §22 on T2 (MAIL-M9-06; R-MAIL-6, D-MAIL-8, FS-123): composed from what MAIL-M9-01 to MAIL-M9-05
// landed, with SMTP's outbound path behind them, adding no mechanism. A failure goes back to the task that owns it.
//
//	S10     the replying half (mailworld's S10Replying, which server's sidecart3 runs on T3): a replying burner's first
//	        selector keeps its <blabel> MX and A, a burn changes no DNS and refuses the label at once, and its last
//	        selector restores the wildcard-only state
//
// The world is mailworld's M9World (m9_world.go): M8's network, whose owner's laptop sends through MailClient and, as
// the member's prover host, through SmtpSender to ScriptedMxs behind SMTP's stub edge. Every name and address is
// synthetic: .example names and RFC 5737 addresses (connect/CODESTYLE.md's test data rule). Nothing sleeps.

package sidecartest_test

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// S10's replying half under the harness and guard (RunScenario's T2 defaults).
func TestScenarioS10ReplyingBurner(t *testing.T) {
	sidecartest.RunScenario(t, mailworld.S10Replying(t, nil), nil)
}
