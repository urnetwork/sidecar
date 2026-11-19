//go:build !sidecar_http && !ios_extension

// MAIL-M9-02's conformance row: sidecartest.FakeSmtpMailbox's contract suite passes on MAIL's real SmtpMailbox, so
// the fake SMTP's tests run on stays honest (D-TEST-2).

package sidecar_test

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The suite on mailSmtpMailbox, o/ planted as Queue writes it.
func TestMailSmtpMailboxPassesTheContractSuite(t *testing.T) {
	mailbox, plant := sidecar.NewMailSmtpMailboxForTest()
	sidecartest.RunSmtpMailboxSuite(t, mailbox, plant)
}
