//go:build !sidecar_http && !ios_extension

// §22.7's S6 (F5, send mail, M9) at T2 (SMTP-M9-31): smtp_send_rows.go's rows on SmtpSendWorld's stub edge. T3 runs
// the same rows on the smtpedge block's engine over server's stores (server/cli/smtpedge's s6_test.go), and the
// engine's own run of the sender is smtpedgeservice's sender_test.go; §15.10's forwarding rows are MAIL's (MAIL-M9-04,
// MAIL-M9-06).

package sidecartest_test

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestS6NoRecordReachesTheMxBeforeItsPart(t *testing.T) {
	sidecartest.RunS6NoRecordReachesTheMxBeforeItsPart(t, sidecartest.NewSmtpSendWorld)
}

func TestS6NoUnauthenticatedMx(t *testing.T) {
	sidecartest.RunS6NoUnauthenticatedMx(t, sidecartest.NewSmtpSendWorld)
}

func TestS6TooLargeForTheNonChunkingDomainAlone(t *testing.T) {
	sidecartest.RunS6TooLargeForTheNonChunkingDomainAlone(t, sidecartest.NewSmtpSendWorld)
}
