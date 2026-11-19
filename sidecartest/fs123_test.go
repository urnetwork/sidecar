//go:build !sidecar_http && !ios_extension

// FS-123 at T2 (SMTP-M9-31, D-SMTP-20): smtp_send_rows.go's rows on SmtpSendWorld's stub edge, sent from a desktop
// and queued from a phone, with deferred, refused and tls_refused reaching or/ and mail_send. T3 runs the same rows
// on the smtpedge block's engine over server's stores (server/cli/smtpedge's s6_test.go).

package sidecartest_test

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs123SentFromADesktop(t *testing.T) {
	sidecartest.RunFs123SentFromADesktop(t, sidecartest.NewSmtpSendWorld)
}

func TestFs123QueuedFromAPhone(t *testing.T) {
	sidecartest.RunFs123QueuedFromAPhone(t, sidecartest.NewSmtpSendWorld)
}

func TestFs123OtherOutcomesReachTheResult(t *testing.T) {
	sidecartest.RunFs123OtherOutcomesReachTheResult(t, sidecartest.NewSmtpSendWorld)
}
