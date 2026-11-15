//go:build !sidecar_http && !ios_extension

// What a receiver's sessions and deposits are tuned by (§15.5, §15.7; MAIL-M7-14), on every leg a receiver's parts
// build on: the depositor's half runs on the js leg too, where no session does, since mox's resolver does not build
// there (mail_session.go).

package sidecar

import (
	"time"
)

// What a session is tuned by (§15.5). Every value must be positive.
type MailSessionSettings struct {
	// From the handshake to the first MAIL (§15.5's 60 s): past it the stream closes.
	MailTimeout time.Duration
	// A session's whole life: the router's 30 min splice (§15.4), past which the stream closes.
	SessionTimeout time.Duration
	// How much of a message one read takes into the spool, and the spool's chunk (§15.5's 64 KiB).
	ChunkByteCount int
	// go-smtp's line bound, which holds DATA's lines as well as commands: far past a command's 512 B, so mail
	// with long lines passes, and a line is what a session holds at most while it reads a command.
	LineMaxByteCount int
	// MailIngress's bound, the router's 1,024 B (§15.5's fence, plan-MAIL-format-bytes#7), whose default is the
	// format's own (MailIngressFormatSettings.MaxByteCount).
	IngressMaxByteCount int
	// A deposit trailer's bound, the reader's own (MailIngestSettings.TrailerMaxByteCount).
	TrailerMaxByteCount int
	// GET /mail/status is read again at most this often for RCPT's 452 4.2.2 (QD-478's 30 s).
	StatusInterval time.Duration
	// GET /sidecar/limits is read again at most this often for SIZE and RCPT's bounds.
	LimitsInterval time.Duration
	// One message's deposits at once: §15.7's 4, 2 on mobile (ApplyMobileMailSessionSettings).
	DepositConcurrency int
}

// The one default: §15.5's and §15.7's numbers.
func DefaultMailSessionSettings() *MailSessionSettings {
	return &MailSessionSettings{
		MailTimeout:         60 * time.Second,
		SessionTimeout:      30 * time.Minute,
		ChunkByteCount:      64 * 1024,
		LineMaxByteCount:    1024 * 1024,
		IngressMaxByteCount: DefaultMailIngressFormatSettings().MaxByteCount,
		TrailerMaxByteCount: DefaultMailIngestSettings().TrailerMaxByteCount,
		StatusInterval:      30 * time.Second,
		LimitsInterval:      5 * time.Minute,
		DepositConcurrency:  4,
	}
}

// §15.7's values for a host that runs on a phone: 2 deposits at once.
func ApplyMobileMailSessionSettings(settings *MailSessionSettings) {
	settings.DepositConcurrency = 2
}

// Whether every value is in range.
func (self *MailSessionSettings) valid() bool {
	return self != nil && 0 < self.MailTimeout && 0 < self.SessionTimeout && 0 < self.ChunkByteCount &&
		0 < self.LineMaxByteCount && 0 < self.IngressMaxByteCount && 0 < self.TrailerMaxByteCount &&
		0 < self.StatusInterval && 0 < self.LimitsInterval && 0 < self.DepositConcurrency
}
