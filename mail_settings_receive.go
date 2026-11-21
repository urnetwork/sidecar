//go:build !sidecar_http && !ios_extension

// MailSettings' receiver part on the legs a receiver's parts build on (MAIL-M7-17): the receiver, its sessions and
// deposits, and its reception-time checks. The page Worker's leg has none (mail_settings_receive_http.go).

package sidecar

import "time"

// A receiver's settings.
type MailReceiveSettings struct {
	// Whether this device runs a receiver once policy grants it the listen on smtp/25/mx (§15.5, §15.6): a desktop,
	// NAS or VPS daemon does, which keeps it up while mail is on, and an app does while it is open (MailHostProfile).
	Enabled  bool
	Receiver *MailReceiverSettings
	Direct   *MailDirectSettings
	Session  *MailSessionSettings
	Auth     *MailAuthSettings
	// The receiver's MTA-STS system publish (mail_mta_sts.go).
	MtaSts *MailMtaStsSettings
}

// The receiver's defaults: on, as a daemon runs.
func defaultMailReceiveSettings() *MailReceiveSettings {
	return &MailReceiveSettings{
		Enabled:  true,
		Receiver: DefaultMailReceiverSettings(),
		Direct:   DefaultMailDirectSettings(),
		Session:  DefaultMailSessionSettings(),
		Auth:     DefaultMailAuthSettings(),
		MtaSts:   DefaultMailMtaStsSettings(),
	}
}

// The receiver part of ApplyMobileMailSettings: the receiver stays on, so an app listens while it is open where policy
// grants its listen (§15.6 step 4; owner decision 197), max_streams and the check slots stay as §15.5 fixes them, and
// deposits drop to 2 at once (§15.7).
func applyMobileMailSettings(settings *MailSettings) {
	if settings == nil || settings.Receive == nil {
		return
	}
	settings.Receive.Enabled = true
	if settings.Receive.Session != nil {
		ApplyMobileMailSessionSettings(settings.Receive.Session)
	}
}

// What a direct listener is tuned by. Every value must be positive.
type MailDirectSettings struct {
	// Sessions at once from one sender /64 or /32, and from one /48 or /24 (§15.4's router caps, reading 2).
	SenderSessionCount          int
	SenderAggregateSessionCount int
	// Sessions at once in all: max_streams' 16 (§15.5).
	SessionCount int
	// The whole pre-TLS dialog's bound: RFC 5321 §4.5.3.2.7's 5 min.
	DialogTimeout time.Duration
	// All a sender may send before TLS, a line's bound without its CRLF, and an EHLO name's: connect's 2,048 B and
	// 510 B, RFC 5321's 255 (§15.3).
	DialogMaxByteCount   int
	LineMaxByteCount     int
	EhloNameMaxByteCount int
	// The TLS handshake's bound, from STARTTLS's 220.
	HandshakeTimeout time.Duration
}

// The one default.
func DefaultMailDirectSettings() *MailDirectSettings {
	return &MailDirectSettings{
		SenderSessionCount:          8,
		SenderAggregateSessionCount: 32,
		SessionCount:                16,
		DialogTimeout:               5 * time.Minute,
		DialogMaxByteCount:          2048,
		LineMaxByteCount:            510,
		EhloNameMaxByteCount:        255,
		HandshakeTimeout:            60 * time.Second,
	}
}

// Whether every value is in range.
func (self *MailDirectSettings) valid() bool {
	return self != nil && 0 < self.SenderSessionCount && 0 < self.SenderAggregateSessionCount && 0 < self.SessionCount &&
		0 < self.DialogTimeout && 0 < self.DialogMaxByteCount && 0 < self.LineMaxByteCount && 0 < self.EhloNameMaxByteCount &&
		0 < self.HandshakeTimeout
}
