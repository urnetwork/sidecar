//go:build !ios_extension

// What a device's mail is tuned by (MAIL-M7-17): MailSettings, one object for every part of §15 on a device, the
// mailcfg table, ingest, the mailbox view and its writers, the component's own waits, and on the legs a receiver
// builds on its receiver, sessions and checks (MailReceiveSettings, mail_settings_receive.go). DefaultMailSettings is
// the one default; a host on a phone adjusts what it is given with ApplyMobileMailSettings rather than keeping a second
// copy of a number.

package sidecar

import (
	"time"
)

// What a device's mail is tuned by. Every duration and count must be positive.
type MailSettings struct {
	// mailcfg's table and writes.
	Config *MailConfigSettings
	// Ingest, with its parse, spam and store bounds.
	Ingest *MailIngestSettings
	// The mailbox view's and the i/ and f/ writers' bounds.
	Store *MailStoreSettings
	// A receiver's parts, on the legs a receiver builds on; nothing on the page Worker's.
	Receive *MailReceiveSettings
	// What IMAP's store lists and keeps (mail_imap_store.go).
	Imap *MailImapSettings
	// What a same-network send is held to (mail_send.go).
	Send *MailSendSettings
	// The most bytes Read takes of one message: the largest mail_inbound_message_bytes (50 MiB, §20.4) and the
	// headers ingest adds, as ingest's own bound holds a deposit.
	ReadMaxByteCount int
	// The header fields Read returns of a message, the most of each field's bytes, and the most fields.
	ReadHeaderValueMaxByteCount int
	ReadHeaderMaxCount          int
	// The most entries a list for one address reads through to fill a page (ur://mail/{alias}), so a mailbox of
	// other mail costs a bounded read.
	AddressScanMaxCount int
	// How often the component looks again at what it runs: the mailbox, mailcfg and whether policy grants this
	// device the receiver's listen. A change it hears of wakes it sooner.
	CheckInterval time.Duration
	// How often it looks while the Sidecar holds nothing to bind yet: no evs component, or no verified state, which
	// land without telling mail.
	UnboundCheckInterval time.Duration
}

// The one default.
func DefaultMailSettings() *MailSettings {
	ingest := DefaultMailIngestSettings()
	return &MailSettings{
		Config:                      DefaultMailConfigSettings(),
		Ingest:                      ingest,
		Store:                       DefaultMailStoreSettings(),
		Receive:                     defaultMailReceiveSettings(),
		Imap:                        DefaultMailImapSettings(),
		Send:                        DefaultMailSendSettings(),
		ReadMaxByteCount:            int(ingest.DepositMaxByteCount),
		ReadHeaderValueMaxByteCount: 4 * 1024,
		ReadHeaderMaxCount:          32,
		AddressScanMaxCount:         4096,
		CheckInterval:               5 * time.Minute,
		UnboundCheckInterval:        30 * time.Second,
	}
}

// Whether every value is in range.
func (self *MailSettings) valid() bool {
	return self != nil && self.Config != nil && self.Ingest != nil && self.Store != nil && self.Receive != nil && self.Imap != nil &&
		self.Send.valid() &&
		0 < self.ReadMaxByteCount && 0 < self.ReadHeaderValueMaxByteCount && 0 < self.ReadHeaderMaxCount &&
		0 < self.AddressScanMaxCount && 0 < self.CheckInterval && 0 < self.UnboundCheckInterval
}
