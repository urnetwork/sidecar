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
	// What a send is held to (mail_send.go).
	Send *MailSendSettings
	// The outbox and the sender's way into the mailbox (mail_outbox.go, mail_smtp_mailbox.go).
	Outbox *MailOutboxSettings
	// Forwarding and its codes (mail_forward.go).
	Forward *MailForwardSettings
	// The member's vault (mail_vault.go) and what OneTimeCodes reads (mail_codes.go).
	Vault *MailVaultSettings
	Codes *MailCodeSettings
	// Burners' labels, limits and sites (mail_burner.go, mail_burner_labels.go).
	Burner *MailBurnerSettings
	// Mail's search join (mail_search.go); nil takes DefaultMailSearchSettings.
	Search *MailSearchSettings
	// The host this runs on, which says when it receives and whether it may be a mail indexer (mail_host.go): a daemon
	// unless ApplyMobileMailSettings names an app.
	Profile MailHostProfile
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
	// The longest the component's opener of a designation's services waits for the config repo's key of the
	// generation they are sealed to, which its GkmClient may fetch (mail_indexer.go): past it that designation reads
	// unknown for that look. 10 s, the config follower's own wait for a config key (RepoKeyTimeout).
	IndexerKeyTimeout time.Duration
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
		Outbox:                      DefaultMailOutboxSettings(),
		Forward:                     DefaultMailForwardSettings(),
		Vault:                       DefaultMailVaultSettings(),
		Codes:                       DefaultMailCodeSettings(),
		Burner:                      DefaultMailBurnerSettings(),
		Search:                      DefaultMailSearchSettings(),
		Profile:                     MailHostProfileDaemon,
		ReadMaxByteCount:            int(ingest.DepositMaxByteCount),
		ReadHeaderValueMaxByteCount: 4 * 1024,
		ReadHeaderMaxCount:          32,
		AddressScanMaxCount:         4096,
		CheckInterval:               5 * time.Minute,
		UnboundCheckInterval:        30 * time.Second,
		IndexerKeyTimeout:           10 * time.Second,
	}
}

// Whether every value is in range.
func (self *MailSettings) valid() bool {
	return self != nil && self.Config != nil && self.Ingest != nil && self.Store != nil && self.Receive != nil && self.Imap != nil &&
		self.Send.valid() && self.Outbox.valid() && self.Forward.valid() && self.Vault != nil && self.Codes.valid() && self.Burner.valid() &&
		0 < self.ReadMaxByteCount && 0 < self.ReadHeaderValueMaxByteCount && 0 < self.ReadHeaderMaxCount &&
		0 < self.AddressScanMaxCount && 0 < self.CheckInterval && 0 < self.UnboundCheckInterval && 0 < self.IndexerKeyTimeout
}

// §18.4's values for an app host of profile (MAIL-M8-04): the profile, which listens only while the app is open and
// is never a mail indexer, and on the legs a receiver builds on its phone values: max_streams' 16 sessions and the 4
// check slots as §15.5 fixes them, and 2 deposits at once, the spool keeping every message off the heap
// (applyMobileMailSettings). A host on a phone adjusts what it is given with this rather than keeping a second copy of
// a number.
func ApplyMobileMailSettings(settings *MailSettings, profile MailHostProfile) {
	if settings == nil {
		return
	}
	settings.Profile = profile
	applyMobileMailSettings(settings)
}

// The u32be length that leads an o/ file (plan-SMTP-wire-gaps#4): a format value.
const mailOutboxLengthByteCount = 4

// What the outbox and the sender's way into the mailbox are held to (MAIL-M9-02). Every value must be positive.
type MailOutboxSettings struct {
	// The most bytes of an o/ entry's Signed: a SmtpOutboxEntry of 100 recipients of at most 254 bytes, its TL4
	// domains and a signature fit 32 KiB, and 64 KiB leaves room for a newer writer's fields.
	OutboxSignedMaxByteCount int
	// The most bytes of an o/ file: the largest message a send takes, the deposit's 50 MiB (§20.4), with its Signed.
	OutboxFileMaxByteCount int
	// The most bytes of an or/ record: one MailOutcome a recipient domain, at most 100, each under 320 bytes.
	OutcomeRecordMaxByteCount int
	// The most bytes of a p/ record.
	ProverRecordMaxByteCount int
	// How many times a replacing write, of or/ or p/, or a removal reads again after another writer moved its path.
	WriteRetryCount int
	// How long an or/ record is kept from its last outcome's update (§15.7's 30 days).
	OutcomeKeepDuration time.Duration
	// How often the mail component sweeps the member's or/ for records past OutcomeKeepDuration: a day, so a record
	// outlives its 30 days by at most one more, and a listing of or/'s shards runs once a day a device.
	OutcomeSweepInterval time.Duration
	// How long the send watch, which raises mail_send from the member's or/ (mail_send_result.go), waits for a change
	// to or/ it hears of before it reads or/ again anyway: the component's 5 min CheckInterval, since a change its
	// subscription to or/ hears of, or a Resync, wakes it at once, and this only bounds one it missed.
	SendWatchInterval time.Duration
	// The most bytes of the send watch's last read of or/ kept in the component's sealed store, which a restart reads
	// back so it raises only what changed since: a record's send and each domain's outcome take some 200 bytes, so 4 MiB
	// holds about 20,000 records, past a member's 30 days of internet mail. Past it the read is kept in memory alone,
	// and the next start reads or/ afresh, raising nothing for what it finds then (the file header's baseline row).
	SendWatchStateMaxByteCount int
}

// The one default.
func DefaultMailOutboxSettings() *MailOutboxSettings {
	return &MailOutboxSettings{
		OutboxSignedMaxByteCount:   64 * 1024,
		OutboxFileMaxByteCount:     50*1024*1024 + 64*1024 + mailOutboxLengthByteCount,
		OutcomeRecordMaxByteCount:  64 * 1024,
		ProverRecordMaxByteCount:   4 * 1024,
		WriteRetryCount:            8,
		OutcomeKeepDuration:        30 * 24 * time.Hour,
		OutcomeSweepInterval:       24 * time.Hour,
		SendWatchInterval:          5 * time.Minute,
		SendWatchStateMaxByteCount: 4 * 1024 * 1024,
	}
}

// Whether every value is in range.
func (self *MailOutboxSettings) valid() bool {
	return self != nil && 0 < self.OutboxSignedMaxByteCount && self.OutboxSignedMaxByteCount < self.OutboxFileMaxByteCount &&
		0 < self.OutcomeRecordMaxByteCount && 0 < self.ProverRecordMaxByteCount && 0 < self.WriteRetryCount &&
		0 < self.OutcomeKeepDuration && 0 < self.OutcomeSweepInterval && 0 < self.SendWatchInterval && 0 < self.SendWatchStateMaxByteCount
}

// What forwarding is held to (MAIL-M9-04; §15.10's forwarding, owner decision 53). Every value must be positive.
type MailForwardSettings struct {
	// The digits of the code that confirms a forwarding address: §15.10's 6.
	CodeDigitCount int
	// How long a code sent to an address stays good: 1 h, long enough for a person to read their mail, short enough
	// that a code found later confirms nothing.
	CodeLifetime time.Duration
	// How many wrong codes a pending address takes before its code is spent and another must be sent: 5, so a guesser
	// reaches at most 5 of the 10^6 codes a code sent.
	CodeAttemptMaxCount int
}

// The one default.
func DefaultMailForwardSettings() *MailForwardSettings {
	return &MailForwardSettings{
		CodeDigitCount:      6,
		CodeLifetime:        time.Hour,
		CodeAttemptMaxCount: 5,
	}
}

// Whether every value is in range: a code of 4 to 9 digits, which a uint32 holds.
func (self *MailForwardSettings) valid() bool {
	return self != nil && 4 <= self.CodeDigitCount && self.CodeDigitCount <= 9 && 0 < self.CodeLifetime && 0 < self.CodeAttemptMaxCount
}
