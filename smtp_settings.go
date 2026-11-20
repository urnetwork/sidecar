//go:build !sidecar_http

// SmtpSender's tunables and the limits assembly holds a message to (§14.4, §14.5, D-SMTP-18, QD-702),
// which SidecarConnectSettings carries beside the prover, since only connect legs send. The issued
// headers' widths are identifiers of their formats and stay constants beside them (DESIGN-DETAILS
// 3.7). Every number here must be positive, as settings.go's header says.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"fmt"
	"reflect"
	"time"
)

// What one host's sender may do and how long it waits.
type SmtpSenderSettings struct {
	// The first retry of a held or failed send: 30 min after it, the interval doubling from there
	// (plan-SMTP-small-readings#9).
	RetryFirstTimeout time.Duration
	// The longest interval between retries, which the doubling stops at: 4 h.
	RetryMaxTimeout time.Duration
	// How long after its creation a message is retried before a DSN gives it up: 5 days. HALTED,
	// QUOTA and TRY_LATER honor retry_after_ms and still end here.
	RetryGiveUpTimeout time.Duration
	// The connection units one message's retries that reach MAIL may spend in a UTC day, past which
	// the message waits for the next UTC day: 2 (plan-SMTP-small-readings#9).
	RetryUnitsPerMessagePerDay int
	// Sends proving at once on this host: 1, since a part's proving does not fit an 8 GB host twice
	// (plan-SMTP-small-readings#19). Proving sits outside MemoryBudgetByteCount.
	ProverConcurrency int
	// How long each MX host's best TLS level for each recipient domain, and each host's post-TLS mode,
	// stay pinned: 90 days (§14.4, §14.5, owner decision 438). Nothing is sent to a domain through a
	// host below its pin there while it holds.
	PinTimeout time.Duration
	// How many pins, counted by (recipient domain, MX host) pair, how many MX hosts' modes, and how many
	// recipient domains' last sessions the pin store keeps: 4,096 each, the one closest to lapsing
	// leaving first past it, so the sealed file stays small enough to rewrite on every send.
	PinMaxCount int
	// How many recipient domains' TL4 allowances the store keeps: 4,096. Past it a new domain's
	// allowance is refused until one ends, rather than another's dropped, since each is a person's
	// consent (§14.4, QD-729).
	TlsAllowanceMaxCount int
	// How long one of TL2's or TL3's DoH lookups, the _mta-sts TXT or the recipient domain's MX, may
	// take before that level counts as unavailable for the send: 15 s, well inside the 5 minutes an MX
	// waits for the ClientHello after STARTTLS's 220.
	TlsLookupTimeout time.Duration
	// How long the HTTPS fetch of an MTA-STS policy may take: 1 min, RFC 8461 §3.3's suggestion.
	MtaStsFetchTimeout time.Duration
	// The largest MTA-STS policy body taken: 64 KiB, RFC 8461 §3.3's suggestion.
	MtaStsPolicyMaxByteCount int
	// How long after a failed fetch for one policy id the next fetch waits: 5 min, RFC 8461 §3.3's
	// floor, so a broken policy host is not asked again on every send.
	MtaStsFetchRetryTimeout time.Duration
	// How many recipient domains' MTA-STS policies stay cached: 4,096, the one closest to its max_age
	// leaving first past it.
	MtaStsPolicyMaxCount int
	// How often a prover host rewrites or/ while a send it took runs: 5 min, so another host can see
	// it is alive (plan-SMTP-small-readings#10).
	OutboxProgressInterval time.Duration
	// How long an entry's or/ goes unchanged before the next host takes the send over: 10 min. A crash
	// can still send twice, which §22.7 allows.
	OutboxTakeoverTimeout time.Duration
	// How long a DKIM selector signs before one POST /smtp/dkim-keys publishes its successor and
	// retires it: 90 days (§14.6).
	DkimRotateTimeout time.Duration
	// How long a retired selector's private key stays in the keychain: 7 days, as long as the server
	// keeps the selector in DNS (§14.6), so a send that pinned it before a rotation still signs and
	// still verifies. A pinned selector outlives this until its send releases it.
	DkimRetiredKeepTimeout time.Duration
	// How long a DKIM signature stays valid: x= is t= plus 7 days (§14.6), and a report about the
	// message joins on the fixed signature only while it holds.
	DkimExpireTimeout time.Duration
	// The octets the header block's head may fill, each line's CRLF included: X-UR-Ref, Feedback-ID,
	// From, Message-ID and, on a BULK message, List-Unsubscribe-Post, then the fixed signature's first
	// line, which carries its d= and s=. 720, under the 831 octets the shortest first record holds (an
	// AES-128-GCM msg shape's head under TLS 1.3), so the prover's cut by length alone leaves them all in
	// the header block's first record, where Z5 requires them (DESIGN-DETAILS 3.2.3, 3.2.4, 3.2.6).
	// Assembly refuses a message past it before the preamble: a long From display name, or a long
	// header-from domain, which From and the fixed signature's d= both carry. At the default, with a
	// Message-ID domain of up to 40 octets, a domain of up to 154 octets can still send BULK and one
	// of up to 180 any other mail, each with a one-octet local part and no display name.
	HeaderHeadMaxByteCount int
	// The longest header block assembly makes, its final CRLF CRLF and every issued value and signature
	// included: 16 KiB, the most the prover cuts into header records, as smtpproof's
	// ProofSettings.HeaderBlockMaxByteCount has it (DESIGN-DETAILS 3.2.8). Assembly refuses a message
	// past it before the preamble.
	HeaderBlockMaxByteCount int
	// How long a send the edge answered KEYS for, with no older ready key set to try, is held before it is
	// tried again: 6 h, leaving its outbox entry for a host whose proofs the edge accepts (DESIGN-DETAILS
	// 3.2.7, 3.5).
	KeysRetryTimeout time.Duration
	// How long a send is held whose preamble OK named an envelope other than its MAIL FROM's (QD-1154) before it
	// reads the strict domains again and is tried: 60 s, smtpedge's gate facts refresh, by which the edge holds the
	// set GET /mail/status names.
	EnvelopeRetryTimeout time.Duration
	// How often a prover host measures itself again with its key set unchanged: 7 days. It also measures
	// when a family becomes ready and when the key set changes (DESIGN-DETAILS 3.7's SMTP-M9-09).
	ProverMeasureInterval time.Duration
	// The envelope group's most commands on the one retry after the MX's replies overflowed every shape:
	// 1, each command proven alone, and kept for the MX host beside its mode (DESIGN-DETAILS 3.2.4, 3.5).
	EnvelopeRetryGroupCount int
	// How long one SMTP_PROOF or SMTP_HANDSHAKE call to the edge waits for its answer: 30 s, inside
	// §6.6's 55 s, where a part verifies in milliseconds.
	ProofCallTimeout time.Duration
	// Calls one part or handshake gets before the send fails: 2. A part resent under its send_id and
	// index, byte for byte, is idempotent at the edge (§14.5), so a call that timed out goes again with
	// its request_id.
	ProofCallAttemptCount int
	// How long the sender waits for SmtpPreambleResult once its preamble is written: 10 min, past the
	// edge's own MX resolution, dial and pre-TLS dialog, each of whose replies an MX may take 5 min over
	// (RFC 5321 §4.5.3.2). The stream is reset past it, and the send held for its next retry.
	PreambleResultTimeout time.Duration
	// How many more streams a send opens at once after one that ended before its preamble's answer,
	// as an edge crash ends it: 1, the §9 backup ticket (§14.9's failure row). One that ends later holds
	// the send for its next retry, since the MX may have seen MAIL.
	EdgeResetRetryCount int
	// How long the sender's self-report of a send, SmtpOutcome, may take to hand off: 15 s (§14.4's
	// step 5). It only tightens, so one that cannot go is dropped.
	OutcomeSendTimeout time.Duration
	// How often a prover host lists the member's o/ when nothing wakes it sooner: 1 min, under the 10 min
	// another host waits before taking over an entry (D-SMTP-18).
	OutboxPollInterval time.Duration
	// How often a prover host runs its idle work, the key checks and measures, when no send's end wakes it
	// sooner: 1 min (DESIGN-DETAILS 3.7's SMTP-M9-09).
	ProverIdleInterval time.Duration
	// How long a SmtpStatus of HALTED or QUOTA that names no retry_after_ms holds the queue: 24 h, a halt's
	// length (§14.8). One that names it holds that long.
	StatusHoldTimeout time.Duration
}

// A fresh value each call, sharing nothing mutable with any other (connect/CODESTYLE.md:151).
func DefaultSmtpSenderSettings() *SmtpSenderSettings {
	return &SmtpSenderSettings{
		RetryFirstTimeout:          30 * time.Minute,
		RetryMaxTimeout:            4 * time.Hour,
		RetryGiveUpTimeout:         5 * 24 * time.Hour,
		RetryUnitsPerMessagePerDay: 2,
		ProverConcurrency:          1,
		PinTimeout:                 90 * 24 * time.Hour,
		PinMaxCount:                4096,
		TlsAllowanceMaxCount:       4096,
		TlsLookupTimeout:           15 * time.Second,
		MtaStsFetchTimeout:         time.Minute,
		MtaStsPolicyMaxByteCount:   64 * 1024,
		MtaStsFetchRetryTimeout:    5 * time.Minute,
		MtaStsPolicyMaxCount:       4096,
		OutboxProgressInterval:     5 * time.Minute,
		OutboxTakeoverTimeout:      10 * time.Minute,
		DkimRotateTimeout:          90 * 24 * time.Hour,
		DkimRetiredKeepTimeout:     7 * 24 * time.Hour,
		DkimExpireTimeout:          7 * 24 * time.Hour,
		HeaderHeadMaxByteCount:     720,
		HeaderBlockMaxByteCount:    16 * 1024,
		KeysRetryTimeout:           6 * time.Hour,
		EnvelopeRetryTimeout:       60 * time.Second,
		ProverMeasureInterval:      7 * 24 * time.Hour,
		EnvelopeRetryGroupCount:    1,
		ProofCallTimeout:           30 * time.Second,
		ProofCallAttemptCount:      2,
		PreambleResultTimeout:      10 * time.Minute,
		EdgeResetRetryCount:        1,
		OutcomeSendTimeout:         15 * time.Second,
		OutboxPollInterval:         time.Minute,
		ProverIdleInterval:         time.Minute,
		StatusHoldTimeout:          24 * time.Hour,
	}
}

// What validateLeg holds a sender's settings to: present, every number positive, the schedules in
// their order, so a retry never waits past giving up and a live host is never taken over, and the
// header block's head inside the block.
func (self *SmtpSenderSettings) validate() error {
	if self == nil {
		return fmt.Errorf("%w: Connect.SmtpSender is nil", errInvalidSettings)
	}
	if err := checkSettingsNumbers("Connect.SmtpSender", reflect.ValueOf(self).Elem(), false); err != nil {
		return err
	}
	if self.RetryMaxTimeout < self.RetryFirstTimeout || self.RetryGiveUpTimeout < self.RetryMaxTimeout {
		return fmt.Errorf("%w: Connect.SmtpSender's retry timeouts are out of order", errInvalidSettings)
	}
	if self.OutboxTakeoverTimeout <= self.OutboxProgressInterval {
		return fmt.Errorf("%w: Connect.SmtpSender takes a send over before its host could show progress", errInvalidSettings)
	}
	if self.HeaderBlockMaxByteCount < self.HeaderHeadMaxByteCount {
		return fmt.Errorf("%w: Connect.SmtpSender's header head passes its header block", errInvalidSettings)
	}
	if MaxCallTimeout < self.ProofCallTimeout {
		return fmt.Errorf("%w: Connect.SmtpSender's proof calls wait past §6.6's maximum", errInvalidSettings)
	}
	return nil
}
