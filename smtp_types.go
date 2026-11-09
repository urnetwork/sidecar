// §14.5's send capability, on every leg: the modes, TLS levels and outcomes a send reports, what
// SmtpSender.Send takes and returns, and what SmtpSender.Check predicts. sdk's CheckSend and
// GetSendResult and MCP's mail_send name these types, so this file names no connect type and builds on
// the sidecar_http leg (§4.4, §18.10). The sender itself is connect-only (SMTP-M9-07 to SMTP-M9-09).
//
// The numbers of SmtpMode, SmtpOutcomeKind and SmtpTlsLevel are the wire's: SmtpProof.mode and
// MailOutcome's mode, outcome and tls_level (§15.7's or/, plan-MAIL-format-bytes#5), so an outcome
// read back from or/ means what the sending device wrote. Every enum keeps 0 for unset, and a writer
// refuses to write it, so a value left unset never reads as a result.

package sidecar

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var errInvalidSmtpOutcome = errors.New("invalid smtp outcome")

// SmtpPreamble.flags, MailOutbox's flags and SmtpOutboxEntry's (§14.5): format values, not settings.
const (
	// The message is bulk mail, so its header block must hold List-Unsubscribe-Post (Z5, R-SMTP-11).
	SmtpFlagBulk uint32 = 1
	// RFC 8689: only TL1 or TL2 and the post-TLS keyword may carry it (plan-SMTP-small-readings#12).
	SmtpFlagRequireTls uint32 = 2
	// From a burner, under <blabel>.<net>.<root> (§15.9).
	SmtpFlagBurner uint32 = 4
	// Every flag this version knows. A preamble or entry with another bit set is refused.
	SmtpFlagsKnown = SmtpFlagBulk | SmtpFlagRequireTls | SmtpFlagBurner
)

// How a recipient domain's MX takes the message (§14.4): BDAT when its post-TLS EHLO reply offers
// CHUNKING, else DATA.
type SmtpMode uint32

const (
	// No session with the domain's MX has reached its post-TLS EHLO reply, and no outcome records one.
	SmtpModeUnknown SmtpMode = 0
	SmtpModeBdat    SmtpMode = 1
	SmtpModeData    SmtpMode = 2
)

// How the sidecar authenticated the MX (§14.4's table), recorded per message (I-11). The numbers are
// TL1 to TL4.
type SmtpTlsLevel uint32

const (
	// No level was reached: the send ended before or during the handshake.
	SmtpTlsLevelUnreached SmtpTlsLevel = 0
	// TL1: TLSA under DNSSEC (RFC 7672), validated to the root from the edge's dnssec_chain.
	SmtpTlsLevelDane SmtpTlsLevel = 1
	// TL2: an enforced MTA-STS policy (RFC 8461) the sidecar fetched itself, and PKIX for a listed MX.
	SmtpTlsLevelMtaSts SmtpTlsLevel = 2
	// TL3: the sidecar's own DoH MX lookup agrees with the edge, and PKIX holds for that host.
	SmtpTlsLevelIndependentMx SmtpTlsLevel = 3
	// TL4: nothing, which only the user's allowance for the domain lets through, and which labels the
	// message "readable by an active URnetwork edge" (§2.8 EX4).
	SmtpTlsLevelUnauthenticated SmtpTlsLevel = 4
)

// §2.8 EX4's label, which mail sent at TL4 carries message by message (I-11).
const SmtpTlsLabelUnauthenticated = "readable by an active URnetwork edge"

// The label a message sent at this level carries (I-11): EX4's at TL4, and none at TL1 to TL3, which
// exclude even an active edge, or when no level was reached.
func (self SmtpTlsLevel) Label() string {
	if self == SmtpTlsLevelUnauthenticated {
		return SmtpTlsLabelUnauthenticated
	}
	return ""
}

// One recipient domain's result of a send (§14.5's outcomes).
type SmtpOutcomeKind uint32

const (
	// Never written, and refused when read.
	SmtpOutcomeUnspecified SmtpOutcomeKind = 0
	// The MX took the message.
	SmtpOutcomeSent SmtpOutcomeKind = 1
	// In the outbox for a prover host (D-SMTP-18).
	SmtpOutcomeQueued SmtpOutcomeKind = 2
	// HALTED, QUOTA or TRY_LATER, or a host whose cap is under the message's bytes, with when to retry.
	SmtpOutcomeDeferred SmtpOutcomeKind = 3
	// DATA mode, and over the cap of every host that could prove it, decided before MAIL.
	SmtpOutcomeTooLarge SmtpOutcomeKind = 4
	// The MX refused it, with its reply code.
	SmtpOutcomeRefused SmtpOutcomeKind = 5
	// TL4 without an allowance, or below the MX host's pin.
	SmtpOutcomeTlsRefused SmtpOutcomeKind = 6
	SmtpOutcomeFailed     SmtpOutcomeKind = 7
)

// What SmtpSender.Check predicts for one recipient domain (§14.5).
type SmtpCheckPrediction uint32

const (
	// Never reported.
	SmtpCheckUnspecified SmtpCheckPrediction = 0
	// Nothing known stops the send.
	SmtpCheckOk SmtpCheckPrediction = 1
	// The domain's mode is data and the bytes pass the cap.
	SmtpCheckTooLarge SmtpCheckPrediction = 2
	// The domain's mode is unknown and the bytes pass the cap, so it depends on the MX.
	SmtpCheckUnknown SmtpCheckPrediction = 3
)

// One internet message for SmtpSender.Send, as MAIL hands it over at §15.10's step 4: the fields of
// its o/ entry (SmtpOutboxEntry, plan-SMTP-wire-gaps#4) and its bytes. MAIL has already applied
// BURNER's header rules, and the message names its own Message-ID; Send splits it by recipient
// domain, strips Bcc, adds the issued headers and DKIM-signs each copy.
type SmtpOutboundMessage struct {
	// D-MCP-11's key of the use. It names the o/ and or/ entries, so a replay finds the earlier
	// outcome; mail claims no exactly-once SMTP (§22.7).
	EffectKey []byte
	// The envelope sender's address at b.<net>.<root> (§14.6).
	Sender string
	// Every recipient, BCC included, as addr-specs. A ReachReceipt lists them all (§16.8).
	Recipients []string
	// The RFC 5322 bytes: the header block, then the body.
	Message []byte
	// SmtpFlagBulk, SmtpFlagRequireTls and SmtpFlagBurner.
	Flags uint32
	// Recipient domains the composing device's approval lets go at TL4 (§14.4). A prover host honors
	// them for this message only, and only from an entry whose signature it verified
	// (plan-SMTP-small-readings#11).
	Tl4Domains []string
	CreateTime time.Time
	// The approval's not_after, whence its retry window (§16 D-MCP-11). Zero is no approval.
	ApprovalNotAfter time.Time
}

// What one Send did, one entry per recipient domain.
type SmtpSendResult struct {
	EffectKey []byte
	// In the order each domain first appears among the recipients.
	Domains []*SmtpDomainOutcome
}

// One recipient domain's outcome, as §15.7's or/ keeps it and every device of the member reads it.
// Only too_large cites the DATA cap, and no outcome names an inbound indexer, receiver or coverage
// setting (§14.5's copy rule).
type SmtpDomainOutcome struct {
	Domain string
	// The mode the domain's MX selected, or unknown if the send ended before it was known.
	Mode SmtpMode
	// too_large: the message's encoded bytes.
	ByteCount uint64
	// too_large: the DATA cap it passed.
	CapByteCount uint64
	Outcome      SmtpOutcomeKind
	// refused: the MX's reply code, such as 550.
	ReplyCode uint32
	// deferred: how long the queue holds the message, from the edge's retry_after_ms.
	RetryAfter time.Duration
	// The sending device's last write of this domain's result.
	UpdateTime time.Time
	// The send's I-11 label.
	TlsLevel SmtpTlsLevel
}

// What Check found for each recipient domain.
type SmtpSendCheck struct {
	// In the order each domain first appears among the recipients.
	Domains []*SmtpDomainCheck
}

// One recipient domain's prediction (§14.5's Check).
type SmtpDomainCheck struct {
	Domain string
	// From this device's last session with the domain's MX, kept as its TLS pin is, or from an or/
	// outcome; else unknown.
	Mode SmtpMode
	// The message's encoded bytes for that mode: headers, DKIM signatures and dot-stuffing included.
	ByteCount uint64
	// The smtp_data_proof_bytes of the host that will prove it or, through an outbox, the largest its
	// member's prover hosts record (p/). 0 when no host has recorded one.
	CapByteCount uint64
	// BDAT's proofs, or a DATA send's parts at the proving host's measured rate, plus through an
	// outbox the wait for a prover host.
	ExpectedDelay time.Duration
	Prediction    SmtpCheckPrediction
}

// Whether the mode is one this version writes, unknown included.
func (self SmtpMode) known() bool {
	return self == SmtpModeUnknown || self == SmtpModeBdat || self == SmtpModeData
}

// Whether the level is one this version writes, unreached included.
func (self SmtpTlsLevel) known() bool {
	return self <= SmtpTlsLevelUnauthenticated
}

// Whether the kind is a result, never unspecified.
func (self SmtpOutcomeKind) known() bool {
	return SmtpOutcomeSent <= self && self <= SmtpOutcomeFailed
}

// The or/ form of an outcome (plan-MAIL-format-bytes#5). It refuses what no reader could take back:
// an unset or unknown kind, mode or level, and a delay MailOutcome's milliseconds cannot hold.
func (self *SmtpDomainOutcome) MailOutcome() (*protocol.MailOutcome, error) {
	if !self.Outcome.known() || !self.Mode.known() || !self.TlsLevel.known() {
		return nil, fmt.Errorf("%w: kind %d, mode %d, level %d", errInvalidSmtpOutcome, self.Outcome, self.Mode, self.TlsLevel)
	}
	if self.RetryAfter < 0 || math.MaxUint32 < self.RetryAfter.Milliseconds() {
		return nil, fmt.Errorf("%w: retry after %v", errInvalidSmtpOutcome, self.RetryAfter)
	}
	updateTimeMs := uint64(0)
	if !self.UpdateTime.IsZero() {
		if self.UpdateTime.UnixMilli() < 0 {
			return nil, fmt.Errorf("%w: update time before the epoch", errInvalidSmtpOutcome)
		}
		updateTimeMs = uint64(self.UpdateTime.UnixMilli())
	}
	return &protocol.MailOutcome{
		Domain:       self.Domain,
		Mode:         protocol.MailSendMode(self.Mode),
		ByteCount:    self.ByteCount,
		CapByteCount: self.CapByteCount,
		Outcome:      protocol.MailOutcomeKind(self.Outcome),
		ReplyCode:    self.ReplyCode,
		RetryAfterMs: uint32(self.RetryAfter.Milliseconds()),
		UpdateTimeMs: updateTimeMs,
		TlsLevel:     uint32(self.TlsLevel),
	}, nil
}

// An outcome read back from or/. A device of another version may have written it, so an unset or
// unknown kind, mode or level is refused rather than read as some other result.
func SmtpDomainOutcomeFromMailOutcome(outcome *protocol.MailOutcome) (*SmtpDomainOutcome, error) {
	if outcome == nil {
		return nil, fmt.Errorf("%w: none", errInvalidSmtpOutcome)
	}
	domainOutcome := &SmtpDomainOutcome{
		Domain:       outcome.GetDomain(),
		Mode:         SmtpMode(outcome.GetMode()),
		ByteCount:    outcome.GetByteCount(),
		CapByteCount: outcome.GetCapByteCount(),
		Outcome:      SmtpOutcomeKind(outcome.GetOutcome()),
		ReplyCode:    outcome.GetReplyCode(),
		RetryAfter:   time.Duration(outcome.GetRetryAfterMs()) * time.Millisecond,
		TlsLevel:     SmtpTlsLevel(outcome.GetTlsLevel()),
	}
	if !domainOutcome.Outcome.known() || !domainOutcome.Mode.known() || !domainOutcome.TlsLevel.known() {
		return nil, fmt.Errorf("%w: kind %d, mode %d, level %d", errInvalidSmtpOutcome, domainOutcome.Outcome, domainOutcome.Mode, domainOutcome.TlsLevel)
	}
	if updateTimeMs := outcome.GetUpdateTimeMs(); updateTimeMs != 0 {
		if math.MaxInt64 < updateTimeMs {
			return nil, fmt.Errorf("%w: update time past the clock", errInvalidSmtpOutcome)
		}
		domainOutcome.UpdateTime = time.UnixMilli(int64(updateTimeMs))
	}
	return domainOutcome, nil
}
