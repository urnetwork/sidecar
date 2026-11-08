// On every leg, the sidecar_http leg's included: this file and smtp_types.go are what sdk and MCP name.

package sidecar

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The root's numbers are the wire's, so an outcome read back from or/ means what was written.
func TestSmtpNumbersAreTheWires(t *testing.T) {
	if SmtpModeBdat != SmtpMode(protocol.MailSendMode_MAIL_SEND_BDAT) || SmtpModeData != SmtpMode(protocol.MailSendMode_MAIL_SEND_DATA) {
		t.Error("modes differ from MailSendMode")
	}
	// SmtpProof.mode: 1 BDAT, 2 DATA (§14.5)
	if SmtpModeBdat != 1 || SmtpModeData != 2 {
		t.Error("modes differ from SmtpProof.mode")
	}
	for kind, name := range protocol.MailOutcomeKind_name {
		if kind != 0 && !SmtpOutcomeKind(kind).known() {
			t.Errorf("%s has no outcome", name)
		}
	}
	if !(SmtpOutcomeSent == 1 && SmtpOutcomeQueued == 2 && SmtpOutcomeDeferred == 3 && SmtpOutcomeTooLarge == 4 &&
		SmtpOutcomeRefused == 5 && SmtpOutcomeTlsRefused == 6 && SmtpOutcomeFailed == 7) {
		t.Error("outcomes differ from §14.5's order")
	}
	if SmtpTlsLevelDane != 1 || SmtpTlsLevelMtaSts != 2 || SmtpTlsLevelIndependentMx != 3 || SmtpTlsLevelUnauthenticated != 4 {
		t.Error("levels are not TL1 to TL4")
	}
	// SmtpPreamble.flags: 1 BULK, 2 REQUIRETLS, 4 BURNER
	if SmtpFlagBulk != 1 || SmtpFlagRequireTls != 2 || SmtpFlagBurner != 4 || SmtpFlagsKnown != 7 {
		t.Error("flags differ from SmtpPreamble.flags")
	}
}

func TestSmtpDomainOutcomeRoundTripsThroughOr(t *testing.T) {
	updateTime := time.UnixMilli(1_790_000_000_000)
	for kind := SmtpOutcomeSent; kind <= SmtpOutcomeFailed; kind += 1 {
		for _, mode := range []SmtpMode{SmtpModeUnknown, SmtpModeBdat, SmtpModeData} {
			for level := SmtpTlsLevelUnreached; level <= SmtpTlsLevelUnauthenticated; level += 1 {
				outcome := &SmtpDomainOutcome{
					Domain:       "mail.example",
					Mode:         mode,
					ByteCount:    2 * 1024 * 1024,
					CapByteCount: 1024 * 1024,
					Outcome:      kind,
					ReplyCode:    550,
					RetryAfter:   90 * time.Second,
					UpdateTime:   updateTime,
					TlsLevel:     level,
				}
				mailOutcome, err := outcome.MailOutcome()
				if err != nil {
					t.Fatal(err)
				}
				read, err := SmtpDomainOutcomeFromMailOutcome(mailOutcome)
				if err != nil {
					t.Fatal(err)
				}
				if *read != *outcome {
					t.Errorf("wrote %+v, read %+v", outcome, read)
				}
			}
		}
	}
	// no update time stays none
	outcome := &SmtpDomainOutcome{Domain: "mail.example", Outcome: SmtpOutcomeQueued}
	mailOutcome, err := outcome.MailOutcome()
	if err != nil {
		t.Fatal(err)
	}
	if read, err := SmtpDomainOutcomeFromMailOutcome(mailOutcome); err != nil || !read.UpdateTime.IsZero() {
		t.Errorf("%v, %v", read, err)
	}
}

// An unset or unknown value is never written, and one read back is refused rather than taken as
// some other result.
func TestSmtpDomainOutcomeRefusesUnsetAndUnknownValues(t *testing.T) {
	for _, outcome := range []*SmtpDomainOutcome{
		{Outcome: SmtpOutcomeUnspecified},
		{Outcome: SmtpOutcomeFailed + 1},
		{Outcome: SmtpOutcomeSent, Mode: SmtpModeData + 1},
		{Outcome: SmtpOutcomeSent, TlsLevel: SmtpTlsLevelUnauthenticated + 1},
		{Outcome: SmtpOutcomeDeferred, RetryAfter: -time.Second},
		{Outcome: SmtpOutcomeDeferred, RetryAfter: 50 * 24 * time.Hour},
		{Outcome: SmtpOutcomeSent, UpdateTime: time.UnixMilli(-1)},
	} {
		if _, err := outcome.MailOutcome(); !errors.Is(err, errInvalidSmtpOutcome) {
			t.Errorf("wrote %+v: %v", outcome, err)
		}
	}
	for _, mailOutcome := range []*protocol.MailOutcome{
		nil,
		{Outcome: protocol.MailOutcomeKind_MAIL_OUTCOME_KIND_UNSPECIFIED},
		{Outcome: protocol.MailOutcomeKind(8)},
		{Outcome: protocol.MailOutcomeKind_MAIL_OUTCOME_SENT, Mode: protocol.MailSendMode(3)},
		{Outcome: protocol.MailOutcomeKind_MAIL_OUTCOME_SENT, TlsLevel: 5},
		{Outcome: protocol.MailOutcomeKind_MAIL_OUTCOME_SENT, UpdateTimeMs: 1 << 63},
	} {
		if _, err := SmtpDomainOutcomeFromMailOutcome(mailOutcome); !errors.Is(err, errInvalidSmtpOutcome) {
			t.Errorf("read %v: %v", mailOutcome, err)
		}
	}
}
