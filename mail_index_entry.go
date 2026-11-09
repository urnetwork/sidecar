// §15.7's IndexEntry (D-MAIL-5, D-MAIL-14, I-11): one message's row in its month's i/ segment, built by ingest
// from the deposit's sealed trailer, the message's walk (MailParseMessage), the label MailLabelDecide gave from
// that trailer (MAIL-M7-10) and the spam score and code MAIL-M7-12 found. Every value is MAIL-FORMAT.md's: each
// text within its cap, auth_results summarized from the sealed evidence, the time the sealed receive time.
//
// The builder holds a label to what the deposit can support, so a caller that labels wrongly fails here rather than
// writing a row that claims more than reception sealed: validated needs a receiver's evidence, member-signed a
// same-network deposit, a basis a receiver's deposit, and strict_custom_mx a sealed strict_chain. It decides no
// label itself, and an unset one stays MAIL_TLS_LABEL_UNSPECIFIED, which no reader shows as validated.
//
// No connect, go-smtp or mox: on every leg. Safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §15.7's spam_score scale, parts per thousand, past which a reader takes 1,000 (MAIL-FORMAT.md). A format value.
const mailSpamScoreMax = 1000

// A deposit, a walk or a label an IndexEntry cannot be built from. The error never repeats an address or a
// header's text (I-13).
var ErrMailIndexEntryInvalid = errors.New("mail index entry invalid")

// What MailBuildIndexEntry builds a row from.
type MailIndexEntryInput struct {
	// The message's id, which is its deposit's id.
	Id Id
	// The deposit's sealed trailer.
	Deposit *protocol.MailDeposit
	// The depositing push's signed time_ms, the receive time of a deposit that seals none (MailDepositReceiveTime).
	PushTimeMillis uint64
	// The message's bytes as received, before ingest's headers.
	ByteCount uint64
	// The message's walk.
	Parsed *MailParsed
	// MailLabelDecide's label and its basis, or unspecified and nil where no label was decided.
	TlsLabel protocol.MailTlsLabel
	TlsBasis *protocol.MailTlsBasis
	// The spam score, parts per thousand, and the one-time code or empty (MAIL-M7-12).
	SpamScore   uint32
	OneTimeCode string
}

// Whether deposit is a receiver's: one that names its receiver, which ingest holds to the push's signer. Any
// other is a same-network deposit (D-MAIL-8), signed by its sender (MAIL-FORMAT.md).
func mailReceiverDeposit(deposit *protocol.MailDeposit) bool {
	return len(deposit.GetReceiverSidecarId()) != 0
}

// What a message list shows of evidence (MAIL-FORMAT.md): the four verdicts, dkim pass if any selected signature
// passed, else the first selected one's, else none; checks incomplete where limits was set; and evidence
// unavailable where a receiver sealed none.
func mailAuthResults(evidence *protocol.MailAuthEvidence) *protocol.MailAuthResults {
	if evidence == nil {
		return &protocol.MailAuthResults{EvidenceUnavailable: true}
	}
	results := &protocol.MailAuthResults{
		Spf:              evidence.GetSpf().GetResult(),
		Dmarc:            evidence.GetDmarc().GetResult(),
		Arc:              evidence.GetArc().GetCv(),
		ChecksIncomplete: evidence.GetLimits() != nil,
	}
	for index, dkim := range evidence.GetDkim() {
		if dkim.GetResult() == protocol.DkimVerdict_DKIM_PASS {
			results.Dkim = protocol.DkimVerdict_DKIM_PASS
			break
		}
		if index == 0 {
			results.Dkim = dkim.GetResult()
		}
	}
	return results
}

// The i/ row of one ingested message, or ErrMailIndexEntryInvalid for a deposit no row can be built from, or a
// label the deposit does not support.
func MailBuildIndexEntry(input *MailIndexEntryInput) (*protocol.IndexEntry, error) {
	invalid := func(reason string) (*protocol.IndexEntry, error) {
		return nil, fmt.Errorf("%w: %s", ErrMailIndexEntryInvalid, reason)
	}
	if input == nil || input.Deposit == nil || input.Parsed == nil {
		return invalid("no deposit or walk")
	}
	deposit := input.Deposit
	recipients := deposit.GetRecipients()
	if len(recipients) == 0 {
		return invalid("the deposit names no recipient")
	}
	// a repo's own recipient, which a receiver parsed, so never past an address's bound
	address := recipients[0]
	if mailIndexAddressMaxByteCount < len(address) || !utf8.ValidString(address) {
		return invalid("the first recipient is not an address")
	}

	receiver := mailReceiverDeposit(deposit)
	evidence := deposit.GetEvidence()
	switch input.TlsLabel {
	case protocol.MailTlsLabel_MAIL_TLS_LABEL_UNSPECIFIED, protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC:
	case protocol.MailTlsLabel_MAIL_TLS_VALIDATED:
		// every input of the rule is the receiver's sealed value, and with none sealed the label is opportunistic
		if !receiver || evidence == nil {
			return invalid("validated without a receiver's evidence")
		}
	case protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED:
		if receiver {
			return invalid("member-signed on a receiver's deposit")
		}
	default:
		return invalid("a label MAIL-FORMAT.md does not have")
	}
	if input.TlsBasis != nil {
		if !receiver {
			return invalid("a basis on a same-network deposit")
		}
		if input.TlsBasis.GetStrictCustomMx() && !evidence.GetStrictChain() {
			return invalid("strict_custom_mx without a sealed strict_chain")
		}
		if mailIndexOperatorIdMaxByteCount < len(input.TlsBasis.GetOperatorId()) {
			return invalid("an operator id past its bound")
		}
	}

	parsed := input.Parsed
	entry := &protocol.IndexEntry{
		Id:          input.Id.Bytes(),
		Address:     address,
		Time:        MailDepositReceiveTime(deposit, input.PushTimeMillis),
		From:        mailCleanLine(parsed.From, mailIndexFromMaxByteCount),
		Subject:     mailCleanLine(parsed.Subject, mailIndexSubjectMaxByteCount),
		Snippet:     mailCleanLine(parsed.Snippet, mailIndexSnippetMaxByteCount),
		ThreadKey:   parsed.ThreadKey(input.Id),
		Size:        input.ByteCount,
		Attachments: []*protocol.MailAttachment{},
		TlsLabel:    input.TlsLabel,
		TlsBasis:    proto.CloneOf(input.TlsBasis),
		SpamScore:   min(input.SpamScore, mailSpamScoreMax),
	}
	// a cut id or code would match nothing, so one past its bound is left out
	if messageId := mailCleanLine(parsed.MessageId, math.MaxInt); len(messageId) <= mailIndexMessageIdMaxByteCount {
		entry.MessageId = messageId
	}
	if code := mailCleanLine(input.OneTimeCode, math.MaxInt); len(code) <= mailIndexOneTimeCodeMaxByteCount {
		entry.OneTimeCode = code
	}
	for _, attachment := range parsed.Attachments {
		if mailIndexAttachmentMaxCount <= len(entry.Attachments) {
			break
		}
		entry.Attachments = append(entry.Attachments, &protocol.MailAttachment{
			Name: mailCleanLine(attachment.GetName(), mailIndexAttachmentNameMaxByteCount),
			Type: mailCleanLine(attachment.GetType(), mailIndexAttachmentTypeMaxByteCount),
			Size: attachment.GetSize(),
		})
	}
	if receiver {
		entry.AuthResults = mailAuthResults(evidence)
	}
	return entry, nil
}
