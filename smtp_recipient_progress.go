//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Encodes domain outcomes with their private recipient progress for the encrypted mailbox. A writer
// retrying a compare-and-swap merges completed recipients from the most recently committed version.
func SmtpMailboxOutcomeRecord(outcomes []*SmtpDomainOutcome, standing *protocol.MailOutcomeRecord) (*protocol.MailOutcomeRecord, error) {
	record := proto.CloneOf(standing)
	if record == nil {
		record = &protocol.MailOutcomeRecord{}
	}
	record.Outcomes, record.RecipientProgress = nil, nil
	if len(record.SendId) != len(Id{}) {
		record.SendId = nil
	}
	progressByDomain, err := smtpProgressByDomain(standing)
	if err != nil {
		return nil, err
	}
	previous := make(map[string]*protocol.MailOutcome, len(standing.GetOutcomes()))
	for _, outcome := range standing.GetOutcomes() {
		previous[outcome.GetDomain()] = outcome
	}
	for _, outcome := range outcomes {
		if outcome == nil {
			return nil, ErrMailOutboxFileInvalid
		}
		public, err := outcome.MailOutcome()
		if err != nil {
			return nil, err
		}
		domain := outcome.Domain
		if prior := previous[domain]; prior != nil {
			public.ProtoReflect().SetUnknown(bytes.Clone(prior.ProtoReflect().GetUnknown()))
		}
		// A stale heartbeat cannot reopen a completed domain. A too_large outcome may be reassigned
		// to another host whose measured DATA cap fits.
		switch previous[domain].GetOutcome() {
		case protocol.MailOutcomeKind_MAIL_OUTCOME_SENT:
			if public.GetOutcome() != protocol.MailOutcomeKind_MAIL_OUTCOME_SENT {
				public = proto.CloneOf(previous[domain])
			}
		case protocol.MailOutcomeKind_MAIL_OUTCOME_REFUSED, protocol.MailOutcomeKind_MAIL_OUTCOME_FAILED, protocol.MailOutcomeKind_MAIL_OUTCOME_TLS_REFUSED:
			switch public.GetOutcome() {
			case protocol.MailOutcomeKind_MAIL_OUTCOME_QUEUED, protocol.MailOutcomeKind_MAIL_OUTCOME_DEFERRED, protocol.MailOutcomeKind_MAIL_OUTCOME_TOO_LARGE:
				public = proto.CloneOf(previous[domain])
			}
		}
		record.Outcomes = append(record.Outcomes, public)
		switch public.GetOutcome() {
		case protocol.MailOutcomeKind_MAIL_OUTCOME_QUEUED, protocol.MailOutcomeKind_MAIL_OUTCOME_DEFERRED, protocol.MailOutcomeKind_MAIL_OUTCOME_TOO_LARGE:
			progress, err := smtpMergeRecipientProgress(progressByDomain[domain], outcome.progress)
			if err != nil {
				return nil, err
			}
			if len(progress.GetDelivered())+len(progress.GetRefused()) > 0 {
				record.RecipientProgress = append(record.RecipientProgress, progress)
			}
		}
	}
	return record, nil
}

// Monotone merge of two attempts over the same immutable envelope. Confirmed message delivery wins
// if a concurrent attempt also observed a permanent refusal from a different MX.
func smtpMergeRecipientProgress(earlier, current *protocol.MailRecipientProgress) (*protocol.MailRecipientProgress, error) {
	if earlier == nil {
		return proto.CloneOf(current), nil
	}
	if current == nil {
		return proto.CloneOf(earlier), nil
	}
	if earlier.Domain != current.Domain || !bytes.Equal(earlier.EnvelopeSha256, current.EnvelopeSha256) {
		return nil, ErrMailOutboxFileInvalid
	}
	merge := func(a, b []uint32) []uint32 {
		all := append(slices.Clone(a), b...)
		slices.Sort(all)
		return slices.Compact(all)
	}
	delivered := merge(earlier.Delivered, current.Delivered)
	refused := merge(earlier.Refused, current.Refused)
	refused = slices.DeleteFunc(refused, func(i uint32) bool {
		_, delivered := slices.BinarySearch(delivered, i)
		return delivered
	})
	combined := proto.CloneOf(earlier)
	combined.Delivered, combined.Refused = delivered, refused
	return combined, nil
}

// Indexes progress by recipient domain, rejecting empty or duplicate domains and wrong-length envelope digests.
func smtpProgressByDomain(record *protocol.MailOutcomeRecord) (map[string]*protocol.MailRecipientProgress, error) {
	progress := make(map[string]*protocol.MailRecipientProgress, len(record.GetRecipientProgress()))
	for _, row := range record.GetRecipientProgress() {
		domain := row.GetDomain()
		if domain == "" || len(row.GetEnvelopeSha256()) != sha256.Size || progress[domain] != nil {
			return nil, ErrMailOutboxFileInvalid
		}
		progress[domain] = row
	}
	return progress, nil
}

// Reads both generations of mailbox records. Public SendResult conversions use MailOutcome alone.
func SmtpMailboxOutcomes(record *protocol.MailOutcomeRecord) ([]*SmtpDomainOutcome, error) {
	progressByDomain, err := smtpProgressByDomain(record)
	if err != nil {
		return nil, err
	}
	outcomes := make([]*SmtpDomainOutcome, 0, len(record.GetOutcomes()))
	for _, public := range record.GetOutcomes() {
		outcome, err := SmtpDomainOutcomeFromMailOutcome(public)
		if err != nil {
			return nil, err
		}
		outcome.progress = proto.CloneOf(progressByDomain[outcome.Domain])
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

// Recipient ordinals are private to the encrypted mailbox. They refer to the sender's stable
// first-occurrence order for this domain in the signed outbox envelope.
type smtpRecipientProgress struct {
	record   *protocol.MailRecipientProgress
	ordinal  map[string]uint32
	finished map[uint32]bool
}

// Verifies saved ordinals before they can suppress a recipient from the current envelope.
func newSmtpRecipientProgress(envelopeHash [sha256.Size]byte, domain *smtpDomainPlan, saved *protocol.MailRecipientProgress) (*smtpRecipientProgress, error) {
	hash := sha256.New()
	field := func(data []byte) {
		hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(data))))
		hash.Write(data)
	}
	field(envelopeHash[:])
	field([]byte(domain.domain))
	progress := &smtpRecipientProgress{ordinal: make(map[string]uint32, len(domain.recipients)), finished: map[uint32]bool{}}
	for i, recipient := range domain.recipients {
		field([]byte(recipient))
		progress.ordinal[recipient] = uint32(i)
	}
	digest := hash.Sum(nil)
	if saved == nil {
		progress.record = &protocol.MailRecipientProgress{Domain: domain.domain, EnvelopeSha256: digest}
		return progress, nil
	}
	if saved.Domain != domain.domain || !bytes.Equal(digest, saved.EnvelopeSha256) {
		return nil, ErrMailOutboxFileInvalid
	}
	progress.record = proto.CloneOf(saved)
	for _, group := range [][]uint32{saved.Delivered, saved.Refused} {
		for _, ordinal := range group {
			if uint64(ordinal) >= uint64(len(domain.recipients)) || progress.finished[ordinal] {
				return nil, ErrMailOutboxFileInvalid
			}
			progress.finished[ordinal] = true
		}
	}
	return progress, nil
}

// Every address that still needs delivery, in envelope order.
func (self *smtpRecipientProgress) remaining(recipients []string) []string {
	var remaining []string
	for _, recipient := range recipients {
		if !self.finished[self.ordinal[recipient]] {
			remaining = append(remaining, recipient)
		}
	}
	return remaining
}

// Records message acceptance or a final per-recipient refusal.
func (self *smtpRecipientProgress) finish(recipient string, delivered bool) {
	i := self.ordinal[recipient]
	if self.finished[i] {
		return
	}
	self.finished[i] = true
	if delivered {
		self.record.Delivered = append(self.record.Delivered, i)
	} else {
		self.record.Refused = append(self.record.Refused, i)
	}
}
