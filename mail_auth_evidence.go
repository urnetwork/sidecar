//go:build !sidecar_http && !js && !ios_extension

// §15.5's evidence row (R-MAIL-16, D-MAIL-14, I-11, FS-121; MAIL-M7-09): MailEvidenceBuilder assembles the
// MailAuthEvidence a receiver seals in each deposit's trailer, bound to the message's hash, its receive time and this
// receiver, at most 8,192 bytes whatever the identifiers. Past the bound, keys and records drop first, the last
// selected first, then whole dkim and arc entries from the end of the selection order, each entry counted in
// limits.dropped, and any drop sets limits' count bit, so the evidence says a bound cut it. The selection order is
// §15.5's dns row's: DMARC's record and the aligned DKIM keys, SPF, the other keys, then ARC's, the newest set first.
// So the drops run:
//
//	keys     each ARC set's key, the oldest set first; the unaligned signatures' keys, the last selected first;
//	         SPF's records; the aligned signatures' keys, the last selected first
//	entries  each ARC set, the oldest first; each DKIM entry, the last selected first
//
// What stays when all of those are gone is under 1 KiB: the verdicts, DMARC's three tags, SPF's domain and the PTR
// name, which this holds to a DNS name's 253 bytes, the hash, the ids, the times and the counts. A drop weakens what
// a reader can recheck, never a verdict a label rests on: a dropped DKIM entry counts for no operator, and DMARC's
// verdict, judged before the drop, stands as sealed. A string that is not valid UTF-8, which marshaling refuses, is
// left out (MAIL-FORMAT.md); the checks' own values are ASCII, so none should be.
//
// Off sidecar_http and js, with the checks. Safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §15.5's bound on MailAuthEvidence's encoding. A format value.
const MailAuthEvidenceMaxByteCount = 8 * 1024

// Evidence that cannot be built: no checks, or no message hash. The receiver then deposits without it, which readers
// label opportunistic, "evidence unavailable", so a failure here only ever weakens a label.
var ErrMailEvidenceInvalid = errors.New("mail evidence invalid")

// A receiver's evidence builder. Safe for concurrent use.
type MailEvidenceBuilder struct {
	// The receiver every evidence names, which ingest holds to the deposit push's signer.
	receiverSidecarId Id
}

// A builder for the receiver receiverSidecarId.
func NewMailEvidenceBuilder(receiverSidecarId Id) *MailEvidenceBuilder {
	return &MailEvidenceBuilder{receiverSidecarId: receiverSidecarId}
}

// What one message's evidence is built from.
type MailEvidenceInput struct {
	// The SHA-256 of the message's bytes as received, before ingest adds any header.
	MessageSha256 []byte
	// When this receiver took the message's last byte, ms since the epoch.
	ReceiveTimeMillis uint64
	// mail.strict's claim (§15.5): SNI named a custom MX host, and this receiver's zone watch holds every recipient
	// domain's MX hosts and that host's TLSA, with this key, customer-signed. False until MAIL-M7-24 and the answer
	// to plan-MAIL-dnssec-evidence, so no mail carries strict_custom_mx meanwhile.
	StrictChain bool
	// What the checks found.
	Outcome *MailAuthOutcome
}

// The message's evidence, at most MailAuthEvidenceMaxByteCount bytes. The outcome is copied, never changed.
func (self *MailEvidenceBuilder) Build(input *MailEvidenceInput) (*protocol.MailAuthEvidence, error) {
	if input == nil || input.Outcome == nil {
		return nil, fmt.Errorf("%w: no checks", ErrMailEvidenceInvalid)
	}
	if len(input.MessageSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: no message hash", ErrMailEvidenceInvalid)
	}
	outcome := input.Outcome
	evidence := &protocol.MailAuthEvidence{
		Version:           mailFormatVersion,
		MessageSha256:     slices.Clone(input.MessageSha256),
		ReceiveTimeMillis: input.ReceiveTimeMillis,
		ReceiverSidecarId: self.receiverSidecarId.Bytes(),
		Spf:               proto.CloneOf(outcome.Spf),
		Dmarc:             proto.CloneOf(outcome.Dmarc),
		PtrName:           outcome.PtrName,
		SniTlsaLive:       outcome.SniTlsaLive,
		Arc:               proto.CloneOf(outcome.Arc),
		StrictChain:       input.StrictChain,
		Limits:            proto.CloneOf(outcome.Limits),
	}
	if evidence.Arc == nil {
		evidence.Arc = &protocol.ArcResult{Cv: protocol.ArcVerdict_ARC_NONE}
	}
	for _, entry := range outcome.Dkim {
		evidence.Dkim = append(evidence.Dkim, proto.CloneOf(entry))
	}
	mailEvidenceClean(evidence)

	if proto.Size(evidence) <= MailAuthEvidenceMaxByteCount {
		return evidence, nil
	}
	// the evidence bound cut it: limits says so, with the checks' counts
	if evidence.Limits == nil {
		evidence.Limits = proto.CloneOf(outcome.Counts)
		if evidence.Limits == nil {
			evidence.Limits = &protocol.AuthLimits{}
		}
	}
	evidence.Limits.Reason |= MailAuthLimitCount
	alignedCount := min(max(0, outcome.DkimAlignedCount), len(evidence.Dkim))
	fits := func() bool {
		return proto.Size(evidence) <= MailAuthEvidenceMaxByteCount
	}
	dropKey := func(key *[]byte) bool {
		*key = nil
		return fits()
	}
	sets := evidence.Arc.Sets
	for index := len(sets) - 1; 0 <= index; index -= 1 {
		if dropKey(&sets[index].PublicKey) {
			return evidence, nil
		}
	}
	for index := len(evidence.Dkim) - 1; alignedCount <= index; index -= 1 {
		if dropKey(&evidence.Dkim[index].PublicKey) {
			return evidence, nil
		}
	}
	if evidence.Spf != nil {
		evidence.Spf.Records = nil
		if fits() {
			return evidence, nil
		}
	}
	for index := alignedCount - 1; 0 <= index; index -= 1 {
		if dropKey(&evidence.Dkim[index].PublicKey) {
			return evidence, nil
		}
	}
	for 0 < len(evidence.Arc.Sets) {
		evidence.Arc.Sets = evidence.Arc.Sets[:len(evidence.Arc.Sets)-1]
		evidence.Limits.Dropped += 1
		if fits() {
			return evidence, nil
		}
	}
	for 0 < len(evidence.Dkim) {
		evidence.Dkim = evidence.Dkim[:len(evidence.Dkim)-1]
		evidence.Limits.Dropped += 1
		if fits() {
			return evidence, nil
		}
	}
	// unreachable while mailEvidenceClean holds the names to a DNS name's length: refused, so the deposit goes
	// without evidence rather than past the bound
	return nil, fmt.Errorf("%w: past %d bytes with every entry dropped", ErrMailEvidenceInvalid, MailAuthEvidenceMaxByteCount)
}

// Leaves out what marshaling would refuse or no DNS name holds: a string that is not valid UTF-8, a domain or PTR
// name past 253 bytes, which was never looked up, so its verdict stands without it.
func mailEvidenceClean(evidence *protocol.MailAuthEvidence) {
	name := func(value string) string {
		if !utf8.ValidString(value) || dnsDomainMaxByteCount < len(value) {
			return ""
		}
		return value
	}
	text := func(value string) string {
		if !utf8.ValidString(value) {
			return ""
		}
		return value
	}
	evidence.PtrName = name(evidence.PtrName)
	if spf := evidence.Spf; spf != nil {
		spf.Domain = name(spf.Domain)
		spf.Records = slices.DeleteFunc(spf.Records, func(record string) bool { return !utf8.ValidString(record) })
	}
	if dmarc := evidence.Dmarc; dmarc != nil {
		dmarc.P, dmarc.Adkim, dmarc.Aspf = text(dmarc.P), text(dmarc.Adkim), text(dmarc.Aspf)
	}
	for _, entry := range evidence.Dkim {
		entry.Domain, entry.Selector = text(entry.Domain), text(entry.Selector)
	}
	for _, set := range evidence.Arc.GetSets() {
		set.Domain, set.Selector = text(set.Domain), text(set.Selector)
	}
}
