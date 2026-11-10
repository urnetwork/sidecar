//go:build !ios_extension

// Owner decision 135's labels (§15.5's Labels; R-MAIL-16, D-MAIL-13, D-MAIL-14, I-11, FS-39, FS-121; MAIL-M7-10):
// MailLabelDecide labels a deposited message from its sealed trailer alone, never from later DNS, a pure function on
// every leg, so every device that ingests a deposit labels it alike.
//
//	validated      MAIL carried REQUIRETLS (RFC 8689); or the SNI host's TLSA held the receiver's key, in our signed
//	               zone or in strict mode the customer's (sni_tlsa_live), and the sender is a listed operator, matched
//	               by the receiver's own forward-confirmed PTR of sender_ip at or under one of its PTR suffixes, or by
//	               a passing DKIM signature whose d= and From's domain both fall at or under one of its DKIM domains
//	opportunistic  anything else; and a receiver's deposit whose evidence is missing, of a version this format does
//	               not have, another receiver's, or of other bytes than the message's, marked "evidence unavailable"
//	member-signed  a same-network deposit whose push signer may send as its From (D-MAIL-8), which ingest checks;
//	               any other same-network deposit is opportunistic, evidence unavailable (MAIL-FORMAT.md)
//
// A listed DKIM domain is an organizational domain, so a d= and a From domain both at or under it align under DMARC's
// relaxed rule: that needs no public suffix list, so every leg decides alike, and it only ever narrows relaxed
// alignment. An incomplete check is no result: only a DKIM entry that passed, a PTR the receiver confirmed and a TLSA
// it saw count, so limits can only weaken a label, and ChecksIncomplete marks one decided under it. tls_basis keeps the
// rule, the operator and the list version for rechecks, and strict_custom_mx only from a sealed strict_chain.
// REQUIRETLS is the rule wherever MAIL carried it, being the only exact mark.
//
// The stated basis never claims path confidentiality: the list is an operator-reputation inference, not proof of a
// DANE or MTA-STS path, and REQUIRETLS records only the final hop's requirement (RFC 8689 §8.3). It cites the operator's
// published DANE enforcement where it publishes one, and its MTA-STS enforcement only where the recipient's domain
// publishes an MTA-STS policy, which no burner domain does and no network does before M8 (§15.5), else the listing
// alone; an operator listed only for MTA-STS still makes burner mail validated (owner decision 135). MailLabelRecheck
// shows a later check apart, and never changes a label (D-MAIL-14).
//
// No connect, go-smtp or mox: on every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// How a label's operator was matched.
type MailLabelMatch int

const (
	MailLabelMatchNone MailLabelMatch = iota
	// The receiver's forward-confirmed PTR at or under one of its PTR suffixes.
	MailLabelMatchPtr
	// A passing DKIM signature whose d= and From's domain fall under one of its DKIM domains.
	MailLabelMatchDkim
)

// What MailLabelDecide reads: the deposit's sealed trailer, and what ingest knows of the message and its recipients.
type MailLabelInput struct {
	// The deposit's sealed trailer.
	Deposit *protocol.MailDeposit
	// The SHA-256 ingest took of the message's bytes as received, which a receiver's evidence must name.
	MessageSha256 []byte
	// The From domain of the message's first From field, as MailParsed.FromDomain gives it, or empty.
	FromDomain string
	// The user root the deposit's recipients are under, which tells a burner's from the rest; a recipient that does
	// not parse under it counts as a burner's, which only narrows what the basis cites.
	Root string
	// The recipient's domain publishes an MTA-STS policy (§15.5's MTA-STS, from M8 on verified networks). False cites
	// no operator's MTA-STS enforcement, as for a burner's domain, which publishes none.
	RecipientMtaSts bool
	// A same-network deposit's push signer may send as the message's From (mail:<alias>#send, §15.10), which ingest
	// checks. Read on a same-network deposit only.
	SignerMaySendAsFrom bool
	// The list decided against; nil takes the embedded one.
	Operators *MailOperatorList
}

// A label and what it rests on.
type MailLabelResult struct {
	Label protocol.MailTlsLabel
	// tls_basis, as ingest writes it, or nil where no receiver's evidence decided the label.
	Basis *protocol.MailTlsBasis
	// The operator the label rests on, from the list decided against, or nil.
	Operator *MailOperator
	// How the operator was matched.
	MatchedBy MailLabelMatch
	// The deposit's evidence was missing or unusable: "evidence unavailable".
	EvidenceUnavailable bool
	// A bound cut the reception-time checks: "checks incomplete".
	ChecksIncomplete bool
	// What the stated basis cites of the operator's published enforcement.
	CitesDane   bool
	CitesMtaSts bool
}

// Whether any recipient is a burner's, or does not parse under root.
func mailLabelBurner(recipients []string, root string) bool {
	for _, recipient := range recipients {
		parsed, err := ParseMailRecipient(root, recipient)
		if err != nil || parsed.Kind == MailAddressKindBurner || parsed.Kind == MailAddressKindReverseAlias {
			return true
		}
	}
	return len(recipients) == 0
}

// The operator evidence matches, and how: the first in list order, by its PTR suffixes, then its DKIM domains.
func mailLabelOperator(list *MailOperatorList, evidence *protocol.MailAuthEvidence, fromDomain string) (*MailOperator, MailLabelMatch) {
	ptrName := dnsAsciiLower(strings.TrimSuffix(evidence.GetPtrName(), "."))
	fromDomain = dnsAsciiLower(fromDomain)
	for _, operator := range list.Operators {
		if ptrName != "" {
			for _, suffix := range operator.PtrSuffixes {
				if mailNameUnder(ptrName, suffix) {
					return operator, MailLabelMatchPtr
				}
			}
		}
		if fromDomain == "" {
			continue
		}
		for _, entry := range evidence.GetDkim() {
			if entry.GetResult() != protocol.DkimVerdict_DKIM_PASS {
				continue
			}
			domain := dnsAsciiLower(entry.GetDomain())
			for _, listed := range operator.DkimDomains {
				if mailNameUnder(domain, listed) && mailNameUnder(fromDomain, listed) {
					return operator, MailLabelMatchDkim
				}
			}
		}
	}
	return nil, MailLabelMatchNone
}

// The label of a deposited message, from its sealed trailer. See the file header.
func MailLabelDecide(input *MailLabelInput) *MailLabelResult {
	unavailable := &MailLabelResult{Label: protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC, EvidenceUnavailable: true}
	deposit := input.Deposit
	if deposit == nil || deposit.GetVersion() != mailFormatVersion {
		return unavailable
	}
	if !mailReceiverDeposit(deposit) {
		if input.SignerMaySendAsFrom {
			return &MailLabelResult{Label: protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED}
		}
		return unavailable
	}
	evidence := deposit.GetEvidence()
	if evidence == nil || evidence.GetVersion() != mailFormatVersion ||
		!bytes.Equal(evidence.GetReceiverSidecarId(), deposit.GetReceiverSidecarId()) ||
		len(input.MessageSha256) != sha256.Size || !bytes.Equal(evidence.GetMessageSha256(), input.MessageSha256) {
		return unavailable
	}
	list := input.Operators
	if list == nil {
		list = mailOperatorListEmbedded
	}
	result := &MailLabelResult{
		Label:            protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC,
		Basis:            &protocol.MailTlsBasis{ListVersion: list.Version, StrictCustomMx: evidence.GetStrictChain()},
		ChecksIncomplete: evidence.GetLimits() != nil,
	}
	switch {
	case deposit.GetRequireTls():
		result.Label = protocol.MailTlsLabel_MAIL_TLS_VALIDATED
		result.Basis.Rule = protocol.MailTlsRule_MAIL_TLS_RULE_REQUIRETLS
	case evidence.GetSniTlsaLive():
		operator, matchedBy := mailLabelOperator(list, evidence, input.FromDomain)
		if operator == nil {
			break
		}
		result.Label = protocol.MailTlsLabel_MAIL_TLS_VALIDATED
		result.Basis.Rule = protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR
		result.Basis.OperatorId = operator.Id
		result.Operator = operator.clone()
		result.MatchedBy = matchedBy
		burner := mailLabelBurner(deposit.GetRecipients(), input.Root)
		result.CitesDane = operator.DaneSource != ""
		result.CitesMtaSts = operator.MtaStsSource != "" && !burner && input.RecipientMtaSts
	}
	return result
}

// A stored label as Read states it (MAIL-M7-17): entry's label, basis and auth results, with the operator its basis
// names looked up in list, nil taking the embedded one. A list of another version than the basis's names the operator
// but cites none of its enforcement, which that version may not have listed. burner and recipientMtaSts are as
// MailLabelInput's for the entry's address.
func MailLabelOfEntry(entry *protocol.IndexEntry, list *MailOperatorList, burner bool, recipientMtaSts bool) *MailLabelResult {
	if list == nil {
		list = mailOperatorListEmbedded
	}
	result := &MailLabelResult{
		Label:               entry.GetTlsLabel(),
		Basis:               proto.CloneOf(entry.GetTlsBasis()),
		EvidenceUnavailable: entry.GetAuthResults().GetEvidenceUnavailable(),
		ChecksIncomplete:    entry.GetAuthResults().GetChecksIncomplete(),
	}
	if result.Label != protocol.MailTlsLabel_MAIL_TLS_VALIDATED || result.Basis.GetRule() != protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR {
		return result
	}
	if operator := list.Operator(result.Basis.GetOperatorId()); operator != nil {
		result.Operator = operator.clone()
		if list.Version == result.Basis.GetListVersion() {
			result.CitesDane = operator.DaneSource != ""
			result.CitesMtaSts = operator.MtaStsSource != "" && !burner && recipientMtaSts
		}
	}
	return result
}

// The label's name as a person reads it.
func mailLabelName(label protocol.MailTlsLabel) string {
	switch label {
	case protocol.MailTlsLabel_MAIL_TLS_VALIDATED:
		return "validated"
	case protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC:
		return "opportunistic"
	case protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED:
		return "member-signed"
	}
	return "no label"
}

// The words the UI and API state beside the label (§15.5): its basis, never a claim of path confidentiality, and
// "checks incomplete" or "evidence unavailable" where they hold.
func (self *MailLabelResult) Statement() string {
	var statement string
	switch self.Label {
	case protocol.MailTlsLabel_MAIL_TLS_VALIDATED:
		switch self.Basis.GetRule() {
		case protocol.MailTlsRule_MAIL_TLS_RULE_REQUIRETLS:
			statement = "Validated: the server that delivered this message required TLS for that hop (REQUIRETLS, RFC 8689). " +
				"That records only the final hop's requirement, not who could read the message before it, URnetwork included."
		default:
			name := self.Basis.GetOperatorId()
			if self.Operator != nil {
				name = self.Operator.Name
			}
			cites := ""
			switch {
			case self.CitesDane && self.CitesMtaSts:
				cites = ", which publishes its DANE and MTA-STS enforcement"
			case self.CitesDane:
				cites = ", which publishes its DANE enforcement"
			case self.CitesMtaSts:
				cites = ", which publishes its MTA-STS enforcement"
			}
			statement = fmt.Sprintf("Validated: sent by %s, an operator on URnetwork's list (version %d)%s, "+
				"while the receiving host's TLSA record held this receiver's key. "+
				"This is an inference from the operator's listing, not proof of how the message travelled.",
				name, self.Basis.GetListVersion(), cites)
		}
	case protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC:
		if self.EvidenceUnavailable {
			statement = "Opportunistic: evidence unavailable. No reception-time checks were sealed for this message, " +
				"so it could have been read in transit, URnetwork included."
		} else {
			statement = "Opportunistic: nothing at reception showed that the sender required TLS or checked this receiver's key, " +
				"so the message could have been read in transit, URnetwork included."
		}
	case protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED:
		statement = "From a member: a device of this network signed this message, and that signature stands in for a TLS label."
	default:
		statement = "No label: no reception decided one for this message."
	}
	if self.ChecksIncomplete {
		statement += " Checks incomplete: a bound cut some reception-time checks, and nothing cut counts toward this label."
	}
	if self.Basis.GetStrictCustomMx() {
		statement += " URnetwork could not redirect a DANE-validating sender's mail for this domain; " +
			"that does not show this sender validated."
	}
	return statement
}

// A later check beside a stored label (D-MAIL-14): what deciding again finds, against a newer list or with later
// evidence, shown apart from the label, which reception decided and which this never changes.
type MailLabelRecheckResult struct {
	// The stored label and basis, as given.
	Label protocol.MailTlsLabel
	Basis *protocol.MailTlsBasis
	// What deciding again found.
	Later *MailLabelResult
	// Whether that differs from the stored label, rule, operator or strict claim.
	Differs bool
}

// The stored label and basis beside a decision on later, both kept as they are: the stored ones copied, never
// rewritten.
func MailLabelRecheck(label protocol.MailTlsLabel, basis *protocol.MailTlsBasis, later *MailLabelInput) *MailLabelRecheckResult {
	result := &MailLabelRecheckResult{Label: label, Basis: proto.CloneOf(basis), Later: MailLabelDecide(later)}
	laterBasis := result.Later.Basis
	result.Differs = result.Later.Label != label || laterBasis.GetRule() != basis.GetRule() ||
		laterBasis.GetOperatorId() != basis.GetOperatorId() || laterBasis.GetStrictCustomMx() != basis.GetStrictCustomMx()
	return result
}

// The words shown apart from the label's own.
func (self *MailLabelRecheckResult) Statement() string {
	against := "a later check"
	if self.Later.Basis != nil {
		against = fmt.Sprintf("a later check against operator list version %d", self.Later.Basis.GetListVersion())
	}
	if !self.Differs {
		return fmt.Sprintf("Rechecked: %s agrees with the label above.", against)
	}
	return fmt.Sprintf("Rechecked: %s would label this message %s. The label above is the one decided at reception, and it stands.",
		against, mailLabelName(self.Later.Label))
}
