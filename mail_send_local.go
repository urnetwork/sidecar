//go:build !ios_extension

// §15.8's same-network mail, its deposit half (R-MAIL-5, D-MAIL-8, I-5, I-8, X7; MAIL-M7-18): a message to an address
// of this network goes to the recipient's repo as a deposit, sealed to that repo's drop key and signed by the sending
// device's identity key in its push (§6.9), with no smtpedge, no send quota and no DKIM. That signature stands in for a
// TLS label: ingest shows "from a member" where the push's signer may send as the message's From (MAIL-M7-15's
// MaySendAs, the same rule Send's From check runs), and anything else as outside mail.
//
//	trailer   message ‖ MailDeposit ‖ u32be(its length), as a receiver's deposit is (MAIL-FORMAT.md), but setting only
//	          version, mail_from and this repo's recipients: no MailIngress, no evidence, no receiver, since the
//	          deposit crossed no edge (MailSameNetworkDeposit)
//	targets   one deposit a repo: a member's mailbox, or a group's repo, which fans the message out to its members
//	          once (§15.7's group mail), each repo's trailer naming only its own recipients, so a Bcc stays unseen
//	members   §8.5 and §8.8 give a device no deposit right in another member's mailbox, so a deposit between different
//	          members refuses closed (plan-MAIL-member-deposit's interim; QD-136's mail_send deposit cell is not in
//	          §8.5's rows yet): within one member, a one-member network and an agent's sponsor all work. Beside that
//	          rule every target must give the sender deposit or write at the installed state (I-5), as evs's own gate
//	          will
//
// Nothing here logs an address, a label or a byte of a message (I-13). On every leg but the extension's.

package sidecar

import (
	"bytes"
	"context"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A same-network deposit's plaintext: the message, then its trailer naming mailFrom and this repo's recipients only,
// then the trailer's length (MAIL-FORMAT.md's same-network deposit).
func MailSameNetworkDeposit(message []byte, mailFrom string, recipients []string) ([]byte, error) {
	return MailDepositPlaintext(message, &protocol.MailDeposit{
		Version:    mailFormatVersion,
		MailFrom:   []byte(mailFrom),
		Recipients: append([]string(nil), recipients...),
	})
}

// What a same-network send asks of §8's verified state. Implementations are safe for concurrent use.
type MailSendAuthority interface {
	// Whether senderSidecarId may send as fromAddress, an address of this network (mail:<alias>#send, §15.10 step 1):
	// the rule ingest holds a same-network deposit's signer to (MailIngestAuthority.MaySendAs).
	MaySendAs(senderSidecarId Id, fromAddress string) bool
	// What a deposit by senderSidecarId into repoId comes to: MailSendDelivered where it may deposit there, else the
	// refusal's outcome. See the file header's members row.
	MayDeposit(senderSidecarId Id, repoId Id) MailSendOutcome
	// Whether senderSidecarId writes repoId, its own member's mailbox, where a sent copy goes.
	Writes(senderSidecarId Id, repoId Id) bool
}

// MailSendAuthority over the installed AclEngine.
type MailSendAclAuthority struct {
	Engine *AclEngine
	// The user root the network's addresses are under.
	Root string
	// Whether a zone is this network's own; nil refuses every From.
	OwnZone func(zone MailZone) bool
	// Nil is real time.
	Clock Clock
}

// The rule ingest holds the deposit's signer to, so the two ends agree.
func (self *MailSendAclAuthority) MaySendAs(senderSidecarId Id, fromAddress string) bool {
	if self == nil {
		return false
	}
	ingest := &MailIngestAclAuthority{Engine: self.Engine, Root: self.Root, OwnZone: self.OwnZone, Clock: self.Clock}
	return ingest.MaySendAs(senderSidecarId, fromAddress)
}

// See MailSendAuthority and the file header's members row.
func (self *MailSendAclAuthority) MayDeposit(senderSidecarId Id, repoId Id) MailSendOutcome {
	if self == nil || self.Engine == nil {
		return MailSendNoDepositRight
	}
	state := self.Engine.State()
	if state == nil {
		return MailSendNoDepositRight
	}
	return mailSendMayDeposit(state, senderSidecarId, repoId, clockOrReal(self.Clock).Now())
}

// See MailSendAuthority.
func (self *MailSendAclAuthority) Writes(senderSidecarId Id, repoId Id) bool {
	if self == nil || self.Engine == nil {
		return false
	}
	state := self.Engine.State()
	if state == nil {
		return false
	}
	rights := state.EvsAccess(AclSidecarSubject(senderSidecarId), repoId, AclTokenAudienceEvs, clockOrReal(self.Clock).Now()).Rights
	return rights.Has(AclEvsWrite)
}

// The member a sending device acts for: an untagged device's own, a tagged one's sponsor. False for one the state does
// not hold or a tagged device no member sponsors.
func mailSendMemberOf(state *AclState, senderSidecarId Id) (Id, bool) {
	sender := state.sidecarState(senderSidecarId)
	switch {
	case sender == nil || !sender.valid || sender.revoked:
		return Id{}, false
	case !sender.tagged:
		return sender.memberId, true
	case sender.hasOwner:
		return sender.owner, true
	}
	return Id{}, false
}

// What a deposit by the sender into the repo comes to at state (the file header's members row).
func mailSendMayDeposit(state *AclState, senderSidecarId Id, repoId Id, now time.Time) MailSendOutcome {
	repo := state.Repo(repoId)
	if repo == nil {
		return MailSendNoDepositRight
	}
	switch repo.GetKind() {
	case protocol.RepoKind_REPO_KIND_MAILBOX:
		ownerMemberId, err := IdFromBytes(repo.GetOwnerMemberId())
		senderMemberId, ok := mailSendMemberOf(state, senderSidecarId)
		if err != nil || !ok || ownerMemberId != senderMemberId {
			// another member's mailbox: no deposit right until QD-136's cell is in §8.5's rows
			return MailSendMemberRefused
		}
	case protocol.RepoKind_REPO_KIND_GENERAL:
		// a group's repo, which its members deposit to through their own access
	default:
		return MailSendNoDepositRight
	}
	rights := state.EvsAccess(AclSidecarSubject(senderSidecarId), repoId, AclTokenAudienceEvs, now).Rights
	if !rights.Has(AclEvsDeposit) && !rights.Has(AclEvsWrite) {
		return MailSendNoDepositRight
	}
	return MailSendDelivered
}

// One repo's recipients of a send, in the order first named.
type mailSendTarget struct {
	repoId     Id
	recipients []string
}

// Deposits message to each target's repo, one deposit a repo naming its own recipients only, in order: each target's
// outcome, delivered or failed. A failure stops nothing: the rest are still tried, and the caller sends the failed
// ones again.
func mailSendDeposit(ctx context.Context, repo func(repoId Id) mailDepositRepo, message []byte, mailFrom string, targets []*mailSendTarget) []MailSendOutcome {
	outcomes := make([]MailSendOutcome, len(targets))
	for index, target := range targets {
		outcomes[index] = MailSendFailed
		depositRepo := repo(target.repoId)
		if depositRepo == nil {
			continue
		}
		plaintext, err := MailSameNetworkDeposit(message, mailFrom, target.recipients)
		if err != nil {
			continue
		}
		key := target.repoId.String()
		testHookBarrier("mail.send.deposit.before", key)
		_, err = depositRepo.Deposit(ctx, &EvsDepositArgs{Body: bytes.NewReader(plaintext), Size: int64(len(plaintext))})
		testHookBarrier("mail.send.deposit.after", key)
		if err == nil {
			outcomes[index] = MailSendDelivered
		}
	}
	return outcomes
}
