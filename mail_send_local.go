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
//	rights    every target must give the sender deposit at the installed state (I-5), the one right the exchange mints
//	          repo:<id>:deposit on and evs's gate honors (D-ACL-21), with no rule of mail's own: write alone is none,
//	          a writer depositing only where the repo takes deposits (QD-1173). So a target the exchange would refuse
//	          answers MailSendNoDepositRight here, before any exchange, not failed after it. A mailbox takes it from its
//	          member's consented devices by their write, from that member's other subjects and the agents it sponsors
//	          by §8.5's kind default, and from every other subject of the network the projection marks mail_send, the
//	          same row's cell for same-network mail between members (D-MAIL-8, owner decision 333). A group's repo
//	          takes deposits only where its RepoCreate marks it an inbox, since only a marked general repo's
//	          generations carry a drop key (§8.5, D-KEYS-17), and there from its deposit grant's subjects and its
//	          writers; one not marked takes none, a deposit grant's subject's included, for which the exchange would
//	          mint a scope that no drop key serves. The From check reads the send grants on mail: that mark a sender,
//	          so a device that may send as its From deposits into every member's mailbox as into its own, but where
//	          the receipts row refuses it. A sender no send grant marks holds deposit in no mailbox but its own
//	          member's or sponsor's, and is answered MailSendNoDepositRight at every other one: only a burner's reply
//	          reaches that answer, its From held to the live label rather than to a grant (mail_burner_reply.go), since
//	          the From check refuses any other send of such a sender first
//	receipts  a deposit right that is §16.8's receipt deposit carries no mail, the one a reader of an owner-bound repo
//	          that does not write holds there: ingest leaves such a depositor's ref to the record's receipts
//	          (MailIngestAclAuthority.DepositorClass), so a send into it refuses closed as MailSendNoDepositRight rather
//	          than answering delivered, another member's mailbox an EvsShare lets the sender read among them. A
//	          read_only device holds no deposit but that one (§7.8; QD-1183), so its send refuses alike to a group it
//	          reads, where it holds r alone and evs refuses its deposit, to its own member's mailbox, where it reads as
//	          a consented device, and to another member's, where the mail_send mark gives it nothing
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
	// refusal's outcome. See the file header's rights and receipts rows.
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

// See MailSendAuthority and the file header's rights and receipts rows.
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

// What a deposit by the sender into the repo comes to at state (the file header's rights and receipts rows).
func mailSendMayDeposit(state *AclState, senderSidecarId Id, repoId Id, now time.Time) MailSendOutcome {
	repo := state.Repo(repoId)
	if repo == nil {
		return MailSendNoDepositRight
	}
	switch repo.GetKind() {
	case protocol.RepoKind_REPO_KIND_MAILBOX:
		// any member's, by the deposit EvsAccess gives below: its member's consented devices by their write, that
		// member's other subjects and the agents it sponsors by the kind default, and every other sender by the
		// mail_send mark §8.5's mailbox row reads (owner decision 333)
	case protocol.RepoKind_REPO_KIND_GENERAL:
		// a group's repo, only where its RepoCreate marks it an inbox: no other general repo's generations carry a
		// drop key (§8.5, D-KEYS-17), so no deposit lands there, whoever holds deposit
		if !gkmRepoTakesDeposits(repo) {
			return MailSendNoDepositRight
		}
	default:
		return MailSendNoDepositRight
	}
	rights := state.EvsAccess(AclSidecarSubject(senderSidecarId), repoId, AclTokenAudienceEvs, now).Rights
	switch {
	case !rights.Has(AclEvsDeposit):
		// the right the exchange mints repo:<id>:deposit on (AclExchangeScopes), which write gives only where the repo
		// takes deposits (QD-1173): write alone is no deposit
		return MailSendNoDepositRight
	case aclRepoKindOwnerBound(repo.GetKind()) && rights.Has(AclEvsRead) && !rights.Has(AclEvsWrite):
		// its deposit there is the receipt deposit, which ingest never takes as mail (the file header's receipts row)
		return MailSendNoDepositRight
	}
	return MailSendDelivered
}

// Where one repo's same-network deposit goes: EvsRepo.Deposit, or a test's.
type mailSendDepositRepo interface {
	Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error)
}

// One repo's recipients of a send, in the order first named.
type mailSendTarget struct {
	repoId     Id
	recipients []string
}

// Deposits message to each target's repo, one deposit a repo naming its own recipients only, in order: each target's
// outcome, delivered or failed. A definitive failure permits the next target. An ambiguous reserved deposit must
// be reconciled first, using its saved push.
func (self *MailClient) depositSend(ctx context.Context, repo func(repoId Id) mailSendDepositRepo, message []byte, mailFrom string, targets []*mailSendTarget, checkpointName string, checkpoint *mailSendCheckpoint) ([]MailSendOutcome, error) {
	outcomes := make([]MailSendOutcome, len(targets))
	for index, target := range targets {
		if checkpoint != nil && index < len(checkpoint.Deposits) {
			outcomes[index] = checkpoint.Deposits[index]
			continue
		}
		outcomes[index] = MailSendFailed
		depositRepo := repo(target.repoId)
		plaintext, err := MailSameNetworkDeposit(message, mailFrom, target.recipients)
		if depositRepo != nil && err == nil {
			args := &EvsDepositArgs{Body: bytes.NewReader(plaintext), Size: int64(len(plaintext))}
			if checkpoint != nil {
				args.pending = checkpoint.Pending
				args.prepare = func(request *evsDepositRequest) error {
					checkpoint.Pending = request
					return self.writeSendCheckpoint(checkpointName, checkpoint)
				}
			}
			key := target.repoId.String()
			testHookBarrier("mail.send.deposit.before", key)
			_, err = depositRepo.Deposit(ctx, args)
			if err == nil {
				outcomes[index] = MailSendDelivered
			}
			testHookBarrier("mail.send.deposit.after", key)
		}
		if checkpoint != nil {
			if checkpoint.Pending != nil && outcomes[index] != MailSendDelivered {
				// Its original push may have committed. Receipt recovery must use those same bytes.
				return nil, ErrMailSendUncertain
			}
			checkpoint.Pending = nil
			checkpoint.Deposits = append(checkpoint.Deposits, outcomes[index])
			if err := self.writeSendCheckpoint(checkpointName, checkpoint); err != nil {
				return nil, err
			}
		}
	}
	return outcomes, nil
}
