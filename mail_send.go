//go:build !ios_extension

// MailClient.Send (§15.10's four steps, §15.8's same-network mail; R-MAIL-1, R-MAIL-5, D-MAIL-8, I-5, I-8, I-9, X7;
// MAIL-M7-18 for members, MAIL-M9-01 for any recipient): one message to this network's own addresses and to the
// internet's, each recipient on its own path. A draft's message is built here; a submission's comes as its client
// wrote it (MailClient.SubmitMessage, mail_submission.go), and both take the same steps.
//
//	from      one of this network's own addresses (its label's, its alias's, a scope's or a verified Team domain's), held to
//	          mail:<alias>#send for this device (D-ACL-12) by the rule ingest holds a deposit's signer to, so a message
//	          the sender may not send as its From is refused here and, if forged, shown as outside mail there. A
//	          burner's From is a reply, which MailClient.Reply alone sends (mail_burner_reply.go), and a bounce or
//	          reverse alias is no From
//	split     each recipient is an address of this network or not. A same-network one is deposited and never routed to
//	          the internet path, whatever form the sender's alias has outside; any other is internet mail
//	gate      §15.10's step 1: mail to members alone, in a run that is not tainted, is W and goes at once. An internet
//	          recipient, or a tainted run's send (I-9), makes the send an outward action (I-8): the whole message waits
//	          on §5.4's gate as one mail_send action (mail_send_gate.go), and nothing is kept, deposited or queued, its
//	          member part included, until the gate passes it. A send whose every internet recipient has an approval
//	          record that verifies now, in a run that is not tainted, is W as well (MailApprovedRecipients, owner
//	          decision 280): it goes at once, queued under a key of its own, and a device with no SpendState bound
//	          reads no record as approving, the closed direction (mail_approved.go)
//	resolve   a same-network recipient goes through the signed mailcfg (MailConfig.Resolve): unknown, burned and
//	          paused alike are MailSendUnknown; a known one's repo is judged by MailSendAuthority.MayDeposit
//	copy      step 2: the message is kept in this device's member's mailbox as an ordinary m/ and i/ entry labeled sent
//	          in f/ (plan-MAIL-small-readings#9), before any deposit or queue, so a copy that cannot be kept sends
//	          nothing. A device with no mailbox it writes, an agent's or an unconsented device's, keeps none, and
//	          queues none
//	deposit   then one deposit a repo (mail_send_local.go), each answered delivered once evs confirmed it, else failed
//	burner    step 3, for a reply from a burner: BURNER's header rules (MailBurnerHeaders), applied before the copy so
//	          the copy is what went
//	queue     step 4: the internet recipients at o/<h>/<effect_key> under the use's effect key (mail_outbox.go), the
//	          envelope sender the mailbox's bounce address (mail_bounce.go), each answered queued, with SMTP's
//	          outcomes following in or/. A probation, suspended or unverified network queues nothing: its internet
//	          recipients answer internet_refused (§21.7, D-SMTP-14). On the sidecar_http leg, which sends no mail, they
//	          answer internet_waits
//
// A send is idempotent only under its gate's effect key: a member-only send keeps none, so sending again after a
// failure deposits again to the repos that took it, and a caller sends only the recipients that failed. A draft's
// message is plain text, UTF-8, quoted-printable, with From, To, Cc, Subject, Date and a Message-ID under the From's
// domain; a Bcc recipient is deposited to or queued and named in no header. Nothing here logs an address, a subject or
// a byte of a message (I-13).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// What Send was given is out of shape: no From, no recipient, past a bound, a header line break, or an address
	// that does not parse. Names no address.
	ErrMailSendInvalid = errors.New("mail send: invalid")
	// The From is no address this device may send as: outside this network, a burner's sent other than as its reply,
	// a bounce or reverse alias, or one policy grants this device no mail:<alias>#send for.
	ErrMailSendFromRefused = errors.New("mail send: this device may not send as that From")
	// The sent copy could not be kept in this device's mailbox, so nothing was sent.
	ErrMailSendCopyFailed = errors.New("mail send: the sent copy was not kept, so nothing was sent")
	// What the call asks of a send is not on this sidecar: a check or a send's result on the page Worker's leg, which
	// sends no mail (mail_send_result_http.go), a DSN deposit into a mailbox this device may deposit nothing to, or a
	// daemon backend that answered nothing. An app reads it as MAIL_UNAVAILABLE.
	ErrMailSendUnavailable = errors.New("mail send: this sidecar cannot do that yet")
	// No send of this device's member has that send_id. Names no id.
	ErrMailSendUnknown = errors.New("mail send: no send has that id")
	// §5.4's gate ran a send's effect and could not say whether it happened (mail_send_gate.go).
	ErrMailSendUncertain = errors.New("mail send: whether the send happened is not known")
)

// What became of one recipient of a Send.
type MailSendOutcome string

const (
	// Deposited to the recipient's repo, and evs confirmed it.
	MailSendDelivered MailSendOutcome = "delivered"
	// No record a receiver honors holds the address, or it is a burned or paused burner's (§15.9).
	MailSendUnknown MailSendOutcome = "unknown"
	// Another member's mailbox, which a device has no deposit right in until QD-136's cell is in §8.5's rows
	// (plan-MAIL-member-deposit's interim): refused, closed.
	MailSendMemberRefused MailSendOutcome = "member_refused"
	// Policy gives this device no deposit or write in the recipient's repo.
	MailSendNoDepositRight MailSendOutcome = "refused"
	// Internet mail queued at o/ for a prover host (§15.10's step 4): §14's outcomes follow in or/.
	MailSendQueued MailSendOutcome = "queued"
	// Internet mail this network may not send: on probation, suspended or unverified (§21.7, D-SMTP-14).
	MailSendInternetRefused MailSendOutcome = "internet_refused"
	// Internet mail this sidecar has no outbox for: the page Worker's leg, or a device with no mailbox it writes, an
	// agent's or an unconsented one. Nothing was queued.
	MailSendInternetWaits MailSendOutcome = "internet_waits"
	// The deposit or the queue did not commit: send to this recipient again.
	MailSendFailed MailSendOutcome = "failed"
)

// What a Send is held to (MAIL-M7-18, MAIL-M9-01). Every value must be positive.
type MailSendSettings struct {
	// The most distinct recipients one send names: a deposit's trailer holds at most ingest's 100
	// (MailIngestSettings.RecipientMaxCount, §20.4's mail_inbound_recipients), which a repo of all of them must pass.
	RecipientMaxCount int
	// The most bytes of an address: RFC 5321's 254 of a path's mailbox.
	AddressMaxByteCount int
	// The most bytes of the subject, before encoding: under RFC 5322's 998-byte line once encoded words fold.
	SubjectMaxByteCount int
	// The most bytes of the text, before encoding: far under a deposit's 50 MiB bound
	// (MailIngestSettings.DepositMaxByteCount), since quoted-printable may triple it.
	TextMaxByteCount int
	// The most bytes of a submitted message (SubmitMessage): the deposit's 50 MiB (§20.4's largest
	// mail_inbound_message_bytes), which a same-network recipient's reader must open.
	MessageMaxByteCount int
	// The most bytes of the Message-ID a reply names: 256, the bound ingest's walk keeps an id to (MailParsed).
	MessageIdMaxByteCount int
	// The most bytes of the preview a send's mail_send action shows an approver (mail_send_gate.go): the canonical
	// action's own bound, CanonicalActionSettings.PreviewMaxByteCount (§16.8's 2 KiB). A larger value builds an
	// action NewCanonicalAction refuses, so the send is refused rather than its preview cut short.
	PreviewMaxByteCount int
}

// The one default.
func DefaultMailSendSettings() *MailSendSettings {
	return &MailSendSettings{
		RecipientMaxCount:     DefaultMailIngestSettings().RecipientMaxCount,
		AddressMaxByteCount:   254,
		SubjectMaxByteCount:   512,
		TextMaxByteCount:      8 * 1024 * 1024,
		MessageMaxByteCount:   50 * 1024 * 1024,
		MessageIdMaxByteCount: 256,
		PreviewMaxByteCount:   DefaultCanonicalActionSettings().PreviewMaxByteCount,
	}
}

// Whether every value is in range.
func (self *MailSendSettings) valid() bool {
	return self != nil && 0 < self.RecipientMaxCount && 0 < self.AddressMaxByteCount && 0 < self.SubjectMaxByteCount &&
		0 < self.TextMaxByteCount && 0 < self.MessageMaxByteCount && 0 < self.MessageIdMaxByteCount && 0 < self.PreviewMaxByteCount
}

// What Send sends.
type MailSendArgs struct {
	// One of this network's addresses this device may send as.
	From string
	// The recipients, each an RFC 5321 address; at least one among the three.
	To  []string
	Cc  []string
	Bcc []string
	// The subject and the plain-text body, UTF-8.
	Subject string
	Text    string
	// The Message-ID replied to, without its brackets, which In-Reply-To and References name; empty for none.
	InReplyTo string
	// What the outward action carries to the gate (I-8) when the send needs one: the run and agent a decision binds,
	// nil for a person's own command or a host's submission, which are no run and so untainted (§16.6's spend step
	// 1), the agent's words and a decision in hand.
	Action MailConfigActionArgs
}

// One recipient's outcome.
type MailSendRecipient struct {
	// Its delivery address, with a canonical domain and the original external local part.
	Address string
	Outcome MailSendOutcome
}

// What Send answers.
type MailSendResult struct {
	// A draft's send id. Queued mail takes the id in its committed Message-ID. A raw SMTP submission can have
	// a client-chosen Message-ID that names no send.
	SendId Id
	// Each distinct recipient, in the order named, To then Cc then Bcc.
	Recipients []*MailSendRecipient
	// Whether the sent copy was kept in this device's member's mailbox.
	SentCopy bool
	// The o/ entry's key, which names its or/ outcomes too; empty where nothing was queued.
	EffectKey []byte
}

// The recipients Delivered, in order.
func (self *MailSendResult) Delivered() []string {
	delivered := []string{}
	for _, recipient := range self.Recipients {
		if recipient.Outcome == MailSendDelivered {
			delivered = append(delivered, recipient.Address)
		}
	}
	return delivered
}

// What a send reaches beyond MailClient's parts, where a test's parts stand in: the authority and the deposits.
type mailSendParts interface {
	sendAuthority() MailSendAuthority
	depositRepo(repoId Id) mailSendDepositRepo
}

// The send's settings, the defaults where none were set.
func (self *MailClient) sendSettings() *MailSendSettings {
	if self.settings.Send != nil {
		return self.settings.Send
	}
	return DefaultMailSendSettings()
}

// What a send carries: a draft whose message Send builds, or the bytes a submission handed in.
type mailSendContent struct {
	// A draft; nil for a submission.
	draft *MailSendArgs
	// A submission's message as its client wrote it; nil for a draft.
	raw []byte
}

// What a send is held to before anything is kept or deposited: the binding and its parts, the zone's row, the
// authority and the deposits over them, the From in its one form with its domain, and the distinct recipients.
type mailSendPlan struct {
	binding     *MailBinding
	parts       mailClientParts
	row         NetworkLabelRow
	authority   MailSendAuthority
	depositRepo func(repoId Id) mailSendDepositRepo
	fromAddress string
	fromDomain  string
	recipients  []string
	// A burner reply's <blabel>, empty for any other send: BURNER's rules and flag apply (MAIL-M9-03).
	burnerLabel string
}

// The recipients that are not this network's, in order.
func (self *mailSendPlan) outsideRecipients() []string {
	outside := []string{}
	for _, address := range self.recipients {
		if _, own := mailSendOwnRecipient(self.row, address); !own {
			outside = append(outside, address)
		}
	}
	return outside
}

// The deposit of repoId over binding and parts: a test's where its parts stand in, else the bound EvsClient's. Nil
// where there is none.
func mailSendDepositRepoOf(binding *MailBinding, parts mailClientParts, repoId Id) mailSendDepositRepo {
	if sendParts, ok := parts.(mailSendParts); ok {
		return sendParts.depositRepo(repoId)
	}
	if binding.Evs == nil {
		return nil
	}
	if repo := binding.Evs.Repo(repoId); repo != nil {
		return repo
	}
	return nil
}

// Holds args to what a draft's send needs before it keeps or deposits anything (see the file header): its shape and
// bounds, the zone, and a From of this network that policy lets this device send as. Send and SubmitSend both start
// here, so a send the gate holds was refused for none of these. An error names no address.
func (self *MailClient) planSend(ctx context.Context, args *MailSendArgs) (*mailSendPlan, error) {
	return self.planSendDraft(ctx, args, "")
}

// planSend for a draft from burnerLabel's burner, a reply's (MailClient.Reply), or "" for any other.
func (self *MailClient) planSendDraft(ctx context.Context, args *MailSendArgs, burnerLabel string) (*mailSendPlan, error) {
	settings := self.sendSettings()
	if args == nil {
		return nil, fmt.Errorf("%w: no message", ErrMailSendInvalid)
	}
	if strings.ContainsAny(args.Subject, "\r\n") || settings.SubjectMaxByteCount < len(args.Subject) || !utf8.ValidString(args.Subject) ||
		settings.TextMaxByteCount < len(args.Text) || !utf8.ValidString(args.Text) {
		return nil, fmt.Errorf("%w: a subject or text out of shape", ErrMailSendInvalid)
	}
	if args.InReplyTo != "" && (settings.MessageIdMaxByteCount < len(args.InReplyTo) || strings.ContainsAny(args.InReplyTo, "<>\r\n \t") ||
		!strings.Contains(args.InReplyTo, "@") || !utf8.ValidString(args.InReplyTo)) {
		return nil, fmt.Errorf("%w: a reply's id out of shape", ErrMailSendInvalid)
	}
	return self.planSendFrom(ctx, args.From, burnerLabel, args.To, args.Cc, args.Bcc)
}

// What a send to the address lists is held to: the zone, its distinct recipients and a From of this network
// that policy lets this device send as. burnerLabel, a reply's, holds a burner's From to its live label in this
// member's mailbox instead (MailClient.Reply).
func (self *MailClient) planSendFrom(ctx context.Context, fromText string, burnerLabel string, lists ...[]string) (*mailSendPlan, error) {
	binding, parts, _, err := self.state()
	if err != nil {
		return nil, err
	}
	row := self.networkRow()
	if binding.Network != nil {
		row = binding.Network()
	}
	if row.Root == "" || row.Label == "" {
		return nil, ErrMailConfigNoZone
	}
	recipients, err := mailSendAddressList(row, self.sendSettings(), lists...)
	if err != nil {
		return nil, err
	}
	authority := MailSendAuthority(&MailSendAclAuthority{
		Engine: binding.Engine,
		Root:   row.Root,
		OwnZone: func(zone MailZone) bool {
			return zone.OfNetwork(row)
		},
		Clock: self.clock,
	})
	if sendParts, ok := parts.(mailSendParts); ok {
		authority = sendParts.sendAuthority()
	}

	// The policy alias stays the network's own. The sender preserves a verified customer domain on the wire.
	from, err := ParseMailRecipient(row.Root, fromText)
	fromDomain := from.Domain()
	if err != nil {
		from, fromDomain, err = mailVerifiedCustomFrom(ctx, binding.Api, row, fromText)
		if err != nil {
			return nil, err
		}
	}
	if !from.Zone.OfNetwork(row) {
		return nil, ErrMailSendFromRefused
	}
	fromAddress := from.LocalPart + "@" + fromDomain
	switch {
	case burnerLabel != "":
		// a reply's From is its burner's, held to the live label in this member's mailbox by the reply's caller
		if from.Kind != MailAddressKindBurner || from.BurnerLabel != burnerLabel {
			return nil, ErrMailSendFromRefused
		}
	case from.Kind != MailAddressKindName && from.Kind != MailAddressKindAdmin:
		return nil, ErrMailSendFromRefused
	case !authority.MaySendAs(self.sidecarId, from.Address()):
		return nil, ErrMailSendFromRefused
	}
	return &mailSendPlan{
		binding:   binding,
		parts:     parts,
		row:       row,
		authority: authority,
		depositRepo: func(repoId Id) mailSendDepositRepo {
			return mailSendDepositRepoOf(binding, parts, repoId)
		},
		fromAddress: fromAddress,
		fromDomain:  fromDomain,
		recipients:  recipients,
		burnerLabel: burnerLabel,
	}, nil
}

// Resolve a custom From to the local alias the device needs permission to use. Status applies the edge's
// Team/downgrade entitlement and verifies the exact domain. Every approval spend repeats the lookup.
func mailVerifiedCustomFrom(ctx context.Context, api MailApi, row NetworkLabelRow, address string) (MailRecipient, string, error) {
	from, domain, ok := mailCustomAddress(MailZone{Net: row.Label, Root: row.Root}, address)
	if !ok || api == nil {
		return MailRecipient{}, "", ErrMailSendFromRefused
	}
	status, err := api.MailStatus(ctx)
	if err != nil {
		return MailRecipient{}, "", err
	}
	if status == nil || !status.MaySendFromCustomDomains || !slices.Contains(status.VerifiedDomains, domain) {
		return MailRecipient{}, "", ErrMailSendFromRefused
	}
	return from, domain, nil
}

// address parsed under row's root, and whether it is an address of row's network. One that does not parse there is
// not: it is outside mail, §14's path, never a deposit. A same-network address is never outside, whatever form the
// sender's alias has elsewhere.
func mailSendOwnRecipient(row NetworkLabelRow, address string) (MailRecipient, bool) {
	parsed, err := ParseMailRecipient(row.Root, address)
	if err != nil || !parsed.Zone.OfNetwork(row) {
		return MailRecipient{}, false
	}
	return parsed, true
}

// Sends a message to any recipient (see the file header): mail to members alone goes at once; one naming an internet
// recipient, or a tainted run's, waits on §5.4's gate, answered *ApprovalPendingError with nothing kept, deposited or
// queued while a person's decision is awaited. An error is the whole send's: nothing was sent. Otherwise each
// recipient's outcome is in the answer.
func (self *MailClient) Send(ctx context.Context, args *MailSendArgs) (*MailSendResult, error) {
	plan, err := self.planSend(ctx, args)
	if err != nil {
		return nil, err
	}
	draft := mailSendCopyArgs(args)
	return self.sendPlanned(ctx, plan, &mailSendContent{draft: draft}, args.Action, func(ctx context.Context) (*mailSendPlan, error) {
		return self.planSend(ctx, draft)
	})
}

// A host's submission of a draft (ur daemon's mail.send, an app's Send): Send, which holds what is outward.
func (self *MailClient) SubmitSend(ctx context.Context, args *MailSendArgs) (*MailSendResult, error) {
	return self.Send(ctx, args)
}

// The send once planned: at once where it is W, else through the gate (the file header's gate row), whose effect
// plans it again with replan at the spend.
func (self *MailClient) sendPlanned(ctx context.Context, plan *mailSendPlan, content *mailSendContent, action MailConfigActionArgs, replan func(context.Context) (*mailSendPlan, error)) (*MailSendResult, error) {
	outside := plan.outsideRecipients()
	tainted := action.RunId != nil && plan.binding.RunTainted != nil && plan.binding.RunTainted(*action.RunId)
	if len(outside) == 0 && !tainted {
		return self.deliverSend(ctx, plan, content, nil)
	}
	if 0 < len(outside) && !tainted && self.ApprovedRecipients().ApprovedAll(ctx, plan.fromAddress, outside) {
		// W by approval records alone: no use of the gate's, so a key of its own names the entry
		return self.deliverSend(ctx, plan, content, mailSendStandingEffectKey())
	}
	return self.gatedSend(ctx, plan, content, action, replan)
}

// A fresh 32-byte effect key, for a send that keeps no use of the gate's: a standing grant's, or one records approve.
func mailSendStandingEffectKey() []byte {
	first, second := NewEvsRandomToken(), NewEvsRandomToken()
	return append(first[:], second[:]...)
}

// The delivery of content once plan holds: the split, the resolution, the burner rules, the sent copy, the deposits
// and the queue. effectKey is the use's, nil for a send to members alone, which queues nothing.
func (self *MailClient) deliverSend(ctx context.Context, plan *mailSendPlan, content *mailSendContent, effectKey []byte) (*MailSendResult, error) {
	row, authority, fromAddress := plan.row, plan.authority, plan.fromAddress
	// A retry may find its queue committed before the gate recorded the answer.
	if replay, err := self.priorSend(ctx, plan, content, effectKey); err != nil || replay != nil {
		return replay, err
	}

	// split and resolve
	result := &MailSendResult{}
	targets := []*mailSendTarget{}
	targetIndexes := map[*MailSendRecipient]int{}
	outside := []*MailSendRecipient{}
	var config *MailConfig
	for _, address := range plan.recipients {
		recipient := &MailSendRecipient{Address: address, Outcome: MailSendInternetWaits}
		result.Recipients = append(result.Recipients, recipient)
		parsed, own := mailSendOwnRecipient(row, address)
		if !own {
			outside = append(outside, recipient)
			continue
		}
		var err error
		if config == nil {
			if config, err = self.syncedConfig(ctx); err != nil {
				return nil, err
			}
		}
		lookup, err := config.Resolve(ctx, parsed)
		if err != nil {
			return nil, err
		}
		if !lookup.Known {
			recipient.Outcome = MailSendUnknown
			continue
		}
		if outcome := authority.MayDeposit(self.sidecarId, lookup.MailboxRepoId); outcome != MailSendDelivered {
			recipient.Outcome = outcome
			continue
		}
		index := slices.IndexFunc(targets, func(target *mailSendTarget) bool { return target.repoId == lookup.MailboxRepoId })
		if index < 0 {
			index = len(targets)
			targets = append(targets, &mailSendTarget{repoId: lookup.MailboxRepoId})
		}
		targets[index].recipients = append(targets[index].recipients, parsed.Address())
		targetIndexes[recipient] = index
	}

	// the queue, where internet mail may go from here
	var queue mailSendQueue
	if 0 < len(outside) {
		var refused MailSendOutcome
		if len(effectKey) != mailEffectKeyByteCount {
			// no use to queue under: never reached by a send the gate passed
			refused = MailSendInternetWaits
		} else {
			queue, refused = self.prepareQueue(ctx, plan)
		}
		if queue == nil {
			for _, recipient := range outside {
				recipient.Outcome = refused
			}
			outside = nil
		}
	}
	if len(targets) == 0 && len(outside) == 0 {
		// nothing to deposit or queue: no copy is kept of a message that went nowhere
		return result, nil
	}

	now := self.clock.Now()
	// mail that leaves the network, and every burner's, names a random id (MailOutboxMessageId); mail to members
	// alone keeps an id's time
	result.SendId = NewId()
	messageDomain := plan.fromDomain
	messageId := strings.ToLower(result.SendId.String()) + "@" + messageDomain
	if queue != nil || plan.burnerLabel != "" {
		result.SendId = newMailOutboxSendId()
		messageId = MailOutboxMessageId(result.SendId, messageDomain)
	}
	message, err := content.message(plan, messageId, now)
	if err != nil {
		return nil, err
	}
	flags := uint32(0)
	if plan.burnerLabel != "" {
		// step 3, before the copy, so the copy is what went
		if message, err = self.burnerHeaders().Apply(message, &MailBurnerHeadersArgs{MessageId: messageId, Now: now}); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMailSendInvalid, err)
		}
		flags |= SmtpFlagBurner
	}
	// what leaves this device for another reader names no Bcc
	sendable := mailSendStripBcc(message)

	// copy: before any deposit or queue, so one that cannot be kept sends nothing
	mailboxId, mailboxErr := self.mailboxId()
	if mailboxErr == nil && authority.Writes(self.sidecarId, mailboxId) {
		if err := self.keepSentCopy(ctx, plan.parts.store(mailboxId), result.SendId, message, fromAddress, now); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMailSendCopyFailed, err)
		}
		result.SentCopy = true
	}
	outcomes := mailSendDeposit(ctx, plan.depositRepo, sendable, fromAddress, targets)
	for recipient, index := range targetIndexes {
		recipient.Outcome = outcomes[index]
	}
	if queue != nil && 0 < len(outside) {
		addresses := make([]string, 0, len(outside))
		for _, recipient := range outside {
			addresses = append(addresses, recipient.Address)
		}
		queued, outcome, err := queue.queue(ctx, &mailSendQueueArgs{
			effectKey:  effectKey,
			recipients: addresses,
			message:    sendable,
			flags:      flags,
			notAfter:   mailSendApprovalNotAfter(ctx),
		})
		if err != nil {
			return nil, err
		}
		for _, recipient := range outside {
			recipient.Outcome = outcome
		}
		if queued != nil {
			if !queued.Created {
				return content.replayedSend(queued.SendId, queued.EffectKey)
			}
			result.EffectKey = queued.EffectKey
			result.SendId = queued.SendId
		}
	}
	return result, nil
}

// The recorded queue result, read before repeating any effect and when a gate answers from its ledger.
func (self *MailClient) priorSend(ctx context.Context, plan *mailSendPlan, content *mailSendContent, effectKey []byte) (*MailSendResult, error) {
	if len(effectKey) != mailEffectKeyByteCount || len(plan.outsideRecipients()) == 0 {
		return nil, nil
	}
	queued, err := self.queuedSend(ctx, plan, effectKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailSendUncertain, err)
	}
	if queued == nil {
		return nil, nil
	}
	return content.replayedSend(queued.SendId, queued.EffectKey)
}

// The result known on replay. A raw submission may carry a client-chosen Message-ID, and an old outcome may
// omit send_id. A draft needs its committed id for GetSendResult.
func (self *mailSendContent) replayedSend(sendId Id, effectKey []byte) (*MailSendResult, error) {
	if sendId == (Id{}) && self.draft != nil {
		return nil, fmt.Errorf("%w: the recorded outcome names no send", ErrMailSendUncertain)
	}
	return &MailSendResult{SendId: sendId, EffectKey: effectKey}, nil
}

// The Message-ID an internet send names, <id>@<domain>: id the lowercase base32 of the send's 16 bytes, which a
// send draws at random for mail that leaves the network (§14.6's 26 base32 random characters), so the entry tells
// Lookup its send and the id tells a recipient nothing of the device, its clock or another message.
func MailOutboxMessageId(sendId Id, domain string) string {
	return mailBinaryName(sendId[:]) + "@" + domain
}

// A send id drawn at random, for MailOutboxMessageId.
func newMailOutboxSendId() Id {
	return Id(NewEvsRandomToken())
}

// What one queue step is given.
type mailSendQueueArgs struct {
	effectKey  []byte
	recipients []string
	message    []byte
	flags      uint32
	notAfter   time.Time
}

// What MailOutbox.Queue committed or found under the same key.
type MailOutboxQueued struct {
	EffectKey []byte
	// The id in the committed message or outcome record, zero if it names none.
	SendId Id
	// This call wrote the entry.
	Created bool
}

// Where a send's internet mail goes: the member's outbox on the legs that send mail (mail_send_queue.go).
type mailSendQueue interface {
	// Queues args' message for its internet recipients. An error means a committed receipt could not be read.
	queue(ctx context.Context, args *mailSendQueueArgs) (*MailOutboxQueued, MailSendOutcome, error)
}

// Canonicalizes a bare recipient. An external SMTP local part is opaque, whereas a local mailcfg name folds case.
func mailSendAddress(row NetworkLabelRow, address string) string {
	address = strings.TrimSpace(address)
	if recipient, own := mailSendOwnRecipient(row, address); own {
		return recipient.Address()
	}
	if at := strings.LastIndexByte(address, '@'); at >= 0 {
		return address[:at+1] + dnsAsciiLower(address[at+1:])
	}
	return address
}

// The distinct delivery addresses in list order, each a bare RFC 5322 address within settings' bounds.
func mailSendAddressList(row NetworkLabelRow, settings *MailSendSettings, lists ...[]string) ([]string, error) {
	recipients := []string{}
	for _, list := range lists {
		for _, address := range list {
			address = mailSendAddress(row, address)
			if address == "" || settings.AddressMaxByteCount < len(address) || strings.ContainsAny(address, "\r\n<>,") {
				return nil, fmt.Errorf("%w: a recipient out of shape", ErrMailSendInvalid)
			}
			parsed, err := mail.ParseAddress(address)
			if err != nil || parsed.Address != address || parsed.Name != "" {
				return nil, fmt.Errorf("%w: a recipient that is no address", ErrMailSendInvalid)
			}
			if !slices.Contains(recipients, address) {
				recipients = append(recipients, address)
			}
		}
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: no recipient", ErrMailSendInvalid)
	}
	if settings.RecipientMaxCount < len(recipients) {
		return nil, fmt.Errorf("%w: past %d recipients", ErrMailSendInvalid, settings.RecipientMaxCount)
	}
	return recipients, nil
}

// The message content sends: a draft's built under messageId, or a submission's as its client wrote it.
func (self *mailSendContent) message(plan *mailSendPlan, messageId string, now time.Time) ([]byte, error) {
	if self.draft == nil {
		return bytes.Clone(self.raw), nil
	}
	return mailSendBuildMessageWithId(self.draft, plan.row, plan.fromAddress, messageId, now)
}

// A draft's message with its send's Message-ID, and the same To and Cc addresses the planner used for delivery.
func mailSendBuildMessageWithId(args *MailSendArgs, row NetworkLabelRow, fromAddress string, messageId string, now time.Time) ([]byte, error) {
	headerAddresses := func(addresses []string) []string {
		distinct := []string{}
		for _, address := range addresses {
			if address = mailSendAddress(row, address); address != "" && !slices.Contains(distinct, address) {
				distinct = append(distinct, address)
			}
		}
		return distinct
	}
	message := &bytes.Buffer{}
	header := func(name string, value string) {
		message.WriteString(name)
		message.WriteString(": ")
		message.WriteString(value)
		message.WriteString("\r\n")
	}
	header("From", fromAddress)
	if to := headerAddresses(args.To); 0 < len(to) {
		header("To", strings.Join(to, ", "))
	}
	if cc := headerAddresses(args.Cc); 0 < len(cc) {
		header("Cc", strings.Join(cc, ", "))
	}
	if args.Subject != "" {
		header("Subject", mime.QEncoding.Encode("utf-8", args.Subject))
	}
	header("Date", now.UTC().Format(time.RFC1123Z))
	header("Message-ID", "<"+messageId+">")
	if args.InReplyTo != "" {
		header("In-Reply-To", "<"+args.InReplyTo+">")
		header("References", "<"+args.InReplyTo+">")
	}
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	message.WriteString("\r\n")
	// lines end CRLF before encoding, so the encoder keeps them as hard breaks
	text := strings.ReplaceAll(strings.ReplaceAll(args.Text, "\r\n", "\n"), "\r", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	writer := quotedprintable.NewWriter(message)
	if _, err := writer.Write([]byte(text)); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if !bytes.HasSuffix(message.Bytes(), []byte("\r\n")) {
		message.WriteString("\r\n")
	}
	return message.Bytes(), nil
}

// message without any Bcc field of its header, the rest byte for byte: what leaves this device for a recipient's
// reader. A message with no header end is handed back whole, since it has no field to strip.
func mailSendStripBcc(message []byte) []byte {
	headerEnd := bytes.Index(message, []byte("\r\n\r\n"))
	lineEnd := []byte("\r\n")
	if headerEnd < 0 {
		if headerEnd = bytes.Index(message, []byte("\n\n")); headerEnd < 0 {
			return message
		}
		lineEnd = []byte("\n")
	}
	header := message[:headerEnd+len(lineEnd)]
	stripped := make([]byte, 0, len(message))
	inBcc := false
	for 0 < len(header) {
		line := header
		if index := bytes.Index(header, lineEnd); 0 <= index {
			line = header[:index+len(lineEnd)]
		}
		header = header[len(line):]
		folded := 0 < len(line) && (line[0] == ' ' || line[0] == '\t')
		if !folded {
			name, _, _ := bytes.Cut(line, []byte(":"))
			inBcc = strings.EqualFold(strings.TrimSpace(string(name)), "bcc")
		}
		if !inBcc {
			stripped = append(stripped, line...)
		}
	}
	return append(stripped, message[headerEnd+len(lineEnd):]...)
}

// Keeps message as the send's copy in store, this device's member's mailbox: its m/ file and i/ row in one push, then
// the label sent in f/ (plan-MAIL-small-readings#9). The row's address is the From, the address it belongs to here.
func (self *MailClient) keepSentCopy(ctx context.Context, store mailStore, sendId Id, message []byte, fromAddress string, now time.Time) error {
	parseSettings := self.settings.Ingest.Parse
	if parseSettings == nil {
		parseSettings = DefaultMailParseSettings()
	}
	parsed, err := MailParseMessage(bytes.NewReader(message), parseSettings)
	if err != nil {
		return err
	}
	nowMillis := uint64(max(now.UnixMilli(), 0))
	entry, err := MailBuildIndexEntry(&MailIndexEntryInput{
		Id:             sendId,
		Deposit:        &protocol.MailDeposit{Version: mailFormatVersion, MailFrom: []byte(fromAddress), Recipients: []string{fromAddress}},
		PushTimeMillis: nowMillis,
		ByteCount:      uint64(len(message)),
		Parsed:         parsed,
	})
	if err != nil {
		return err
	}
	month := MailYearMonthOf(entry.GetTime())
	messagePath := MailMessagePath(month, sendId)
	testHookBarrier("mail.send.copy.before", "")
	_, err = NewMailIndexWriter(store, self.settings.Store).Append(ctx, entry, &mailStoreWrite{Path: messagePath, Content: message})
	testHookBarrier("mail.send.copy.after", "")
	if err != nil {
		return err
	}
	_, err = NewMailFlagWriter(store, NewMailHlc(self.clock), self.sidecarId, self.settings.Store).Apply(ctx, []*MailFlagChange{{
		Month: month, MessageId: sendId, Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: MailLabelSent,
	}})
	return err
}
