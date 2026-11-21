//go:build !sidecar_http && !ios_extension

// Burner replies (§15.9's Replies, §15.10's step 3; R-MAIL-6, D-MAIL-7, D-DNS-11, owner decisions 30, 79; MAIL-M9-03):
// a reply from <name>@<blabel>.<net>.<root> goes through §14 with header_from_domain <blabel>.<net>.<root> and flag
// BURNER, so it passes strict DMARC under the burner's own selector, since SPF never aligns and only strict DKIM
// separates networks (D-SMTP-5).
//
//	from      a live burner of this member's mailbox, its label resolved through the signed mailcfg; a paused or
//	          burned one, another member's, or a label no record holds sends nothing (ErrMailSendFromRefused)
//	send      Send's steps (mail_send.go): the gate for any internet recipient, the copy, the deposits, then
//	          BURNER's header rules (MailBurnerHeaders) and o/ under the use's key with SmtpFlagBurner, so the prover
//	          host's sender signs under the burner's domain
//	selector  the first reply's DKIM selector is published by the sending host's SmtpDkimKeys through POST
//	          /smtp/dkim-keys at its first signature, whose server write adds the label's MX and A/AAAA copies in the
//	          same journal write (D-DNS-11); never by another path. Here the record learns it is replying, so every
//	          device of the member reads it and a burn knows to retire
//	burn      a burn retires this device's selectors for the label through the bound MailBurnerSelectors, and every
//	          other device of the member retires its own once it reads the burned record
//	          (MailClient.RetireBurnedSelectors), the server deleting the copies with the last
//	quota     each reply is a connection, against the network's daily connection quota at smtpedge (owner decision 30)
//
// Nothing here logs an address or a label (I-13). Off the page Worker's leg, which writes no mailcfg.

package sidecar

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// What Reply sends.
type MailReplyArgs struct {
	// The burner's address the reply goes From, <name>@<blabel>.<net>.<root>.
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
	// What the outward action carries to the gate (I-8).
	Action MailConfigActionArgs
}

// The burner a reply's From names, held to the file header's from row: its label, live, in this member's mailbox.
func (self *MailClient) replyBurner(ctx context.Context, from string) (string, error) {
	row := self.networkRow()
	if binding, _, err := self.bound(); err == nil && binding.Network != nil {
		row = binding.Network()
	}
	recipient, err := ParseMailRecipient(row.Root, from)
	if err != nil || recipient.Kind != MailAddressKindBurner || !recipient.Zone.OfNetwork(row) {
		return "", ErrMailSendFromRefused
	}
	mailboxId, err := self.mailboxId()
	if err != nil {
		return "", err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return "", err
	}
	lookup, err := config.Resolve(ctx, recipient)
	if err != nil {
		return "", err
	}
	if !lookup.Known || lookup.MailboxRepoId != mailboxId {
		return "", ErrMailSendFromRefused
	}
	return recipient.BurnerLabel, nil
}

// Replies from a burner (see the file header): Send's answer, *ApprovalPendingError while an internet recipient's
// send waits for a person's decision. The burner reads replying once its reply is queued.
func (self *MailClient) Reply(ctx context.Context, args *MailReplyArgs) (*MailSendResult, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no reply", ErrMailSendInvalid)
	}
	label, err := self.replyBurner(ctx, args.From)
	if err != nil {
		return nil, err
	}
	draft := &MailSendArgs{
		From: args.From, To: args.To, Cc: args.Cc, Bcc: args.Bcc, Subject: args.Subject, Text: args.Text,
		InReplyTo: args.InReplyTo, Action: args.Action,
	}
	plan, err := self.planSendDraft(ctx, draft, label)
	if err != nil {
		return nil, err
	}
	content := &mailSendContent{draft: mailSendCopyArgs(draft)}
	result, err := self.sendPlanned(ctx, plan, content, args.Action, func(ctx context.Context) (*mailSendPlan, error) {
		// the burner held live again at the spend, as the From is
		if _, err := self.replyBurner(ctx, args.From); err != nil {
			return nil, err
		}
		return self.planSendDraft(ctx, content.draft, label)
	})
	if err != nil {
		return nil, err
	}
	if 0 < len(result.EffectKey) {
		self.markBurnerReplying(ctx, label)
	}
	return result, nil
}

// Marks label's record replying, once: a burner with its own selector and records (§15.9). A write that fails is
// logged, naming no label, and the next reply marks it.
func (self *MailClient) markBurnerReplying(ctx context.Context, label string) {
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return
	}
	burners, err := config.Burners()
	if err != nil {
		return
	}
	for _, burner := range burners {
		if burner.Label == label && burner.Replying {
			return
		}
	}
	if err := config.SetBurnerReplying(ctx, label, true); err != nil {
		self.log.Warningf("[mail]a replying burner was not marked: %v", err)
	}
}

// A burner label's domain under the bound zone: <blabel>.<net>.<root>.
func (self *MailClient) burnerDomain(label string) string {
	row := self.networkRow()
	if binding, _, err := self.bound(); err == nil && binding.Network != nil {
		row = binding.Network()
	}
	return MailRecipient{Kind: MailAddressKindBurner, BurnerLabel: label, Zone: MailZone{Root: row.Root, Net: row.Label}}.Domain()
}

// Retires this device's selectors for label's domain through the bound MailBurnerSelectors, if any is bound: what a
// burn does here (the file header's burn row). Retiring a domain with no selector is no error.
func (self *MailClient) retireBurnerSelectors(ctx context.Context, label string) error {
	binding, _, err := self.bound()
	if err != nil || binding.BurnerSelectors == nil {
		return nil
	}
	testHookBarrier("mail.burner.retire.before", "")
	err = binding.BurnerSelectors.Retire(ctx, self.burnerDomain(label))
	testHookBarrier("mail.burner.retire.after", "")
	return err
}

// Retires this device's selectors of every burned burner of this member's that replied, as each device does once it
// reads a burn another made (the file header's burn row): the count retired, and the first error, the rest still
// tried. Nothing to do without a bound MailBurnerSelectors.
func (self *MailClient) RetireBurnedSelectors(ctx context.Context) (int, error) {
	binding, _, err := self.bound()
	if err != nil || binding.BurnerSelectors == nil {
		return 0, nil
	}
	burners, err := self.Burners(ctx)
	if err != nil {
		return 0, err
	}
	retired := 0
	var firstErr error
	for _, burner := range burners {
		if burner.State != protocol.MailBurnerState_MAIL_BURNER_BURNED || !burner.Replying {
			continue
		}
		if err := self.retireBurnerSelectors(ctx, burner.Label); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		retired += 1
	}
	return retired, firstErr
}
