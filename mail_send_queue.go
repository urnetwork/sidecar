//go:build !sidecar_http && !ios_extension

// The queue step of a send on the legs that send internet mail (§15.10's step 4; MAIL-M9-01, MAIL-M9-02): the member's
// outbox under the bound signer and standing, its envelope sender the mailbox's bounce address, and the outbox's
// Lookup on the client's gate for kind mail, so a restart reconciles a reserved send with no caller alive.
// mail_send_queue_http.go is the page Worker's twin, which queues nothing. Also MailClient.SmtpMailbox, the member's
// mailbox as §14's sender and outbox runner reach it.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

// The outbox settings, the defaults where none were set.
func (self *MailClient) outboxSettings() *MailOutboxSettings {
	if self.settings.Outbox != nil {
		return self.settings.Outbox
	}
	return DefaultMailOutboxSettings()
}

// Registers kind mail's Lookup on gate, once a gate, in place of one on an earlier gate.
func (self *MailClient) registerOutboxLookup(gate MailConfigGate) {
	if gate == nil {
		return
	}
	previous, registered := func() (func(), bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.outboxLookupGate == gate {
			return nil, true
		}
		previous := self.outboxLookupRemove
		self.outboxLookupGate, self.outboxLookupRemove = gate, nil
		return previous, false
	}()
	if registered {
		return
	}
	if previous != nil {
		previous()
	}
	remove := gate.RegisterEffectLookup(SidecarActionMail, self.outboxLookup)
	stale := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.outboxLookupGate != gate {
			return true
		}
		self.outboxLookupRemove = remove
		return false
	}()
	if stale {
		remove()
	}
}

// Kind mail's Lookup: the member's outbox's (MailOutbox.Lookup), uncertain where the mailbox cannot be read.
func (self *MailClient) outboxLookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	outbox, err := self.memberOutbox(nil)
	if err != nil {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	return outbox.Lookup(ctx, canonical, effectKey)
}

// The outbox of this device's member's mailbox over the bound parts, standing read through standing.
func (self *MailClient) memberOutbox(standing MailOutboxStanding) (*MailOutbox, error) {
	binding, parts, err := self.bound()
	if err != nil {
		return nil, err
	}
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	var sign SmtpOutboxSigner
	if binding.Sign != nil {
		sign = binding.Sign
	}
	return NewMailOutbox(&MailOutboxArgs{
		Store:    parts.store(mailboxId),
		Sign:     sign,
		Standing: standing,
		Settings: self.outboxSettings(),
		Clock:    self.clock,
	})
}

// The member's outbox, its standing read once, as one send's queue: nil and the outcome its internet recipients
// answer where this device may queue none (mail_send.go's queue row).
func (self *MailClient) prepareQueue(ctx context.Context, plan *mailSendPlan) (mailSendQueue, MailSendOutcome) {
	mailboxId, err := self.mailboxId()
	if err != nil || !plan.authority.Writes(self.sidecarId, mailboxId) {
		// an agent's or an unconsented device holds no outbox of its member's
		return nil, MailSendInternetWaits
	}
	if plan.binding.Sign == nil {
		return nil, MailSendFailed
	}
	if plan.binding.Standing == nil {
		return nil, MailSendInternetRefused
	}
	status, err := plan.binding.Standing(ctx)
	if err != nil {
		// a standing not read queues nothing, and a send again may find it
		return nil, MailSendFailed
	}
	if !mailOutboxStandingAllows(status) {
		return nil, MailSendInternetRefused
	}
	outbox, err := self.memberOutbox(func(ctx context.Context) (*AbuseStatus, error) { return status, nil })
	if err != nil {
		return nil, MailSendFailed
	}
	sender, err := self.BounceRecipient(ctx)
	if err != nil {
		return nil, MailSendFailed
	}
	return &mailSendOutboxQueue{outbox: outbox, sender: sender}, ""
}

// One send's queue: the outbox and the envelope sender.
type mailSendOutboxQueue struct {
	outbox *MailOutbox
	sender string
}

// See mailSendQueue.
func (self *mailSendOutboxQueue) queue(ctx context.Context, args *mailSendQueueArgs) MailSendOutcome {
	_, err := self.outbox.Queue(ctx, &MailOutboxQueueArgs{
		EffectKey:        args.effectKey,
		Sender:           self.sender,
		Recipients:       args.recipients,
		Message:          args.message,
		Flags:            args.flags,
		ApprovalNotAfter: args.notAfter,
	})
	switch {
	case err == nil:
		return MailSendQueued
	case errors.Is(err, ErrMailOutboxStanding):
		return MailSendInternetRefused
	}
	return MailSendFailed
}

// The member's mailbox as §14's sender and outbox runner reach it (SmtpSenderArgs.Mailbox,
// SmtpOutboxRunnerArgs.Mailbox): o/, or/, p/ and DSN deposits through MAIL's formats alone (mail_smtp_mailbox.go).
// ErrMailNoMailbox for a device with no mailbox of its own.
func (self *MailClient) SmtpMailbox() (SmtpMailbox, error) {
	binding, parts, err := self.bound()
	if err != nil {
		return nil, err
	}
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	deposit := mailSendDepositRepoOf(binding, parts, mailboxId)
	if deposit == nil {
		return nil, fmt.Errorf("%w: no deposit into the mailbox", ErrMailUnbound)
	}
	return newMailSmtpMailbox(parts.store(mailboxId), deposit, self.BounceRecipient, self.outboxSettings(), self.clock), nil
}
