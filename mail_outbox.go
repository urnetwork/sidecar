//go:build !sidecar_http && !ios_extension

// The outbox (§15.7's o/, §15.10's step 4; R-MAIL-1, R-MAIL-12, D-MAIL-5, D-MCP-11, D-SMTP-18, I-8, X7; MAIL-M9-02):
// internet mail a member's device leaves for a desktop-class prover host to send through §14's SmtpSender. A phone
// only queues, and a desktop's own mail takes the same path, so one runner, SMTP-M9-09's SmtpOutboxRunner, serves both.
//
//	queue     o/<h>/<effect_key>, created only if absent: u32be(length) ‖ Signed ‖ the message, the Signed
//	          SIGNED_SMTP_OUTBOX under purpose smtp-outbox, by this device's identity key, over SmtpOutboxEntry
//	          (plan-SMTP-wire-gaps#4; SignSmtpOutboxEntry). A second Queue under one key, a retry's, a restart's or
//	          another device's, finds the entry that stands and answers it, so one effect leaves one object whatever
//	          signer won (MailOutboxQueued.Created)
//	key       the use's effect_key (D-MCP-11), which also names the send's or/; a forward's is derived from its message
//	          id (MAIL-M9-04), so racing readers queue one
//	standing  probation and anonymous-only networks deliver only same-network deposits (§21.7, D-SMTP-14): Queue reads
//	          the network's standing first, and a probation, suspended or unverified network, or a standing that cannot
//	          be read, queues nothing (ErrMailOutboxStanding). A restricted one queues, at Community caps, which smtpedge
//	          holds it to
//	lookup    Lookup reconciles a reserved mail_send use at a restart from the stored action and its key alone: an o/
//	          entry under the key is done, its effect ref the send's id, which the entry's Message-ID carries
//	          (MailOutboxMessageId); an or/ record with no o/, an entry sent and removed past its approval's window,
//	          is done with no ref; neither, both read whole, is not_done; a read that fails is uncertain
//	removal   o/ goes once sent and past its approval's retry window, which SmtpOutboxRunner decides through
//	          SmtpMailbox.RemoveOutbox; or/ is kept 30 days (mailSmtpMailbox.RemoveExpiredOutcomes)
//
// SmtpMailbox is the sender's only way into these paths: nothing outside MAIL builds one. Nothing here logs an
// address, a domain or a byte of a message (I-13). Safe for concurrent use.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"
)

var (
	// The network may send no internet mail: on probation, suspended or unverified (§21.7, D-SMTP-14), or its
	// standing could not be read. Nothing was queued.
	ErrMailOutboxStanding = errors.New("mail outbox: this network may not send internet mail")
	// What Queue was given does not hold together: no 32-byte key, no sender, no recipient or no message.
	ErrMailOutboxInvalid = errors.New("mail outbox: invalid entry")
)

// What Queue writes: an SmtpOutboundMessage's fields, which the entry's SmtpOutboxEntry carries.
type MailOutboxQueueArgs struct {
	// The use's D-MCP-11 key, 32 bytes, which names o/ and or/.
	EffectKey []byte
	// The envelope sender, the sending mailbox's bounce address at b.<net>.<root> (MailBounceRecipient).
	Sender string
	// Every internet recipient of this send, Bcc included; never a same-network one, which is deposited instead.
	Recipients []string
	// The RFC 5322 bytes as the sender is to send them: BURNER's rules already applied, no Bcc field.
	Message []byte
	// SmtpFlagBulk, SmtpFlagRequireTls and SmtpFlagBurner.
	Flags uint32
	// Domains the composing device's approval lets go at TL4 (§14.4).
	Tl4Domains []string
	// The approval's not_after, whence the entry's retry window; zero for none.
	ApprovalNotAfter time.Time
}

// What Queue did.
type MailOutboxQueued struct {
	EffectKey []byte
	// This call wrote the entry; false for one that stood under the key already.
	Created bool
}

// A network's standing as GET /abuse/status gives it (SidecarApi.AbuseStatus).
type MailOutboxStanding func(ctx context.Context) (*AbuseStatus, error)

// What NewMailOutbox builds on.
type MailOutboxArgs struct {
	// The sending member's mailbox.
	Store mailStore
	// This device's identity key's signature: Sidecar.Sign, or a test's key.
	Sign SmtpOutboxSigner
	// The network's standing, read at each Queue; nil queues nothing (ErrMailOutboxStanding).
	Standing MailOutboxStanding
	// Nil takes DefaultMailOutboxSettings.
	Settings *MailOutboxSettings
	// Nil is real time.
	Clock Clock
}

// One member's outbox. See the file header.
type MailOutbox struct {
	store    mailStore
	sign     SmtpOutboxSigner
	standing MailOutboxStanding
	settings *MailOutboxSettings
	clock    Clock
	mailbox  *mailSmtpMailbox
}

// The outbox over args' store.
func NewMailOutbox(args *MailOutboxArgs) (*MailOutbox, error) {
	if args == nil || args.Store == nil {
		return nil, fmt.Errorf("%w: an outbox needs its mailbox", ErrMailOutboxInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailOutboxSettings()
	}
	if !settings.valid() {
		return nil, fmt.Errorf("%w: settings out of range", ErrMailOutboxInvalid)
	}
	clock := clockOrReal(args.Clock)
	return &MailOutbox{
		store:    args.Store,
		sign:     args.Sign,
		standing: args.Standing,
		settings: settings,
		clock:    clock,
		mailbox:  newMailSmtpMailbox(args.Store, nil, nil, settings, clock),
	}, nil
}

// The send an o/ entry's message names in its Message-ID, false where it names none of MailOutboxMessageId's form.
func mailOutboxSendIdOf(message []byte) (Id, bool) {
	parsed, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return Id{}, false
	}
	messageId := strings.TrimSpace(parsed.Header.Get("Message-ID"))
	messageId, ok := strings.CutPrefix(messageId, "<")
	if !ok {
		return Id{}, false
	}
	messageId, ok = strings.CutSuffix(messageId, ">")
	if !ok {
		return Id{}, false
	}
	local, _, found := strings.Cut(messageId, "@")
	if !found {
		return Id{}, false
	}
	idBytes, err := evsTokenEncoding.DecodeString(local)
	if err != nil || mailBinaryName(idBytes) != local {
		return Id{}, false
	}
	sendId, err := IdFromBytes(idBytes)
	return sendId, err == nil
}

// Whether standing lets the network send internet mail (the file header's standing row).
func mailOutboxStandingAllows(status *AbuseStatus) bool {
	if status == nil || !status.Verified {
		return false
	}
	switch status.Standing {
	case AbuseStandingStandard, AbuseStandingTrusted, AbuseStandingRestricted:
		return true
	}
	return false
}

// Writes args' entry at o/<h>/<effect_key>, created only if absent (see the file header). ErrMailOutboxStanding for a
// network that may send no internet mail; any other error leaves the entry unwritten or, where the write's answer was
// lost, maybe written, which a Queue under the same key settles.
func (self *MailOutbox) Queue(ctx context.Context, args *MailOutboxQueueArgs) (*MailOutboxQueued, error) {
	if args == nil || len(args.EffectKey) != mailEffectKeyByteCount || args.Sender == "" || len(args.Recipients) == 0 || len(args.Message) == 0 {
		return nil, ErrMailOutboxInvalid
	}
	path, err := MailOutboxPath(args.EffectKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailOutboxInvalid, err)
	}
	if self.standing == nil {
		return nil, fmt.Errorf("%w: no standing to read", ErrMailOutboxStanding)
	}
	status, err := self.standing(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailOutboxStanding, err)
	}
	if !mailOutboxStandingAllows(status) {
		return nil, ErrMailOutboxStanding
	}
	if self.sign == nil {
		return nil, fmt.Errorf("%w: no signer", ErrMailOutboxInvalid)
	}
	// one that stands answers the key: a retry, a restart's or another device's
	if _, err := self.mailbox.ReadOutbox(ctx, args.EffectKey); err == nil {
		return &MailOutboxQueued{EffectKey: bytes.Clone(args.EffectKey)}, nil
	} else if !errors.Is(err, ErrSmtpMailboxNotFound) && !errors.Is(err, ErrMailOutboxFileInvalid) {
		return nil, err
	}
	signed, err := SignSmtpOutboxEntry(&SmtpOutboundMessage{
		EffectKey:        args.EffectKey,
		Sender:           args.Sender,
		Recipients:       slices.Clone(args.Recipients),
		Message:          args.Message,
		Flags:            args.Flags,
		Tl4Domains:       slices.Clone(args.Tl4Domains),
		CreateTime:       self.clock.Now(),
		ApprovalNotAfter: args.ApprovalNotAfter,
	}, self.sign)
	if err != nil {
		return nil, err
	}
	if self.settings.OutboxSignedMaxByteCount < len(signed) {
		return nil, fmt.Errorf("%w: a signed entry past its bound", ErrMailOutboxInvalid)
	}
	content := mailOutboxFileBytes(signed, args.Message)
	if self.settings.OutboxFileMaxByteCount < len(content) {
		return nil, fmt.Errorf("%w: a message past the outbox's bound", ErrMailOutboxInvalid)
	}
	testHookBarrier("mail.outbox.queue.before", "")
	_, err = self.store.Write(ctx, []*mailStoreWrite{{Path: path, Content: content, IfVersion: 0}})
	testHookBarrier("mail.outbox.queue.after", "")
	if err == nil {
		return &MailOutboxQueued{EffectKey: bytes.Clone(args.EffectKey), Created: true}, nil
	}
	if !mailStoreConflictOn(err, path) {
		return nil, err
	}
	// another writer's entry stands under the key: that is this effect's one object
	if _, readErr := self.mailbox.ReadOutbox(ctx, args.EffectKey); readErr != nil {
		return nil, err
	}
	return &MailOutboxQueued{EffectKey: bytes.Clone(args.EffectKey)}, nil
}

// A kind mail use's Lookup (see the file header's lookup row): from the stored action and its key alone.
func (self *MailOutbox) Lookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	if _, err := MailOutboxPath(effectKey); err != nil {
		// no entry can stand under a key of another length
		return &SidecarOutcome{State: ApprovalOutcomeNotDone}, nil
	}
	file, err := self.mailbox.ReadOutbox(ctx, effectKey)
	switch {
	case err == nil:
		outcome := &SidecarOutcome{State: ApprovalOutcomeDone}
		if sendId, ok := mailOutboxSendIdOf(file.Message); ok {
			outcome.EffectRef = sendId.Bytes()
		}
		return outcome, nil
	case errors.Is(err, ErrMailOutboxFileInvalid):
		// something stands under the key that no Queue wrote: whether this use wrote first is not known
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	case !errors.Is(err, ErrSmtpMailboxNotFound):
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	_, err = self.mailbox.ReadOutcomes(ctx, effectKey)
	switch {
	case err == nil:
		return &SidecarOutcome{State: ApprovalOutcomeDone}, nil
	case errors.Is(err, ErrSmtpMailboxNotFound):
		return &SidecarOutcome{State: ApprovalOutcomeNotDone}, nil
	}
	return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
}
