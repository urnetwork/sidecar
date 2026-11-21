//go:build !sidecar_http && !ios_extension

// The outbox on a prover host (D-SMTP-18, D-SMTP-20, R-SMTP-6, I-8, I-11; SMTP-M9-09): a phone never proves, so
// its internet mail waits at o/<h>/<effect_key>, signed by its identity key (§15.7, plan-SMTP-wire-gaps#4), until
// one of its member's consented prover hosts sends it through SmtpSender. A desktop's own mail takes the same path,
// so one runner serves both.
//
//	take      only a consented device of the mailbox's member that proves takes an entry (§8.5, owner decision
//	          126); an agent sidecar holding a wrap, or a device whose consent is not given, takes none
//	verify    each entry's Signed is SIGNED_SMTP_OUTBOX under purpose smtp-outbox, by the identity key of an
//	          admitted device of the member, over a SmtpOutboxEntry naming this entry's effect key and its
//	          message's SHA-256; anything else is skipped, never sent, and counted as refused
//	pick      the rendezvous hash of the effect key over the member's consented hosts in p/ picks the one that
//	          sends (plan-SMTP-small-readings#10), so two hosts rarely collide; another takes over only once the
//	          picked one has shown no progress in or/ for OutboxTakeoverTimeout, or none at all that long after
//	          the entry's creation. A collision may send twice, which §22.7 allows
//	cap       a domain the sender found too_large is left, as deferred with its bytes, to a consented host whose
//	          recorded DATA cap fits, which takes it over by the same hash among the hosts that fit; too_large
//	          stands only when none fits (§14.5)
//	hold      a SmtpStatus hint on topic mail holds the whole queue until its retry_after_ms (SmtpStatusHold)
//	remove    o/ goes once every domain's outcome is an end and the approval's retry window, its not_after, has
//	          passed (§15.7, D-MCP-11); or/ stays its 30 days
//
// The TL4 domains an entry names pass only from an entry whose signature verified, for that message alone
// (plan-SMTP-small-readings#11): the runner hands them to Send as the message's own, and never keeps them. The
// message's SendId is the send its Message-ID names (MailOutboxSendIdOf; QD-1122), so the mail_send events this
// host's Send raises name the send the composing device answered, as or/'s send_id does.
//
// Nothing here logs an address, a domain or a byte of a message (I-13). Safe for concurrent use; RunOnce passes do
// not overlap.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose SIGNED_SMTP_OUTBOX signs under (plan-SMTP-wire-gaps#4). identity_sign.go names it as a literal on
// legs this file is off.
const SmtpOutboxPurpose = "smtp-outbox"

var (
	// An o/ entry this runner will not send: its Signed is not an admitted member device's over this entry.
	ErrSmtpOutboxEntryRefused = errors.New("smtp outbox entry refused")
)

// The host the rendezvous hash of effectKey picks among records' sidecars: the greatest SHA-256 of effectKey and
// the sidecar's id, and false for none.
func smtpRendezvousHost(effectKey []byte, records map[Id]*SmtpProverRecord) (Id, bool) {
	var picked Id
	var pickedScore []byte
	found := false
	for sidecarId := range records {
		score := sha256.Sum256(append(bytes.Clone(effectKey), sidecarId.Bytes()...))
		if !found || 0 < bytes.Compare(score[:], pickedScore) {
			picked, pickedScore, found = sidecarId, score[:], true
		}
	}
	return picked, found
}

// What one o/ entry gives once its signature verifies.
type SmtpOutboxMessage struct {
	Message *SmtpOutboundMessage
	// The composing device, which signed the entry.
	SignerId Id
	// Exactly the authenticated SmtpOutboxEntry, including fields a newer writer may have added.
	signedBody []byte
}

// Verifies one o/ entry: its Signed is SIGNED_SMTP_OUTBOX by signerKey's sidecar, over a SmtpOutboxEntry naming
// file's effect key and its message's SHA-256. memberDeviceKey answers the identity key of an admitted device of
// the mailbox's member, nil for any other sidecar. Everything refused is ErrSmtpOutboxEntryRefused. The message's
// SendId is the send its Message-ID names, the zero Id where it names none of MailOutboxMessageId's form.
func VerifySmtpOutboxEntry(file *SmtpOutboxFile, memberDeviceKey func(sidecarId Id) ed25519.PublicKey) (*SmtpOutboxMessage, error) {
	if file == nil || memberDeviceKey == nil {
		return nil, ErrSmtpOutboxEntryRefused
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(file.Signed, signed); err != nil {
		return nil, ErrSmtpOutboxEntryRefused
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, ErrSmtpOutboxEntryRefused
	}
	key := memberDeviceKey(signerId)
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrSmtpOutboxEntryRefused
	}
	if err := bridge.VerifySigned(signed, SmtpOutboxPurpose, bridge.SignedType_SIGNED_SMTP_OUTBOX, bridge.SignedKeyAlgEd25519, key); err != nil {
		return nil, ErrSmtpOutboxEntryRefused
	}
	entry := &protocol.SmtpOutboxEntry{}
	if err := proto.Unmarshal(signed.GetBody(), entry); err != nil {
		return nil, ErrSmtpOutboxEntryRefused
	}
	messageSha256 := sha256.Sum256(file.Message)
	if !bytes.Equal(entry.GetEffectKey(), file.EffectKey) || !bytes.Equal(entry.GetMessageSha256(), messageSha256[:]) {
		return nil, ErrSmtpOutboxEntryRefused
	}
	message := &SmtpOutboundMessage{
		EffectKey:  bytes.Clone(file.EffectKey),
		Sender:     entry.GetSender(),
		Recipients: slices.Clone(entry.GetRecipients()),
		Message:    bytes.Clone(file.Message),
		Flags:      entry.GetFlags(),
		Tl4Domains: slices.Clone(entry.GetTl4Domains()),
		CreateTime: time.UnixMilli(int64(min(entry.GetCreateTimeMs(), uint64(1)<<62))),
	}
	if notAfter := entry.GetApprovalNotAfter(); notAfter != 0 {
		message.ApprovalNotAfter = time.UnixMilli(int64(min(notAfter, uint64(1)<<62)))
	}
	if sendId, ok := MailOutboxSendIdOf(message.Message); ok {
		message.SendId = sendId
	}
	return &SmtpOutboxMessage{Message: message, SignerId: signerId, signedBody: signed.GetBody()}, nil
}

// SignSmtpOutboxEntry's signer: Sidecar.Sign, or a test's key.
type SmtpOutboxSigner func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error)

// The o/ entry for message as its composing device writes it (§15.10's step 4): the Signed's bytes over its
// SmtpOutboxEntry, which MAIL stores ahead of the message's bytes. MAIL writes o/; this is the form it signs.
func SignSmtpOutboxEntry(message *SmtpOutboundMessage, sign SmtpOutboxSigner) ([]byte, error) {
	if message == nil || len(message.EffectKey) == 0 || sign == nil {
		return nil, ErrSmtpSendInvalid
	}
	body, err := smtpOutboxEntryBody(message)
	if err != nil {
		return nil, err
	}
	signed, err := sign(SmtpOutboxPurpose, bridge.SignedType_SIGNED_SMTP_OUTBOX, body)
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// The deterministic bytes signed by the composing device. A sender also binds its encrypted
// per-recipient progress to this envelope when another host takes over.
func smtpOutboxEntryBody(message *SmtpOutboundMessage) ([]byte, error) {
	messageSha256 := sha256.Sum256(message.Message)
	entry := &protocol.SmtpOutboxEntry{
		EffectKey:     message.EffectKey,
		MessageSha256: messageSha256[:],
		Sender:        message.Sender,
		Recipients:    message.Recipients,
		Flags:         message.Flags,
		Tl4Domains:    message.Tl4Domains,
		CreateTimeMs:  uint64(max(message.CreateTime.UnixMilli(), 0)),
	}
	if !message.ApprovalNotAfter.IsZero() {
		entry.ApprovalNotAfter = uint64(max(message.ApprovalNotAfter.UnixMilli(), 0))
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(entry)
}

// What a runner is made of.
type SmtpOutboxRunnerArgs struct {
	Sender  *SmtpSender
	Mailbox SmtpMailbox
	// This host.
	SidecarId Id
	// The identity key of an admitted, consented device of the mailbox's member, nil for any other sidecar: what an
	// entry's signature and a p/ record's host are held to (§8.5, owner decision 126).
	MemberDeviceKey func(sidecarId Id) ed25519.PublicKey
	// Whether this host takes the member's mail at all: a consented device of the member, never an agent sidecar
	// holding a wrap. nil takes nothing.
	Consented func() bool
	// The queue's hold on SmtpStatus hints; nil holds nothing.
	Hold *SmtpStatusHold
	// The DATA cap this host records, its own p/'s, so the cap rule knows whether this host fits; nil is none.
	OwnCap func() uint64
	// Must have passed validate.
	Settings *SmtpSenderSettings
	Clock    Clock
	Log      Logger
}

// What one pass did, counted.
type SmtpOutboxPass struct {
	// Entries sent, each through one Send.
	Sent int
	// Entries left to the host the hash picks, or waiting on a hold or a cap.
	Left int
	// Entries whose signature did not verify, or that named another entry.
	Refused int
	// o/ entries removed: every outcome an end, past the approval's window.
	Removed int
	// The queue was held for this whole pass.
	Held bool
}

// The prover host's runner over the member's o/. See the file header.
type SmtpOutboxRunner struct {
	args     *SmtpOutboxRunnerArgs
	settings *SmtpSenderSettings
	clock    Clock
	log      Logger

	// one pass at a time
	passLock sync.Mutex
}

// A runner over args, whose Sender, Mailbox, MemberDeviceKey, Consented and Settings must be set.
func NewSmtpOutboxRunner(args *SmtpOutboxRunnerArgs) (*SmtpOutboxRunner, error) {
	if args == nil || args.Sender == nil || args.Mailbox == nil || args.MemberDeviceKey == nil || args.Consented == nil || args.Settings == nil {
		return nil, errors.New("smtp outbox runner: missing parts")
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &SmtpOutboxRunner{args: args, settings: args.Settings, clock: clockOrReal(args.Clock), log: log}, nil
}

// The member's consented hosts' p/ records.
func (self *SmtpOutboxRunner) memberRecords(ctx context.Context) (map[Id]*SmtpProverRecord, error) {
	records, err := self.args.Mailbox.ListProverRecords(ctx)
	if err != nil {
		return nil, err
	}
	for sidecarId := range records {
		if len(self.args.MemberDeviceKey(sidecarId)) != ed25519.PublicKeySize {
			delete(records, sidecarId)
		}
	}
	return records, nil
}

// Whether the entry's or/ shows a send that is alive: a queued outcome written within OutboxTakeoverTimeout.
func (self *SmtpOutboxRunner) liveElsewhere(outcomes []*SmtpDomainOutcome, now time.Time) bool {
	for _, outcome := range outcomes {
		if outcome.Outcome == SmtpOutcomeQueued && now.Before(outcome.UpdateTime.Add(self.settings.OutboxTakeoverTimeout)) {
			return true
		}
	}
	return false
}

// Whether every outcome is an end, so the entry has nothing left to send.
func smtpOutcomesEnded(outcomes []*SmtpDomainOutcome, domainCount int) bool {
	if len(outcomes) < domainCount {
		return false
	}
	for _, outcome := range outcomes {
		switch outcome.Outcome {
		case SmtpOutcomeSent, SmtpOutcomeRefused, SmtpOutcomeTooLarge, SmtpOutcomeTlsRefused, SmtpOutcomeFailed:
		default:
			return false
		}
	}
	return true
}

// The bytes of the largest message a domain of outcomes left deferred to a host whose cap fits, 0 for none.
func smtpCapDeferredByteCount(outcomes []*SmtpDomainOutcome) uint64 {
	byteCount := uint64(0)
	for _, outcome := range outcomes {
		if outcome.Outcome == SmtpOutcomeDeferred && outcome.CapByteCount == 0 {
			byteCount = max(byteCount, outcome.ByteCount)
		}
	}
	return byteCount
}

// Whether this host takes the entry now: the hash picks it among the hosts that fit the entry's needs, or the
// pick has shown no progress for OutboxTakeoverTimeout.
func (self *SmtpOutboxRunner) takes(message *SmtpOutboundMessage, outcomes []*SmtpDomainOutcome, records map[Id]*SmtpProverRecord, now time.Time) bool {
	if self.liveElsewhere(outcomes, now) {
		return false
	}
	candidates := records
	if needed := smtpCapDeferredByteCount(outcomes); needed != 0 {
		// a domain left for a host whose cap fits: the hash runs over those alone
		candidates = map[Id]*SmtpProverRecord{}
		for sidecarId, record := range records {
			if needed <= record.Measure.DataProofBytes {
				candidates[sidecarId] = record
			}
		}
		if self.args.OwnCap == nil || self.args.OwnCap() < needed {
			return false
		}
	}
	picked, ok := smtpRendezvousHost(message.EffectKey, candidates)
	if !ok || picked == self.args.SidecarId {
		// no host recorded p/ yet, or this one is the pick
		return true
	}
	// the pick never started: another host takes over once the entry is that old
	newest := message.CreateTime
	for _, outcome := range outcomes {
		if outcome.UpdateTime.After(newest) {
			newest = outcome.UpdateTime
		}
	}
	return !now.Before(newest.Add(self.settings.OutboxTakeoverTimeout))
}

// Rewrites each too_large domain as deferred with its bytes when a consented host's recorded cap fits it, so that
// host takes it over; too_large stands where none does.
func (self *SmtpOutboxRunner) leaveTooLarge(ctx context.Context, message *SmtpOutboundMessage, result *SmtpSendResult, records map[Id]*SmtpProverRecord) error {
	changed := false
	for _, outcome := range result.Domains {
		if outcome.Outcome != SmtpOutcomeTooLarge {
			continue
		}
		for sidecarId, record := range records {
			if sidecarId != self.args.SidecarId && outcome.ByteCount <= record.Measure.DataProofBytes {
				outcome.Outcome = SmtpOutcomeDeferred
				outcome.CapByteCount = 0
				outcome.RetryAfter = 0
				outcome.UpdateTime = self.clock.Now()
				changed = true
				break
			}
		}
	}
	if !changed {
		return nil
	}
	return self.args.Mailbox.WriteOutcomes(ctx, message.EffectKey, result.Domains)
}

// One pass over o/: each entry this host may take now is sent, each that is done and past its window removed. An
// error is the mailbox's, and the pass stops there; an entry that fails alone is counted and skipped.
func (self *SmtpOutboxRunner) RunOnce(ctx context.Context) (*SmtpOutboxPass, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	pass := &SmtpOutboxPass{}
	if !self.args.Consented() {
		return pass, nil
	}
	if self.args.Hold != nil {
		if held, _ := self.args.Hold.Held(); held {
			pass.Held = true
			return pass, nil
		}
	}
	effectKeys, err := self.args.Mailbox.ListOutbox(ctx)
	if err != nil {
		return nil, err
	}
	records, err := self.memberRecords(ctx)
	if err != nil {
		return nil, err
	}
	for _, effectKey := range effectKeys {
		if err := ctx.Err(); err != nil {
			return pass, err
		}
		file, err := self.args.Mailbox.ReadOutbox(ctx, effectKey)
		if errors.Is(err, ErrSmtpMailboxNotFound) {
			continue
		}
		if err != nil {
			return pass, err
		}
		verified, err := VerifySmtpOutboxEntry(file, self.args.MemberDeviceKey)
		if err != nil {
			pass.Refused += 1
			continue
		}
		message := verified.Message
		outcomes, err := self.args.Mailbox.ReadOutcomes(ctx, effectKey)
		if err != nil && !errors.Is(err, ErrSmtpMailboxNotFound) {
			return pass, err
		}
		now := self.clock.Now()
		domainCount := smtpDomainCount(message.Recipients)
		if smtpOutcomesEnded(outcomes, domainCount) {
			if message.ApprovalNotAfter.IsZero() || !now.Before(message.ApprovalNotAfter) {
				if err := self.args.Mailbox.RemoveOutbox(ctx, effectKey); err != nil {
					return pass, err
				}
				pass.Removed += 1
			}
			continue
		}
		if self.args.Sender.localMeasure() == nil || !self.takes(message, outcomes, records, now) {
			pass.Left += 1
			continue
		}
		result, err := self.args.Sender.send(ctx, message, verified.signedBody)
		if err != nil {
			if self.log.V(1).Enabled() {
				self.log.Infof("[smtp]outbox %s: not sent: %v\n", hex.EncodeToString(effectKey), err)
			}
			pass.Left += 1
			continue
		}
		if err := self.leaveTooLarge(ctx, message, result, records); err != nil {
			return pass, err
		}
		pass.Sent += 1
	}
	return pass, nil
}

// The recipient domains of recipients, each once.
func smtpDomainCount(recipients []string) int {
	domains := []string{}
	for _, recipient := range recipients {
		if _, domain, ok := SplitSmtpEnvelopeAddress(recipient); ok && !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return len(domains)
}

// Runs passes until ctx ends: one at once, then each OutboxPollInterval, at a hold's end, and at each wake (a push
// hint on topic mail, a new o/ entry). Called once, by the daemon's composition.
func (self *SmtpOutboxRunner) Run(ctx context.Context, wake <-chan struct{}) {
	for {
		if _, err := self.RunOnce(ctx); err != nil && ctx.Err() == nil {
			self.log.Warningf("[smtp]outbox pass: %v\n", err)
		}
		wait := self.settings.OutboxPollInterval
		if self.args.Hold != nil {
			if held, until := self.args.Hold.Held(); held {
				wait = min(wait, max(until.Sub(self.clock.Now()), 0))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-self.clock.After(wait):
		}
	}
}
