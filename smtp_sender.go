//go:build !sidecar_http && !ios_extension

// SmtpSender: §14.5's send capability, the sidecar's half of outbound internet mail (§14.9's table, D-SMTP-2,
// D-SMTP-20, R-SMTP-6, I-11; SMTP-M9-08). MAIL hands it a finished message (§15.10's step 4), and Send makes one
// connection a recipient domain with all of that domain's recipients, and returns one outcome a domain:
//
//	split     recipients by domain, in the order each domain first appears; a domain's recipients are never
//	          split over connections, since the envelope goes in groups inside the prover (owner decision 434,
//	          DESIGN-DETAILS 3.7); the tier's smtp_recipients_per_message is the edge's to hold, QUOTA past it
//	assembly  once for every domain: Bcc gone from the header block, the relation's normal form, the issued
//	          values' room (AssembleSmtpMessage); a message assembly refuses fails at every domain, with a DSN
//	mode      the domain's pin's post-TLS mode, else BDAT, declares the count (plan-SMTP-preamble-byte-count);
//	          a mismatch reconnects once with the other count and retry_of_send_id, a second is deferred
//	envelope  MAIL FROM is the message's Sender, or what SmtpSenderArgs.Envelope answers at each attempt: the
//	          bounce address at the envelope the edge derives then, which strict mode moves (QD-1129)
//	outcomes  sent; queued (no ready key set: the host only queues, D-SMTP-18); deferred with retry_after_ms
//	          (HALTED, QUOTA, TRY_LATER, KEYS, a temporary failure, a host whose cap is under the bytes, the day's
//	          retry units spent); too_large with the bytes and the cap; refused with the MX's code; tls_refused
//	          (TL4, below a pin, REQUIRETLS short of TL2); failed. A held send never reports failed while it holds
//	keys      KEYS tries the next older key set the prover host reports ready, once, else deferred for
//	          KeysRetryTimeout, leaving an outbox entry for another host (DESIGN-DETAILS 3.7)
//	groups    EnvelopeRetry retries once with EnvelopeGroupMaxCount at EnvelopeRetryGroupCount and
//	          retry_of_send_id, the count kept on the MX host's pin entry beside its mode; a second is failed
//	mixed     a send refused at some RCPTs and taken at others resends at once to the taken ones alone, on a new
//	          connection and a new unit; the refused get a DSN, and a 4xx's recipients wait for the next retry
//	retries   new connections, new units (§14.7), on SmtpRetryPolicy's schedule; at most
//	          RetryUnitsPerMessagePerDay units a UTC day for a message's retries
//	DSNs      every end but sent, RFC 3464 (smtp_dsn.go), deposited to the sending mailbox through SmtpMailbox
//	labels    each domain's outcome carries tls_level, its I-11 label, which or/ keeps for the sent copy
//	events    SidecarEvent mail_send, naming the message's send id, for each domain whose outcome changed
//	receipts  a ReachReceipt note for each recipient an MX took, Bcc recipients included (§16.8)
//
// or/ (§15.7) holds the outcomes, under the message's effect key: Send reads it first, keeps a domain's final
// outcome and a deferral not yet due, takes over a queued one that has not changed for OutboxTakeoverTimeout,
// writes queued for each domain as it starts, rewrites it every OutboxProgressInterval while the send runs, and
// writes each result as it comes. A replay after a crash between MAIL and the result therefore sends that
// domain at most once more and says so in ResentDomains: the effect key finds the earlier outcome, and mail
// claims no exactly-once SMTP (§22.7).
//
// Sends prove one at a time on the host by default (ProverConcurrency, 1, for 8 GB hosts), a slot held from the
// dial to the outcome, so the edge's idle timers never run while the send waits for the prover. Close cancels
// every send, which resets each stream under its prover, and joins them.
//
// Copy (§14.5): only too_large cites the DATA cap, naming that domain, the size and the cap, and no outcome or
// DSN names an inbound indexer, receiver or coverage setting. Nothing here logs an address, a domain, a subject or
// a byte of a message (I-13).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// What Send was handed does not hold together: no effect key, a sender or recipient that is no envelope
	// address, unknown flags, or no message. Names no address.
	ErrSmtpSendInvalid = errors.New("smtp send: invalid message")
	// The sender has closed.
	ErrSmtpSenderClosed = errors.New("smtp sender closed")
)

// What a network's sender is made of. Dialer, Policy, Pins, Dkim, Mailbox and Settings are needed; the rest may
// be nil.
type SmtpSenderArgs struct {
	// smtpedge through ur/smtpedge: NewSidecarSmtpEdgeDialer's in a daemon.
	Dialer SmtpEdgeDialer
	// The prover cli injects on desktop builds; nil, as on a phone, only queues (D-SMTP-18).
	Prover SmtpProver
	Policy *SmtpTlsPolicy
	Pins   *SmtpPinStore
	Dkim   *SmtpDkimKeys
	// The member's mailbox: or/ for the outcomes, the DSN deposits, and p/ for Check's caps.
	Mailbox SmtpMailbox
	// Whether a sidecar is one of the mailbox owner's consented devices (§8.5; owner decision 126), whose p/ records
	// alone Check reads; nil counts none.
	MemberDevice func(sidecarId Id) bool
	// The host's last measure (SmtpProverHost.Measure), for Check's cap and delay and too_large's cap; nil
	// reads none.
	Measure func() *SmtpProverMeasure
	// The key sets the host's last PrepareKeys reported ready, newest first, which KEYS falls back on; nil
	// reads none.
	ReadyKeySets func() [][]byte
	// Taken as a send starts proving and released as it ends, so the prover host stops its idle key checks
	// for the send (SmtpProverHost.HoldForSend); nil holds nothing.
	SendHold func() (release func())
	// §16.8's reach receipts (RecordReach.Note); nil writes none.
	Reach func(note *RecordReachNote) error
	// The mail_send grant a message's receipts name; nil, or a nil answer, writes none.
	ReachGrant func(message *SmtpOutboundMessage) *SmtpReachGrant
	// Where mail_send events go (the Sidecar's emitEvent); nil raises none.
	Events func(event SidecarEvent)
	// The envelope sender a domain's connections take for a message whose header From is in headerFromDomain, asked
	// at each attempt once its proving slot is held: MAIL's bounce address at the envelope the edge derives now from
	// the network's custom domains in strict mode (MailClient.BounceSender; QD-1129), since a strict-mode MX host
	// mapped or unmapped after the message was queued moves it, and MAIL FROM away from the edge's envelope is a cut
	// (§14.7). Nil sends at the message's own Sender. An error holds the domain's send for its next retry.
	Envelope func(ctx context.Context, headerFromDomain string) (string, error)
	// The preamble frames' bound; nil is DefaultSmtpFrameSettings'.
	Frame *SmtpFrameSettings
	// Must have passed validate.
	Settings *SmtpSenderSettings
	// nil is real time.
	Clock Clock
	// nil is silence.
	Log Logger
}

// One domain's send state that outlives a Send in this process: what a retry starts from.
type smtpDomainRetry struct {
	// the last connection's send_id, which the next names as retry_of_send_id
	retryOfSendId []byte
	// recipients already taken, which a retry leaves out, and those still to send; nil is every recipient
	delivered []string
}

// One network's sender. See the file header.
type SmtpSender struct {
	args       *SmtpSenderArgs
	settings   *SmtpSenderSettings
	clock      Clock
	log        Logger
	connection *smtpConnection
	retry      *SmtpRetryPolicy
	units      *SmtpRetryUnits
	// ProverConcurrency slots
	proving chan struct{}

	ctx     context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	stateLock sync.Mutex
	closed    bool
	// effect keys with a Send running in this process
	sendingEffectKeys map[string]bool
	// by effect key and domain
	domainRetries map[string]*smtpDomainRetry
	// DSNs made or received since the last SmtpOutcome that went, and the hard bounces among them
	dsnCount        uint32
	hardBounceCount uint32
}

// A sender over args. See SmtpSenderArgs for what must be set.
func NewSmtpSender(args *SmtpSenderArgs) (*SmtpSender, error) {
	if args == nil || args.Dialer == nil || args.Policy == nil || args.Pins == nil || args.Dkim == nil ||
		args.Mailbox == nil || args.Settings == nil {
		return nil, errors.New("smtp sender: missing parts")
	}
	if err := args.Settings.validate(); err != nil {
		return nil, err
	}
	clock := clockOrReal(args.Clock)
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	frame := args.Frame
	if frame == nil {
		frame = DefaultSmtpFrameSettings()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &SmtpSender{
		args:     args,
		settings: args.Settings,
		clock:    clock,
		log:      log,
		connection: &smtpConnection{
			dialer:   args.Dialer,
			prover:   args.Prover,
			policy:   args.Policy,
			dkim:     args.Dkim,
			frame:    frame,
			settings: args.Settings,
			clock:    clock,
			log:      log,
		},
		retry:             NewSmtpRetryPolicy(args.Settings),
		units:             NewSmtpRetryUnits(args.Settings),
		proving:           make(chan struct{}, args.Settings.ProverConcurrency),
		ctx:               ctx,
		cancel:            cancel,
		sendingEffectKeys: map[string]bool{},
		domainRetries:     map[string]*smtpDomainRetry{},
	}, nil
}

// Cancels every send, each stream reset under its prover, and returns once they have all ended. Send then
// answers ErrSmtpSenderClosed.
func (self *SmtpSender) Close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	self.cancel()
	self.workers.Wait()
}

// Counts a DSN received for this network's mail, such as a late bounce MAIL deposits (MAIL-M9-05), so the next
// SmtpOutcome reports it (§14.8's self-reports); hard is a 5.x.x.
func (self *SmtpSender) NoteDsn(hard bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dsnCount += 1
	if hard {
		self.hardBounceCount += 1
	}
}

// The DSN counts the next SmtpOutcome carries.
func (self *SmtpSender) dsnCounts() (uint32, uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.dsnCount, self.hardBounceCount
}

// Takes reported counts off once an outcome carrying them went.
func (self *SmtpSender) dsnCountsSent(dsnCount uint32, hardBounceCount uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dsnCount -= min(dsnCount, self.dsnCount)
	self.hardBounceCount -= min(hardBounceCount, self.hardBounceCount)
}

// One recipient domain of a send.
type smtpDomainPlan struct {
	// lowercase, with no trailing dot
	domain string
	// addr-specs, the domain lowercase, in the order named, each once
	recipients []string
}

// What Send works from, once the message is checked.
type smtpSendPlan struct {
	message *SmtpOutboundMessage
	domains []*smtpDomainPlan
	// nil when assembly refused the message, assembleErr saying why
	wire        *SmtpWireMessage
	assembleErr error
	// the DSN's To: the From's address, else the envelope sender
	dsnTo string
	// the original's header block for DSNs, Bcc gone
	dsnHeaders []byte
	// the envelope sender's domain, b.<net>.<root>
	envelopeDomain string
}

// The domains of a header block's From and Message-ID, and the From's address, as MAIL wrote them. Assembly
// holds each to its form; this only finds them.
func smtpMessageDomains(message []byte) (fromAddress string, fromDomain string, messageIdDomain string) {
	normalized, err := smtpNormalizeLines(message)
	if err != nil {
		return "", "", ""
	}
	header, _ := smtpSplitMessage(normalized)
	fields, err := smtpParseFields(header)
	if err != nil {
		return "", "", ""
	}
	for _, field := range fields {
		switch {
		case field.is("From") && fromAddress == "":
			if parsed, err := mail.ParseAddress(field.value); err == nil {
				fromAddress = parsed.Address
				if _, domain, ok := strings.Cut(parsed.Address, "@"); ok {
					fromDomain = strings.ToLower(domain)
				}
			}
		case field.is("Message-ID") && messageIdDomain == "":
			value := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(field.value), "<"), ">")
			if _, domain, ok := strings.Cut(value, "@"); ok {
				messageIdDomain = strings.ToLower(domain)
			}
		}
	}
	return fromAddress, fromDomain, messageIdDomain
}

// The header block of message with every Bcc field gone, for a DSN to return.
func smtpDsnHeaders(message []byte) []byte {
	normalized, err := smtpNormalizeLines(message)
	if err != nil {
		return nil
	}
	header, _ := smtpSplitMessage(normalized)
	fields, err := smtpParseFields(header)
	if err != nil {
		return nil
	}
	var out bytes.Buffer
	for _, field := range fields {
		if field.is("Bcc") {
			continue
		}
		folded, err := smtpFoldLine(field.line())
		if err != nil {
			continue
		}
		out.Write(folded)
	}
	return out.Bytes()
}

// Checks message and splits it by domain. An error is ErrSmtpSendInvalid's; a message assembly refuses is a plan
// whose every domain fails.
func (self *SmtpSender) plan(message *SmtpOutboundMessage) (*smtpSendPlan, error) {
	if message == nil || len(message.EffectKey) == 0 || len(message.Message) == 0 || message.Flags&^SmtpFlagsKnown != 0 {
		return nil, ErrSmtpSendInvalid
	}
	_, envelopeDomain, ok := SplitSmtpEnvelopeAddress(message.Sender)
	if !ok {
		return nil, fmt.Errorf("%w: the envelope sender", ErrSmtpSendInvalid)
	}
	plan := &smtpSendPlan{message: message, envelopeDomain: envelopeDomain}
	seen := map[string]bool{}
	for _, recipient := range message.Recipients {
		local, domain, ok := SplitSmtpEnvelopeAddress(recipient)
		if !ok {
			return nil, fmt.Errorf("%w: a recipient", ErrSmtpSendInvalid)
		}
		address := local + "@" + domain
		if seen[address] {
			continue
		}
		seen[address] = true
		index := slices.IndexFunc(plan.domains, func(domainPlan *smtpDomainPlan) bool { return domainPlan.domain == domain })
		if index < 0 {
			index = len(plan.domains)
			plan.domains = append(plan.domains, &smtpDomainPlan{domain: domain})
		}
		plan.domains[index].recipients = append(plan.domains[index].recipients, address)
	}
	if len(plan.domains) == 0 {
		return nil, fmt.Errorf("%w: no recipient", ErrSmtpSendInvalid)
	}
	fromAddress, fromDomain, messageIdDomain := smtpMessageDomains(message.Message)
	plan.dsnTo = fromAddress
	if plan.dsnTo == "" {
		plan.dsnTo = message.Sender
	}
	plan.dsnHeaders = smtpDsnHeaders(message.Message)
	plan.wire, plan.assembleErr = AssembleSmtpMessage(&SmtpAssembleArgs{
		Message:          message.Message,
		HeaderFromDomain: fromDomain,
		MessageIdDomain:  messageIdDomain,
		Flags:            message.Flags,
		Now:              self.clock.Now(),
		Settings:         self.settings,
	})
	return plan, nil
}

// Takes one send's place: false once closed, or while another Send of the same effect key runs here.
func (self *SmtpSender) startSend(effectKey []byte) (started bool, closed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return false, true
	}
	if self.sendingEffectKeys[string(effectKey)] {
		return false, false
	}
	self.sendingEffectKeys[string(effectKey)] = true
	self.workers.Add(1)
	return true, false
}

// Gives back startSend's place.
func (self *SmtpSender) endSend(effectKey []byte) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.sendingEffectKeys, string(effectKey))
	}()
	self.workers.Done()
}

// What an earlier outcome means for this Send: kept, or sent again, and whether that send may repeat an attempt
// the MX took.
func (self *SmtpSender) replay(earlier *SmtpDomainOutcome, now time.Time) (keep bool, resend bool) {
	if earlier == nil {
		return false, false
	}
	switch earlier.Outcome {
	case SmtpOutcomeSent, SmtpOutcomeRefused, SmtpOutcomeTooLarge, SmtpOutcomeTlsRefused, SmtpOutcomeFailed:
		return true, false
	case SmtpOutcomeDeferred:
		return now.Before(earlier.UpdateTime.Add(earlier.RetryAfter)), false
	case SmtpOutcomeQueued:
		// an attempt that began and stopped writing its progress: taken over, and maybe sent twice
		if now.Before(earlier.UpdateTime.Add(self.settings.OutboxTakeoverTimeout)) {
			return true, false
		}
		return false, true
	}
	return false, false
}

// Sends message: see the file header. An error is the whole send's: an invalid message, a mailbox that cannot
// answer (the send is held), or a closed sender. Otherwise every domain has its outcome in the answer, in the
// order each domain first appears among the recipients.
func (self *SmtpSender) Send(ctx context.Context, message *SmtpOutboundMessage) (*SmtpSendResult, error) {
	plan, err := self.plan(message)
	if err != nil {
		return nil, err
	}
	started, closed := self.startSend(message.EffectKey)
	if closed {
		return nil, ErrSmtpSenderClosed
	}
	if !started {
		// another Send of this message runs here: what or/ says is its answer
		return self.currentResult(ctx, plan)
	}
	defer self.endSend(message.EffectKey)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopClose := context.AfterFunc(self.ctx, cancel)
	defer stopClose()

	if self.args.Prover == nil || len(self.args.Prover.KeySet()) == 0 {
		// a host with no ready key set only queues: its outbox entry waits for a prover host (D-SMTP-18)
		result := &SmtpSendResult{EffectKey: bytes.Clone(message.EffectKey)}
		now := self.clock.Now()
		for _, domainPlan := range plan.domains {
			result.Domains = append(result.Domains, &SmtpDomainOutcome{Domain: domainPlan.domain, Outcome: SmtpOutcomeQueued, UpdateTime: now})
		}
		return result, nil
	}

	earlierOutcomes, err := self.args.Mailbox.ReadOutcomes(ctx, message.EffectKey)
	if err != nil && !errors.Is(err, ErrSmtpMailboxNotFound) {
		return nil, err
	}
	earlierByDomain := map[string]*SmtpDomainOutcome{}
	for _, earlier := range earlierOutcomes {
		earlierByDomain[earlier.Domain] = earlier
	}
	now := self.clock.Now()
	outcomes := &smtpOutcomeBoard{sender: self, effectKey: message.EffectKey, sendId: message.SendId}
	result := &SmtpSendResult{EffectKey: bytes.Clone(message.EffectKey)}
	toSend := []*smtpDomainPlan{}
	for _, domainPlan := range plan.domains {
		earlier := earlierByDomain[domainPlan.domain]
		keep, resend := self.replay(earlier, now)
		if keep {
			outcomes.keep(earlier)
			continue
		}
		if resend {
			result.ResentDomains = append(result.ResentDomains, domainPlan.domain)
		}
		outcomes.set(&SmtpDomainOutcome{Domain: domainPlan.domain, Outcome: SmtpOutcomeQueued, UpdateTime: now}, earlier)
		toSend = append(toSend, domainPlan)
	}
	// queued as each starts, before any connection, so a crash between MAIL and the result is seen
	if len(toSend) != 0 {
		if err := outcomes.write(ctx); err != nil {
			return nil, err
		}
	}
	stopProgress := outcomes.progress(ctx)
	for _, domainPlan := range toSend {
		outcome := self.sendDomain(ctx, plan, domainPlan, earlierByDomain[domainPlan.domain])
		outcomes.set(outcome, earlierByDomain[domainPlan.domain])
		if err := outcomes.write(ctx); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[smtp]send %s: or/ was not written: %v\n", hex.EncodeToString(message.EffectKey), err)
		}
	}
	stopProgress()
	outcomes.emitChanged()
	for _, domainPlan := range plan.domains {
		result.Domains = append(result.Domains, outcomes.of(domainPlan.domain))
	}
	return result, nil
}

// The outcomes or/ holds for plan, queued for a domain it names none of: what a second Send of a running one
// answers.
func (self *SmtpSender) currentResult(ctx context.Context, plan *smtpSendPlan) (*SmtpSendResult, error) {
	earlierOutcomes, err := self.args.Mailbox.ReadOutcomes(ctx, plan.message.EffectKey)
	if err != nil && !errors.Is(err, ErrSmtpMailboxNotFound) {
		return nil, err
	}
	result := &SmtpSendResult{EffectKey: bytes.Clone(plan.message.EffectKey)}
	for _, domainPlan := range plan.domains {
		index := slices.IndexFunc(earlierOutcomes, func(outcome *SmtpDomainOutcome) bool { return outcome.Domain == domainPlan.domain })
		if index < 0 {
			result.Domains = append(result.Domains, &SmtpDomainOutcome{Domain: domainPlan.domain, Outcome: SmtpOutcomeQueued, UpdateTime: self.clock.Now()})
			continue
		}
		result.Domains = append(result.Domains, earlierOutcomes[index])
	}
	return result, nil
}

// The retry state of one domain of one message.
func (self *SmtpSender) domainRetry(effectKey []byte, domain string) *smtpDomainRetry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := string(effectKey) + "\x00" + domain
	retry := self.domainRetries[key]
	if retry == nil {
		retry = &smtpDomainRetry{}
		self.domainRetries[key] = retry
	}
	return retry
}

// Forgets a domain's retry state once its outcome is an end.
func (self *SmtpSender) forgetDomainRetry(effectKey []byte, domain string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.domainRetries, string(effectKey)+"\x00"+domain)
}

// The ready key sets to try, newest first: the prover's own first, then the host's older ones.
func (self *SmtpSender) keySets() [][]byte {
	keySets := [][]byte{}
	if keySet := self.args.Prover.KeySet(); len(keySet) != 0 {
		keySets = append(keySets, keySet)
	}
	if self.args.ReadyKeySets != nil {
		for _, keySet := range self.args.ReadyKeySets() {
			if len(keySet) != 0 && !slices.ContainsFunc(keySets, func(held []byte) bool { return bytes.Equal(held, keySet) }) {
				keySets = append(keySets, keySet)
			}
		}
	}
	return keySets
}

// The DATA cap the host's last measure records, 0 when none.
func (self *SmtpSender) dataProofByteCount() uint64 {
	if self.args.Measure == nil {
		return 0
	}
	if measure := self.args.Measure(); measure != nil {
		return measure.DataProofBytes
	}
	return 0
}

// Waits for a proving slot, and the prover host's hold, until ctx ends.
func (self *SmtpSender) takeProvingSlot(ctx context.Context) (release func(), err error) {
	select {
	case self.proving <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	releaseHold := func() {}
	if self.args.SendHold != nil {
		releaseHold = self.args.SendHold()
	}
	return func() {
		releaseHold()
		<-self.proving
	}, nil
}

// One domain's send, from its first connection to its outcome, with every immediate reconnect §14.5 and
// DESIGN-DETAILS 3.7 allow, and the DSN an end gives.
func (self *SmtpSender) sendDomain(ctx context.Context, plan *smtpSendPlan, domainPlan *smtpDomainPlan, earlier *SmtpDomainOutcome) *SmtpDomainOutcome {
	message := plan.message
	domain := domainPlan.domain
	outcome := &SmtpDomainOutcome{Domain: domain}
	end := func(kind SmtpOutcomeKind, dsn *SmtpDsn) *SmtpDomainOutcome {
		outcome.Outcome = kind
		outcome.UpdateTime = self.clock.Now()
		self.forgetDomainRetry(message.EffectKey, domain)
		if dsn != nil {
			self.depositDsn(ctx, plan, domain, dsn)
		}
		return outcome
	}
	hold := func(next time.Time, held bool, reason string) *SmtpDomainOutcome {
		now := self.clock.Now()
		if !held {
			// past the give-up time: the message ends with a DSN
			return end(SmtpOutcomeFailed, &SmtpDsn{
				Outcome:    SmtpOutcomeFailed,
				Recipients: self.dsnRecipients(domainPlan.recipients, smtpDsnStatusExpired, 0),
				Reason:     "It could not be delivered within " + smtpDurationText(self.settings.RetryGiveUpTimeout) + ". " + reason,
			})
		}
		outcome.Outcome = SmtpOutcomeDeferred
		outcome.RetryAfter = max(next.Sub(now), 0)
		outcome.UpdateTime = now
		return outcome
	}
	scheduled := func(reason string) *SmtpDomainOutcome {
		next, held := self.retry.Next(message.CreateTime, self.clock.Now())
		return hold(next, held, reason)
	}
	if plan.wire == nil {
		return end(SmtpOutcomeFailed, &SmtpDsn{
			Outcome:    SmtpOutcomeFailed,
			Recipients: self.dsnRecipients(domainPlan.recipients, smtpDsnStatusOther, 0),
			Reason:     "The message's headers could not be brought into the form a provable send needs.",
		})
	}
	retryState := self.domainRetry(message.EffectKey, domain)
	pending := slices.DeleteFunc(slices.Clone(domainPlan.recipients), func(recipient string) bool {
		return slices.Contains(retryState.delivered, recipient)
	})
	if len(pending) == 0 {
		outcome.Outcome = SmtpOutcomeSent
		outcome.UpdateTime = self.clock.Now()
		self.forgetDomainRetry(message.EffectKey, domain)
		return outcome
	}
	// a retry's units: at most RetryUnitsPerMessagePerDay a UTC day
	isRetry := earlier != nil
	if isRetry {
		if allowed, nextDay := self.units.Allows(message.EffectKey, self.clock.Now()); !allowed {
			return hold(nextDay, nextDay.Before(self.retry.GiveUpTime(message.CreateTime)), "")
		}
	}

	mode, err := self.args.Pins.DomainMode(domain)
	if err != nil {
		return scheduled("")
	}
	if mode == SmtpModeUnknown {
		mode = SmtpModeBdat
	}
	groupMaxCount, err := self.args.Pins.EnvelopeGroupMaxCount(domain)
	if err != nil {
		return scheduled("")
	}
	keySets := self.keySets()
	if len(keySets) == 0 {
		outcome.Outcome = SmtpOutcomeQueued
		outcome.UpdateTime = self.clock.Now()
		return outcome
	}
	release, err := self.takeProvingSlot(ctx)
	if err != nil {
		return scheduled("")
	}
	defer release()
	// the envelope as the edge derives it now, read once the slot is held so no wait for it can stale the read
	sender := message.Sender
	if self.args.Envelope != nil {
		sender, err = self.args.Envelope(ctx, plan.wire.HeaderFromDomain())
		if err != nil {
			return scheduled("")
		}
	}

	keySetIndex := 0
	reconnected, envelopeRetried, resent := false, false, false
	refused := []*SmtpDsnRecipient{}
	// recipients a 4xx at RCPT left for the next retry
	temporary := []string{}
	delivered := slices.Clone(retryState.delivered)
	retryOfSendId := retryState.retryOfSendId
	for {
		dsnCount, hardBounceCount := self.dsnCounts()
		locals := make([]string, 0, len(pending))
		for _, recipient := range pending {
			local, _, _ := SplitSmtpEnvelopeAddress(recipient)
			locals = append(locals, local)
		}
		connectionResult := self.connection.Run(ctx, &smtpConnectionArgs{
			EffectKey:             message.EffectKey,
			Wire:                  plan.wire,
			SenderAddress:         sender,
			RecipientDomain:       domain,
			RecipientLocals:       locals,
			Flags:                 message.Flags,
			MessageTl4Domains:     message.Tl4Domains,
			Mode:                  mode,
			RetryOfSendId:         retryOfSendId,
			KeySet:                keySets[keySetIndex],
			EnvelopeGroupMaxCount: groupMaxCount,
			DsnCount:              dsnCount,
			HardBounceCount:       hardBounceCount,
		})
		if connectionResult.OutcomeSent {
			self.dsnCountsSent(dsnCount, hardBounceCount)
		}
		if connectionResult.MailMayHaveGone() && (isRetry || reconnected || envelopeRetried || resent) {
			self.units.Spend(message.EffectKey, self.clock.Now())
		}
		if len(connectionResult.SendId) != 0 {
			retryOfSendId = connectionResult.SendId
			retryState.retryOfSendId = connectionResult.SendId
		}
		outcome.TlsLevel = connectionResult.TlsLevel
		if connectionResult.Proof != nil && connectionResult.Proof.Mode != 0 {
			outcome.Mode = SmtpMode(connectionResult.Proof.Mode)
		}
		if self.log.V(2).Enabled() {
			self.log.Infof("[smtp]send %s: %s\n", hex.EncodeToString(message.EffectKey), connectionResult.describe())
		}

		switch {
		case connectionResult.NoProver:
			outcome.Outcome = SmtpOutcomeQueued
			outcome.UpdateTime = self.clock.Now()
			return outcome
		case connectionResult.KeysRefused:
			if keySetIndex+1 < len(keySets) && keySetIndex == 0 {
				keySetIndex += 1
				continue
			}
			next, held := self.retry.Hold(message.CreateTime, self.clock.Now(), self.settings.KeysRetryTimeout)
			return hold(next, held, "")
		case connectionResult.EnvelopeRefused:
			// the edge's facts and this attempt's strict domains differ: the next attempt reads them again once the
			// edge's refresh has passed (QD-1154)
			next, held := self.retry.Hold(message.CreateTime, self.clock.Now(), self.settings.EnvelopeRetryTimeout)
			return hold(next, held, "")
		}
		switch connectionResult.PreambleCode {
		case protocol.SmtpPreambleCode_SMTP_PREAMBLE_CODE_UNSPECIFIED:
			if errors.Is(connectionResult.Err, ErrSmtpDkimPublishRefused) {
				return end(SmtpOutcomeFailed, &SmtpDsn{
					Outcome:    SmtpOutcomeFailed,
					Recipients: self.dsnRecipients(pending, smtpDsnStatusOther, 0),
					Reason:     "This device's signing key for the sender's domain was refused, so the message could not be signed.",
				})
			}
			if errors.Is(connectionResult.Err, ErrSmtpDkimSelectorUnanswered) {
				// a custom domain's first selector awaits the domain's answer (QD-1130): held, and named if it ends
				return scheduled("The sender's domain does not publish this device's signing key yet: a network admin adds the DKIM CNAME the network's DNS settings list.")
			}
			return scheduled("")
		case protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA,
			protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER:
			next, held := self.retry.Hold(message.CreateTime, self.clock.Now(), time.Duration(connectionResult.RetryAfterMillis)*time.Millisecond)
			return hold(next, held, "")
		case protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS,
			protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED:
			return end(SmtpOutcomeFailed, &SmtpDsn{
				Outcome:    SmtpOutcomeFailed,
				Recipients: self.dsnRecipients(pending, smtpDsnStatusOther, 0),
				Reason:     smtpPreambleEndReason(connectionResult.PreambleCode),
			})
		case protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK:
		default:
			return scheduled("")
		}

		if refusal := connectionResult.TlsRefusal; refusal != nil {
			return end(SmtpOutcomeTlsRefused, &SmtpDsn{
				Outcome:    SmtpOutcomeTlsRefused,
				Recipients: self.dsnRecipients(pending, SmtpTlsRefusalStatus, 0),
				Reason:     refusal.Reason(),
			})
		}
		proof := connectionResult.Proof
		if proof == nil {
			// failed after the preamble's OK without saying how far: the MX may have seen MAIL
			return scheduled("")
		}
		switch {
		case proof.TooLarge:
			byteCount, _ := plan.wire.ByteCount(SmtpModeData)
			outcome.ByteCount = byteCount
			outcome.CapByteCount = proof.DataProofByteCount
			if outcome.CapByteCount == 0 {
				outcome.CapByteCount = self.dataProofByteCount()
			}
			return end(SmtpOutcomeTooLarge, &SmtpDsn{
				Outcome:      SmtpOutcomeTooLarge,
				Recipients:   self.dsnRecipients(pending, smtpDsnStatusTooLarge, 0),
				ByteCount:    outcome.ByteCount,
				CapByteCount: outcome.CapByteCount,
			})
		case proof.ReconnectByteCount != 0:
			if reconnected {
				return scheduled("")
			}
			// the other mode's count, once (plan-SMTP-preamble-byte-count)
			reconnected = true
			if mode == SmtpModeBdat {
				mode = SmtpModeData
			} else {
				mode = SmtpModeBdat
			}
			continue
		case proof.EnvelopeRetry:
			if envelopeRetried {
				return end(SmtpOutcomeFailed, &SmtpDsn{
					Outcome:    SmtpOutcomeFailed,
					Recipients: self.dsnRecipients(pending, smtpDsnStatusOther, 0),
					Reason:     "The receiving mail server's replies could not be proven, even one command at a time.",
				})
			}
			envelopeRetried = true
			groupMaxCount = self.settings.EnvelopeRetryGroupCount
			if err := self.args.Pins.RecordEnvelopeGroupCount(domain, connectionResult.MxHost, groupMaxCount); err != nil && self.log.V(1).Enabled() {
				self.log.Infof("[smtp]send %s: the envelope group count was not kept: %v\n", hex.EncodeToString(message.EffectKey), err)
			}
			continue
		case proof.Accepted:
			delivered = append(delivered, pending...)
			self.noteReach(message, pending, plan.wire, connectionResult.MxHost)
			var dsn *SmtpDsn
			if len(refused) != 0 {
				dsn = &SmtpDsn{Outcome: SmtpOutcomeRefused, Recipients: refused}
			}
			if len(temporary) != 0 {
				// the taken are delivered; the 4xx's wait for the next retry, which leaves the delivered out
				retryState.delivered = delivered
				if dsn != nil {
					self.depositDsn(ctx, plan, domain, dsn)
				}
				return scheduled("")
			}
			return end(SmtpOutcomeSent, dsn)
		}

		// refused somewhere. A send the MX took some recipients of and refused others at RCPT resends at once to
		// the taken alone; the refused get a DSN, and a 4xx's recipients wait for the next retry
		codes := proof.RecipientReplyCodes
		if len(codes) == len(pending) && !resent {
			taken := []string{}
			temporaryHere := []string{}
			refusedHere := []*SmtpDsnRecipient{}
			for i, recipient := range pending {
				switch code := codes[i]; {
				case 200 <= code && code < 300:
					taken = append(taken, recipient)
				case 500 <= code && code < 600:
					refusedHere = append(refusedHere, &SmtpDsnRecipient{Address: recipient, Status: smtpDsnStatusOfReply(code), ReplyCode: code})
				default:
					temporaryHere = append(temporaryHere, recipient)
				}
			}
			if 0 < len(taken) && len(taken) < len(pending) {
				resent = true
				refused = append(refused, refusedHere...)
				temporary = temporaryHere
				pending = taken
				continue
			}
		}
		// no recipient taken: the reply that ended the send speaks for every one left
		code, _ := strconv.ParseUint(proof.RefusedCode, 10, 32)
		if 500 <= code && code < 600 {
			outcome.ReplyCode = uint32(code)
			for _, recipient := range pending {
				if !slices.ContainsFunc(refused, func(dsnRecipient *SmtpDsnRecipient) bool { return dsnRecipient.Address == recipient }) {
					refused = append(refused, &SmtpDsnRecipient{Address: recipient, Status: smtpDsnStatusOfReply(uint32(code)), ReplyCode: uint32(code)})
				}
			}
			if 0 < len(delivered) {
				return end(SmtpOutcomeSent, &SmtpDsn{Outcome: SmtpOutcomeRefused, Recipients: refused})
			}
			return end(SmtpOutcomeRefused, &SmtpDsn{Outcome: SmtpOutcomeRefused, Recipients: refused})
		}
		// a 4xx, or no reply code: the next retry
		retryState.delivered = delivered
		if len(refused) != 0 {
			self.depositDsn(ctx, plan, domain, &SmtpDsn{Outcome: SmtpOutcomeRefused, Recipients: refused})
		}
		return scheduled("")
	}
}

// One DSN recipient a recipient, all under status.
func (self *SmtpSender) dsnRecipients(recipients []string, status string, replyCode uint32) []*SmtpDsnRecipient {
	dsnRecipients := make([]*SmtpDsnRecipient, 0, len(recipients))
	for _, recipient := range recipients {
		dsnRecipients = append(dsnRecipients, &SmtpDsnRecipient{Address: recipient, Status: status, ReplyCode: replyCode})
	}
	return dsnRecipients
}

// The DSN's account of an edge's refusal that ends the message.
func smtpPreambleEndReason(code protocol.SmtpPreambleCode) string {
	switch code {
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX:
		return "The recipient domain has no mail server that takes mail."
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS:
		return "None of the recipient domain's mail servers offers STARTTLS, which every send requires."
	}
	return "URnetwork's sending edge refused this send."
}

// A whole number of days or hours, for a DSN's account.
func smtpDurationText(duration time.Duration) string {
	if duration%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", duration/(24*time.Hour))
	}
	return fmt.Sprintf("%d hours", (duration+time.Hour-1)/time.Hour)
}

// Lowercase unpadded base32, the DSN's Message-ID and boundary alphabet.
var smtpDsnBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Fills dsn's common facts and deposits it to the sending mailbox. A DSN that cannot be made or deposited is
// logged with no name and dropped: the outcome in or/ still says what happened.
func (self *SmtpSender) depositDsn(ctx context.Context, plan *smtpSendPlan, domain string, dsn *SmtpDsn) {
	random := make([]byte, 32)
	if _, err := cryptorand.Read(random); err != nil {
		return
	}
	dsn.ReportingDomain = plan.envelopeDomain
	dsn.To = plan.dsnTo
	dsn.RecipientDomain = domain
	dsn.OriginalHeaders = plan.dsnHeaders
	dsn.ArrivalTime = plan.message.CreateTime
	dsn.Now = self.clock.Now()
	dsn.MessageId = smtpDsnBase32.EncodeToString(random[:16]) + "@" + plan.envelopeDomain
	dsn.Boundary = "dsn-" + smtpDsnBase32.EncodeToString(random[16:])
	encoded, err := dsn.Encode()
	if err == nil {
		err = self.args.Mailbox.DepositDsn(ctx, plan.message.EffectKey, encoded)
	}
	if err != nil {
		self.log.Warningf("[smtp]send %s: a dsn was not deposited: %v\n", hex.EncodeToString(plan.message.EffectKey), err)
		return
	}
	self.NoteDsn(dsn.Outcome != SmtpOutcomeTooLarge)
}

// §16.8's receipt notes for the recipients an MX took. A note the receipts refuse is logged and holds nothing
// back.
func (self *SmtpSender) noteReach(message *SmtpOutboundMessage, recipients []string, wire *SmtpWireMessage, mxHost string) {
	if self.args.Reach == nil || self.args.ReachGrant == nil {
		return
	}
	byteCount, _ := wire.ByteCount(SmtpModeBdat)
	for _, note := range smtpReachNotes(self.args.ReachGrant(message), recipients, byteCount, mxHost) {
		if err := self.args.Reach(note); err != nil {
			self.log.Warningf("[smtp]send %s: a reach receipt was refused: %v\n", hex.EncodeToString(message.EffectKey), err)
		}
	}
}
