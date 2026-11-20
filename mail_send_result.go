//go:build !sidecar_http && !ios_extension

// A send's check and its results by send_id, and the mail_send a member's device raises from or/ (§14.5's Check and
// outcomes, §15.7's or/, §15.10's step 4, §18.5's CheckSend, GetSendResult and mail_send; QD-1122, owner decisions 125
// and 288; D-SDK-31, FS-123, I-13):
//
//	check     the message Send would make of a draft: its plan (mail_send.go), so a draft Send refuses is refused
//	          alike; a random send id named in its Message-ID, as internet mail names one; Bcc gone; the internet
//	          recipients alone; a fresh effect key standing for the use's, which only the gate draws; and an envelope
//	          sender of the bounce address's form, which a check reads only for its form, so none is made for it. The
//	          bound sender (MailBinding.Sender) checks it at this host's own cap and measure where it proves. A host
//	          with none checks it with an SmtpSender of its own over the member's mailbox and no prover, which reads
//	          the cap and the pricing measure from the member's consented prover hosts' p/ records and the modes from
//	          or/ alone, since a host that sends nothing has met no MX: its pins are empty, and it dials nothing.
//	          Nothing is signed, kept, deposited or queued, and no gate is asked
//	result    the member's or/ record whose send_id is the send's: the one the watch's last read names, else each
//	          record read until one does; else an o/ entry whose Message-ID names the send, signed by a consented
//	          device of the member as SmtpOutboxRunner holds it, answered by its or/ record where one stands under its
//	          key, naming no send as an older writer's would, and else queued at each of its domains from its
//	          creation, no prover host having started it; else ErrMailSendUnknown. A record or entry that could not be
//	          read leaves the answer untold, its error, never unknown
//	watch     while mail is on, one goroutine a component run reads the member's or/ at once, at each change its
//	          subscription to or/ hears of, at each Resync and each SendWatchInterval, and raises mail_send {send_id}
//	          once for each domain whose outcome differs from its last read of that record, the outcome's time aside,
//	          as SmtpSender raises one for each outcome it changes; a record that names no send raises none
//	last read kept in the component's sealed store within SendWatchStateMaxByteCount, raised first and kept after, so a
//	          restart raises only what changed since and a crash between repeats an event rather than losing one; a
//	          record gone from or/ leaves it, and one that could not be read keeps its last read until it can be
//	baseline  with no last read kept, as at a device's first start or once the read outgrew its bound, the first read
//	          is kept and raises nothing, so a member's 30 days of sends do not announce themselves to a new device
//
// Every device of the member that runs the component raises from or/, the composing device among them (§15.10's step
// 4), so a desktop app's daemon follows its phone's sends as the phone does (§18.5). A prover host whose composition
// gives its sender Events also raises from Send for what it writes, so an app there may hear one change twice: a
// mail_send is a cue to read GetSendResult again and claims nothing more. A raw submission keeps its client's
// Message-ID, so its record names no send and nothing here follows it. Nothing here logs an address, a domain or a
// send's id (I-13). Safe for concurrent use.
//
// Off the sidecar_http leg: a page Worker sends no mail (mail_send_result_http.go is its twin).

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
)

// The send watch's last read in the component's sealed store (the file header's last read row).
const mailSendWatchFileName = "sends.json"

var (
	// The dialer of a check's own sender, which dials nothing: a sender with no prover only queues.
	errMailCheckDials = errors.New("mail: a send's check dials no edge")
	// A check's own sender's store, which keeps no pins.
	errMailCheckStoreReadOnly = errors.New("mail: a send's check keeps nothing")
)

// See MailClient.CheckSend and the file header's check row.
func (self *MailClient) checkSend(ctx context.Context, args *MailSendArgs) (*SmtpSendCheck, error) {
	plan, err := self.planSend(args)
	if err != nil {
		return nil, err
	}
	outside := plan.outsideRecipients()
	if len(outside) == 0 {
		// mail to the network's own addresses alone: nothing of it goes through §14
		return &SmtpSendCheck{Domains: []*SmtpDomainCheck{}}, nil
	}
	now := self.clock.Now()
	sendId := newMailOutboxSendId()
	content, err := (&mailSendContent{draft: mailSendCopyArgs(args)}).message(plan.fromAddress, MailOutboxMessageId(sendId, plan.fromDomain), now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailSendInvalid, err)
	}
	message := &SmtpOutboundMessage{
		EffectKey:  mailSendStandingEffectKey(),
		SendId:     sendId,
		Sender:     MailBounceAddress(MailZone{Root: plan.row.Root, Net: plan.row.Label}, newMailBounceToken()),
		Recipients: outside,
		Message:    mailSendStripBcc(content),
		CreateTime: now,
	}
	if plan.binding.Sender != nil {
		return plan.binding.Sender.Check(ctx, message)
	}
	sender, err := self.checkSender(plan)
	if err != nil {
		return nil, err
	}
	defer sender.Close()
	return sender.Check(ctx, message)
}

// The sender a check runs on where none is bound (the file header's check row): no prover, empty pins, a dialer that
// dials nothing and a policy no check consults, over the member's mailbox, holding p/ to the member's consented
// devices. Close ends it.
func (self *MailClient) checkSender(plan *mailSendPlan) (*SmtpSender, error) {
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	state := plan.binding.Engine.State()
	if state == nil {
		return nil, ErrMailUnbound
	}
	memberId, ok := mailMemberOf(state, self.sidecarId)
	if !ok {
		return nil, ErrMailNoMailbox
	}
	settings := self.smtpSenderSettings()
	pins := NewSmtpPinStore(mailCheckStore{}, settings, self.clock, self.log)
	return NewSmtpSender(&SmtpSenderArgs{
		Dialer:  mailCheckDialer{},
		Policy:  NewSmtpTlsPolicy(nil, nil, pins, nil, nil, nil, nil, settings, self.clock),
		Pins:    pins,
		Dkim:    NewSmtpDkimKeys(nil, nil, settings, self.clock, self.log),
		Mailbox: newMailSmtpMailbox(plan.parts.store(mailboxId), nil, nil, self.outboxSettings(), self.clock),
		MemberDevice: func(sidecarId Id) bool {
			return state.ConsentedFor(sidecarId, memberId)
		},
		Settings: settings,
		Clock:    self.clock,
		Log:      self.log,
	})
}

// The sender settings a check runs on: its Sidecar's, for a client made over one, else the one default.
func (self *MailClient) smtpSenderSettings() *SmtpSenderSettings {
	if sidecar := self.sidecar; sidecar != nil && sidecar.settings != nil && sidecar.settings.Connect != nil && sidecar.settings.Connect.SmtpSender != nil {
		return sidecar.settings.Connect.SmtpSender
	}
	return DefaultSmtpSenderSettings()
}

// The dialer of a check's own sender: it dials nothing, since a sender with no prover only queues.
type mailCheckDialer struct{}

// See SmtpEdgeDialer: never a stream.
func (self mailCheckDialer) DialSmtpEdge(ctx context.Context) (SmtpEdgeStream, error) {
	return nil, errMailCheckDials
}

// The pin store's store for a check's own sender: it holds nothing and keeps nothing, so every domain's mode comes
// from or/ (the file header's check row).
type mailCheckStore struct{}

// See SidecarStore: nothing is there.
func (self mailCheckStore) Open(name string) (io.ReadCloser, error) {
	return nil, ErrSidecarStoreAbsent
}

// See SidecarStore: refused, since a check keeps nothing.
func (self mailCheckStore) Create(name string) (SidecarStoreWriter, error) {
	return nil, errMailCheckStoreReadOnly
}

// See SidecarStore: nothing to take away.
func (self mailCheckStore) Remove(name string) error {
	return nil
}

// See SidecarStore: no file.
func (self mailCheckStore) List(prefix string) ([]SidecarStoreEntry, error) {
	return []SidecarStoreEntry{}, nil
}

// See SidecarStore: the same empty store.
func (self mailCheckStore) Directory(name string, class string) (SidecarStore, error) {
	return self, nil
}

// The member's mailbox as or/ and o/ are read here, and the identity key of each consented device of the member,
// which an o/ entry's signature is held to as SmtpOutboxRunner holds it. ErrMailNoMailbox for a device with no mailbox
// of its own.
func (self *MailClient) sendMailbox() (*mailSmtpMailbox, func(sidecarId Id) ed25519.PublicKey, error) {
	_, parts, state, err := self.state()
	if err != nil {
		return nil, nil, err
	}
	memberId, ok := mailMemberOf(state, self.sidecarId)
	if !ok {
		return nil, nil, ErrMailNoMailbox
	}
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, nil, err
	}
	memberDeviceKey := func(sidecarId Id) ed25519.PublicKey {
		if !state.ConsentedFor(sidecarId, memberId) {
			return nil
		}
		sidecar := state.sidecarState(sidecarId)
		if sidecar == nil || sidecar.facts == nil {
			return nil
		}
		key := sidecar.facts.Row.GetIdentityPublicKey()
		if len(key) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(bytes.Clone(key))
	}
	return newMailSmtpMailbox(parts.store(mailboxId), nil, nil, self.outboxSettings(), self.clock), memberDeviceKey, nil
}

// See MailClient.SendResult and the file header's result row.
func (self *MailClient) sendResult(ctx context.Context, sendId Id) (*SmtpSendResult, error) {
	if sendId == (Id{}) {
		return nil, fmt.Errorf("%w: no send_id", ErrMailSendInvalid)
	}
	mailbox, memberDeviceKey, err := self.sendMailbox()
	if err != nil {
		return nil, err
	}
	// the record the watch's last read names, at one read
	if effectKey, ok := self.sendWatchState().effectKeyOf(sendId); ok {
		named, outcomes, err := mailbox.ReadSendOutcomes(ctx, effectKey)
		switch {
		case err == nil && named == sendId:
			return &SmtpSendResult{EffectKey: effectKey, Domains: outcomes}, nil
		case err != nil && !errors.Is(err, ErrSmtpMailboxNotFound):
			return nil, err
		}
	}
	// else every record, a read that fails leaving the answer untold rather than unknown
	var unread error
	effectKeys, err := mailbox.ListOutcomes(ctx)
	if err != nil {
		return nil, err
	}
	for _, effectKey := range effectKeys {
		named, outcomes, err := mailbox.ReadSendOutcomes(ctx, effectKey)
		switch {
		case errors.Is(err, ErrSmtpMailboxNotFound):
		case err != nil:
			if unread == nil {
				unread = err
			}
		case named == sendId:
			return &SmtpSendResult{EffectKey: effectKey, Domains: outcomes}, nil
		}
	}
	// else an entry still in o/
	outboxKeys, err := mailbox.ListOutbox(ctx)
	if err != nil {
		return nil, err
	}
	for _, effectKey := range outboxKeys {
		file, err := mailbox.ReadOutbox(ctx, effectKey)
		switch {
		case errors.Is(err, ErrSmtpMailboxNotFound), errors.Is(err, ErrMailOutboxFileInvalid):
			continue
		case err != nil:
			if unread == nil {
				unread = err
			}
			continue
		}
		verified, err := VerifySmtpOutboxEntry(file, memberDeviceKey)
		if err != nil || verified.Message.SendId != sendId {
			// an entry no consented device of the member signed names none of the member's sends
			continue
		}
		// a host may have written its outcomes since the records were read, or written them naming no send
		_, outcomes, err := mailbox.ReadSendOutcomes(ctx, effectKey)
		switch {
		case err == nil:
			return &SmtpSendResult{EffectKey: effectKey, Domains: outcomes}, nil
		case !errors.Is(err, ErrSmtpMailboxNotFound):
			return nil, err
		}
		result := &SmtpSendResult{EffectKey: bytes.Clone(effectKey), Domains: []*SmtpDomainOutcome{}}
		for _, recipient := range verified.Message.Recipients {
			_, domain, ok := SplitSmtpEnvelopeAddress(recipient)
			if !ok || slices.ContainsFunc(result.Domains, func(outcome *SmtpDomainOutcome) bool { return outcome.Domain == domain }) {
				continue
			}
			result.Domains = append(result.Domains, &SmtpDomainOutcome{Domain: domain, Outcome: SmtpOutcomeQueued, UpdateTime: verified.Message.CreateTime})
		}
		return result, nil
	}
	if unread != nil {
		return nil, unread
	}
	return nil, ErrMailSendUnknown
}

// The send watch on a client (the file header's watch, last read and baseline rows). Safe for concurrent use.
type mailSendWatch struct {
	// one read of or/ at a time, so two reads never raise one change twice
	passLock sync.Mutex
	// a read is due at once: buffered 1, so wakes between two reads are one
	wake chan struct{}

	stateLock sync.Mutex
	// the component run whose goroutine follows or/
	run *mailComponentRun
	// the last read by effect key, in or/'s lowercase base32; nil until a read loads or makes it
	records map[string]*mailSendWatchRecord
}

// One or/ record as the watch last read it: the send it names, and each domain's outcome but its time.
type mailSendWatchRecord struct {
	SendId   Id                      `json:"send_id"`
	Outcomes []*mailSendWatchOutcome `json:"outcomes"`
}

// One domain's outcome but its time: what SmtpSender's smtpOutcomeSame compares.
type mailSendWatchOutcome struct {
	Domain           string `json:"domain"`
	Outcome          uint32 `json:"outcome"`
	Mode             uint32 `json:"mode,omitempty"`
	ByteCount        uint64 `json:"byte_count,omitempty"`
	CapByteCount     uint64 `json:"cap_byte_count,omitempty"`
	ReplyCode        uint32 `json:"reply_code,omitempty"`
	RetryAfterMillis int64  `json:"retry_after_ms,omitempty"`
	TlsLevel         uint32 `json:"tls_level,omitempty"`
}

// The last read as the store keeps it.
type mailSendWatchFile struct {
	Records map[string]*mailSendWatchRecord `json:"records"`
}

// outcome as the watch compares it.
func mailSendWatchOutcomeOf(outcome *SmtpDomainOutcome) *mailSendWatchOutcome {
	return &mailSendWatchOutcome{
		Domain:           outcome.Domain,
		Outcome:          uint32(outcome.Outcome),
		Mode:             uint32(outcome.Mode),
		ByteCount:        outcome.ByteCount,
		CapByteCount:     outcome.CapByteCount,
		ReplyCode:        outcome.ReplyCode,
		RetryAfterMillis: outcome.RetryAfter.Milliseconds(),
		TlsLevel:         uint32(outcome.TlsLevel),
	}
}

// How many of this record's domains say something else than last's, a domain last does not hold among them.
func (self *mailSendWatchRecord) changedCount(last *mailSendWatchRecord) int {
	count := 0
	for _, outcome := range self.Outcomes {
		index := -1
		if last != nil && last.SendId == self.SendId {
			index = slices.IndexFunc(last.Outcomes, func(lastOutcome *mailSendWatchOutcome) bool { return lastOutcome.Domain == outcome.Domain })
		}
		if index < 0 || *last.Outcomes[index] != *outcome {
			count += 1
		}
	}
	return count
}

// Whether two records say the same.
func (self *mailSendWatchRecord) same(other *mailSendWatchRecord) bool {
	return other != nil && self.SendId == other.SendId && slices.EqualFunc(self.Outcomes, other.Outcomes, func(a *mailSendWatchOutcome, b *mailSendWatchOutcome) bool {
		return *a == *b
	})
}

// Makes the next read due at once, without waiting.
func (self *mailSendWatch) wakeUp() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// The effect key of the record the last read names sendId in, false for none.
func (self *mailSendWatch) effectKeyOf(sendId Id) ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for name, record := range self.records {
		if record.SendId != sendId {
			continue
		}
		effectKey, err := evsTokenEncoding.DecodeString(name)
		if err != nil || len(effectKey) != mailEffectKeyByteCount {
			return nil, false
		}
		return effectKey, true
	}
	return nil, false
}

// The client's send watch, made at the first call.
func (self *MailClient) sendWatchState() *mailSendWatch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	watch, ok := self.sendWatch.(*mailSendWatch)
	if !ok {
		watch = &mailSendWatch{wake: make(chan struct{}, 1)}
		self.sendWatch = watch
	}
	return watch
}

// Makes the send watch's next read due at once, where one runs: what Resync and a test's step wake.
func (self *MailClient) wakeSends() {
	self.sendWatchState().wakeUp()
}

// Starts run's send watch, once a run: the component's outcomes step calls it at each pass while mail is on
// (mail_send_queue.go).
func (self *MailClient) followSends(run *mailComponentRun) {
	watch := self.sendWatchState()
	start := func() bool {
		watch.stateLock.Lock()
		defer watch.stateLock.Unlock()
		if watch.run == run {
			return false
		}
		watch.run = run
		return true
	}()
	if start {
		go self.runSendWatch(run, watch)
	}
}

// The watch's goroutine for run (the file header's watch row): a read at once, then one at each wake and each
// SendWatchInterval until run ends, its subscription to the member's or/ following the mailbox each read resolves.
func (self *MailClient) runSendWatch(run *mailComponentRun, watch *mailSendWatch) {
	followedRepoId := Id{}
	var stopFollow func()
	defer func() {
		if stopFollow != nil {
			stopFollow()
		}
	}()
	for {
		if _, err := self.passSendWatch(run.ctx); err != nil && run.ctx.Err() == nil && self.log.V(1).Enabled() {
			self.log.Infof("[mail]the send watch did not read or/: %v", err)
		}
		if mailboxId, err := self.mailboxId(); err == nil && mailboxId != followedRepoId {
			if stopFollow != nil {
				stopFollow()
			}
			followedRepoId = mailboxId
			stopFollow = self.followOutcomes(run.ctx, mailboxId, watch.wakeUp)
		}
		select {
		case <-run.ctx.Done():
			return
		case <-watch.wake:
		case <-self.clock.After(self.outboxSettings().SendWatchInterval):
		}
	}
}

// What parts over evs add for the watch: a subscription to paths of a repo's refs, each change a call of changed.
type mailClientFollower interface {
	follow(ctx context.Context, repoId Id, paths []string, changed func()) (func(), error)
}

// See mailClientFollower. changed runs on the subscriber's goroutine, which must not block.
func (self *mailEvsClientParts) follow(ctx context.Context, repoId Id, paths []string, changed func()) (func(), error) {
	subscription, err := self.evs.Repo(repoId).Subscribe(ctx, &EvsSubscribeArgs{
		Paths:   paths,
		Changes: func(change *EvsRepoChange) { changed() },
	})
	if err != nil {
		return nil, err
	}
	return subscription.Close, nil
}

// A subscription to mailboxId's or/ whose changes call wake, leased on a goroutine of its own, since a lease may wait
// on evs; nil where the parts follow nothing, as a test's stand-ins. What it answers ends the subscription and waits
// for its goroutine.
func (self *MailClient) followOutcomes(ctx context.Context, mailboxId Id, wake func()) func() {
	_, parts, err := self.bound()
	if err != nil {
		return nil
	}
	follower, ok := parts.(mailClientFollower)
	if !ok {
		return nil
	}
	followCtx, cancel := context.WithCancel(ctx)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		stop, err := follower.follow(followCtx, mailboxId, []string{mailOutcomeFamily}, wake)
		if err != nil {
			if followCtx.Err() == nil && self.log.V(1).Enabled() {
				self.log.Infof("[mail]the send watch follows or/ on its interval alone: %v", err)
			}
			return
		}
		<-followCtx.Done()
		stop()
	}()
	return func() {
		cancel()
		<-ended
	}
}

// One read of the member's or/ (the file header's watch row), between its two barriers: each record that names a send
// compared with the last read, one mail_send raised for each domain whose outcome changed, then the read kept. The
// number raised.
func (self *MailClient) passSendWatch(ctx context.Context) (int, error) {
	watch := self.sendWatchState()
	watch.passLock.Lock()
	defer watch.passLock.Unlock()
	testHookBarrier("mail.send.watch.before", "")
	// every wake until now is this read's
	select {
	case <-watch.wake:
	default:
	}
	raised, err := self.readSendWatch(ctx, watch)
	testHookBarrier("mail.send.watch.after", "")
	return raised, err
}

// See passSendWatch, under its pass lock.
func (self *MailClient) readSendWatch(ctx context.Context, watch *mailSendWatch) (int, error) {
	mailbox, _, err := self.sendMailbox()
	if err != nil {
		return 0, err
	}
	last := func() map[string]*mailSendWatchRecord {
		watch.stateLock.Lock()
		defer watch.stateLock.Unlock()
		return watch.records
	}()
	baseline := false
	if last == nil {
		if last = self.loadSendWatch(); last == nil {
			baseline = true
		}
	}
	effectKeys, err := mailbox.ListOutcomes(ctx)
	if err != nil {
		return 0, err
	}
	read := map[string]*mailSendWatchRecord{}
	sendIds := []Id{}
	for _, effectKey := range effectKeys {
		name := mailBinaryName(effectKey)
		sendId, outcomes, err := mailbox.ReadSendOutcomes(ctx, effectKey)
		switch {
		case errors.Is(err, ErrSmtpMailboxNotFound):
			continue
		case err != nil:
			// unread this time: its last read stands until a read can tell
			if kept := last[name]; kept != nil {
				read[name] = kept
			}
			continue
		case sendId == (Id{}):
			continue
		}
		record := &mailSendWatchRecord{SendId: sendId, Outcomes: []*mailSendWatchOutcome{}}
		for _, outcome := range outcomes {
			record.Outcomes = append(record.Outcomes, mailSendWatchOutcomeOf(outcome))
		}
		read[name] = record
		if !baseline {
			for range record.changedCount(last[name]) {
				sendIds = append(sendIds, sendId)
			}
		}
	}
	changed := baseline || !maps.EqualFunc(read, last, func(a *mailSendWatchRecord, b *mailSendWatchRecord) bool { return a.same(b) })
	func() {
		watch.stateLock.Lock()
		defer watch.stateLock.Unlock()
		watch.records = read
	}()
	// raised before the read is kept, so a crash between repeats an event and loses none
	binding, _, _ := self.bound()
	for _, sendId := range sendIds {
		if binding != nil && binding.Event != nil {
			eventSendId := sendId
			binding.Event(SidecarEvent{Kind: SidecarEventMailSend, SendId: &eventSendId})
		}
	}
	if changed {
		self.storeSendWatch(read)
	}
	return len(sendIds), nil
}

// The last read the store keeps, nil where it keeps none this can read within its bound: the next read is then a
// baseline (the file header's baseline row).
func (self *MailClient) loadSendWatch() map[string]*mailSendWatchRecord {
	reader, err := self.store.Open(mailSendWatchFileName)
	if err != nil {
		return nil
	}
	defer reader.Close()
	maxByteCount := self.outboxSettings().SendWatchStateMaxByteCount
	data, err := io.ReadAll(io.LimitReader(reader, int64(maxByteCount)+1))
	if err != nil || maxByteCount < len(data) {
		return nil
	}
	file := &mailSendWatchFile{}
	if err := json.Unmarshal(data, file); err != nil || file.Records == nil {
		return nil
	}
	for name, record := range file.Records {
		if record == nil || record.SendId == (Id{}) {
			delete(file.Records, name)
		}
	}
	return file.Records
}

// Keeps records as the last read, or, past its bound, removes what the store kept, so a restart takes a baseline
// rather than an older read. A store that fails is logged: the read stands in memory, and the next change tries again.
func (self *MailClient) storeSendWatch(records map[string]*mailSendWatchRecord) {
	data, err := json.Marshal(&mailSendWatchFile{Records: records})
	if err == nil && self.outboxSettings().SendWatchStateMaxByteCount < len(data) {
		err = self.store.Remove(mailSendWatchFileName)
		if err == nil {
			return
		}
	}
	if err == nil {
		err = func() error {
			writer, err := self.store.Create(mailSendWatchFileName)
			if err != nil {
				return err
			}
			defer writer.Close()
			if _, err := writer.Write(data); err != nil {
				return err
			}
			return writer.Commit()
		}()
	}
	if err != nil {
		self.log.Warningf("[mail]the send watch's last read was not kept: %v", err)
	}
}
