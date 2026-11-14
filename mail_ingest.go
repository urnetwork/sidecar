//go:build !ios_extension

// §15.7's ingest (R-MAIL-5, R-MAIL-10, R-MAIL-16, D-MAIL-5, D-MAIL-6, D-MAIL-14, I-9, I-11, FS-13; MAIL-M7-15): a
// reader of a mailbox or a group repo takes each depositor's deposits in version order and writes each message once,
// into the repo's file-mode ref, then consumes the deposit.
//
//	order     one pass reads the erasure ref first, then each depositor's ref in id order, its standing deposits
//	          oldest first; a deposit that settles (written, found written, erased or refused) joins the ref's one
//	          CONSUME at the end of its read, and one left standing holds nothing back
//	class     the depositor is judged at the deposit push's own pin (MailIngestAuthority): a reader that does not
//	          write deposits §16.8's read receipts, which are the record's and are left alone; one with no right to
//	          deposit there is consumed unrecorded; a pin this device does not hold yet leaves the deposit for a later
//	          pass
//	erased    a message a committed ERASE names is never written again (FS-13): its deposit is consumed with no
//	          message, opened or not, since the ERASE took the deposit's slot too. The eraser removes no m/ path
//	          (mail_erase.go), so an erasure that commits after this pass read the erasure ref still meets the path
//	          standing, which is the 409 below
//	trailer   the plaintext splits into the message and its MailDeposit (mail_ingest_reader.go); one that does not
//	          split, or names no recipient, is consumed unrecorded, and one of an unknown version or past this
//	          reader's bound stands for a reader that knows it
//	evidence  a receiver's deposit names its receiver, which is held to the push's signer, and its evidence must name
//	          this message's hash and that receiver (D-MAIL-14): a deposit that fails the first keeps nothing it says
//	          of the session, and evidence that fails the second is dropped, so either is "evidence unavailable" and
//	          labeled opportunistic, with an alarm. No authentication result refuses mail (D-MAIL-5): the message is
//	          written either way. Labels, scores and the Authentication-Results field come only from that sealed
//	          evidence, never from a later lookup: nothing here resolves a name
//	write     Authentication-Results and Received go above the message (mail_ingest_headers.go), and m/ and the
//	          message's i/ row go in one push (MailIndexWriter.Append), m/ created only while absent. The deposit id
//	          is the message id and <yyyymm> the sealed receive time's, so racing readers write one path: a conflict
//	          on m/ means another reader, or this one before a crash, wrote it, and the deposit is only consumed
//	receipt   the reader whose push wrote the message notes §16.8's reach receipt (RecordReach.Note), Used at for a
//	          burner's recipient (MailVault.NoteUsedAt) and its caller's Message, in that order, before the CONSUME;
//	          none of them holds the CONSUME back, and a crash between the push and them loses those notes, never
//	          the message
//	consume   one CONSUME a depositor's ref, with the highest version below which nothing is left; a deposit another
//	          reader consumed first counts consumed. A crash after the push and before the CONSUME leaves the deposit
//	          and its slot, and the next pass meets m/ standing and only consumes; evs_consume.go's journal sends a
//	          CONSUME whose answer was lost again
//	trust     outside mail is untrusted and taints a run that reads it (R-MAIL-10, I-9): every message but a
//	          same-network one whose signer may send as its From (MAIL_TLS_MEMBER_SIGNED) is marked so
//	          (MailEntryUntrusted). No mail is an approval, whatever it says (owner decision 80): ingest writes m/ and
//	          i/ and decides nothing
//
// A group repo is general, so a push creating a path waits out 412 PATH_EPOCH_DUE while an immediate path epoch is
// due, which EvsRepo.WritePaths does (evs_write.go's waitPathEpoch); a mailbox keeps creating. Slot ids are evs's,
// drawn per statement (evs_upload.go), never from a deposit or message id.
//
// Not built here: the message's search-index delta in the same push, which is MAIL-M10-01's; and the judging of a
// same-network deposit's From beyond MailIngestAuthority.MaySendAs, which MAIL-M7-18 completes.
//
// On every leg but the extension's. A MailIngestor is safe for concurrent use: one pass runs at a time.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// This sidecar may not ingest the repo: it does not read and write it, or no authority says it does.
var ErrMailNotIngester = errors.New("mail repo not ingested by this sidecar")

// What a depositor's deposits in a mail repo are, at one pin.
type MailDepositorClass int

const (
	// The state at the pin is not held yet, or no authority answers: the deposit stands for a later pass.
	MailDepositorUnknown MailDepositorClass = iota
	// No right to deposit there at the pin: its deposits are consumed unrecorded.
	MailDepositorNone
	// A receiver or a member's device: its deposits are mail.
	MailDepositorMail
	// A reader that does not write (§8.5, §11.12): its deposits are §16.8's read receipts, which mail leaves alone.
	MailDepositorReceipts
)

// What ingest asks of §8's verified state. Implementations are safe for concurrent use.
type MailIngestAuthority interface {
	// Whether sidecarId reads and writes repoId now: a consented device of a mailbox's owner that is not read-only,
	// or a group repo's reader that writes (§15.7's readers).
	Ingests(repoId Id, sidecarId Id) bool
	// What depositorId's deposits in repoId are at pin, the deposit push's own; a nil pin asks at the installed
	// state.
	DepositorClass(repoId Id, depositorId Id, pin *bridge.AuthPin) MailDepositorClass
	// Whether signerSidecarId may send as fromAddress, an address of this network (mail:<alias>#send, §15.10): a
	// same-network deposit's label rests on it (D-MAIL-8).
	MaySendAs(signerSidecarId Id, fromAddress string) bool
}

// MailIngestAuthority over the installed AclEngine.
//
// MaySendAs is judged at the installed state, since a device holds alias patterns only for the policy it runs
// (AclEngine.AllowAlias), and only for an address under Root whose zone OwnZone takes: with no OwnZone it refuses.
type MailIngestAclAuthority struct {
	Engine *AclEngine
	// The user root the network's addresses are under.
	Root string
	// Whether a zone is this network's own: its label, its alias or one of its scopes. Nil refuses every From.
	OwnZone func(zone MailZone) bool
	// Nil is real time.
	Clock Clock
}

// Read and write on the repo at the installed state.
func (self *MailIngestAclAuthority) Ingests(repoId Id, sidecarId Id) bool {
	if self == nil || self.Engine == nil {
		return false
	}
	state := self.Engine.State()
	if state == nil {
		return false
	}
	access := state.EvsAccess(AclSidecarSubject(sidecarId), repoId, AclTokenAudienceEvs, clockOrReal(self.Clock).Now())
	return access.Rights.Has(AclEvsRead | AclEvsWrite)
}

// The depositor's rights at the pin: read without write is a receipt depositor, deposit or write a mail depositor.
func (self *MailIngestAclAuthority) DepositorClass(repoId Id, depositorId Id, pin *bridge.AuthPin) MailDepositorClass {
	if self == nil || self.Engine == nil {
		return MailDepositorUnknown
	}
	state := self.Engine.State()
	if pin != nil {
		pinned, err := self.Engine.stateAt(pin)
		if err != nil {
			return MailDepositorUnknown
		}
		state = pinned
	}
	if state == nil {
		return MailDepositorUnknown
	}
	rights := state.EvsAccess(AclSidecarSubject(depositorId), repoId, AclTokenAudienceEvs, clockOrReal(self.Clock).Now()).Rights
	switch {
	case rights.Has(AclEvsRead) && !rights.Has(AclEvsWrite):
		return MailDepositorReceipts
	case rights.Has(AclEvsDeposit) || rights.Has(AclEvsWrite):
		return MailDepositorMail
	}
	return MailDepositorNone
}

// AclEngine.AllowAlias for the signer's send on the address's local part.
func (self *MailIngestAclAuthority) MaySendAs(signerSidecarId Id, fromAddress string) bool {
	if self == nil || self.Engine == nil || self.OwnZone == nil {
		return false
	}
	recipient, err := ParseMailRecipient(self.Root, fromAddress)
	if err != nil || recipient.Kind == MailAddressKindBurner || recipient.Kind == MailAddressKindReverseAlias || !self.OwnZone(recipient.Zone) {
		return false
	}
	now := clockOrReal(self.Clock).Now()
	return self.Engine.AllowAlias(AclSidecarSubject(signerSidecarId), protocol.AclAction_ACL_ACTION_SEND, recipient.LocalPart, now).Allowed
}

// What MailIngestor is tuned by (MAIL-M7-15).
type MailIngestSettings struct {
	// The most bytes of one deposit's plaintext this reader opens: the message and its trailer. pro.yml's
	// mail_inbound_message_bytes is 50 MiB at its highest (§20.4), which the component sets from GET /sidecar/limits;
	// the default holds that and a trailer. A deposit past it stands unread. Non-positive opens none.
	DepositMaxByteCount int64
	// The most bytes of a deposit's trailer: MailIngress's 1,024, MailAuthEvidence's 8,192 and 100 recipients of at
	// most 318 bytes fit 48 KiB, and 64 KiB leaves room for a newer writer's fields. Non-positive takes none.
	TrailerMaxByteCount int
	// The most recipients one trailer names (§15.7's 100, pro.yml's mail_inbound_recipients): past it the deposit is
	// consumed unrecorded, as no receiver makes one. Non-positive takes none.
	RecipientMaxCount int
	// How long Run waits for a change before it ingests anyway, which covers a hint that never came: an hour, as
	// evs's own resync is. Non-positive ingests only on a change.
	ResyncInterval time.Duration
	// How long Run waits after a pass that failed before it tries again. Non-positive takes MinPassInterval.
	RetryInterval time.Duration
	// The least time between two of Run's passes, so a burst of hints is one pass. Non-positive takes none.
	MinPassInterval time.Duration
	// The message walk's bounds; nil takes DefaultMailParseSettings.
	Parse *MailParseSettings
	// The spam scorer's; nil takes DefaultMailSpamSettings.
	Spam *MailSpamSettings
	// The i/ writer's; nil takes DefaultMailStoreSettings.
	Store *MailStoreSettings
}

// The one default.
func DefaultMailIngestSettings() *MailIngestSettings {
	return &MailIngestSettings{
		DepositMaxByteCount: 50*1024*1024 + 64*1024,
		TrailerMaxByteCount: 64 * 1024,
		RecipientMaxCount:   100,
		ResyncInterval:      time.Hour,
		RetryInterval:       30 * time.Second,
		MinPassInterval:     time.Second,
	}
}

// Why ingest raised an alarm.
type MailIngestAlarmKind string

const (
	// A deposit that is not a message and its trailer, or names no recipient: consumed unrecorded.
	MailIngestAlarmBadDeposit MailIngestAlarmKind = "bad_deposit"
	// A deposit from a sidecar with no right to deposit there at its pin: consumed unrecorded.
	MailIngestAlarmDepositor MailIngestAlarmKind = "depositor"
	// A receiver's deposit whose receiver is not the push's signer: written as evidence unavailable.
	MailIngestAlarmWrongSigner MailIngestAlarmKind = "wrong_signer"
	// Evidence that names another message, receiver or version: dropped, the message evidence unavailable.
	MailIngestAlarmEvidence MailIngestAlarmKind = "evidence"
	// A deposit that did not open and that no erasure names: left standing.
	MailIngestAlarmUnopened MailIngestAlarmKind = "unopened"
	// A deposit of an unknown version or past this reader's bound: left standing.
	MailIngestAlarmUnread MailIngestAlarmKind = "unread"
)

// One alarm. Ids only (I-13).
type MailIngestAlarm struct {
	Kind        MailIngestAlarmKind
	RepoId      Id
	DepositorId Id
	// The deposit's id, the message's.
	MessageId Id
}

// One message as ingest wrote it.
type MailMessage struct {
	RepoId Id
	// The message's id, its deposit's.
	Id Id
	// The month its m/ and i/ paths are under.
	Month MailYearMonth
	// Its i/ row.
	Entry *protocol.IndexEntry
	// Its label and what it rests on (I-11).
	Label *MailLabelResult
	// The sidecar that deposited it: its receiver, or for same-network mail its sender's device.
	DepositorId Id
	// Outside mail, which taints a run that reads it (R-MAIL-10, I-9): everything but member-signed mail.
	Untrusted bool
	// The message's bytes as received.
	ByteCount uint64
}

// Whether a message's row marks it untrusted (R-MAIL-10, I-9): every label but MAIL_TLS_MEMBER_SIGNED, which only a
// same-network deposit whose signer may send as its From takes. A row with no label, a sent copy's, is this
// network's own.
func MailEntryUntrusted(entry *protocol.IndexEntry) bool {
	switch entry.GetTlsLabel() {
	case protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED, protocol.MailTlsLabel_MAIL_TLS_LABEL_UNSPECIFIED:
		return false
	}
	return true
}

// The grant a received message's reach receipt names: the fields RecordReachNote takes of it.
type MailIngestGrant struct {
	GrantId       []byte
	PolicyVersion uint64
	Owner         []byte
	Approver      []byte
	ActionId      []byte
}

// What one pass did.
type MailIngestPass struct {
	// Messages this pass wrote.
	Ingested int
	// Deposits whose message stood already: another reader's write, or this one's before a crash.
	Present int
	// Deposits of erased messages, consumed with no message.
	Erased int
	// Deposits consumed unrecorded.
	Refused int
	// Deposits left standing: unopened, unread, a depositor not yet judged, or read receipts.
	Left int
	// Deposits a CONSUME named.
	Consumed int
}

// What NewMailIngestor builds on.
type MailIngestArgs struct {
	// The mailbox or the group repo.
	Repo *EvsRepo
	// This sidecar.
	SidecarId Id
	// The user root its addresses are under, which tells a burner's recipient from the rest.
	Root string
	// Nil refuses every pass.
	Authority MailIngestAuthority
	// The operator list labels are decided against; nil takes the embedded one.
	Operators *MailOperatorList
	// RecordReach.Note, with the grant a recipient's listen rests on; either nil notes no receipt.
	Reach      func(note *RecordReachNote) error
	ReachGrant func(address string, depositorId Id) *MailIngestGrant
	// MailVault.NoteUsedAt on a consented device of the mailbox's owner, nil elsewhere.
	UsedAt func(ctx context.Context, address string, domain string, at time.Time) error
	// Called with each message this device's push wrote, on the pass's goroutine.
	Message func(message *MailMessage)
	// Called with each alarm, on the pass's goroutine. MAIL-M7-25 raises them as mail_receiver_alarm events.
	Alarm func(alarm *MailIngestAlarm)
	// Nil is real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailIngestSettings.
	Settings *MailIngestSettings
}

// One mail repo's ingester on this device. See the file header.
type MailIngestor struct {
	repoId    Id
	sidecarId Id
	root      string
	repo      mailIngestRepo
	index     *MailIndexWriter
	scorer    *MailSpamScorer
	erased    *mailErasedView
	authority MailIngestAuthority
	operators *MailOperatorList
	args      *MailIngestArgs
	clock     Clock
	log       Logger
	settings  *MailIngestSettings

	// Held over a pass, so one runs at a time.
	passLock sync.Mutex
	// One pending wake.
	wake chan struct{}
}

// The ingestor of args.Repo.
func NewMailIngestor(args *MailIngestArgs) (*MailIngestor, error) {
	if args == nil || args.Repo == nil {
		return nil, fmt.Errorf("%w: no repo", ErrMailNotIngester)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailIngestSettings()
	}
	storeSettings := settings.Store
	if storeSettings == nil {
		storeSettings = DefaultMailStoreSettings()
	}
	store := newMailEvsStore(args.Repo, nil, storeSettings)
	return newMailIngestor(args.Repo.RepoId(), &mailIngestEvsRepo{repo: args.Repo}, store, args), nil
}

// An ingestor of repoId over repo's deposit refs and store's files.
func newMailIngestor(repoId Id, repo mailIngestRepo, store mailStore, args *MailIngestArgs) *MailIngestor {
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailIngestSettings()
	}
	storeSettings := settings.Store
	if storeSettings == nil {
		storeSettings = DefaultMailStoreSettings()
	}
	spamSettings := settings.Spam
	if spamSettings == nil {
		spamSettings = DefaultMailSpamSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &MailIngestor{
		repoId:    repoId,
		sidecarId: args.SidecarId,
		root:      args.Root,
		repo:      repo,
		index:     NewMailIndexWriter(store, storeSettings),
		scorer:    NewMailSpamScorer(store, spamSettings),
		erased:    newMailErasedView(),
		authority: args.Authority,
		operators: args.Operators,
		args:      args,
		clock:     clockOrReal(args.Clock),
		log:       log,
		settings:  settings,
		wake:      make(chan struct{}, 1),
	}
}

// Asks Run for a pass soon. Never blocks.
func (self *MailIngestor) Wake() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Ingests until ctx ends: a pass at the start, at each change of the repo's refs and every ResyncInterval, a failed
// pass tried again after RetryInterval. Its owner calls it once and tears the ingestor down when it returns.
func (self *MailIngestor) Run(ctx context.Context) {
	stop, err := self.repo.Watch(ctx, self.Wake)
	if err != nil {
		self.log.Warningf("[mail]ingest %s: no watch, ingesting on the timer alone: %v", self.repoId, err)
	} else {
		defer stop()
	}
	for {
		_, err := self.Ingest(ctx)
		if ctx.Err() != nil {
			return
		}
		// the least gap first, so a burst of hints is one pass
		gap := max(self.settings.MinPassInterval, 0)
		wait := self.settings.ResyncInterval
		if err != nil {
			if !errors.Is(err, ErrMailNotIngester) {
				self.log.Warningf("[mail]ingest %s: %v", self.repoId, err)
			}
			if wait = self.settings.RetryInterval; wait <= 0 {
				wait = gap
			}
		}
		if 0 < gap {
			select {
			case <-ctx.Done():
				return
			case <-self.clock.After(gap):
			}
		}
		if 0 < wait && wait <= gap {
			// the timed wait is spent: the next pass is due
			continue
		}
		// with no timed wait, only a change brings the next pass
		var timer <-chan time.Time
		if 0 < wait {
			timer = self.clock.After(wait - gap)
		}
		select {
		case <-ctx.Done():
			return
		case <-self.wake:
		case <-timer:
		}
	}
}

// One pass over the repo's deposit refs: see the file header. The first failure to read, write or consume stops the
// pass, which keeps what it did, and what a pass leaves the next takes up.
func (self *MailIngestor) Ingest(ctx context.Context) (*MailIngestPass, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	pass := &MailIngestPass{}
	if self.authority == nil || !self.authority.Ingests(self.repoId, self.sidecarId) {
		return pass, ErrMailNotIngester
	}
	if _, err := self.erased.refresh(ctx, self.repo.Erasures); err != nil {
		return pass, err
	}
	depositorIds, err := self.repo.Depositors(ctx)
	if err != nil {
		return pass, err
	}
	for _, depositorId := range depositorIds {
		if err := ctx.Err(); err != nil {
			return pass, err
		}
		if self.authority.DepositorClass(self.repoId, depositorId, nil) == MailDepositorReceipts {
			// a reader's receipt ref, which the record ingests: never opened here
			continue
		}
		if err := self.ingestRef(ctx, depositorId, pass); err != nil {
			return pass, err
		}
	}
	return pass, nil
}

// One depositor's ref: each standing deposit ingested, then one CONSUME of those that settled.
func (self *MailIngestor) ingestRef(ctx context.Context, depositorId Id, pass *MailIngestPass) error {
	settledIds := []Id{}
	// the highest version at or below which this read left nothing standing
	consumedThrough := uint64(0)
	anyLeft := false
	seen := func(deposit *EvsDeposit, settled bool) {
		if !settled {
			anyLeft = true
			pass.Left += 1
			return
		}
		settledIds = append(settledIds, Id(deposit.EntryId))
		if !anyLeft {
			consumedThrough = max(consumedThrough, deposit.Version)
		}
	}
	afterVersion := uint64(0)
	var readErr error
	for {
		readErr = self.repo.ReadDeposits(ctx, depositorId, afterVersion, func(deposit *EvsDeposit, body io.Reader) error {
			settled, err := self.ingestDeposit(ctx, depositorId, deposit, body, pass)
			if err != nil {
				return err
			}
			afterVersion = max(afterVersion, deposit.Version)
			seen(deposit, settled)
			return nil
		})
		var openError *EvsDepositOpenError
		if !errors.As(readErr, &openError) || openError.Deposit == nil || openError.Deposit.Version <= afterVersion || ctx.Err() != nil {
			break
		}
		settled, passable := self.unopened(depositorId, openError, pass)
		if !passable {
			break
		}
		// read on after the deposit that did not open
		afterVersion = openError.Deposit.Version
		seen(openError.Deposit, settled)
		readErr = nil
	}
	if 0 < len(settledIds) {
		testHookBarrier("mail.ingest.consume.before", "")
		err := self.repo.Consume(ctx, depositorId, settledIds, consumedThrough)
		testHookBarrier("mail.ingest.consume.after", "")
		if err != nil {
			return err
		}
		pass.Consumed += len(settledIds)
	}
	return readErr
}

// A deposit that did not open. One an erasure names is consumed with no message (FS-13): settled. One whose slot or
// key is gone with no erasure naming it stands, with an alarm, and the read goes on past it. Any other failure, a
// transport's among them, is not passable: the read stops there.
func (self *MailIngestor) unopened(depositorId Id, openError *EvsDepositOpenError, pass *MailIngestPass) (settled bool, passable bool) {
	messageId := Id(openError.Deposit.EntryId)
	if _, erased := self.erased.erased(messageId); erased {
		pass.Erased += 1
		return true, true
	}
	if errors.Is(openError.Err, ErrEvsSealInvalid) || errors.Is(openError.Err, ErrEvsObjectMissing) || errors.Is(openError.Err, ErrEvsEntryRefused) {
		self.alarm(MailIngestAlarmUnopened, depositorId, messageId)
		return false, true
	}
	return false, false
}

// One alarm to the caller's sink.
func (self *MailIngestor) alarm(kind MailIngestAlarmKind, depositorId Id, messageId Id) {
	if self.args.Alarm != nil {
		self.args.Alarm(&MailIngestAlarm{Kind: kind, RepoId: self.repoId, DepositorId: depositorId, MessageId: messageId})
	}
}

// What ingest takes of a deposit's trailer: the sealed trailer with everything dropped that its push's signer or its
// evidence's own names do not support (the file header's evidence row). Every reader drops the same, so racing
// readers still agree on the receive time and the path.
func (self *MailIngestor) effectiveDeposit(depositorId Id, deposit *EvsDeposit, sealed *protocol.MailDeposit, messageSha256 []byte) *protocol.MailDeposit {
	messageId := Id(deposit.EntryId)
	effective := proto.CloneOf(sealed)
	dropSession := func() {
		effective.Ingress, effective.Evidence = nil, nil
		effective.RequireTls = false
		effective.TlsVersion, effective.TlsSuite = 0, 0
	}
	if !mailReceiverDeposit(sealed) {
		// a same-network deposit sets version, mail_from and recipients only (MAIL-FORMAT.md)
		dropSession()
		return effective
	}
	if !bytes.Equal(sealed.GetReceiverSidecarId(), deposit.SignerSidecarId.Bytes()) {
		self.alarm(MailIngestAlarmWrongSigner, depositorId, messageId)
		dropSession()
		return effective
	}
	if ingress := sealed.GetIngress(); ingress != nil && ingress.GetVersion() != mailFormatVersion {
		effective.Ingress = nil
	}
	if evidence := sealed.GetEvidence(); evidence != nil {
		if evidence.GetVersion() != mailFormatVersion || !bytes.Equal(evidence.GetReceiverSidecarId(), sealed.GetReceiverSidecarId()) ||
			!bytes.Equal(evidence.GetMessageSha256(), messageSha256) {
			self.alarm(MailIngestAlarmEvidence, depositorId, messageId)
			effective.Evidence = nil
		}
	}
	return effective
}

// The first address of a From value, lowercase, or empty where it holds none.
func mailFromAddress(from string) string {
	if from == "" || mailFromParseMaxByteCount < len(from) {
		return ""
	}
	parser := &mail.AddressParser{WordDecoder: mailWordDecoder}
	addresses, err := parser.ParseList(from)
	if err != nil || len(addresses) == 0 {
		return ""
	}
	return dnsAsciiLower(addresses[0].Address)
}

// One opened deposit: true once it is settled and may be consumed, false where it stands for a later pass or another
// reader. An error is a failure to write, which stops the pass.
func (self *MailIngestor) ingestDeposit(ctx context.Context, depositorId Id, deposit *EvsDeposit, body io.Reader, pass *MailIngestPass) (bool, error) {
	messageId := Id(deposit.EntryId)
	if _, erased := self.erased.erased(messageId); erased {
		pass.Erased += 1
		return true, nil
	}
	switch self.authority.DepositorClass(self.repoId, depositorId, deposit.AuthPin) {
	case MailDepositorMail:
	case MailDepositorNone:
		self.alarm(MailIngestAlarmDepositor, depositorId, messageId)
		pass.Refused += 1
		return true, nil
	default:
		// read receipts, or a pin this device does not hold yet
		return false, nil
	}
	plaintext, err := mailReadDeposit(body, self.settings.DepositMaxByteCount)
	if errors.Is(err, ErrMailDepositTooLarge) {
		self.alarm(MailIngestAlarmUnread, depositorId, messageId)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	message, sealed, err := mailSplitDeposit(plaintext, self.settings.TrailerMaxByteCount)
	if errors.Is(err, ErrMailDepositVersion) {
		self.alarm(MailIngestAlarmUnread, depositorId, messageId)
		return false, nil
	}
	if err != nil || len(sealed.GetRecipients()) == 0 || self.settings.RecipientMaxCount < len(sealed.GetRecipients()) {
		self.alarm(MailIngestAlarmBadDeposit, depositorId, messageId)
		pass.Refused += 1
		return true, nil
	}
	messageSha256 := sha256.Sum256(message)
	effective := self.effectiveDeposit(depositorId, deposit, sealed, messageSha256[:])
	pushTimeMillis := uint64(max(deposit.Time.UnixMilli(), 0))
	receiveTimeMillis := MailDepositReceiveTime(effective, pushTimeMillis)
	month := MailYearMonthOf(receiveTimeMillis)

	parseSettings := self.settings.Parse
	if parseSettings == nil {
		parseSettings = DefaultMailParseSettings()
	}
	parsed, err := MailParseMessage(bytes.NewReader(message), parseSettings)
	if err != nil {
		return false, err
	}
	sameNetwork := !mailReceiverDeposit(effective)
	signerMaySendAsFrom := false
	if sameNetwork {
		if fromAddress := mailFromAddress(parsed.From); fromAddress != "" {
			signerMaySendAsFrom = self.authority.MaySendAs(deposit.SignerSidecarId, fromAddress)
		}
	}
	label := MailLabelDecide(&MailLabelInput{
		Deposit:             effective,
		MessageSha256:       messageSha256[:],
		FromDomain:          parsed.FromDomain,
		Root:                self.root,
		SignerMaySendAsFrom: signerMaySendAsFrom,
		Operators:           self.operators,
	})
	verdict, err := self.scorer.Score(ctx, parsed, effective)
	if err != nil {
		return false, err
	}
	entry, err := MailBuildIndexEntry(&MailIndexEntryInput{
		Id:             messageId,
		Deposit:        effective,
		PushTimeMillis: pushTimeMillis,
		ByteCount:      uint64(len(message)),
		Parsed:         parsed,
		TlsLabel:       label.Label,
		TlsBasis:       label.Basis,
		SpamScore:      verdict.Score,
		OneTimeCode:    MailExtractOneTimeCode(parsed.Subject, parsed.Text),
	})
	if err != nil {
		// a first recipient that is no address: no row can name the message
		self.alarm(MailIngestAlarmBadDeposit, depositorId, messageId)
		pass.Refused += 1
		return true, nil
	}
	headers := MailIngestHeaders(effective, messageId, parsed.FromDomain)
	content := make([]byte, 0, len(headers)+len(message))
	content = append(content, headers...)
	content = append(content, message...)
	messagePath := MailMessagePath(month, messageId)

	testHookBarrier("mail.ingest.push.before", "")
	_, err = self.index.Append(ctx, entry, &mailStoreWrite{Path: messagePath, Content: content})
	testHookBarrier("mail.ingest.push.after", "")
	if mailStoreConflictOn(err, messagePath) {
		// another reader won, or this one did before a crash: only the CONSUME is left
		pass.Present += 1
		return true, nil
	}
	if err != nil {
		return false, err
	}
	pass.Ingested += 1

	ingested := &MailMessage{
		RepoId: self.repoId, Id: messageId, Month: month, Entry: entry, Label: label, DepositorId: depositorId,
		Untrusted: MailEntryUntrusted(entry), ByteCount: uint64(len(message)),
	}
	self.noteReach(effective, ingested)
	self.noteUsedAt(ctx, effective, parsed, receiveTimeMillis)
	if self.args.Message != nil {
		self.args.Message(ingested)
	}
	return true, nil
}

// §16.8's reach receipt for one received message: a receive under the grant its first recipient's listen rests on,
// its peer the depositing sidecar, its relay the host the sender named. Never for same-network mail, which crossed
// no edge. A note the receipts refuse is logged and holds nothing back.
func (self *MailIngestor) noteReach(deposit *protocol.MailDeposit, message *MailMessage) {
	if self.args.Reach == nil || self.args.ReachGrant == nil || !mailReceiverDeposit(deposit) {
		return
	}
	grant := self.args.ReachGrant(message.Entry.GetAddress(), message.DepositorId)
	if grant == nil {
		return
	}
	note := &RecordReachNote{
		Kind: RecordReachKindReceive, GrantId: grant.GrantId, PolicyVersion: grant.PolicyVersion,
		Owner: grant.Owner, Approver: grant.Approver, ActionId: grant.ActionId,
		Peers: [][]byte{message.DepositorId.Bytes()}, StreamCount: 1, ByteCount: message.ByteCount,
	}
	if host := dnsAsciiLower(deposit.GetIngress().GetSni()); isMailHostName(host) {
		note.Relays = []RecordReachRelay{{Host: host}}
	}
	if err := self.args.Reach(note); err != nil {
		self.log.Warningf("[mail]ingest %s: a reach receipt was refused: %v", self.repoId, err)
	}
}

// Used at for each burner the deposit names (§15.8), by the sender's From domain at the sealed receive time. A use
// that fails is logged and holds nothing back.
func (self *MailIngestor) noteUsedAt(ctx context.Context, deposit *protocol.MailDeposit, parsed *MailParsed, receiveTimeMillis uint64) {
	if self.args.UsedAt == nil || parsed.FromDomain == "" || !mailReceiverDeposit(deposit) {
		return
	}
	at := time.UnixMilli(int64(min(receiveTimeMillis, mailLastMillis))).UTC()
	for _, address := range deposit.GetRecipients() {
		recipient, err := ParseMailRecipient(self.root, address)
		if err != nil || recipient.Kind != MailAddressKindBurner {
			continue
		}
		if err := self.args.UsedAt(ctx, recipient.Address(), parsed.FromDomain, at); err != nil && !errors.Is(err, ErrMailVaultEntryAbsent) {
			self.log.Warningf("[mail]ingest %s: used at was not noted: %v", self.repoId, err)
		}
	}
}
