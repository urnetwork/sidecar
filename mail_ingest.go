//go:build !ios_extension

// §15.7's ingest (R-MAIL-5, R-MAIL-10, R-MAIL-16, D-MAIL-5, D-MAIL-6, D-MAIL-14, I-9, I-11, FS-13; MAIL-M7-15): a
// reader of a mailbox or a group repo takes each depositor's deposits in version order and writes each message once,
// into the repo's file-mode ref, then consumes the deposit.
//
//	order     one pass reads the erasure ref first, then each depositor's ref in id order, its standing deposits
//	          oldest first; a deposit that settles (written, found written, erased or refused) joins the ref's one
//	          CONSUME at the end of its read, and one left standing holds nothing back
//	class     the depositor is judged at the deposit push's own pin (MailIngestAuthority). Only an owner-bound repo,
//	          a mailbox, takes read receipts (§11.12; QD-1181): there a reader that does not write deposits §16.8's
//	          read receipts, which are the record's and are left alone. In a group repo, a general one, deposit or
//	          write makes a mail depositor even while it reads, so the member's other devices deposit a personal
//	          network's group mail; a read_only sidecar's deposit is the receipt deposit alone (§7.8's exchange), so
//	          none of its deposits there is mail. One with no right to deposit there is consumed unrecorded; a pin
//	          this device does not hold yet leaves the deposit for a later pass, which Run makes after RetryInterval
//	          rather than its hourly resync, since no change of the mailbox comes when this device's state catches up.
//	          A pin before what this device retains, a lagging depositor's once two bases landed since it read, is
//	          not judged and counts against no one (QD-1196, as QD-1178 has it for evs statements): the depositor is
//	          classed at the installed state, and one that state gives no right leaves its deposit standing, unjudged
//	          (MailIngestAclAuthority.DepositorClass). A deposit ref takes only its depositor's own deposits (§11.8's
//	          refs table), so one another sidecar signed is consumed unrecorded
//	erased    a signed ERASE consumes its deposit without a message. If a deposit-only ERASE races the mailbox push,
//	          the post-commit check withholds callbacks. Readers mask the signed message id and a repo admin's next
//	          pass destroys any new body and index slots under the original erasure id (mail_erase_late.go)
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
//	index     where the repo's search index is on (§15.7's search index row; R-MAIL-17, D-MAIL-16, I-19; MAIL-M10-01),
//	          that push carries the message's index delta too: the client's in-ref writer (evs_index_writer.go) sees
//	          the push's plan, extracts m/ by indexExtractMail's rule and adds this device's head to it, so one head
//	          CAS commits m/, i/ and the delta. Only m/ is a document, keyed by its path, which names the message id;
//	          i/, f/, s/model, vault/ and every other family stay out (indexExcluded), so seen, labels, trash and spam
//	          never reach the index, and the doc table holds subject, from, to and date. The m/ write carries the
//	          outside mark (EvsPathWrite.Outside) for every message MailEntryUntrusted marks, which its rows keep, so a
//	          search hit on outside mail reads untrusted and taints the run that takes its text (I-9). A CUT landing
//	          between the build and the push gets the push 409 INDEX_EPOCH, and the sender plans it again from a fresh
//	          read, its head without what the erasure set lists (§11.14's epoch row). With the index off, outside the
//	          format2 gate or in a format-1 repo the push is m/ and i/ alone: i/ stays the message list, which search
//	          never replaces
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
// A push creating a path waits out 412 PATH_EPOCH_DUE while a mapper's block holds the ref, which EvsRepo.WritePaths
// does (evs_write.go's waitPathEpoch); no due holds a creation, every due being batched (QD-1046). Slot ids are evs's,
// drawn per statement (evs_upload.go), never from a deposit or message id.
//
// Not built here: the judging of a same-network deposit's From beyond MailIngestAuthority.MaySendAs, which MAIL-M7-18
// completes. A mailbox's or group repo's mail from before its index is indexed by one first build
// (mail_index_build.go).
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
	// A receiver or a member's device, by its deposit or write, which in a group repo holds while it also reads: its
	// deposits are mail.
	MailDepositorMail
	// In an owner-bound repo, a reader that does not write (§8.5, §11.12): its deposits are §16.8's read receipts,
	// which mail leaves alone. No other repo takes receipts (QD-1181).
	MailDepositorReceipts
	// The push's pin is before what this device retains, so it is not judged, and the installed state gives the
	// depositor no right there: the deposit stands, counting against no one, and no pass waits for it, since no later
	// state of this device judges that pin (QD-1196).
	MailDepositorUnjudged
)

// What ingest asks of §8's verified state. Implementations are safe for concurrent use.
type MailIngestAuthority interface {
	// Whether sidecarId reads and writes repoId now: a consented device of a mailbox's owner that is not read-only,
	// or a group repo's reader that writes (§15.7's readers).
	Ingests(repoId Id, sidecarId Id) bool
	// What depositorId's deposits in repoId are at pin, the deposit push's own; a nil pin asks at the installed
	// state, which never answers MailDepositorUnjudged.
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
	// A verified custom From maps to its own network's policy alias. An unavailable answer grants no identity.
	CustomFrom func(address string) (MailRecipient, bool)
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

// The depositor's rights at the pin. In an owner-bound repo read without write is a receipt depositor (§11.12), the
// one kind the read-receipt gate deposits into (evs_receipt_gate.go); in any other, a group repo among them, deposit
// or write is a mail depositor even while it reads (QD-1181), but a read_only sidecar, whose deposit is §16.8's
// receipt deposit alone (§7.8's exchange), deposits no mail there.
//
// A pin before what this device retains (ErrConfigPinNotRetained from a log that judges pins: before its previous
// base, as a depositor's push is when it deposited on a state two bases behind this device's, or before the base a
// restored log starts at) is not judged, and counts against no one (QD-1196), as the evs read took the deposit's push
// (QD-1178, §10.9's judged row): that read checked the push's signature by the key the oldest retained rows give its
// signer, refusing a signer they do not admit at the pin, and ingest holds the signer to the depositor. Left for a
// later state, such a deposit would stand forever, since no later state of this device judges that pin, and the mail
// it carried, answered delivered, would never be listed. So the depositor is classed at the installed state, whose
// repo kind and sidecar row no later state changes: a receipt depositor or a read_only one outside an owner-bound
// repo as above, and a mail depositor where that state gives it deposit or write. One that state gives no right, a
// sidecar revoked or a grant ended since its deposit, is MailDepositorUnjudged: its deposit stands rather than being
// refused at a state it was not made at, or taken from a depositor that holds no right now. A pin ahead of the state,
// off its chain, or asked of an engine with no log stays MailDepositorUnknown.
func (self *MailIngestAclAuthority) DepositorClass(repoId Id, depositorId Id, pin *bridge.AuthPin) MailDepositorClass {
	if self == nil || self.Engine == nil {
		return MailDepositorUnknown
	}
	state := self.Engine.State()
	judged := true
	if pin != nil {
		pinned, err := self.Engine.stateAt(pin)
		switch {
		case err == nil:
			state = pinned
		case errors.Is(err, ErrConfigPinNotRetained) && self.Engine.states != nil:
			// before what this device retains: classed at the installed state, unjudged
			judged = false
		default:
			return MailDepositorUnknown
		}
	}
	if state == nil {
		return MailDepositorUnknown
	}
	rights := state.EvsAccess(AclSidecarSubject(depositorId), repoId, AclTokenAudienceEvs, clockOrReal(self.Clock).Now()).Rights
	ownerBound := aclRepoKindOwnerBound(state.Repo(repoId).GetKind())
	depositor := state.sidecarState(depositorId)
	switch {
	case ownerBound && rights.Has(AclEvsRead) && !rights.Has(AclEvsWrite):
		return MailDepositorReceipts
	case !ownerBound && depositor != nil && depositor.readOnly:
		// its deposit right is for receipts, which no repo but an owner-bound one takes: its row's, whatever the pin
		return MailDepositorNone
	case rights.Has(AclEvsDeposit) || rights.Has(AclEvsWrite):
		return MailDepositorMail
	case !judged:
		return MailDepositorUnjudged
	}
	return MailDepositorNone
}

// AclEngine.AllowAlias for the signer's send on the address's local part.
func (self *MailIngestAclAuthority) MaySendAs(signerSidecarId Id, fromAddress string) bool {
	if self == nil || self.Engine == nil || self.OwnZone == nil {
		return false
	}
	recipient, err := ParseMailRecipient(self.Root, fromAddress)
	if err != nil {
		if self.CustomFrom == nil {
			return false
		}
		var ok bool
		recipient, ok = self.CustomFrom(fromAddress)
		if !ok {
			return false
		}
	}
	if recipient.Kind == MailAddressKindBurner || recipient.Kind == MailAddressKindReverseAlias || !self.OwnZone(recipient.Zone) {
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
	// How long Run waits after a pass that failed, or that left a deposit whose pin this device does not hold yet,
	// before it tries again. Non-positive takes MinPassInterval.
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
	// A receiver's deposit, internet mail, rather than a same-network one, and the SNI its sealed MailIngress names,
	// empty for none: what a reader's mail_receiver_alarm judges (MAIL-M7-25).
	ReceiverDeposit bool
	Sni             string
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
	// Of those, the deposits whose depositor is not judged yet: their push's pin is one this device does not hold.
	Pending int
	// Of those, the deposits no state of this device judges, pinned before what it retains, whose depositor the
	// installed state gives no right there (MailDepositorUnjudged).
	Unjudged int
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
	eraser    *MailEraser
	authority MailIngestAuthority
	operators *MailOperatorList
	args      *MailIngestArgs
	clock     Clock
	log       Logger
	settings  *MailIngestSettings

	// Held over a pass, so one runs at a time.
	passLock sync.Mutex
	// A finished sweep covers only these two signed ref versions. A restart starts at zero.
	reconciledMain    uint64
	reconciledErasure uint64
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
	ingestor := newMailIngestor(args.Repo.RepoId(), &mailIngestEvsRepo{repo: args.Repo}, store, args)
	authority, ok := args.Authority.(MailEraseAuthority)
	if !ok {
		authority = &mailIngestEvsRepo{repo: args.Repo}
	}
	eraser, err := NewMailEraser(&MailEraserArgs{Repo: args.Repo, SidecarId: args.SidecarId, Authority: authority, Clock: args.Clock, Log: args.Log})
	if err != nil {
		return nil, err
	}
	ingestor.eraser = eraser
	return ingestor, nil
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
	mailRunPasses(ctx, self.clock, self.settings.MinPassInterval, self.wake, func() time.Duration {
		pass, err := self.Ingest(ctx)
		if ctx.Err() != nil {
			return 0
		}
		if err != nil && !errors.Is(err, ErrMailNotIngester) {
			self.log.Warningf("[mail]ingest %s: %v", self.repoId, err)
		}
		if err != nil || 0 < pass.Pending {
			// a failed pass, or a deposit whose pin this device's state has yet to reach, which no hint announces
			return self.settings.retryWait()
		}
		return self.settings.ResyncInterval
	})
}

// How long a pass that failed, or that left a deposit whose pin this device does not hold yet, waits before the next:
// RetryInterval, else MinPassInterval, and with neither positive only a change brings it.
func (self *MailIngestSettings) retryWait() time.Duration {
	if 0 < self.RetryInterval {
		return self.RetryInterval
	}
	return max(self.MinPassInterval, 0)
}

// Passes on the caller's goroutine until ctx ends: one at once, then one at each wake and once the wait the last pass
// answered runs out, never two within gap of each other, so wakes that come while a pass runs or within gap after it
// bring one pass. A wait that is not positive leaves the next pass to a wake alone. Both waits run from the pass's end,
// each a time waited for itself (QD-1425), so a move of the clock past the gap's end does not push the timed wait
// later. MailIngestor.Run's loop, and a group repo's on the mail component (mail_component_group.go). No pass starts
// once ctx has ended, a wake or a timer taken as it ended included, so nothing is ingested or written on the dead
// context, and an ended ctx asks the clock for nothing.
func mailRunPasses(ctx context.Context, clock Clock, gap time.Duration, wake <-chan struct{}, pass func() (wait time.Duration)) {
	gap = max(gap, 0)
	// select takes any of its ready cases at random: a wake or a timer taken as ctx ended reads as the end
	for ctx.Err() == nil {
		wait := pass()
		if ctx.Err() != nil {
			return
		}
		passEnd := clock.Now()
		// the least gap first, so a burst of wakes is one pass
		if 0 < gap {
			select {
			case <-ctx.Done():
				return
			case <-ClockAfterAt(clock, passEnd.Add(gap)):
			}
			if ctx.Err() != nil {
				return
			}
		}
		if 0 < wait && wait <= gap {
			// the timed wait is spent: the next pass is due
			continue
		}
		// with no timed wait, only a wake brings the next pass
		var timer <-chan time.Time
		if 0 < wait {
			timer = ClockAfterAt(clock, passEnd.Add(wait))
		}
		select {
		case <-ctx.Done():
		case <-wake:
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
	if err := self.reconcileErased(ctx); err != nil {
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
			// an owner-bound repo's reader's receipt ref, which the record ingests: never opened here
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
	if deposit.SignerSidecarId != depositorId {
		// a deposit ref takes only its depositor's own deposits (§11.8's refs table): the evs read holds that at a
		// judged pin and takes a push pinned before what it retains unjudged (QD-1178), so ingest holds it here
		self.alarm(MailIngestAlarmDepositor, depositorId, messageId)
		pass.Refused += 1
		return true, nil
	}
	switch self.authority.DepositorClass(self.repoId, depositorId, deposit.AuthPin) {
	case MailDepositorMail:
	case MailDepositorNone:
		self.alarm(MailIngestAlarmDepositor, depositorId, messageId)
		pass.Refused += 1
		return true, nil
	case MailDepositorReceipts:
		return false, nil
	case MailDepositorUnjudged:
		// no state of this device judges it, and no pass waits for one
		pass.Unjudged += 1
		return false, nil
	default:
		// a pin this device does not hold yet: Run tries again after RetryInterval
		pass.Pending += 1
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

	// Skip a deposit erased since it opened. The post-commit check below and the
	// admin's durable reconciliation also cover an ERASE that races this push.
	if _, err := self.erased.refresh(ctx, self.repo.Erasures); err != nil {
		return false, err
	}
	if _, erased := self.erased.erased(messageId); erased {
		pass.Erased += 1
		return true, nil
	}
	testHookBarrier("mail.ingest.push.before", "")
	// the m/ write's mark: where the search index is on, its rows of the message carry the outside bit (search's)
	_, err = self.index.Append(ctx, entry, &mailStoreWrite{Path: messagePath, Content: content, Outside: MailEntryUntrusted(entry)})
	testHookBarrier("mail.ingest.push.after", "")
	present := mailStoreConflictOn(err, messagePath)
	if !present && err != nil {
		return false, err
	}
	// Do not announce, forward or consume an unverified candidate. Even if this
	// process stops here, any admin's next pass finds the copy from the ERASE.
	if _, err := self.erased.refresh(ctx, self.repo.Erasures); err != nil {
		return false, err
	}
	if _, erased := self.erased.erased(messageId); erased {
		if err := self.reconcileErased(ctx); err != nil {
			return false, err
		}
		pass.Erased++
		return true, nil
	}
	if present {
		pass.Present++
		return true, nil
	}
	pass.Ingested += 1

	ingested := &MailMessage{
		RepoId: self.repoId, Id: messageId, Month: month, Entry: entry, Label: label, DepositorId: depositorId,
		Untrusted: MailEntryUntrusted(entry), ByteCount: uint64(len(message)),
		ReceiverDeposit: mailReceiverDeposit(effective), Sni: dnsAsciiLower(effective.GetIngress().GetSni()),
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
