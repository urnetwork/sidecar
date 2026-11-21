//go:build !ios_extension

// RecordEraser (proposed; RECORD-M3-06, RECORD-M10-01; §16.8's Erasure, §11.12's closure, cut and reconcile rows,
// RECORD.md section 8, DESIGN-DETAILS 15.2.10 and 15.7's note; R-MCP-8, R-MCP-13, R-EVS-11, D-EVS-26, D-MCP-24, FI-19,
// FS-47, FS-80, FS-111): a log admin's erasure of entries of one log by key destruction, on every leg the record
// writes from, and in a format-2 log the search index's part of it.
//
//	who       only admin on the log erases (§11.12): a repo admin of a team log, and in a vault a consented device of
//	          its owner; a person's erasure, reason 1 or 3, runs only once its command was confirmed on /dev/tty or in an
//	          app's UI and never from a caller with a harness process among its ancestors (§5.8), so no MCP tool and no
//	          prompt-injected shell reaches it; a class 7 entry, which lasts as long as the log, is refused
//	journal   one file a erasure, written before the first push and after each step, so a restart goes on from evs's
//	          state: Resume sends a journaled ERASE again under its push id, which evs answers as it answered it, and
//	          takes up the step the journal names. An erasure that waits, or that a failure stopped after its first
//	          ERASE, is tried again by the record's loop from its journal's next try (hookErasures)
//	copies    step 1: the log is read to its head, every stream and deposit ref (RECORD.md section 8's every copy): the
//	          named entries are marked erased in this device's reader before anything else, so an ingest pass refuses
//	          them (section 5.4's erased step); a log this device ingests is ingested first, so a deposit holding a named
//	          entry is consumed and its slot deleted with no other entry lost; a deposit still standing after that, as
//	          at the storage limit, has its slot named in the ERASE and is consumed, its batch's other entries then a gap
//	erase     step 2: the ERASEs name every copy's (key_slot_id, key_index) and those deposit slots, at most
//	          EraseKeyCount a push, the first holding the entries' own keys, so at the storage limit the bodies go at
//	          once; each carries the erasure id, whether it completes the erasure, and as its sealed note the erasure's
//	          ErasureBody, so a reader that holds only the ERASE knows which entries it took; NOTHING_TO_ERASE is done.
//	          evs takes them under a preservation hold too (owner decision 133)
//	reread    step 3: the log's streams are read to their heads again and a copy found now is erased as step 2's
//	          were, so every copy's ERASE is on the erasure ref before the CUT (15.2.10's fence)
//	cut       step 4, in a format-2 log whose index takes part (SetEraseIndex binds RecordEraseIndex): IndexEraser.Cut
//	          on the log's ur/index lists each copy RECORD.md 7.1 makes a document, at its path's entry version, and
//	          the card of each stream holding a copy of a run card's source entry, through the epoch the CUT names
//	          (QD-779, QD-781). No ERASE of steps 2 and 3 then says complete: an erasure is complete only after its
//	          CUT. A full erasure set makes the erasure wait RetryInterval, its bodies gone already, and one whose CUT
//	          would list more than CutDocumentCount documents is refused before anything is erased. An erasure none of
//	          whose entries is a document or a card's source lists nothing, takes none of steps 4 to 6, and its last
//	          ERASE says complete, as in format 1
//	again     step 5: each listed card is folded again at its stream's head, which this device's reader holds, without
//	          the erased entries, and entered full in this device's own index head (IndexEraser.Reenter): an erased
//	          entry leaves its run card there, the card above every version the CUT lists. A quota refusal holds back
//	          no file and is tried again from ReentryRetryInterval
//	rewrite   step 6: IndexEraser.Rewrite's CLOSURE and ERASE pairs over every index file holding a listed version,
//	          its last ERASE saying complete with the ErasureBody as its note; a wait on an allowance or the limit, or
//	          a list it could not prove whole, keeps the erasure journaled and tried again. A rewrite that finds no
//	          file to rewrite leaves no ERASE with a key to say complete, so a completion ERASE does (QD-1132;
//	          evs_erase_completion.go): it names a key an ERASE of the erasure named first and no ERASE named since,
//	          and readers read it as destroying nothing new. It goes with the record's ERASEs, journaled under its push
//	          id, so the index's eraser is not asked for one (IndexRewriteArgs.Completion), flagged COMPLETION (QD-1137):
//	          evs refuses one whose key a completion named last, NOTHING_TO_ERASE, and the erasure then counts not
//	          completed, its set entry staying
//	entry     step 7: the erasure entry, RECORD.md's ErasureBody, in this device's own stream of the log, which the
//	          writer retries while §11.13's limit refuses it; until it lands the committed ERASE is the record. Headers
//	          and chains still verify: only keys go, and the entry files stay
//	after     this device's reader drops every decrypted copy of a named entry's body and refuses its keys at once;
//	          another reader does at its next sync, the ERASE's hint (record_reader.go)
//	late      a log admin's daemon that reads, at a later sync, a live copy of an entry an erasure names ERASEs that
//	          copy's key row under the same erasure id, its note the erasure's own, then takes steps 4 to 6 for that
//	          copy, the CUT adding its documents to the erasure's set entry (EraseLateCopies); no second erasure entry
//	          is written, the first naming the entry
//	complete  in a format-2 log an erasure is complete while its newest ERASE says so (recordEraseNewestStore and the
//	          binding's complete), so a late copy's ERASE opens it again until that copy's rewrite ends it, and no CUT
//	          drops its set entry meanwhile
//	reach     an erasure names entries of one log: a copy or twin in another log is not reached, and the result names
//	          the log it reached
//
// Off the ios_extension legs, which link the record's other files but none of its erasures. Not here: expiry's own
// erasures (RECORD-M6-03, which calls this eraser and so takes the same steps), the directory's announcement
// documents and cards (RECORD-M10-05, whose log's index this eraser leaves alone), and the search and ur://record
// caches' own deletes, which are their components'. Safe for concurrent use: one erasure at a time.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Why an erasure ran (ErasureBody.reason).
type RecordErasureReason uint32

const (
	RecordErasureReasonUnspecified RecordErasureReason = 0
	// A person's act at a device.
	RecordErasureReasonPerson RecordErasureReason = 1
	// Expiry under a retention policy a person signed.
	RecordErasureReasonRetention RecordErasureReason = 2
	// A moderator's act.
	RecordErasureReasonModeration RecordErasureReason = 3
	// A repo owner's revocation, through a DirectoryErasureRequest.
	RecordErasureReasonRevocation RecordErasureReason = 4
)

// The eraser's journal's format values.
const (
	recordEraseJournalDirectory = "erase/"
	recordEraseJournalVersion   = 1
	// Nothing sent, or step 2's ERASEs drawn.
	recordEraseStepPlanned = "planned"
	// Step 2's ERASEs and CONSUMEs committed.
	recordEraseStepErased = "erased"
	// Step 3's ERASEs committed, and the CUT's documents journaled.
	recordEraseStepReread = "reread"
	// The CUT committed, or none was owed: steps 5 to 7 follow.
	recordEraseStepCut = "cut"
)

var (
	// The erasure cannot run as asked: no entry, too many, a reason or log it does not take. Nothing was erased.
	ErrRecordEraseInvalid = errors.New("record erase invalid")
	// This sidecar is not an admin of the log, or in a vault not a consented device of its owner (§11.12).
	ErrRecordEraseNotAdmin = errors.New("record erase: only an admin of the log erases")
	// A person's erasure that was not confirmed on /dev/tty or in an app's UI, or that a harness process's descendant
	// asked for (§5.8): nothing was erased.
	ErrRecordEraseUnconfirmed = errors.New("record erase: not confirmed by a person")
	// A named entry is of class 7, which lasts as long as the log (RECORD.md section 8): nothing was erased.
	ErrRecordEraseLogClass = errors.New("record erase: a log-class entry lasts as long as the log")
	// An erasure whose CUT would list more search documents than CutDocumentCount: the caller erases the entries in
	// smaller batches. Nothing was erased.
	ErrRecordEraseTooLarge = errors.New("record erase: more search documents than one CUT lists")
	// A format-2 log's erasure whose index side did not open, or a copy whose stream states no ref: the erasure
	// stays journaled and its CUT, re-entry and rewrite wait for it.
	ErrRecordEraseIndexUnavailable = errors.New("record erase: the log's search index is unavailable")
)

// What the eraser runs by.
type RecordEraserSettings struct {
	// The entries one erasure names, within ErasureBody.entry_ids' 1,024 (record.proto): each of its ERASEs carries
	// the erasure's ErasureBody as its note, and an ERASE's note rides its push's sealed metadata (QD-682), the push
	// one part, so 512 keeps a note near 10 KiB. A larger erasure is several.
	EntryCount int
	// The keys one ERASE names, so its push stays within one part beside its note.
	EraseKeyCount int
	// The most documents one erasure's CUT lists on its log's ur/index, run cards among them: 256, about 6 KiB of the
	// erasure set's 16,208 B, so pending erasures share the set, a reading, as mail's CutDocumentMaxCount. An erasure
	// of more is refused before anything is erased (ErrRecordEraseTooLarge). Positive.
	CutDocumentCount int
	// Between tries of an erasure that waits on a full erasure set, or that a failure stopped after its first ERASE:
	// 10 min, a reading, as the index's re-entry retry (IndexEraseSettings.ReentryRetryInterval). Positive.
	RetryInterval time.Duration
}

// 512 entries an erasure and 512 keys an ERASE, 256 documents a CUT, and 10 min between tries.
func DefaultRecordEraserSettings() *RecordEraserSettings {
	return &RecordEraserSettings{
		EntryCount:       512,
		EraseKeyCount:    512,
		CutDocumentCount: 256,
		RetryInterval:    10 * time.Minute,
	}
}

// One erasure asked of the eraser.
type RecordEraseArgs struct {
	LogId    Id
	EntryIds []Id
	Reason   RecordErasureReason
	// Reason 4's DirectoryErasureRequest id, which the erasure's id is (plan-RECORD-small-readings #12).
	RequestId []byte
	// A person confirmed the command on /dev/tty or in an app's UI (§5.8).
	Confirmed bool
	// The caller has a harness process among its ancestors: a person's erasure is then refused.
	HarnessAncestor bool
}

// What an erasure did.
type RecordEraseResult struct {
	ErasureId Id
	// The one log it reached: copies and twins in other logs are not.
	LogId Id
	// Named entries this device found in the log, every copy's key now gone.
	Erased []Id
	// Named entries no stream or deposit of the log held.
	Missing []Id
	// The keys its ERASEs named.
	Keys []*RecordSlotKey
	// The erasure entry, in the writer's journal; nil when the erasure resumed it, when it was written at an earlier
	// call, or for a late copy, which writes none.
	Entry *RecordEntryRef
	// Format 2's steps 4 to 6 at this call; nil where the log's index takes no part.
	Index *RecordEraseIndexResult
}

// What format 2's steps 4 to 6 came to at one call (DESIGN-DETAILS 15.2.10).
type RecordEraseIndexResult struct {
	// The documents the CUT lists, and of them the run cards, listed through its epoch.
	DocumentCount int
	CardCount     int
	// The CUT committed: from it no index push built before it commits, and every reader masks what it lists.
	Fenced bool
	// Cards folded again and entered in this device's own index head, and those that entered nothing: an empty fold,
	// one blocked or past the version's bits, or one standing above the list already.
	EnteredCount int
	SkippedCount int
	// The rewrite's state as it stopped: rewriting, waiting or done, with what is left.
	Erasure *SidecarErasure
	// An ERASE of the rewrite said complete.
	Completed bool
	// The rewrite could not prove its list whole: nothing said complete, and the erasure stays journaled.
	Unproven bool
	// The erasure waits, on a full erasure set, an allowance, the limit or a quota, and goes on from NextTry.
	Waiting bool
	NextTry time.Time
}

// What a record erasure asks of its log's search index in a format-2 repo (§16.8's Erasure; DESIGN-DETAILS 15.2.10):
// the index's eraser on the log's ur/index, the log's kind, and the doc_keys its documents are drawn under. Every push
// it makes takes admin. recordEraseIndex is one, over EvsRepo (NewRecordEvsEraseIndex) or the index's fake in tests.
type RecordEraseIndex interface {
	// The log's kind as its repo states it: vault, team record or record, whose documents are the record class's.
	LogKind() protocol.RepoKind
	// The doc_key of the document registered under name in the stream whose ref is refId, chunk 0 (§11.14's key row).
	DocKey(refId Id, name []byte) ([indexIdByteCount]byte, error)
	// IndexEraser.Cut; called again with nothing new it pushes nothing, and for an erasure the set has dropped it
	// adds the entry again.
	Cut(ctx context.Context, args *IndexCutArgs) (*IndexCutResult, error)
	// IndexEraser.Reenter.
	Reenter(ctx context.Context, args *IndexReenterArgs) (*IndexReenterResult, error)
	// IndexEraser.Rewrite, from evs's state.
	Rewrite(ctx context.Context, args *IndexRewriteArgs) (*IndexRewriteResult, error)
	// IndexEraser.Resume: for another device's erasure, the CUT where it is missing, then the rewrite, each only once
	// it is this device's by §11.12's reconcile row.
	Resume(ctx context.Context, args *IndexResumeArgs) (*IndexResumeResult, error)
}

// Opens a log's format-2 index side for its erasures: nil and no error where the log has none, in format 1 or for a
// log whose documents are not the record class's, the directory's among them.
type RecordEraseIndexOpen func(ctx context.Context, logId Id) (RecordEraseIndex, error)

// One erasure in the journal.
type recordEraseJournal struct {
	Version   int    `json:"version"`
	ErasureId Id     `json:"erasure_id"`
	LogId     Id     `json:"log_id"`
	EntryIds  []Id   `json:"entry_ids"`
	Reason    uint32 `json:"reason"`
	RequestId []byte `json:"request_id,omitempty"`
	Step      string `json:"step"`
	// the ERASEs, each drawn and journaled before it first goes
	Erases []*recordEraseJournalPush `json:"erases,omitempty"`
	// the deposits consumed after their slots were named
	Consumes []*recordEraseJournalConsume `json:"consumes,omitempty"`
	Erased   []Id                         `json:"erased,omitempty"`
	Missing  []Id                         `json:"missing,omitempty"`
	// Format 2's: the log's index takes part, so no ERASE before the rewrite's says complete; the documents the CUT
	// lists and the cards the re-entry folds, journaled before the CUT.
	Listing   bool                          `json:"listing,omitempty"`
	Documents []*recordEraseJournalDocument `json:"documents,omitempty"`
	Cards     []*recordEraseJournalCard     `json:"cards,omitempty"`
	// Step 3's read was taken and its ERASEs drawn, from Erases[RereadFrom:].
	Reread     bool `json:"reread,omitempty"`
	RereadFrom int  `json:"reread_from,omitempty"`
	// An ERASE of steps 2 and 3 (or a late copy's) committed: one whose every ERASE found its keys gone already, as
	// when another admin's pass took them first, committed nothing and never began (§11.12's reconcile row), so it
	// lists nothing, the erasure that took the keys listing their documents.
	Began bool `json:"began,omitempty"`
	// The completion ERASE's push id, drawn and journaled before it first goes (QD-1132).
	CompletionPushId Id `json:"completion_push_id,omitempty"`
	// The erasure entry was appended (step 7).
	Entered bool `json:"entered,omitempty"`
	// A late copy's erasure: its ERASEs' note is Note, the erasure's own as its first ERASE carried it, and no erasure
	// entry follows.
	Late bool   `json:"late,omitempty"`
	Note []byte `json:"note,omitempty"`
	// When the record's loop goes on with an erasure that waits or that a failure stopped, in Unix ms; 0 for none.
	NextTryMillis int64 `json:"next_try_ms,omitempty"`
}

// One ERASE of an erasure.
type recordEraseJournalPush struct {
	PushId   Id               `json:"push_id"`
	Keys     []*RecordSlotKey `json:"keys"`
	Complete bool             `json:"complete"`
	// A completion ERASE (QD-1137), whose statement a retry under its push id builds alike.
	Completion bool `json:"completion,omitempty"`
}

// One CONSUME of a deposit whose slot an ERASE named.
type recordEraseJournalConsume struct {
	PushId      Id   `json:"push_id"`
	DepositorId Id   `json:"depositor_id"`
	DepositIds  []Id `json:"deposit_ids"`
}

// One document a CUT lists.
type recordEraseJournalDocument struct {
	Key []byte `json:"key"`
	// The path's entry version; unread for ThroughEpoch.
	Version uint64 `json:"version,omitempty"`
	// A run card, listed through the epoch the CUT names.
	ThroughEpoch bool `json:"through_epoch,omitempty"`
}

// One run card the re-entry folds again: its stream and run.
type recordEraseJournalCard struct {
	Key             []byte `json:"key"`
	StreamSidecarId Id     `json:"stream_sidecar_id"`
	RefId           Id     `json:"ref_id"`
	RunId           Id     `json:"run_id"`
}

// The erasures' state beside the eraser, which SidecarRecord holds: the format-2 index side SetEraseIndex binds, the
// logs a sync read since the record's loop last looked at them, when it last looked for others' erasures in each, and
// the erasures this process ran or took up to their end, which a look passes over though no ERASE says complete (a
// rewrite with no file to rewrite has no key left to say so).
type recordErasing struct {
	stateLock         sync.Mutex
	open              RecordEraseIndexOpen
	hooked            bool
	lateLogIds        map[Id]bool
	othersLogIdLooks  map[Id]time.Time
	settledErasureIds map[Id]bool
}

// Whether erasureId ran to its end in this process.
func (self *recordErasing) settled(erasureId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.settledErasureIds[erasureId]
}

// Notes that erasureId ran to its end here.
func (self *recordErasing) settle(erasureId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.settledErasureIds[erasureId] = true
}

// The record's erasures' state, made at its first use.
func (self *SidecarRecord) erasingState() *recordErasing {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	erasing, _ := self.erasing.(*recordErasing)
	if erasing == nil {
		erasing = &recordErasing{lateLogIds: map[Id]bool{}, othersLogIdLooks: map[Id]time.Time{}, settledErasureIds: map[Id]bool{}}
		self.erasing = erasing
	}
	return erasing
}

// Binds the format-2 index side of the record's erasures (DESIGN-DETAILS 15.2.10): NewRecordEvsEraseIndex over the
// network's evs client. Nil unbinds it, and every erasure is then format 1's, with no CUT.
func (self *SidecarRecord) SetEraseIndex(open RecordEraseIndexOpen) {
	erasing := self.erasingState()
	erasing.stateLock.Lock()
	defer erasing.stateLock.Unlock()
	erasing.open = open
}

// From here each sync of a log marks it for a look, and each pass of the record's loop erases the late copies it finds
// there, takes up others' erasures there at most once a RetryInterval, and goes on with every journaled erasure whose
// next try has come. Once a record; NewRecordComponent calls it.
func (self *SidecarRecord) hookErasures() {
	erasing := self.erasingState()
	hooked := func() bool {
		erasing.stateLock.Lock()
		defer erasing.stateLock.Unlock()
		hooked := erasing.hooked
		erasing.hooked = true
		return hooked
	}()
	if hooked {
		return
	}
	self.reader.addSyncHook(func(ctx context.Context, logId Id) {
		erasing.stateLock.Lock()
		defer erasing.stateLock.Unlock()
		erasing.lateLogIds[logId] = true
	})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.tendHooks = append(self.tendHooks, func(ctx context.Context) {
		self.Eraser().tend(ctx)
	})
}

// The eraser of a record. Its erasures run one at a time, under the record's own lock, whichever eraser of the record
// runs them.
type RecordEraser struct {
	record   *SidecarRecord
	store    SidecarStore
	settings *RecordEraserSettings
}

// The record's eraser.
func (self *SidecarRecord) Eraser() *RecordEraser {
	return &RecordEraser{record: self, store: self.writer.store, settings: DefaultRecordEraserSettings()}
}

// The journal's file of erasureId.
func recordEraseJournalName(erasureId Id) string {
	return recordEraseJournalDirectory + hex.EncodeToString(erasureId[:])
}

// Writes journal durably.
func (self *RecordEraser) writeJournal(journal *recordEraseJournal) error {
	journal.Version = recordEraseJournalVersion
	content, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(recordEraseJournalName(journal.ErasureId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// Every journaled erasure, in id order.
func (self *RecordEraser) readJournals() ([]*recordEraseJournal, error) {
	entries, err := self.store.List(recordEraseJournalDirectory)
	if err != nil {
		return nil, err
	}
	journals := []*recordEraseJournal{}
	for _, entry := range entries {
		reader, err := self.store.Open(entry.Name)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return nil, err
		}
		journal := &recordEraseJournal{}
		if err := json.Unmarshal(content, journal); err != nil || journal.Version != recordEraseJournalVersion || recordEraseJournalName(journal.ErasureId) != entry.Name {
			return nil, fmt.Errorf("%w: erasure journal %s", ErrRecordChainCorrupt, entry.Name)
		}
		journals = append(journals, journal)
	}
	return journals, nil
}

// The ErasureBody an erasure's entry and its ERASEs' notes carry.
func (self *recordEraseJournal) body() *protocol.ErasureBody {
	body := &protocol.ErasureBody{ErasureId: self.ErasureId.Bytes(), Reason: self.Reason, RequestId: self.RequestId}
	for _, entryId := range self.EntryIds {
		body.EntryIds = append(body.EntryIds, entryId.Bytes())
	}
	return body
}

// The sealed note every ERASE of the erasure carries: its ErasureBody, or for a late copy the note its first ERASE
// carried.
func (self *recordEraseJournal) note() ([]byte, error) {
	if self.Late {
		return self.Note, nil
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(self.body())
}

// Every key the journal's ERASEs name, in order.
func (self *recordEraseJournal) keys() []*RecordSlotKey {
	keys := []*RecordSlotKey{}
	for _, push := range self.Erases {
		keys = append(keys, push.Keys...)
	}
	return keys
}

// The CUT's documents as the index's eraser takes them.
func (self *recordEraseJournal) cutDocuments() ([]*IndexCutDocument, error) {
	documents := make([]*IndexCutDocument, 0, len(self.Documents))
	for _, document := range self.Documents {
		if len(document.Key) != indexIdByteCount {
			return nil, fmt.Errorf("%w: erasure journal %s", ErrRecordChainCorrupt, self.ErasureId)
		}
		documents = append(documents, &IndexCutDocument{
			Key: [indexIdByteCount]byte(document.Key), Version: document.Version, ThroughEpoch: document.ThroughEpoch,
		})
	}
	return documents, nil
}

// The cards among the documents.
func (self *recordEraseJournal) cardCount() int {
	count := 0
	for _, document := range self.Documents {
		if document.ThroughEpoch {
			count += 1
		}
	}
	return count
}

// Erases args' entries of one log: see the file header.
func (self *RecordEraser) Erase(ctx context.Context, args *RecordEraseArgs) (*RecordEraseResult, error) {
	switch {
	case args == nil || len(args.EntryIds) == 0 || self.settings.EntryCount < len(args.EntryIds):
		return nil, fmt.Errorf("%w: an erasure names 1 to %d entries", ErrRecordEraseInvalid, self.settings.EntryCount)
	case args.Reason == RecordErasureReasonUnspecified || RecordErasureReasonRevocation < args.Reason:
		return nil, fmt.Errorf("%w: reason %d", ErrRecordEraseInvalid, args.Reason)
	case args.Reason == RecordErasureReasonRevocation && len(args.RequestId) != len(Id{}):
		return nil, fmt.Errorf("%w: a revocation's erasure names its request", ErrRecordEraseInvalid)
	}
	if (args.Reason == RecordErasureReasonPerson || args.Reason == RecordErasureReasonModeration) && (!args.Confirmed || args.HarnessAncestor) {
		return nil, ErrRecordEraseUnconfirmed
	}
	self.record.eraseLock.Lock()
	defer self.record.eraseLock.Unlock()
	writer := self.record.writer
	reader := self.record.reader
	if err := recordEraseAdmin(writer.auth(), writer.sidecarId, args.LogId); err != nil {
		return nil, err
	}
	if err := reader.Sync(ctx, args.LogId); err != nil {
		return nil, err
	}
	entryIds := slices.Clone(args.EntryIds)
	slices.SortFunc(entryIds, Id.Cmp)
	entryIds = slices.Compact(entryIds)
	for _, entryId := range entryIds {
		if entry, ok := reader.Entry(args.LogId, entryId); ok && entry.Header.Kind().Class() == RecordClassLog {
			return nil, fmt.Errorf("%w: entry %s", ErrRecordEraseLogClass, entryId)
		}
	}
	erasureId, err := writer.drawId()
	if err != nil {
		return nil, err
	}
	if args.Reason == RecordErasureReasonRevocation {
		erasureId = recordIdOf(args.RequestId)
	}
	journal := &recordEraseJournal{
		ErasureId: erasureId, LogId: args.LogId, EntryIds: entryIds, Reason: uint32(args.Reason), RequestId: args.RequestId,
		Step: recordEraseStepPlanned,
	}
	if err := self.writeJournal(journal); err != nil {
		return nil, err
	}
	return self.run(ctx, journal)
}

// Whether sidecarId erases in logId: an admin of the log, and of a vault a consented device of its owner.
func recordEraseAdmin(auth RecordAuthView, sidecarId Id, logId Id) error {
	if !auth.Admins(logId, sidecarId) || (!recordIsTeamLog(auth, logId) && !auth.Consented(logId, sidecarId)) {
		return fmt.Errorf("%w: %s", ErrRecordEraseNotAdmin, logId)
	}
	return nil
}

// Goes on with every journaled erasure from where it stopped: what a restart runs. The first failure stops it, the
// rest left for the next.
func (self *RecordEraser) Resume(ctx context.Context) error {
	self.record.eraseLock.Lock()
	defer self.record.eraseLock.Unlock()
	journals, err := self.readJournals()
	if err != nil {
		return err
	}
	for _, journal := range journals {
		if _, err := self.run(ctx, journal); err != nil {
			return err
		}
	}
	return nil
}

// The record loop's erasure work, one pass: late copies in each log a sync read since the last pass, then each
// journaled erasure whose next try has come. Failures wait for the next pass, or for a journal's next try.
func (self *RecordEraser) tend(ctx context.Context) {
	erasing := self.record.erasingState()
	logIds := func() []Id {
		erasing.stateLock.Lock()
		defer erasing.stateLock.Unlock()
		logIds := []Id{}
		for logId := range erasing.lateLogIds {
			logIds = append(logIds, logId)
		}
		clear(erasing.lateLogIds)
		return logIds
	}()
	slices.SortFunc(logIds, Id.Cmp)
	log := self.record.writer.log
	for _, logId := range logIds {
		// the sync that marked the log is the one this look reads: another would mark it again
		if _, err := self.eraseLateCopies(ctx, logId, false); err != nil && log.V(1).Enabled() {
			log.Infof("[record]a look for late copies in %s stopped: %s", logId, err)
		}
		// others' erasures, which become this device's 25 h on at the soonest, at most once a RetryInterval
		now := self.record.writer.clock.Now()
		looked := func() bool {
			erasing.stateLock.Lock()
			defer erasing.stateLock.Unlock()
			if lookedAt, ok := erasing.othersLogIdLooks[logId]; ok && now.Before(lookedAt.Add(self.settings.RetryInterval)) {
				return true
			}
			erasing.othersLogIdLooks[logId] = now
			return false
		}()
		if looked {
			continue
		}
		if _, err := self.ResumeOthers(ctx, logId); err != nil && log.V(1).Enabled() {
			log.Infof("[record]a look for erasures to take up in %s stopped: %s", logId, err)
		}
	}
	if err := self.resumeDue(ctx); err != nil && log.V(1).Enabled() {
		log.Infof("[record]an erasure did not go on: %s", err)
	}
}

// Goes on with each journaled erasure whose next try has come.
func (self *RecordEraser) resumeDue(ctx context.Context) error {
	self.record.eraseLock.Lock()
	defer self.record.eraseLock.Unlock()
	journals, err := self.readJournals()
	if err != nil {
		return err
	}
	now := self.record.writer.clock.Now().UnixMilli()
	for _, journal := range journals {
		if journal.NextTryMillis == 0 || now < journal.NextTryMillis {
			continue
		}
		if _, err := self.run(ctx, journal); err != nil {
			return err
		}
	}
	return nil
}

// The log's format-2 index side, nil where none is bound or the log has none.
func (self *RecordEraser) indexOf(ctx context.Context, logId Id) (RecordEraseIndex, error) {
	erasing := self.record.erasingState()
	open := func() RecordEraseIndexOpen {
		erasing.stateLock.Lock()
		defer erasing.stateLock.Unlock()
		return erasing.open
	}()
	if open == nil {
		return nil, nil
	}
	index, err := open(ctx, logId)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecordEraseIndexUnavailable, err)
	}
	return index, nil
}

// The documents a CUT lists for copies of entryIds (DESIGN-DETAILS 15.2.10's step 4; 15.7's note): each copy that
// RECORD.md 7.1 makes a document of its own, at its path's entry version, and the card of each stream holding a copy of
// a run card's source entry, through the CUT's epoch, with that card's stream and run for the re-entry; documents by
// doc_key. include picks the copies, nil taking every one.
func (self *RecordEraser) documentsOf(index RecordEraseIndex, logId Id, entryIds []Id, include func(entryCopy *RecordEntryCopy) bool) ([]*recordEraseJournalDocument, []*recordEraseJournalCard, error) {
	reader := self.record.reader
	logKind := index.LogKind()
	streams, _ := reader.Streams(logId)
	streamRefIds := map[Id]Id{}
	for _, stream := range streams {
		streamRefIds[stream.StreamSidecarId] = stream.RefId
	}
	sources := indexRunCardSources(logKind)
	keyDocuments := map[[indexIdByteCount]byte]*recordEraseJournalDocument{}
	cards := []*recordEraseJournalCard{}
	for _, entryId := range entryIds {
		entry, ok := reader.Entry(logId, entryId)
		if !ok || entry.Header == nil || entry.Header.Header == nil {
			continue
		}
		kind := entry.Kind()
		indexed := indexRecordIndexesEntry(logKind, kind)
		runId, hasRun := Id{}, len(entry.Header.Header.GetRunId()) == len(Id{})
		if hasRun {
			runId = Id(entry.Header.Header.GetRunId())
		}
		source := hasRun && slices.Contains(sources, kind)
		if !indexed && !source {
			continue
		}
		for _, entryCopy := range entry.Copies {
			if entryCopy.Path == "" || (include != nil && !include(entryCopy)) {
				continue
			}
			refId := streamRefIds[entryCopy.StreamSidecarId]
			if refId == (Id{}) {
				// a document this erasure cannot name would stay unlisted: nothing is listed until it can be
				return nil, nil, fmt.Errorf("%w: the stream of a copy states no ref", ErrRecordEraseIndexUnavailable)
			}
			if indexed {
				key, err := index.DocKey(refId, []byte(entryCopy.Path))
				if err != nil {
					return nil, nil, err
				}
				if held := keyDocuments[key]; held == nil || held.Version < entryCopy.Version {
					keyDocuments[key] = &recordEraseJournalDocument{Key: bytes.Clone(key[:]), Version: entryCopy.Version}
				}
			}
			if source {
				key, err := index.DocKey(refId, indexRunCardName(runId))
				if err != nil {
					return nil, nil, err
				}
				if keyDocuments[key] == nil {
					keyDocuments[key] = &recordEraseJournalDocument{Key: bytes.Clone(key[:]), ThroughEpoch: true}
					cards = append(cards, &recordEraseJournalCard{
						Key: bytes.Clone(key[:]), StreamSidecarId: entryCopy.StreamSidecarId, RefId: refId, RunId: runId,
					})
				}
			}
		}
	}
	documents := make([]*recordEraseJournalDocument, 0, len(keyDocuments))
	for _, document := range keyDocuments {
		documents = append(documents, document)
	}
	slices.SortFunc(documents, func(a *recordEraseJournalDocument, b *recordEraseJournalDocument) int {
		return bytes.Compare(a.Key, b.Key)
	})
	slices.SortFunc(cards, func(a *recordEraseJournalCard, b *recordEraseJournalCard) int {
		return bytes.Compare(a.Key, b.Key)
	})
	return documents, cards, nil
}

// Draws ERASE pushes for keys, at most EraseKeyCount keys a push, the last saying complete where complete.
func (self *RecordEraser) drawErases(keys []*RecordSlotKey, complete bool) ([]*recordEraseJournalPush, error) {
	pushes := []*recordEraseJournalPush{}
	for start := 0; start < len(keys); start += self.settings.EraseKeyCount {
		pushId, err := self.record.writer.drawId()
		if err != nil {
			return nil, err
		}
		end := min(len(keys), start+self.settings.EraseKeyCount)
		pushes = append(pushes, &recordEraseJournalPush{PushId: pushId, Keys: keys[start:end], Complete: complete && end == len(keys)})
	}
	return pushes, nil
}

// Step 1: what the erasure takes, journaled before anything goes: the copies' keys and the deposits standing, the
// ERASEs and CONSUMEs drawn, and in a format-2 log whether its index takes part. ErrRecordEraseTooLarge before
// anything is drawn where its CUT would list too many documents.
func (self *RecordEraser) plan(ctx context.Context, journal *recordEraseJournal, index RecordEraseIndex) error {
	writer := self.record.writer
	reader := self.record.reader
	streams := writer.boundStreams()
	logId := journal.LogId
	named := map[Id]bool{}
	for _, entryId := range journal.EntryIds {
		named[entryId] = true
	}
	found := map[Id]bool{}
	// the deposits standing that hold a named entry, by depositor: once before the ingest, for what was found, and
	// once after, for the slots the ERASE names
	standing := func() (map[Id][]*RecordStreamDepositVersion, error) {
		refs, err := streams.DepositRefs(ctx, logId)
		if err != nil {
			return nil, err
		}
		holding := map[Id][]*RecordStreamDepositVersion{}
		for _, ref := range refs {
			deposits, err := streams.ReadDeposits(ctx, logId, ref.SidecarId)
			if err != nil {
				return nil, err
			}
			for _, deposit := range deposits {
				entries, err := RecordDepositBatchParse(deposit.Batch, writer.settings.DepositByteCount)
				if err != nil {
					continue
				}
				for _, entry := range entries {
					header, _, err := recordSignedHeader(entry.Signed)
					if err != nil || !named[recordIdOf(header.Header.GetEntryId())] {
						continue
					}
					found[recordIdOf(header.Header.GetEntryId())] = true
					if !slices.Contains(holding[ref.SidecarId], deposit) {
						holding[ref.SidecarId] = append(holding[ref.SidecarId], deposit)
					}
				}
			}
		}
		return holding, nil
	}
	if _, err := standing(); err != nil {
		return err
	}
	if recordIngests(writer.auth(), writer.sidecarId, logId) {
		// a deposit holding a named entry is consumed with its slot, and its other entries written first
		if err := self.record.ingester.Ingest(ctx, logId); err != nil && writer.log.V(1).Enabled() {
			writer.log.Infof("[record]an erasure's ingest of %s stopped: %s", logId, err)
		}
	}
	holding, err := standing()
	if err != nil {
		return err
	}
	if err := reader.Sync(ctx, logId); err != nil {
		return err
	}
	keys := []*RecordSlotKey{}
	for _, entryId := range journal.EntryIds {
		entry, ok := reader.Entry(logId, entryId)
		if !ok {
			continue
		}
		found[entryId] = true
		for _, entryCopy := range entry.Copies {
			key := &RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}
			if !slices.ContainsFunc(keys, func(held *RecordSlotKey) bool { return *held == *key }) {
				keys = append(keys, key)
			}
		}
	}
	if index != nil {
		// format 2: the documents its CUT would list now, a late read adding at most a few
		documents, _, err := self.documentsOf(index, logId, journal.EntryIds, nil)
		if err != nil {
			return err
		}
		if self.settings.CutDocumentCount < len(documents) {
			return fmt.Errorf("%w: %d documents, at most %d", ErrRecordEraseTooLarge, len(documents), self.settings.CutDocumentCount)
		}
		journal.Listing = 0 < len(documents)
	}
	// a deposit the ingest could not take: its slot goes, then the deposit, its other entries a gap
	depositorIds := []Id{}
	for depositorId := range holding {
		depositorIds = append(depositorIds, depositorId)
	}
	slices.SortFunc(depositorIds, Id.Cmp)
	for _, depositorId := range depositorIds {
		consume := &recordEraseJournalConsume{DepositorId: depositorId}
		for _, deposit := range holding[depositorId] {
			if deposit.SlotId != (Id{}) {
				keys = append(keys, &RecordSlotKey{SlotId: deposit.SlotId, KeyIndex: 0})
			}
			consume.DepositIds = append(consume.DepositIds, deposit.DepositId)
		}
		pushId, err := writer.drawId()
		if err != nil {
			return err
		}
		consume.PushId = pushId
		journal.Consumes = append(journal.Consumes, consume)
	}
	for _, entryId := range journal.EntryIds {
		if found[entryId] {
			journal.Erased = append(journal.Erased, entryId)
		} else {
			journal.Missing = append(journal.Missing, entryId)
		}
	}
	// at most EraseKeyCount keys a push, the entries' own first; complete only where no CUT follows
	erases, err := self.drawErases(keys, !journal.Listing)
	if err != nil {
		return err
	}
	journal.Erases = erases
	return self.writeJournal(journal)
}

// Sends pushes, each again under its push id where it went before; NOTHING_TO_ERASE is done. True where one committed,
// a retry evs answers with its commit included.
func (self *RecordEraser) sendErases(ctx context.Context, logId Id, erasureId Id, note []byte, pushes []*recordEraseJournalPush) (bool, error) {
	streams := self.record.writer.boundStreams()
	committed := false
	for _, push := range pushes {
		testHookBarrier("record.erase.before", recordChainIdText(logId))
		_, err := streams.Erase(ctx, logId, &RecordStreamErase{
			PushId: push.PushId, ErasureId: erasureId, Complete: push.Complete, Completion: push.Completion, Keys: push.Keys, SealedNote: note,
		})
		testHookBarrier("record.erase.after", recordChainIdText(logId))
		if code, ok := RecordStreamRefusalCode(err); ok && code == protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE {
			// every key it names is gone already: done
			continue
		}
		if err != nil {
			return committed, err
		}
		committed = true
	}
	return committed, nil
}

// Step 3: reads the log's streams again and draws an ERASE for each copy of a named entry found now, journaled before
// it goes, with the CUT's documents in a format-2 log.
func (self *RecordEraser) reread(ctx context.Context, journal *recordEraseJournal, index RecordEraseIndex) error {
	reader := self.record.reader
	logId := journal.LogId
	if err := reader.Sync(ctx, logId); err != nil {
		return err
	}
	held := map[RecordSlotKey]bool{}
	for _, key := range journal.keys() {
		held[*key] = true
	}
	keys := []*RecordSlotKey{}
	for _, entryId := range journal.EntryIds {
		entry, ok := reader.Entry(logId, entryId)
		if !ok {
			continue
		}
		if slices.Contains(journal.Missing, entryId) {
			// missing at the first read and found now: erased with the rest
			journal.Missing = slices.DeleteFunc(journal.Missing, func(missing Id) bool { return missing == entryId })
			journal.Erased = append(journal.Erased, entryId)
		}
		for _, entryCopy := range entry.Copies {
			key := RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}
			if entryCopy.SlotId == (Id{}) || held[key] {
				continue
			}
			held[key] = true
			keys = append(keys, &key)
		}
	}
	if index != nil && !journal.Late {
		documents, cards, err := self.documentsOf(index, logId, journal.EntryIds, nil)
		if err != nil {
			return err
		}
		journal.Listing = journal.Listing || 0 < len(documents)
		if journal.Listing {
			journal.Documents, journal.Cards = documents, cards
		}
	}
	if journal.Listing && index == nil {
		return ErrRecordEraseIndexUnavailable
	}
	erases, err := self.drawErases(keys, !journal.Listing)
	if err != nil {
		return err
	}
	journal.RereadFrom = len(journal.Erases)
	journal.Erases = append(journal.Erases, erases...)
	journal.Reread = true
	return self.writeJournal(journal)
}

// A wait or a failure after the erasure's first ERASE: the record's loop goes on with it from RetryInterval, or from
// nextTry where that is later.
func (self *RecordEraser) deferJournal(journal *recordEraseJournal, nextTry time.Time) {
	now := self.record.writer.clock.Now()
	if nextTry.Before(now.Add(self.settings.RetryInterval)) {
		nextTry = now.Add(self.settings.RetryInterval)
	}
	journal.NextTryMillis = nextTry.UnixMilli()
	if err := self.writeJournal(journal); err != nil {
		self.record.writer.log.Warningf("[record]an erasure's next try was not journaled: %s", err)
	}
}

// One erasure from its journal's step to its end: see the file header's rows.
func (self *RecordEraser) run(ctx context.Context, journal *recordEraseJournal) (*RecordEraseResult, error) {
	result, err := self.runSteps(ctx, journal)
	if err != nil && (journal.Step != recordEraseStepPlanned || 0 < len(journal.Erases)) {
		// once its ERASEs are drawn an erasure is never left for a restart alone
		self.deferJournal(journal, time.Time{})
	}
	return result, err
}

// run's steps.
func (self *RecordEraser) runSteps(ctx context.Context, journal *recordEraseJournal) (*RecordEraseResult, error) {
	writer := self.record.writer
	reader := self.record.reader
	logId := journal.LogId
	// from here no ingest of this device takes a named entry
	reader.noteErased(logId, journal.EntryIds, nil)
	if RecordErasureReason(journal.Reason) == RecordErasureReasonRetention {
		// expiry's erasure: its entries read expired (record_retention.go)
		reader.noteExpired(logId, journal.EntryIds)
	}
	index, indexErr := self.indexOf(ctx, logId)
	if journal.Step == recordEraseStepPlanned && len(journal.Erases) == 0 {
		if indexErr != nil {
			// nothing has gone: the erasure waits for its index side as it would for evs
			return nil, indexErr
		}
		if err := self.plan(ctx, journal, index); err != nil {
			if errors.Is(err, ErrRecordEraseTooLarge) {
				// refused, nothing erased: no restart takes it up
				if removeErr := self.store.Remove(recordEraseJournalName(journal.ErasureId)); removeErr != nil {
					return nil, removeErr
				}
			}
			return nil, err
		}
	}
	result := &RecordEraseResult{ErasureId: journal.ErasureId, LogId: logId, Erased: journal.Erased, Missing: journal.Missing}
	note, err := journal.note()
	if err != nil {
		return nil, err
	}
	if journal.Step == recordEraseStepPlanned {
		// step 2
		began, err := self.sendErases(ctx, logId, journal.ErasureId, note, journal.Erases)
		journal.Began = journal.Began || began
		if err != nil {
			return nil, err
		}
		streams := writer.boundStreams()
		for _, consume := range journal.Consumes {
			_, err := streams.Consume(ctx, logId, &RecordStreamConsume{PushId: consume.PushId, DepositorSidecarId: consume.DepositorId, DepositIds: consume.DepositIds})
			if code, ok := RecordStreamRefusalCode(err); ok && code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT {
				// consumed already
				err = nil
			}
			if err != nil {
				return nil, err
			}
		}
		journal.Step = recordEraseStepErased
		if err := self.writeJournal(journal); err != nil {
			return nil, err
		}
	}
	if journal.Step == recordEraseStepErased {
		// step 3, its ERASEs committed before any CUT is built
		if !journal.Reread {
			if indexErr != nil {
				// whether a copy found now is a document is the index side's to say: the read waits for it
				return result, indexErr
			}
			if err := self.reread(ctx, journal, index); err != nil {
				return nil, err
			}
		}
		began, err := self.sendErases(ctx, logId, journal.ErasureId, note, journal.Erases[journal.RereadFrom:])
		journal.Began = journal.Began || began
		if err != nil {
			return nil, err
		}
		if journal.Listing && !journal.Began {
			// every ERASE found its keys gone: evs's erasure ref says whether one of this erasure committed all the same,
			// as a retry past evs's memory of its push id answers
			erasures, err := writer.boundStreams().ReadErasures(ctx, logId, 0)
			if err != nil {
				return nil, err
			}
			journal.Began = slices.ContainsFunc(erasures, func(erasure *RecordStreamErasure) bool { return erasure.ErasureId == journal.ErasureId })
			if !journal.Began {
				// another erasure took every key, and its CUT lists the documents: this one never began
				journal.Listing = false
			}
		}
		journal.Step = recordEraseStepReread
		if err := self.writeJournal(journal); err != nil {
			return nil, err
		}
	}
	result.Erased, result.Missing = journal.Erased, journal.Missing
	result.Keys = journal.keys()
	reader.noteErased(logId, journal.EntryIds, result.Keys)
	if journal.Listing {
		if index == nil {
			if indexErr != nil {
				return result, indexErr
			}
			return result, ErrRecordEraseIndexUnavailable
		}
		result.Index = &RecordEraseIndexResult{DocumentCount: len(journal.Documents), CardCount: journal.cardCount()}
	}
	if journal.Step == recordEraseStepReread {
		// step 4
		if journal.Listing {
			documents, err := journal.cutDocuments()
			if err != nil {
				return result, err
			}
			testHookBarrier("record.erase.cut.before", recordChainIdText(logId))
			_, err = index.Cut(ctx, &IndexCutArgs{ErasureId: journal.ErasureId, Documents: documents})
			testHookBarrier("record.erase.cut.after", recordChainIdText(logId))
			if errors.Is(err, ErrIndexErasureSetFull) {
				// the CUT waits while pending erasures finish, and steps 5 to 7 with it: the bodies are gone already
				self.deferJournal(journal, time.Time{})
				result.Index.Waiting, result.Index.NextTry = true, time.UnixMilli(journal.NextTryMillis)
				return result, nil
			}
			if err != nil {
				return result, err
			}
		}
		journal.Step = recordEraseStepCut
		journal.NextTryMillis = 0
		if err := self.writeJournal(journal); err != nil {
			return result, err
		}
	}
	owed := time.Time{}
	if journal.Listing {
		result.Index.Fenced = true
		var err error
		if owed, err = self.indexParts(ctx, journal, index, note, result.Index); err != nil {
			return result, err
		}
	}
	// step 7
	if !journal.Late && !journal.Entered {
		source := RecordSourceObserved
		if journal.Reason == uint32(RecordErasureReasonPerson) || journal.Reason == uint32(RecordErasureReasonModeration) {
			source = RecordSourceApprover
		}
		refs, err := writer.Append(&RecordDraft{Kind: RecordKindErasure, Source: source, NoSession: true, Body: journal.body(), LogId: &logId})
		if err != nil {
			return result, err
		}
		if 0 < len(refs) {
			result.Entry = refs[0]
		}
		journal.Entered = true
		if err := self.writeJournal(journal); err != nil {
			return result, err
		}
	}
	if !owed.IsZero() {
		// the index's part is owed still: the record's loop goes on with it from then
		self.deferJournal(journal, owed)
		result.Index.NextTry = time.UnixMilli(journal.NextTryMillis)
		return result, nil
	}
	// the entry is in the writer's journal, which carries it to evs: the erasure's own journal is done
	if err := self.store.Remove(recordEraseJournalName(journal.ErasureId)); err != nil {
		return result, err
	}
	self.record.erasingState().settle(journal.ErasureId)
	return result, nil
}

// A key an ERASE of erasureId destroyed, as the log's erasure ref holds it: what a completion ERASE names. Nil where
// no ERASE of it names one.
func (self *RecordEraser) erasedKeyOf(ctx context.Context, logId Id, erasureId Id) (*RecordSlotKey, error) {
	erasures, err := self.record.writer.boundStreams().ReadErasures(ctx, logId, 0)
	if err != nil {
		return nil, err
	}
	return recordEraseCompletionKey(erasures, erasureId), nil
}

// The key a completion ERASE of erasureId names among erasures, every ERASE of the log's erasure ref oldest first: one
// an ERASE of the erasure named first and no ERASE named since (evs_erase_completion.go), so after a late copy reopened
// an erasure a completion took a key of, the next names another. Nil where there is none.
func recordEraseCompletionKey(erasures []*RecordStreamErasure, erasureId Id) *RecordSlotKey {
	key, _ := evsCompletionKeyOf(erasures, erasureId, func(erasure *RecordStreamErasure) (Id, []*RecordSlotKey) {
		return erasure.ErasureId, erasure.Keys
	})
	return key
}

// Step 5: each of cards folded at its stream's head as this device's reader reads it, without what the log's ERASEs
// and the set at the push's base say is erased at its epoch, and entered in this device's own index head.
func (self *RecordEraser) reenter(ctx context.Context, logId Id, index RecordEraseIndex, erasureId Id, cards []*recordEraseJournalCard) (*IndexReenterResult, error) {
	reader := self.record.reader
	erasures, err := self.record.writer.boundStreams().ReadErasures(ctx, logId, 0)
	if err != nil {
		return nil, err
	}
	args := &IndexReenterArgs{ErasureId: erasureId, Erasures: erasures}
	for _, card := range cards {
		if len(card.Key) != indexIdByteCount {
			return nil, fmt.Errorf("%w: erasure journal %s", ErrRecordChainCorrupt, erasureId)
		}
		streamSidecarId := card.StreamSidecarId
		args.Cards = append(args.Cards, &IndexReenterCard{
			Key:    [indexIdByteCount]byte(card.Key),
			Stream: newIndexRecordReaderStream(reader, logId, index.LogKind(), streamSidecarId, card.RefId),
			RunId:  card.RunId,
			Head: func(ctx context.Context) (uint64, error) {
				// the stream's head from evs, read after the index's
				if err := reader.Sync(ctx, logId); err != nil {
					return 0, err
				}
				streams, _ := reader.Streams(logId)
				for _, stream := range streams {
					if stream.StreamSidecarId == streamSidecarId && 0 < len(stream.Pushes) {
						return stream.Pushes[len(stream.Pushes)-1].Version, nil
					}
				}
				return 0, nil
			},
		})
	}
	testHookBarrier("record.erase.reenter.before", recordChainIdText(logId))
	reentered, err := index.Reenter(ctx, args)
	testHookBarrier("record.erase.reenter.after", recordChainIdText(logId))
	return reentered, err
}

// Steps 5 and 6 on the log's index: the listed cards folded again, then the rewrite. Answers when the erasure's index
// part is owed again, zero where nothing is: a re-entry or rewrite that waits, or a list the rewrite could not prove
// whole.
func (self *RecordEraser) indexParts(ctx context.Context, journal *recordEraseJournal, index RecordEraseIndex, note []byte, indexResult *RecordEraseIndexResult) (time.Time, error) {
	writer := self.record.writer
	logId := journal.LogId
	owed := time.Time{}
	owe := func(at time.Time) {
		if at.IsZero() {
			at = writer.clock.Now()
		}
		if owed.IsZero() || at.Before(owed) {
			owed = at
		}
	}
	if 0 < len(journal.Cards) {
		// step 5
		reentered, err := self.reenter(ctx, logId, index, journal.ErasureId, journal.Cards)
		switch {
		case errors.Is(err, ErrIndexEraseNotCut):
			// complete, and its set entry dropped since: a card left out is folded by its stream's again unit
		case err != nil:
			return owed, err
		default:
			indexResult.EnteredCount, indexResult.SkippedCount = reentered.EnteredCount, reentered.SkippedCount
			if reentered.Waiting {
				// a quota refused it: no file of the erasure waits for it (15.2.5)
				owe(reentered.NextTry)
			}
		}
	}
	// step 6
	testHookBarrier("record.erase.rewrite.before", recordChainIdText(logId))
	rewritten, err := index.Rewrite(ctx, &IndexRewriteArgs{ErasureId: journal.ErasureId, Complete: true, Note: note})
	testHookBarrier("record.erase.rewrite.after", recordChainIdText(logId))
	if err != nil {
		return owed, err
	}
	indexResult.Erasure, indexResult.Completed, indexResult.Unproven = rewritten.Erasure, rewritten.Completed, rewritten.Unproven
	if rewritten.Erasure != nil && rewritten.Erasure.State == SidecarErasureWaiting {
		owe(rewritten.Erasure.NextTry)
	}
	if recordEraseRewriteEndedUnsaid(rewritten) {
		// no file held a listed version, so no ERASE with a key was left to say complete (QD-1132): a completion ERASE
		// names a key an ERASE of this erasure destroyed, as evs's erasure ref holds it
		key, err := self.erasedKeyOf(ctx, logId, journal.ErasureId)
		if err != nil || key == nil {
			return owed, err
		}
		if journal.CompletionPushId == (Id{}) {
			pushId, err := writer.drawId()
			if err != nil {
				return owed, err
			}
			journal.CompletionPushId = pushId
			if err := self.writeJournal(journal); err != nil {
				return owed, err
			}
		}
		completed, err := self.sendErases(ctx, logId, journal.ErasureId, note, []*recordEraseJournalPush{{
			PushId: journal.CompletionPushId, Keys: []*RecordSlotKey{key}, Complete: true, Completion: true,
		}})
		if err != nil {
			return owed, err
		}
		indexResult.Completed = completed
	}
	if rewritten.Unproven {
		owe(time.Time{})
	}
	indexResult.Waiting = !owed.IsZero() && !rewritten.Unproven
	indexResult.NextTry = owed
	return owed, nil
}

// Erases each live copy of an erased entry this device reads in logId now (the file header's late row): one whose
// key row no ERASE names, of an entry an erasure's note names, erased under that erasure, the first naming it, with
// steps 4 to 6 for its copies in a format-2 log. Nothing where this sidecar does not erase in the log, and an erasure
// this device still journals is left to its own steps. A result an erasure taken up.
func (self *RecordEraser) EraseLateCopies(ctx context.Context, logId Id) ([]*RecordEraseResult, error) {
	return self.eraseLateCopies(ctx, logId, true)
}

// EraseLateCopies, the log read to its head first where sync says.
func (self *RecordEraser) eraseLateCopies(ctx context.Context, logId Id, sync bool) ([]*RecordEraseResult, error) {
	self.record.eraseLock.Lock()
	defer self.record.eraseLock.Unlock()
	writer := self.record.writer
	reader := self.record.reader
	if recordEraseAdmin(writer.auth(), writer.sidecarId, logId) != nil {
		return nil, nil
	}
	if sync {
		if err := reader.Sync(ctx, logId); err != nil {
			return nil, err
		}
	}
	erasures, err := writer.boundStreams().ReadErasures(ctx, logId, 0)
	if err != nil {
		return nil, err
	}
	journals, err := self.readJournals()
	if err != nil {
		return nil, err
	}
	journaled := map[Id]bool{}
	for _, journal := range journals {
		journaled[journal.ErasureId] = true
	}
	erasedKeys := map[RecordSlotKey]bool{}
	entryErasureIds := map[Id]Id{}
	erasureNotes := map[Id][]byte{}
	erasureBodies := map[Id]*protocol.ErasureBody{}
	for _, erasure := range erasures {
		for _, key := range erasure.destroyedKeys() {
			erasedKeys[*key] = true
		}
		body, ok := recordErasureNoteBody(erasure)
		if !ok {
			continue
		}
		if _, held := erasureNotes[erasure.ErasureId]; !held {
			erasureNotes[erasure.ErasureId] = bytes.Clone(erasure.SealedNote)
			erasureBodies[erasure.ErasureId] = body
		}
		for _, entryId := range body.GetEntryIds() {
			if len(entryId) != len(Id{}) {
				continue
			}
			if _, named := entryErasureIds[Id(entryId)]; !named {
				entryErasureIds[Id(entryId)] = erasure.ErasureId
			}
		}
	}
	// the late copies, by the erasure that named their entry
	erasureKeys := map[Id][]*RecordSlotKey{}
	erasureEntryIds := map[Id][]Id{}
	for _, entry := range reader.Entries(logId) {
		erasureId, named := entryErasureIds[entry.EntryId]
		if !named || journaled[erasureId] || entry.Header == nil || entry.Kind().Class() == RecordClassLog {
			continue
		}
		for _, entryCopy := range entry.Copies {
			key := RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}
			if entryCopy.SlotId == (Id{}) || erasedKeys[key] {
				continue
			}
			erasedKeys[key] = true
			erasureKeys[erasureId] = append(erasureKeys[erasureId], &key)
			if !slices.Contains(erasureEntryIds[erasureId], entry.EntryId) {
				erasureEntryIds[erasureId] = append(erasureEntryIds[erasureId], entry.EntryId)
			}
		}
	}
	if len(erasureKeys) == 0 {
		return nil, nil
	}
	index, err := self.indexOf(ctx, logId)
	if err != nil {
		return nil, err
	}
	erasureIds := []Id{}
	for erasureId := range erasureKeys {
		erasureIds = append(erasureIds, erasureId)
	}
	slices.SortFunc(erasureIds, Id.Cmp)
	results := []*RecordEraseResult{}
	for _, erasureId := range erasureIds {
		keys := erasureKeys[erasureId]
		entryIds := erasureEntryIds[erasureId]
		slices.SortFunc(entryIds, Id.Cmp)
		body := erasureBodies[erasureId]
		journal := &recordEraseJournal{
			ErasureId: erasureId, LogId: logId, EntryIds: entryIds, Reason: body.GetReason(), RequestId: body.GetRequestId(),
			Step: recordEraseStepPlanned, Erased: entryIds, Late: true, Note: erasureNotes[erasureId],
			// a late copy takes no step 3: the next sync's look finds a later one
			Reread: true,
		}
		if index != nil {
			lateKeys := map[RecordSlotKey]bool{}
			for _, key := range keys {
				lateKeys[*key] = true
			}
			documents, cards, err := self.documentsOf(index, logId, entryIds, func(entryCopy *RecordEntryCopy) bool {
				return lateKeys[RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}]
			})
			if err != nil {
				return results, err
			}
			journal.Listing = 0 < len(documents)
			journal.Documents, journal.Cards = documents, cards
		}
		if journal.Erases, err = self.drawErases(keys, !journal.Listing); err != nil {
			return results, err
		}
		journal.RereadFrom = len(journal.Erases)
		if err := self.writeJournal(journal); err != nil {
			return results, err
		}
		result, err := self.run(ctx, journal)
		if result != nil {
			results = append(results, result)
		}
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

// Takes up, in a format-2 log, each erasure another device began and did not end (§11.12's reconcile row; §16.8's
// Erasure: should the eraser die between its ERASE and its CUT, another device resumes with the CUT): one a record
// ERASE's note names, not journaled here, whose newest ERASE does not say complete. The eraser's own device takes it up
// at once, its journal lost; another device of the eraser's member ResumeAfter (25 h) past its CUT or its last ERASE;
// any device that erases in the log once the eraser no longer does; a device of another member never while the eraser
// erases. The CUT is committed where it is missing, listing the documents of the note's entries as this device reads
// their copies now, the index files are rewritten, and the listed cards are folded again. No erasure entry is written:
// the committed ERASE stands as the record until the eraser's own lands. A result an erasure taken up or not yet this
// device's, the latter waiting until its NextTry.
func (self *RecordEraser) ResumeOthers(ctx context.Context, logId Id) ([]*RecordEraseResult, error) {
	self.record.eraseLock.Lock()
	defer self.record.eraseLock.Unlock()
	writer := self.record.writer
	reader := self.record.reader
	auth := writer.auth()
	if recordEraseAdmin(auth, writer.sidecarId, logId) != nil {
		return nil, nil
	}
	index, err := self.indexOf(ctx, logId)
	if err != nil || index == nil {
		// in format 1 an erasure ends with its own ERASEs
		return nil, err
	}
	if err := reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	erasures, err := writer.boundStreams().ReadErasures(ctx, logId, 0)
	if err != nil {
		return nil, err
	}
	journals, err := self.readJournals()
	if err != nil {
		return nil, err
	}
	journaled := map[Id]bool{}
	for _, journal := range journals {
		journaled[journal.ErasureId] = true
	}
	complete := recordEraseCompleteByNewest(erasures, (*RecordStreamErasure).completionState)
	// each record erasure's first ERASE: its eraser and its note
	erasureIds := []Id{}
	firstErasures := map[Id]*RecordStreamErasure{}
	for _, erasure := range erasures {
		if _, held := firstErasures[erasure.ErasureId]; held {
			continue
		}
		if _, ok := recordErasureNoteBody(erasure); !ok {
			continue
		}
		firstErasures[erasure.ErasureId] = erasure
		erasureIds = append(erasureIds, erasure.ErasureId)
	}
	erasing := self.record.erasingState()
	results := []*RecordEraseResult{}
	for _, erasureId := range erasureIds {
		first := firstErasures[erasureId]
		if journaled[erasureId] || complete[erasureId] || erasing.settled(erasureId) {
			continue
		}
		role, ok := self.resumeRole(auth, logId, first.EraserSidecarId)
		if !ok {
			continue
		}
		body, _ := recordErasureNoteBody(first)
		entryIds := []Id{}
		for _, entryId := range body.GetEntryIds() {
			if len(entryId) == len(Id{}) {
				entryIds = append(entryIds, Id(entryId))
			}
		}
		documents, cards, err := self.documentsOf(index, logId, entryIds, nil)
		if err != nil {
			return results, err
		}
		if len(documents) == 0 {
			// nothing to list: its own ERASEs end it
			continue
		}
		journal := &recordEraseJournal{ErasureId: erasureId, Documents: documents}
		cutDocuments, err := journal.cutDocuments()
		if err != nil {
			return results, err
		}
		result := &RecordEraseResult{
			ErasureId: erasureId, LogId: logId, Erased: entryIds,
			Index: &RecordEraseIndexResult{DocumentCount: len(documents), CardCount: journal.cardCount()},
		}
		testHookBarrier("record.erase.resume.before", recordChainIdText(logId))
		resumed, err := index.Resume(ctx, &IndexResumeArgs{
			ErasureId: erasureId, Role: role, Documents: cutDocuments, Complete: true, Note: bytes.Clone(first.SealedNote),
		})
		testHookBarrier("record.erase.resume.after", recordChainIdText(logId))
		switch {
		case errors.Is(err, ErrIndexErasureSetFull):
			// the CUT waits while pending erasures finish
			result.Index.Waiting, result.Index.NextTry = true, writer.clock.Now().Add(self.settings.RetryInterval)
			results = append(results, result)
			continue
		case err != nil:
			return results, err
		case !resumed.NotBefore.IsZero():
			// not this device's yet
			result.Index.Waiting, result.Index.NextTry = true, resumed.NotBefore
			results = append(results, result)
			continue
		}
		result.Index.Fenced = true
		if rewritten := resumed.Rewrite; rewritten != nil {
			result.Index.Erasure, result.Index.Completed, result.Index.Unproven = rewritten.Erasure, rewritten.Completed, rewritten.Unproven
			if rewritten.Erasure != nil && rewritten.Erasure.State == SidecarErasureWaiting {
				result.Index.Waiting, result.Index.NextTry = true, rewritten.Erasure.NextTry
			}
		}
		key := recordEraseCompletionKey(erasures, erasureId)
		if resumed.Rewrite != nil && recordEraseRewriteEndedUnsaid(resumed.Rewrite) && key != nil {
			// no file held a listed version: a completion ERASE ends it, naming a key an ERASE of it destroyed (QD-1132)
			pushId, err := writer.drawId()
			if err != nil {
				return results, err
			}
			completed, err := self.sendErases(ctx, logId, erasureId, first.SealedNote, []*recordEraseJournalPush{{
				PushId: pushId, Keys: []*RecordSlotKey{key}, Complete: true, Completion: true,
			}})
			if err != nil {
				return results, err
			}
			result.Index.Completed = completed
		}
		if !result.Index.Waiting && !result.Index.Unproven {
			// its pairs ran to their end here
			erasing.settle(erasureId)
		}
		// a listed card's files never wait for its re-entry, which follows here
		if 0 < len(cards) {
			reentered, err := self.reenter(ctx, logId, index, erasureId, cards)
			switch {
			case errors.Is(err, ErrIndexEraseNotCut):
				// complete, and its set entry dropped since
			case err != nil:
				return results, err
			default:
				result.Index.EnteredCount, result.Index.SkippedCount = reentered.EnteredCount, reentered.SkippedCount
			}
		}
		results = append(results, result)
	}
	return results, nil
}

// Who this device is to an erasure eraserId began, by §11.12's reconcile row: the eraser itself; another device of its
// member while it erases in the log; any device that erases there once it does not. False for a device of another
// member while the eraser erases.
func (self *RecordEraser) resumeRole(auth RecordAuthView, logId Id, eraserId Id) (IndexResumeRole, bool) {
	sidecarId := self.record.writer.sidecarId
	switch {
	case eraserId == sidecarId:
		return IndexResumeEraser, true
	case eraserId == (Id{}) || recordEraseAdmin(auth, eraserId, logId) != nil:
		return IndexResumeAny, true
	}
	memberId, ok := auth.Member(sidecarId)
	eraserMemberId, eraserOk := auth.Member(eraserId)
	if ok && eraserOk && memberId == eraserMemberId {
		return IndexResumeMember, true
	}
	return 0, false
}

// A dry run of args: what an erasure would take, nothing written. The same refusals as Erase but a person's
// confirmation, which comes after the person has seen this.
func (self *RecordEraser) Plan(ctx context.Context, args *RecordEraseArgs) (*RecordErasePlan, error) {
	if args == nil || len(args.EntryIds) == 0 || self.settings.EntryCount < len(args.EntryIds) {
		return nil, fmt.Errorf("%w: an erasure names 1 to %d entries", ErrRecordEraseInvalid, self.settings.EntryCount)
	}
	if args.HarnessAncestor && (args.Reason == RecordErasureReasonPerson || args.Reason == RecordErasureReasonModeration) {
		return nil, ErrRecordEraseUnconfirmed
	}
	writer := self.record.writer
	reader := self.record.reader
	if err := recordEraseAdmin(writer.auth(), writer.sidecarId, args.LogId); err != nil {
		return nil, err
	}
	if err := reader.Sync(ctx, args.LogId); err != nil {
		return nil, err
	}
	index, err := self.indexOf(ctx, args.LogId)
	if err != nil {
		return nil, err
	}
	entries := reader.Entries(args.LogId)
	plan := &RecordErasePlan{LogId: args.LogId}
	for _, entryId := range args.EntryIds {
		entry, ok := reader.Entry(args.LogId, entryId)
		if !ok {
			plan.Missing = append(plan.Missing, entryId)
			continue
		}
		if entry.Header.Kind().Class() == RecordClassLog {
			return nil, fmt.Errorf("%w: entry %s", ErrRecordEraseLogClass, entryId)
		}
		item := &RecordErasePlanItem{
			EntryId: entryId, Kind: entry.Header.Kind(), TimeMillis: entry.Header.Header.GetTimeMillis(), CopyCount: len(entry.Copies),
			Erased: entry.State.KeyGone(),
		}
		if index != nil && entry.Kind() == RecordKindContext {
			item.KeptContextCount = recordEraseKeptContextCount(index.LogKind(), entries, entry, args.EntryIds)
		}
		plan.Items = append(plan.Items, item)
	}
	return plan, nil
}

// For a context entry, how many documents of its run's other entries keep the agent label and session ids it gave
// them (fields 9 and 11; DESIGN-DETAILS 15.2.8; QD-782): each copy a log of logKind indexes as an entry of its own, of
// the run's live entries the erasure does not name, in each stream where this entry is the run's first context entry in
// the fold's order. They keep them after the erasure, so a person who wants them gone erases those entries too.
func recordEraseKeptContextCount(logKind protocol.RepoKind, entries []*RecordReadEntry, context *RecordReadEntry, erasingEntryIds []Id) int {
	runId := context.Header.Header.GetRunId()
	if len(runId) != len(Id{}) {
		return 0
	}
	foldBefore := func(a *RecordReadEntry, b *RecordReadEntry) bool {
		if a.Header.Header.GetSeq() != b.Header.Header.GetSeq() {
			return a.Header.Header.GetSeq() < b.Header.Header.GetSeq()
		}
		return bytes.Compare(a.EntryId[:], b.EntryId[:]) < 0
	}
	inStream := func(entry *RecordReadEntry, streamSidecarId Id) int {
		count := 0
		for _, entryCopy := range entry.Copies {
			if entryCopy.StreamSidecarId == streamSidecarId {
				count += 1
			}
		}
		return count
	}
	count := 0
	streamIds := []Id{}
	for _, entryCopy := range context.Copies {
		if !slices.Contains(streamIds, entryCopy.StreamSidecarId) {
			streamIds = append(streamIds, entryCopy.StreamSidecarId)
		}
	}
	for _, streamSidecarId := range streamIds {
		first := true
		for _, entry := range entries {
			if entry.Header == nil || !bytes.Equal(entry.Header.Header.GetRunId(), runId) || entry.Kind() != RecordKindContext ||
				entry.EntryId == context.EntryId || entry.State.KeyGone() || inStream(entry, streamSidecarId) == 0 {
				continue
			}
			if foldBefore(entry, context) {
				first = false
			}
		}
		if !first {
			continue
		}
		for _, entry := range entries {
			if entry.Header == nil || !bytes.Equal(entry.Header.Header.GetRunId(), runId) || entry.EntryId == context.EntryId ||
				entry.State.KeyGone() || slices.Contains(erasingEntryIds, entry.EntryId) || !indexRecordIndexesEntry(logKind, entry.Kind()) {
				continue
			}
			count += inStream(entry, streamSidecarId)
		}
	}
	return count
}

// What an erasure would take: one item a named entry this device's reader holds.
type RecordErasePlan struct {
	LogId   Id
	Items   []*RecordErasePlanItem
	Missing []Id
}

// One entry an erasure would take, by its header alone.
type RecordErasePlanItem struct {
	EntryId    Id
	Kind       RecordKind
	TimeMillis int64
	// The copies whose keys the ERASE names, and whether an erasure took them already.
	CopyCount int
	Erased    bool
	// For a context entry in a format-2 log: the documents of its run's other entries that keep its agent label and
	// session ids (recordEraseKeptContextCount), which `ur record erase` names before it asks.
	KeptContextCount int
}

// What the format-2 index side of a network's record logs runs on.
type RecordEvsEraseIndexArgs struct {
	Client *EvsClient
	// The record's authorization state now (SidecarRecordArgs.Auth): the erasure set and index settings versions an
	// eraser counts are those a log's admin signed. Nil counts none, and every eraser's view reads its set as
	// unreadable, so no erasure lists anything (fail closed).
	Auth func() RecordAuthView
	// The index's format and its erasers' settings; nil for the defaults.
	IndexFormat *IndexFormatSettings
	IndexErase  *IndexEraseSettings
	// §5.4's erasure event as the index's part moves (Sidecar.raiseErasure); nil raises none.
	Events func(erasure *SidecarErasure)
}

// The format-2 index side of a network's record logs over its EvsClient (RecordEraseIndexOpen): in the format2 gate,
// for a vault, a team record or a `record` repo, the index's eraser on the log's ur/index, built as each erasure opens
// it, signing as this device, its K_ref and pad key from the repo's current key, and an erasure complete while its
// newest ERASE on the erasure ref says so. An explicitly closed gate allows format 1 erasure only on a format 1 repo
// without a companion index. A migrated repo waits for the gate to reopen before erasure can proceed.
func NewRecordEvsEraseIndex(args *RecordEvsEraseIndexArgs) (RecordEraseIndexOpen, error) {
	if args == nil || args.Client == nil {
		return nil, fmt.Errorf("%w: a record's erase index needs an evs client", ErrRecordEraseIndexUnavailable)
	}
	format := args.IndexFormat
	if format == nil {
		format = DefaultIndexFormatSettings()
	}
	settings := args.IndexErase
	if settings == nil {
		settings = DefaultIndexEraseSettings()
	}
	client := args.Client
	return func(ctx context.Context, logId Id) (RecordEraseIndex, error) {
		repo := client.Repo(logId)
		kind, err := repo.repoKind()
		if err != nil {
			return nil, err
		}
		if !recordEraseIndexedKind(kind) {
			return nil, nil
		}
		admitted, known := client.Format2Gate()
		if !known {
			return nil, ErrRecordEraseIndexUnavailable
		}
		if admitted && client.format2Reader() == nil {
			return nil, ErrEvsFormatUnsupported
		}
		store := newIndexEvsStore(repo, nil, true)
		refId, err := store.refId(ctx)
		if err != nil {
			return nil, recordEvsRefusal(err)
		}
		if !admitted {
			// A rollback closes admission without reverting a migrated repo or its existing index.
			listing, err := repo.ListRefs(ctx, nil)
			if err != nil {
				return nil, err
			}
			if listing.Format != EvsRepoFormat1 {
				return nil, ErrRecordEraseIndexUnavailable
			}
			head, err := repo.readHeadAlone(ctx, refId, true)
			if err != nil {
				return nil, err
			}
			if head.Version != 0 {
				return nil, ErrRecordEraseIndexUnavailable
			}
			return nil, nil
		}
		repoKey, err := client.args.Gkm.CurrentRepoKey(ctx, logId)
		if err != nil {
			return nil, err
		}
		refKey, err := indexRefKey(repoKey)
		if err != nil {
			return nil, err
		}
		padKey, err := indexNewPadKey(repoKey)
		if err != nil {
			return nil, err
		}
		identity := client.args.Identity()
		if identity == nil {
			return nil, ErrEvsNoConfig
		}
		auth := args.Auth
		return recordNewEraseIndex(&recordEraseIndexArgs{
			store: store, eraseStore: store, repoId: logId, refId: refId, logKind: kind,
			isAdmin: func(file *indexFileVersion) bool {
				if auth == nil {
					return false
				}
				view := auth()
				return view != nil && view.Admins(logId, file.signerSidecarId)
			},
			format: format, settings: settings, eraser: identity.SidecarId,
			complete: func(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
				erasures, err := repo.ReadErasures(ctx, 0)
				if err != nil {
					return nil, err
				}
				return recordEraseCompleteByNewest(erasures, (*EvsErasure).completionState), nil
			},
			refKey: refKey, padKey: padKey, events: args.Events, clock: client.clock, log: client.log,
		})
	}, nil
}

// Whether a rewrite ran to its end with nothing left to rewrite and no ERASE of it saying complete: not waiting, its
// list proven whole, and the erasure not complete already.
func recordEraseRewriteEndedUnsaid(rewritten *IndexRewriteResult) bool {
	if rewritten == nil || rewritten.Completed || rewritten.Unproven {
		return false
	}
	return rewritten.Erasure == nil || (rewritten.Erasure.State != SidecarErasureWaiting && rewritten.Erasure.State != SidecarErasureDone)
}

// Whether a log of kind holds the record class's documents, which a record erasure's CUT lists.
func recordEraseIndexedKind(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_RECORD:
		return true
	}
	return false
}

// The erasures whose newest ERASE says complete (the file header's complete row), from erases, every ERASE of the
// erasure ref oldest first. A stray completion has no effect on an earlier state.
func recordEraseCompleteByNewest[T any](erases []T, state func(T) (id Id, complete bool, applies bool)) map[Id]bool {
	complete := map[Id]bool{}
	for _, erase := range erases {
		id, done, applies := state(erase)
		if !applies {
			continue
		}
		if done {
			complete[id] = true
		} else {
			delete(complete, id)
		}
	}
	return complete
}

// What one log's index side is built on: the index's stores and judges, and the erasure ref's newest word on each
// erasure.
type recordEraseIndexArgs struct {
	store      indexRefStore
	eraseStore indexEraseStore
	repoId     Id
	// ur/index's own id.
	refId   Id
	logKind protocol.RepoKind
	isAdmin func(file *indexFileVersion) bool
	format  *IndexFormatSettings
	// Nil takes DefaultIndexEraseSettings.
	settings *IndexEraseSettings
	eraser   Id
	// Which erasures are complete by their newest ERASE.
	complete func(ctx context.Context, erasureIds []Id) (map[Id]bool, error)
	refKey   []byte
	// Nil refuses a re-entry that would merge inside its push.
	padKey *indexPadKey
	events func(erasure *SidecarErasure)
	clock  Clock
	log    Logger
}

// One log's index side: the index's eraser on the log's ur/index with the log's K_ref and kind.
type recordEraseIndex struct {
	*IndexEraser
	refKey  []byte
	logKind protocol.RepoKind
}

var _ RecordEraseIndex = (*recordEraseIndex)(nil)

// The index side of args, its eraser reading an erasure's progress through recordEraseNewestStore.
func recordNewEraseIndex(args *recordEraseIndexArgs) (*recordEraseIndex, error) {
	if args == nil || args.store == nil || args.eraseStore == nil || len(args.refKey) == 0 || !recordEraseIndexedKind(args.logKind) {
		return nil, ErrRecordEraseIndexUnavailable
	}
	var padKey func(ctx context.Context) (*indexPadKey, error)
	if args.padKey != nil {
		padKey = func(ctx context.Context) (*indexPadKey, error) { return args.padKey, nil }
	}
	eraser, err := indexNewEraser(&indexEraserArgs{
		store: args.store, eraseStore: &recordEraseNewestStore{indexEraseStore: args.eraseStore},
		repoId: args.repoId, refId: args.refId, repoKind: args.logKind, companion: true, isAdmin: args.isAdmin,
		format: args.format, settings: args.settings, eraser: args.eraser, complete: args.complete,
		refKey: args.refKey, tables: indexLinkedTables(), mayMerge: func() bool { return true }, padKey: padKey,
		events: args.events, clock: args.clock, log: args.log,
	})
	if err != nil {
		return nil, err
	}
	return &recordEraseIndex{IndexEraser: eraser, refKey: bytes.Clone(args.refKey), logKind: args.logKind}, nil
}

// See RecordEraseIndex.
func (self *recordEraseIndex) LogKind() protocol.RepoKind {
	return self.logKind
}

// See RecordEraseIndex.
func (self *recordEraseIndex) DocKey(refId Id, name []byte) ([indexIdByteCount]byte, error) {
	return indexDocKey(self.refKey, refId, name, 0)
}

// The index's eraser store with an erasure read complete only while its newest ERASE says so (the file header's
// complete row): a late copy's ERASE, which does not, opens an erasure an earlier ERASE completed, so its rewrite
// runs and no resume reads it done.
type recordEraseNewestStore struct {
	indexEraseStore
}

// See indexEraseStore: the erasure's progress, every ERASE's complete taken back where its newest does not say so.
func (self *recordEraseNewestStore) Progress(ctx context.Context, erasureId Id) (*indexEraseProgress, error) {
	progress, err := self.indexEraseStore.Progress(ctx, erasureId)
	if err != nil || len(progress.erases) == 0 || progress.erases[len(progress.erases)-1].complete {
		return progress, err
	}
	reopened := &indexEraseProgress{closures: progress.closures, completionKey: progress.completionKey}
	for _, erased := range progress.erases {
		copied := *erased
		copied.complete = false
		reopened.erases = append(reopened.erases, &copied)
	}
	return reopened, nil
}
