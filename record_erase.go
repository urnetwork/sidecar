// RecordEraser (proposed; RECORD-M3-06; §16.8's Erasure, §11.12's closure row, RECORD.md section 8; R-MCP-8,
// R-EVS-11, D-EVS-26, FS-47): a log admin's erasure of entries of one log by key destruction, on every leg the record
// writes from.
//
//	who       only admin on the log erases (§11.12): a repo admin of a team log, and in a vault a consented device of
//	          its owner; a person's erasure, reason 1 or 3, runs only once its command was confirmed on /dev/tty or in an
//	          app's UI and never from a caller with a harness process among its ancestors (§5.8), so no MCP tool and no
//	          prompt-injected shell reaches it; a class 7 entry, which lasts as long as the log, is refused
//	journal   one file a erasure, written before the first push and after each step, so a restart goes on from evs's
//	          state: Resume sends a journaled ERASE again under its push id, which evs answers as it answered it, and
//	          appends the erasure entry an ERASE left unwritten
//	copies    the log is read to its head first, every stream and deposit ref (RECORD.md section 8's every copy): the
//	          named entries are marked erased in this device's reader before anything else, so an ingest pass refuses
//	          them (section 5.4's erased step); a log this device ingests is ingested first, so a deposit holding a named
//	          entry is consumed and its slot deleted with no other entry lost; a deposit still standing after that, as
//	          at the storage limit, has its slot named in the ERASE and is consumed, its batch's other entries then a gap
//	erase     the ERASEs name every copy's (key_slot_id, key_index) and those deposit slots, at most EraseKeyCount a
//	          push, the first holding the entries' own keys, so at the storage limit the bodies go at once; each carries
//	          the erasure id, whether it completes the erasure, and as its sealed note the erasure's ErasureBody, so a
//	          reader that holds only the ERASE knows which entries it took; NOTHING_TO_ERASE is done. evs takes them under
//	          a preservation hold too (owner decision 133)
//	entry     then the erasure entry, RECORD.md's ErasureBody, in this device's own stream of the log, which the writer
//	          retries while §11.13's limit refuses it; until it lands the committed ERASE is the record. Headers and
//	          chains still verify: only keys go, and the entry files stay
//	after     this device's reader drops every decrypted copy of a named entry's body and refuses its keys at once;
//	          another reader does at its next sync, the ERASE's hint (record_reader.go)
//	reach     an erasure names entries of one log: a copy or twin in another log is not reached, and the result names
//	          the log it reached
//
// Not here: format 2's CUT and CLOSUREs of search and run cards (RECORD-M10-01), expiry's erasures (RECORD-M6-03), and
// the search and ur://record caches' own deletes, which are their components'. Safe for concurrent use: one erasure at
// a time.

package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

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
	recordEraseStepPlanned      = "planned"
	recordEraseStepErased       = "erased"
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
)

// What the eraser runs by.
type RecordEraserSettings struct {
	// The entries one erasure names, within ErasureBody.entry_ids' 1,024 (record.proto): each of its ERASEs carries
	// the erasure's ErasureBody as its note, and an ERASE's note rides inline, at most 16 KiB with its record
	// (EvsInlineMaxByteCount), which about 850 entry ids fill, so 512 leaves room. A larger erasure is several.
	EntryCount int
	// The keys one ERASE names, so its push stays within one part beside its inline note.
	EraseKeyCount int
}

// 512 entries an erasure and 512 keys an ERASE.
func DefaultRecordEraserSettings() *RecordEraserSettings {
	return &RecordEraserSettings{
		EntryCount:    512,
		EraseKeyCount: 512,
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
	// The erasure entry, in the writer's journal; nil when the erasure resumed it.
	Entry *RecordEntryRef
}

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
}

// One ERASE of an erasure.
type recordEraseJournalPush struct {
	PushId   Id               `json:"push_id"`
	Keys     []*RecordSlotKey `json:"keys"`
	Complete bool             `json:"complete"`
}

// One CONSUME of a deposit whose slot an ERASE named.
type recordEraseJournalConsume struct {
	PushId      Id   `json:"push_id"`
	DepositorId Id   `json:"depositor_id"`
	DepositIds  []Id `json:"deposit_ids"`
}

// The eraser of a record.
type RecordEraser struct {
	record   *SidecarRecord
	store    SidecarStore
	settings *RecordEraserSettings

	eraseLock sync.Mutex
}

// The record's eraser, made on first use.
func (self *SidecarRecord) Eraser() *RecordEraser {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.eraser == nil {
		self.eraser = &RecordEraser{record: self, store: self.writer.store, settings: DefaultRecordEraserSettings()}
	}
	return self.eraser
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
	self.eraseLock.Lock()
	defer self.eraseLock.Unlock()
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
	self.eraseLock.Lock()
	defer self.eraseLock.Unlock()
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

// One erasure from its journal's step to its end: see the file header's copies, erase, entry and after rows.
func (self *RecordEraser) run(ctx context.Context, journal *recordEraseJournal) (*RecordEraseResult, error) {
	writer := self.record.writer
	reader := self.record.reader
	streams := writer.boundStreams()
	logId := journal.LogId
	// from here no ingest of this device takes a named entry
	reader.noteErased(logId, journal.EntryIds, nil)
	if journal.Step == recordEraseStepPlanned && len(journal.Erases) == 0 {
		named := map[Id]bool{}
		for _, entryId := range journal.EntryIds {
			named[entryId] = true
		}
		found := map[Id]bool{}
		// the deposits standing that hold a named entry, by depositor: once before the ingest, for what was found,
		// and once after, for the slots the ERASE names
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
			return nil, err
		}
		if recordIngests(writer.auth(), writer.sidecarId, logId) {
			// a deposit holding a named entry is consumed with its slot, and its other entries written first
			if err := self.record.ingester.Ingest(ctx, logId); err != nil && writer.log.V(1).Enabled() {
				writer.log.Infof("[record]an erasure's ingest of %s stopped: %s", logId, err)
			}
		}
		holding, err := standing()
		if err != nil {
			return nil, err
		}
		if err := reader.Sync(ctx, logId); err != nil {
			return nil, err
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
				return nil, err
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
		// at most EraseKeyCount keys a push, the entries' own first
		for start := 0; start < len(keys); start += self.settings.EraseKeyCount {
			pushId, err := writer.drawId()
			if err != nil {
				return nil, err
			}
			end := min(len(keys), start+self.settings.EraseKeyCount)
			journal.Erases = append(journal.Erases, &recordEraseJournalPush{PushId: pushId, Keys: keys[start:end], Complete: end == len(keys)})
		}
		if err := self.writeJournal(journal); err != nil {
			return nil, err
		}
	}
	result := &RecordEraseResult{ErasureId: journal.ErasureId, LogId: logId, Erased: journal.Erased, Missing: journal.Missing}
	if journal.Step == recordEraseStepPlanned {
		note, err := proto.MarshalOptions{Deterministic: true}.Marshal(journal.body())
		if err != nil {
			return nil, err
		}
		for _, push := range journal.Erases {
			testHookBarrier("record.erase.before", recordChainIdText(logId))
			_, err := streams.Erase(ctx, logId, &RecordStreamErase{
				PushId: push.PushId, ErasureId: journal.ErasureId, Complete: push.Complete, Keys: push.Keys, SealedNote: note,
			})
			testHookBarrier("record.erase.after", recordChainIdText(logId))
			if code, ok := RecordStreamRefusalCode(err); ok && code == protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE {
				// every key it names is gone already: done
				err = nil
			}
			if err != nil {
				return nil, err
			}
		}
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
	keys := []*RecordSlotKey{}
	for _, push := range journal.Erases {
		keys = append(keys, push.Keys...)
	}
	result.Keys = keys
	reader.noteErased(logId, journal.EntryIds, keys)
	source := RecordSourceObserved
	if journal.Reason == uint32(RecordErasureReasonPerson) || journal.Reason == uint32(RecordErasureReasonModeration) {
		source = RecordSourceApprover
	}
	refs, err := writer.Append(&RecordDraft{Kind: RecordKindErasure, Source: source, NoSession: true, Body: journal.body(), LogId: &logId})
	if err != nil {
		return nil, err
	}
	if 0 < len(refs) {
		result.Entry = refs[0]
	}
	// the entry is in the writer's journal, which carries it to evs: the erasure's own journal is done
	if err := self.store.Remove(recordEraseJournalName(journal.ErasureId)); err != nil {
		return nil, err
	}
	return result, nil
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
		plan.Items = append(plan.Items, &RecordErasePlanItem{
			EntryId: entryId, Kind: entry.Header.Kind(), TimeMillis: entry.Header.Header.GetTimeMillis(), CopyCount: len(entry.Copies),
			Erased: entry.State == RecordEntryErased,
		})
	}
	return plan, nil
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
}

// The ERASE's note as an erasure's: its ErasureBody, holding the erasure id the ERASE carries, or false for a note
// of another kind's, a mailbox's paths, say.
func recordErasureNoteBody(erasure *RecordStreamErasure) (*protocol.ErasureBody, bool) {
	body := &protocol.ErasureBody{}
	if len(erasure.SealedNote) == 0 || proto.Unmarshal(erasure.SealedNote, body) != nil || !strings.EqualFold(hex.EncodeToString(body.GetErasureId()), hex.EncodeToString(erasure.ErasureId[:])) {
		return nil, false
	}
	return body, true
}
