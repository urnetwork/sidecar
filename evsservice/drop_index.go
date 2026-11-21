// A process's index of committed DROPs (DESIGN-DETAILS 10.2.7, 10.2.9; EVS2-M10-09, EVS2-M10-10): the parsed bodies of
// the DROPs it has met, by the ref version each committed at, which 5h's fence and §11.9's serve rows read; per repo
// what serving reads; and the committed DROPs it has appended to their tables, so a push or read that meets a bit-5
// window entry appends it again only once a process.
//
//	bodies    a DROP's statement as received and its EvsDropHistory bytes, read from its record (a seal's from its
//	          part 1, where the body rides whole: 10.2.5), checked against the statement's drop_sha256 and its shape
//	          (sidecar.NewEvsDropLists) and kept by (cluster, repo, ref, version, push id), never changing once
//	          committed
//	repos     per repo: drops/<repo>/_ as a GET cached TableCacheTtl, absent for a repo that never had a drop; its list
//	          files, listed again each IndexRefresh; its withheld ids, reused only while the same immutable files stand
//	bound     bodies and repos share one recency list, least recently used out past IndexByteCount
//	appended  the (cluster, repo, ref, version) of each DROP whose append this process made, at most AppendedCount
//
// A record that is not the push its window entry names, or whose body does not hash to its statement's drop_sha256,
// is ErrEvsStatementMismatch: a wrong place breaks only the chain a reader checks, and alarms.
//
// Safe for concurrent use: nothing here holds its lock across I/O.

package evsservice

import (
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A committed DROP as the fence, the reply and the table read it.
type DropBody struct {
	RefId   sidecar.Id
	Version uint64
	PushId  sidecar.Id
	// Its record's place, as its window entry names it.
	Place *protocol.EvsPlace
	// Its Signed EvsPush as received, and its EvsDropHistory's bytes, which drop_sha256 covers.
	Statement []byte
	Body      []byte
	// The body, checked and indexed by lineage entry.
	Lists *sidecar.EvsDropLists
}

// Whether it is a drop, action 1, rather than a cancel.
func (self *DropBody) Drop() bool {
	return self.Lists.History().GetAction() == evsDropActionDrop
}

// Its drop id, or the id of the drop a cancel ends.
func (self *DropBody) DropId() sidecar.Id {
	history := self.Lists.History()
	if self.Drop() {
		return sidecar.Id(history.GetDropId())
	}
	return sidecar.Id(history.GetCancelsDropId())
}

// The bytes it keeps in the index.
func (self *DropBody) byteCount() int64 {
	return int64(len(self.Statement)) + 2*int64(len(self.Body)) + 256
}

// EvsDropHistory.action's cancel, beside drop_resolve.go's drop.
const evsDropActionCancel = 2

// One body's key.
type dropBodyKey struct {
	clusterId string
	repoId    sidecar.Id
	refId     sidecar.Id
	version   uint64
	pushId    sidecar.Id
}

// One appended DROP's key.
type dropAppendedKey struct {
	clusterId string
	repoId    sidecar.Id
	refId     sidecar.Id
	version   uint64
}

// One item of the recency list: a body, or what read_drop.go keeps of a repo's list files.
type dropIndexItem struct {
	key       any
	value     any
	byteCount int64
}

// See the file header.
type DropIndex struct {
	settings *DropSettings
	records  *RecordCache
	locator  *RecordLocator

	stateLock sync.Mutex
	keyItems  map[any]*list.Element
	recency   *list.List
	byteCount int64
	// the appended DROPs, oldest first
	appended      map[dropAppendedKey]*list.Element
	appendedOrder *list.List
	// body reads from a record, for tests
	readCount int
}

// An empty index over the engine's records and locator.
func NewDropIndex(settings *DropSettings, records *RecordCache, locator *RecordLocator) *DropIndex {
	if settings == nil {
		settings = DefaultDropSettings()
	}
	return &DropIndex{
		settings:      settings,
		records:       records,
		locator:       locator,
		keyItems:      map[any]*list.Element{},
		recency:       list.New(),
		appended:      map[dropAppendedKey]*list.Element{},
		appendedOrder: list.New(),
	}
}

// The value at key, if the index holds it.
func (self *DropIndex) get(key any) (any, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	element, ok := self.keyItems[key]
	if !ok {
		return nil, false
	}
	self.recency.MoveToFront(element)
	return element.Value.(*dropIndexItem).value, true
}

// Keeps value at key, evicting the least recently used past IndexByteCount. A value larger than the bound is not kept.
func (self *DropIndex) put(key any, value any, byteCount int64) {
	if self.settings.IndexByteCount < byteCount {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if element, ok := self.keyItems[key]; ok {
		item := element.Value.(*dropIndexItem)
		self.byteCount += byteCount - item.byteCount
		item.value, item.byteCount = value, byteCount
		self.recency.MoveToFront(element)
	} else {
		self.keyItems[key] = self.recency.PushFront(&dropIndexItem{key: key, value: value, byteCount: byteCount})
		self.byteCount += byteCount
	}
	for self.settings.IndexByteCount < self.byteCount {
		oldest := self.recency.Back()
		item := oldest.Value.(*dropIndexItem)
		self.recency.Remove(oldest)
		delete(self.keyItems, item.key)
		self.byteCount -= item.byteCount
	}
}

// Forgets the value at key.
func (self *DropIndex) forget(key any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if element, ok := self.keyItems[key]; ok {
		self.byteCount -= element.Value.(*dropIndexItem).byteCount
		self.recency.Remove(element)
		delete(self.keyItems, key)
	}
}

// How many bodies it has read from a record.
func (self *DropIndex) BodyReadCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.readCount
}

// The DROP committed at version of refId, whose window entry is entry: this process's copy, else read from its
// record. ErrEvsStatementMismatch for a record that is not that push or a body off its statement.
func (self *DropIndex) Body(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, version uint64, entry *sidecar.EvsWindowEntry) (*DropBody, error) {
	key := dropBodyKey{clusterId: cluster.ClusterId(), repoId: repoId, refId: refId, version: version, pushId: entry.PushId}
	if value, ok := self.get(key); ok {
		return value.(*DropBody), nil
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.readCount += 1
	}()
	record, err := ReadRecordLocated(ctx, self.records, self.locator, cluster, repoId, refId, entry.Place)
	if err != nil {
		return nil, err
	}
	if record.PushId != entry.PushId || record.RepoId != repoId || record.RefId != refId {
		return nil, fmt.Errorf("%w: a bit-5 version's record is another push's", ErrEvsStatementMismatch)
	}
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return nil, err
	}
	var bodyBytes []byte
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH:
		_, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		payload, err := sidecar.ParseEvsPayloadFormat2(payloadBytes)
		if err != nil {
			return nil, err
		}
		bodyBytes = payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY)
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		// the body rides whole in part 1 (DESIGN-DETAILS 10.2.5), so only part 1 is read
		_, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		partRecord, err := ReadRecordLocated(ctx, self.records, self.locator, cluster, repoId, refId, parts[0].Place)
		if err != nil {
			return nil, err
		}
		if partRecord.PushId != entry.PushId {
			return nil, fmt.Errorf("%w: a DROP's part 1 is another push's", ErrEvsStatementMismatch)
		}
		if bodyBytes, err = evsPartDropBody(partRecord); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: a bit-5 version at a record of type %d", ErrEvsStatementMismatch, record.Type)
	}
	lists, err := sidecar.NewEvsDropLists(statement.Push, bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsStatementMismatch, err)
	}
	body := &DropBody{
		RefId: refId, Version: version, PushId: entry.PushId, Place: entry.Place,
		Statement: statement.Bytes, Body: bodyBytes, Lists: lists,
	}
	self.put(key, body, body.byteCount())
	return body, nil
}

// A part record's DROP body, section 9 of its sections slice; empty for a part that carries none.
func evsPartDropBody(partRecord *sidecar.EvsBatchRecord) ([]byte, error) {
	_, partBytes, _, _, err := sidecar.ParseEvsSealPartRecord(partRecord)
	if err != nil {
		return nil, err
	}
	sections, err := evsPartSections(partBytes)
	if err != nil {
		return nil, err
	}
	return sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY), nil
}

// An EvsPushPart's sections slice, parsed as format 2's payload sections.
func evsPartSections(partBytes []byte) (*sidecar.EvsPayload, error) {
	part := &protocol.EvsPushPart{}
	if err := proto.Unmarshal(partBytes, part); err != nil {
		return nil, fmt.Errorf("%w: a part that does not parse", sidecar.ErrEvsPushInvalid)
	}
	return sidecar.ParseEvsPayloadFormat2(part.GetSections())
}

// Whether this process has appended the DROP committed at version of refId.
func (self *DropIndex) Appended(clusterId string, repoId sidecar.Id, refId sidecar.Id, version uint64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	_, ok := self.appended[dropAppendedKey{clusterId: clusterId, repoId: repoId, refId: refId, version: version}]
	return ok
}

// Notes that this process appended the DROP committed at version of refId, forgetting the oldest past AppendedCount.
func (self *DropIndex) NoteAppended(clusterId string, repoId sidecar.Id, refId sidecar.Id, version uint64) {
	if self.settings.AppendedCount <= 0 {
		return
	}
	key := dropAppendedKey{clusterId: clusterId, repoId: repoId, refId: refId, version: version}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.appended[key]; ok {
		return
	}
	self.appended[key] = self.appendedOrder.PushBack(key)
	for self.settings.AppendedCount < len(self.appended) {
		oldest := self.appendedOrder.Front()
		self.appendedOrder.Remove(oldest)
		delete(self.appended, oldest.Value.(dropAppendedKey))
	}
}

// What a process keeps of one repo's drops for serving (read_drop.go, read_withheld.go): its table and when it read
// it, its list files and when it listed them.
type dropRepoState struct {
	tableReadAt time.Time
	// nil while drops/<repo>/_ is absent: the repo never had a drop
	table *DropTableState

	listedAt time.Time
	lists    []*DropListFile
	// the list files' bytes as read, which their index entry counts
	listByteCount int64
}

// One repo's serving state's key.
type dropRepoKey struct {
	clusterId string
	repoId    sidecar.Id
}

// The repo's serving state, a copy the caller may fill and put back.
func (self *DropIndex) repoState(clusterId string, repoId sidecar.Id) *dropRepoState {
	if value, ok := self.get(dropRepoKey{clusterId: clusterId, repoId: repoId}); ok {
		copied := *value.(*dropRepoState)
		return &copied
	}
	return &dropRepoState{}
}

// Keeps the repo's serving state, counted at its list files' bytes.
func (self *DropIndex) putRepoState(clusterId string, repoId sidecar.Id, state *dropRepoState) {
	byteCount := int64(256) + state.listByteCount
	self.put(dropRepoKey{clusterId: clusterId, repoId: repoId}, state, byteCount)
}

// The repo's drop table as a GET of drops/<repo>/_ cached TableCacheTtl, as repo/ is (DESIGN-DETAILS 10.2.9's step 0):
// nil while it is absent, which is all a repo that never had a drop pays.
func (self *DropIndex) Table(ctx context.Context, table *DropTable, cluster sidecar.BlobCluster, repoId sidecar.Id, now time.Time) (*DropTableState, error) {
	state := self.repoState(cluster.ClusterId(), repoId)
	if !state.tableReadAt.IsZero() && now.Sub(state.tableReadAt) < self.settings.TableCacheTtl {
		return state.table, nil
	}
	read, err := table.Read(ctx, cluster, repoId)
	if err != nil {
		return nil, err
	}
	state.tableReadAt = now
	state.table = nil
	if read.Etag != "" {
		state.table = read.State
	}
	self.putRepoState(cluster.ClusterId(), repoId, state)
	return state.table, nil
}

// The repo's list files on the segment cluster, listed again each IndexRefresh, each read whole and held to its layout
// (DESIGN-DETAILS 10.2.9's step 2). An unreadable file is an error: a read answers 503 rather than serve a version it
// could not clear.
func (self *DropIndex) Lists(ctx context.Context, segmentCluster sidecar.BlobCluster, clusterId string, repoId sidecar.Id, now time.Time) ([]*DropListFile, error) {
	state := self.repoState(clusterId, repoId)
	if !state.listedAt.IsZero() && now.Sub(state.listedAt) < self.settings.IndexRefresh {
		return state.lists, nil
	}
	files, byteCount, err := ReadDropListFiles(ctx, segmentCluster, repoId, self.settings)
	if err != nil {
		return nil, err
	}
	state.listedAt, state.lists, state.listByteCount = now, files, byteCount
	self.putRepoState(clusterId, repoId, state)
	return files, nil
}

// Each immutable file in the snapshot used to authorize a content read.
type withheldFile struct {
	jobId    sidecar.Id
	kind     DropFileKind
	sequence uint32
}

type withheldSnapshot struct {
	files []withheldFile
	ids   map[DropScanId]bool
}

type withheldKey struct{ dropRepoKey }

// Lists every active job's del and held files on each check. A writer can publish
// a new file before it checkpoints the table, including on a different instance.
// Only an identical inventory permits reuse of the decoded withheld IDs.
func (self *DropIndex) Withheld(ctx context.Context, segmentCluster sidecar.BlobCluster, clusterId string, repoId sidecar.Id, table *DropTableState, _ time.Time) (map[DropScanId]bool, error) {
	if table == nil || (table.Job == nil && len(table.HeldJobs) == 0) {
		return nil, nil
	}
	var inventory []withheldFile
	for _, jobId := range table.JobIds() {
		files := NewDropFiles(segmentCluster, repoId, jobId, self.settings)
		for _, kind := range []DropFileKind{DropFileDel, DropFileHeld} {
			sequences, err := files.Sequences(ctx, kind)
			if err != nil {
				return nil, err
			}
			for _, sequence := range sequences {
				inventory = append(inventory, withheldFile{jobId: jobId, kind: kind, sequence: sequence})
			}
		}
	}
	key := withheldKey{dropRepoKey{clusterId: clusterId, repoId: repoId}}
	if prior, ok := self.get(key); ok {
		snapshot := prior.(*withheldSnapshot)
		if slices.Equal(snapshot.files, inventory) {
			return snapshot.ids, nil
		}
	}
	withheld := map[DropScanId]bool{}
	for _, item := range inventory {
		files := NewDropFiles(segmentCluster, repoId, item.jobId, self.settings)
		file, err := files.Read(ctx, item.kind, item.sequence)
		if err != nil {
			return nil, err
		}
		if file == nil {
			return nil, fmt.Errorf("%w: %s %d listed and gone", ErrDropFileInvalid, item.kind, item.sequence)
		}
		for _, answer := range file.Answers {
			switch answer.Outcome {
			case DropOutcomeDeleted, DropOutcomeHeld, DropOutcomePacked:
				withheld[answer.DropScanId] = true
			}
		}
		for _, id := range file.Ids {
			withheld[id] = true
		}
	}
	byteCount := int64(256) + int64(len(inventory))*24 + int64(len(withheld))*int64(sha256.Size+8)
	self.put(key, &withheldSnapshot{files: inventory, ids: withheld}, byteCount)
	return withheld, nil
}
