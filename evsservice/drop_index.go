// A process's index of committed DROPs (DESIGN-DETAILS 10.2.7, 10.2.9; EVS2-M10-09, EVS2-M10-10): the parsed bodies of
// the DROPs it has met, by the ref version each committed at, which 5h's fence and §11.9's serve rows read, and the
// committed DROPs it has appended to their tables, so a push or read that meets a bit-5 window entry appends it
// again only once a process.
//
//	bodies    a DROP's statement as received and its EvsDropHistory bytes, read from its record (a seal's from its
//	          part 1, where the body rides whole: 10.2.5), checked against the statement's drop_sha256 and its shape
//	          (sidecar.NewEvsDropLists) and kept by (cluster, repo, ref, version, push id), never changing once
//	          committed; least recently used out past IndexByteCount, with what the list files keep (read_drop.go)
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
	"fmt"
	"sync"

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
