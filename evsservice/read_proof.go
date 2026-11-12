// What a read serves a reader to check a path's version against its statement (§11.9's reply and reader rows;
// EVS1-M2-14): the statement that wrote it, when the reply does not carry it among those after the pin; its Merkle
// proof to changes_root, part level last, when the change list is not inline; and for each later statement whose
// list is not inline and whose covering prefixes reach the path or a prefix holding it, the adjacent-leaf proofs
// that it is not among the changes (§11.6's merkle row), or, for a prefix the statement changed by a delta, which
// does not end the path, that delta's inclusion proof in the absence's present; a directory's deltas after its table
// each carry their own proof (QD-681). A removal is proven by its own change, or by the change removing the prefix
// that ended the path. A change of an older path epoch is found by the leaf place its fold
// recorded (changeAt), since evs is never sent that epoch's token of a path it did not hold (read.go).
//
// Pushes are read by version: a window version's record at the place its entry names, an older one's statement
// from its log page and its record at the place the page's entry names, each read once a request and the records
// through this process's cache (§11.8's read row). A sealed push's parts are read only where the path or its
// neighbours lie: the part whose run holds the path, and the part before or after it for an absence proof at a
// run's edge, since the seal record keeps each part's root and first token path.
//
// Not safe for concurrent use: one readPushes lives on one request.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The record at place: this process's cache, else its batch, else its container through pidx/ (RecordLocator).
// ErrEvsRecordEvacuated only when pidx/ names no container either.
func (self *EvsEngine) readRecordAt(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, place *protocol.EvsPlace) (*sidecar.EvsBatchRecord, error) {
	record, err := ReadRecord(ctx, self.records, cluster, place)
	if !errors.Is(err, ErrEvsRecordEvacuated) {
		return record, err
	}
	recordBytes, err := self.locator.ReadRecord(ctx, cluster, repoId, refId, place)
	if err != nil {
		return nil, err
	}
	record, err = sidecar.ParseEvsBatchRecord(recordBytes)
	if err != nil {
		return nil, err
	}
	self.records.Put(cluster.ClusterId(), place, recordBytes)
	return record, nil
}

// The record's bytes at place, as its batch held them, for a push record a read serves whole.
func (self *EvsEngine) readRecordBytesAt(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, place *protocol.EvsPlace) ([]byte, error) {
	if recordBytes, ok := self.records.Get(cluster.ClusterId(), place); ok {
		return recordBytes, nil
	}
	if _, err := self.readRecordAt(ctx, cluster, repoId, refId, place); err != nil {
		return nil, err
	}
	recordBytes, ok := self.records.Get(cluster.ClusterId(), place)
	if !ok {
		// a cache that keeps nothing: one more read of the same place
		return self.locator.ReadRecord(ctx, cluster, repoId, refId, place)
	}
	return recordBytes, nil
}

// A push a read serves from: its window or page entry, its statement, and its change list as far as it was read.
type readPush struct {
	version uint64
	entry   *sidecar.EvsWindowEntry
	// The statement as received.
	statement *sidecar.EvsStatement
	// A one-part push's changes, once its record was read.
	payload *sidecar.EvsCheckedPayload
	// A sealed push's parts, once its record was read, and those parts read and checked, by part index from 0.
	sealParts    []*sidecar.EvsSealPart
	checkedParts map[int]*sidecar.EvsCheckedPart
	recordRead   bool
}

// Whether the push's change list is under changes_root.
func (self *readPush) rooted() bool {
	return len(self.statement.Push.GetChangesRoot()) != 0
}

// The pushes of one ref as one read serves them.
type readPushes struct {
	engine  *EvsEngine
	ctx     context.Context
	cluster sidecar.BlobCluster
	repoId  sidecar.Id
	refId   sidecar.Id
	head    *protocol.EvsHead
	pushes  map[uint64]*readPush
}

func newReadPushes(engine *EvsEngine, ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *protocol.EvsHead) *readPushes {
	return &readPushes{engine: engine, ctx: ctx, cluster: cluster, repoId: repoId, refId: refId, head: head, pushes: map[uint64]*readPush{}}
}

// The push committed at version, with its statement: from the window's record, or the log page below the window.
func (self *readPushes) at(version uint64) (*readPush, error) {
	if push, ok := self.pushes[version]; ok {
		return push, nil
	}
	if version == 0 || self.head.GetVersion() < version {
		return nil, fmt.Errorf("%w: version %d past the head's %d", ErrEvsStatementMismatch, version, self.head.GetVersion())
	}
	push := &readPush{version: version}
	if entry := windowEntryAt(self.head, version); entry != nil {
		push.entry = entry
		if err := self.readRecord(push); err != nil {
			return nil, err
		}
	} else {
		page, err := self.engine.readLogPage(self.ctx, self.cluster, self.repoId, self.refId, EvsLogPageOf(version))
		if err != nil {
			return nil, err
		}
		entry, statementBytes, ok := page.At(version)
		if !ok {
			return nil, fmt.Errorf("%w: log page %d lacks version %d", ErrEvsStatementMismatch, page.Page, version)
		}
		statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		if !entry.Names(sidecar.Id(statement.Push.GetPushId()), statement.Sha256) {
			return nil, fmt.Errorf("%w: a log page statement its entry does not name", ErrEvsStatementMismatch)
		}
		push.entry = entry
		push.statement = statement
	}
	self.pushes[version] = push
	return push, nil
}

// The push's record at its entry's place: its statement and, for a one-part push, its checked changes, or for a seal
// its parts.
func (self *readPushes) readRecord(push *readPush) error {
	if push.recordRead {
		return nil
	}
	record, err := self.engine.readRecordAt(self.ctx, self.cluster, self.repoId, self.refId, push.entry.Place)
	if err != nil {
		return err
	}
	if record.PushId != push.entry.PushId || record.RepoId != self.repoId || record.RefId != self.refId {
		return fmt.Errorf("%w: another push's record", ErrEvsStatementMismatch)
	}
	var statementBytes []byte
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		var payloadBytes []byte
		statementBytes, payloadBytes, err = sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return err
		}
		statement, err := self.statementOf(push.entry, statementBytes)
		if err != nil {
			return err
		}
		payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		push.statement = statement
		push.payload = payload
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		var parts []*sidecar.EvsSealPart
		statementBytes, parts, err = sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return err
		}
		statement, err := self.statementOf(push.entry, statementBytes)
		if err != nil {
			return err
		}
		push.statement = statement
		push.sealParts = parts
		push.checkedParts = map[int]*sidecar.EvsCheckedPart{}
	default:
		return fmt.Errorf("%w: a record of type %d at a version's place", ErrEvsStatementMismatch, record.Type)
	}
	push.recordRead = true
	return nil
}

// The statement's bytes parsed and held to the window entry's push id and hash prefix. A committed statement is
// served as stored, of either format (format1_guard.go).
func (self *readPushes) statementOf(entry *sidecar.EvsWindowEntry, statementBytes []byte) (*sidecar.EvsStatement, error) {
	statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
	}
	if !entry.Names(sidecar.Id(statement.Push.GetPushId()), statement.Sha256) {
		return nil, fmt.Errorf("%w: the statement's hash", ErrEvsStatementMismatch)
	}
	return statement, nil
}

// One part of a sealed push, read once and matched to the seal's root for it.
func (self *readPushes) checkedPart(push *readPush, part int) (*sidecar.EvsCheckedPart, error) {
	if checked, ok := push.checkedParts[part]; ok {
		return checked, nil
	}
	sealPart := push.sealParts[part]
	record, err := self.engine.readRecordAt(self.ctx, self.cluster, self.repoId, self.refId, sealPart.Place)
	if err != nil {
		return nil, err
	}
	if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART || record.PushId != push.entry.PushId {
		return nil, fmt.Errorf("%w: a seal's part place holds another record", ErrEvsStatementMismatch)
	}
	statementBytes, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(statementBytes, push.statement.Bytes) {
		return nil, fmt.Errorf("%w: a part of another statement", ErrEvsStatementMismatch)
	}
	checked, err := sidecar.EvsCheckStoredPart(push.statement, partBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
	}
	if checked.Root != sealPart.ChangesRoot {
		return nil, fmt.Errorf("%w: a part whose changes_root the seal does not name", ErrEvsStatementMismatch)
	}
	push.checkedParts[part] = checked
	return checked, nil
}

// The push's changes in part (0 for a one-part push), read as needed.
func (self *readPushes) changesOf(push *readPush, part int) ([]*sidecar.EvsCheckedChange, error) {
	if err := self.readRecord(push); err != nil {
		return nil, err
	}
	if push.sealParts == nil {
		return push.payload.Changes, nil
	}
	if part < 0 || len(push.sealParts) <= part {
		return nil, fmt.Errorf("%w: part %d of %d", ErrEvsStatementMismatch, part, len(push.sealParts))
	}
	checked, err := self.checkedPart(push, part)
	if err != nil {
		return nil, err
	}
	return checked.Changes, nil
}

// The leaves of the push's change list in part (0 for a one-part push), read as needed.
func (self *readPushes) leavesOf(push *readPush, part int) ([][]byte, error) {
	changes, err := self.changesOf(push, part)
	if err != nil {
		return nil, err
	}
	leaves := make([][]byte, len(changes))
	for i, change := range changes {
		leaves[i] = change.Leaf
	}
	return leaves, nil
}

// Where tokenPath sits in the push's change list: the part and index of the first change at or after it, and
// whether that change is the path itself. index equals the part's length when the path sorts past its last change,
// and part equals the part count when it sorts past every part's first path and the last part's end.
func (self *readPushes) position(push *readPush, tokenPath sidecar.EvsTokenPath) (int, int, bool, error) {
	if err := self.readRecord(push); err != nil {
		return 0, 0, false, err
	}
	part := 0
	if push.sealParts != nil {
		part = max(0, sealPartHolding(push.sealParts, tokenPath))
	}
	changes, err := self.changesOf(push, part)
	if err != nil {
		return 0, 0, false, err
	}
	index := sort.Search(len(changes), func(i int) bool { return 0 <= changes[i].TokenPath.Compare(tokenPath) })
	present := index < len(changes) && changes[index].TokenPath.Equal(tokenPath)
	return part, index, present, nil
}

// The change the push makes to tokenPath itself, with its part and index, or nil when it makes none.
func (self *readPushes) changeOf(push *readPush, tokenPath sidecar.EvsTokenPath) (*sidecar.EvsCheckedChange, int, int, error) {
	part, index, present, err := self.position(push, tokenPath)
	if err != nil || !present {
		return nil, 0, 0, err
	}
	changes, err := self.changesOf(push, part)
	if err != nil {
		return nil, 0, 0, err
	}
	return changes[index], part, index, nil
}

// The change by which the push removed tokenPath: its own removal, else the removal of the longest prefix holding it.
func (self *readPushes) removalOf(push *readPush, tokenPath sidecar.EvsTokenPath) (*sidecar.EvsCheckedChange, int, int, error) {
	for length := len(tokenPath); 0 < length; length -= 1 {
		change, part, index, err := self.changeOf(push, tokenPath[:length])
		if err != nil {
			return nil, 0, 0, err
		}
		if change != nil && !change.WritesEntry() {
			return change, part, index, nil
		}
	}
	return nil, 0, 0, nil
}

// The change at place in the push's list (DESIGN-DETAILS 9.2.2's leaf row), with its part and index there: a
// one-part push's place names part 0, a sealed push's its part from 1. ErrEvsIndexEntryInvalid for a place the push
// does not have, which only a fold's fault records.
func (self *readPushes) changeAt(push *readPush, place evsLeafPlace) (*sidecar.EvsCheckedChange, int, int, error) {
	if err := self.readRecord(push); err != nil {
		return nil, 0, 0, err
	}
	part := 0
	switch {
	case push.sealParts != nil && (place.part == 0 || uint32(len(push.sealParts)) < place.part):
		return nil, 0, 0, fmt.Errorf("%w: part %d of a seal of %d", ErrEvsIndexEntryInvalid, place.part, len(push.sealParts))
	case push.sealParts != nil:
		part = int(place.part) - 1
	case place.part != 0:
		return nil, 0, 0, fmt.Errorf("%w: part %d of a one-part push", ErrEvsIndexEntryInvalid, place.part)
	}
	changes, err := self.changesOf(push, part)
	if err != nil {
		return nil, 0, 0, err
	}
	if place.index == 0 || uint32(len(changes)) < place.index {
		return nil, 0, 0, fmt.Errorf("%w: change %d of a list of %d", ErrEvsIndexEntryInvalid, place.index, len(changes))
	}
	index := int(place.index) - 1
	return changes[index], part, index, nil
}

// The whole EvsEntryVersion bytes of a version an inline list wrote, which its entry holds elided: the one write of
// the push whose bytes elide to the version's. nil when none does, or more than one, which only a fault makes; an
// inline list is a one-part push of a few changes, so this reads no more than the statement's record.
func (self *readPushes) inlineEntryVersionEliding(push *readPush, elided *protocol.EvsIndexVersion) ([]byte, error) {
	changes, err := self.changesOf(push, 0)
	if err != nil {
		return nil, err
	}
	var found []byte
	for _, change := range changes {
		if !change.WritesEntry() {
			continue
		}
		cut := elideEvsIndexVersion(&protocol.EvsIndexVersion{EntryVersion: change.EntryVersion})
		if !cut.GetElided() || !bytes.Equal(cut.GetEntryVersion(), elided.GetEntryVersion()) {
			continue
		}
		if found != nil {
			return nil, nil
		}
		found = change.EntryVersion
	}
	return found, nil
}

// The proofs of the change at (part, index) to changes_root, part level last; nil for an inline list.
func (self *readPushes) inclusionProof(push *readPush, part int, index int) ([]*protocol.EvsMerkleProof, error) {
	if !push.rooted() {
		return nil, nil
	}
	leaves, err := self.leavesOf(push, part)
	if err != nil {
		return nil, err
	}
	tree, err := sidecar.NewEvsChangeTree(leaves)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
	}
	proofs, err := tree.InclusionProof(0, index)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
	}
	if push.sealParts == nil {
		return proofs, nil
	}
	// the statement's root is over the parts that hold changes, which come first (DESIGN-DETAILS 8.2.2's parts row)
	partRoots := [][]byte{}
	for _, sealPart := range push.sealParts {
		if sealPart.Changeless {
			break
		}
		partRoots = append(partRoots, sealPart.ChangesRoot[:])
	}
	if len(partRoots) <= part {
		return nil, fmt.Errorf("%w: a proof of part %d of %d with changes", ErrEvsStatementMismatch, part, len(partRoots))
	}
	partTree := sidecar.NewEvsMerkleTree(partRoots)
	path, err := partTree.InclusionPath(part)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
	}
	return append(proofs, &protocol.EvsMerkleProof{Leaf: partRoots[part], Index: uint64(part), Size: uint64(len(partRoots)), Path: path}), nil
}

// The adjacent-leaf proofs that the push did not change tokenPath (§11.6's merkle row); nil when it did, which an
// inclusion proof of that change shows instead, and nil for an inline list.
func (self *readPushes) absenceProof(push *readPush, tokenPath sidecar.EvsTokenPath) (*protocol.EvsAbsenceProof, error) {
	if !push.rooted() {
		return nil, nil
	}
	part, index, present, err := self.position(push, tokenPath)
	if err != nil || present {
		return nil, err
	}
	absence := &protocol.EvsAbsenceProof{Version: push.version, TokenPath: tokenPath.Components()}
	partCount := 1
	if push.sealParts != nil {
		// the parts that hold changes: a changeless part comes after them and holds no leaf
		partCount = 0
		for _, sealPart := range push.sealParts {
			if sealPart.Changeless {
				break
			}
			partCount += 1
		}
	}
	belowPart, belowIndex := part, index-1
	for belowIndex < 0 && 0 < belowPart {
		belowPart -= 1
		leaves, err := self.leavesOf(push, belowPart)
		if err != nil {
			return nil, err
		}
		belowIndex = len(leaves) - 1
	}
	if 0 <= belowIndex {
		if absence.Below, err = self.inclusionProof(push, belowPart, belowIndex); err != nil {
			return nil, err
		}
	}
	abovePart, aboveIndex := part, index
	for abovePart < partCount {
		leaves, err := self.leavesOf(push, abovePart)
		if err != nil {
			return nil, err
		}
		if aboveIndex < len(leaves) {
			break
		}
		abovePart, aboveIndex = abovePart+1, 0
	}
	if abovePart < partCount {
		if absence.Above, err = self.inclusionProof(push, abovePart, aboveIndex); err != nil {
			return nil, err
		}
	}
	return absence, nil
}

// For a prefix of a path a reply speaks for that the push changed by a delta, which does not end the path (§11.7's
// newest row): that change's inclusion proof in an absence's present, in place of below and above (QD-681). nil when
// the push did not change prefix or removed it, and nil for an inline list.
func (self *readPushes) presentProof(push *readPush, prefix sidecar.EvsTokenPath) (*protocol.EvsAbsenceProof, error) {
	if !push.rooted() {
		return nil, nil
	}
	change, part, index, err := self.changeOf(push, prefix)
	if err != nil || change == nil || !change.WritesEntry() {
		return nil, err
	}
	present, err := self.inclusionProof(push, part, index)
	if err != nil {
		return nil, err
	}
	return &protocol.EvsAbsenceProof{Version: push.version, TokenPath: prefix.Components(), Present: present}, nil
}
