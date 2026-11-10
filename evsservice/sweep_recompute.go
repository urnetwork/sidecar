// A marked purge list recomputed (§11.13's sweep row, "recomputing a marked list from the replaced versions", and its
// purge row; I-EVS-9, FI-16; EVSB-M10-02). A record lists no candidates once they would pass 2,048 ids or its room
// (PurgeCandidates), and the sweep recomputes them by step 5's rule from the versions u replaced, which a repo keeps for
// its life (§11.7's history row):
//
//	u          the record's own changes, which name what it replaced: a one-part push's, a part's, or a seal's every
//	           part's; and the new versions of every part, read through u's version on its ref, since a candidate is
//	           what no version of u's push names, a rename's target in another part included
//	           (questions/evs2-m10-04-purge-across-parts)
//	replaced   for each change with a base, its path's version numbered as that base: a write's by its own
//	           prev_push_id and prev_commit_version; else from the path's folded entry (idx/), which keeps a path's
//	           newest versions beside its removal marker; else by a walk back from u through the ref's window and log
//	           pages to the newest push changing the path, at most RecomputeVersionCount versions
//	list       PurgeCandidates' rule with no bound (purgeCandidateList)
//
// Every version is matched to its path in u's path epoch, so one written in another epoch, a PATH_EPOCH push met on
// the walk, or one past the walk's bound leaves that path unfound: its content stays and the caller alarms, keeping
// being the safe way to err, and the nightly count keeps the stored bytes honest. A record that does not match its
// entry, or changes that do not parse, leave the whole list where it is; a store that does not answer is the caller's
// retry.
//
// Not safe for concurrent use: one recompute lives on one call.

package evsservice

import (
	"bytes"
	"context"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One push of u's ref as the recompute read it: its statement and every change, part by part in order.
type sweepRecomputePush struct {
	statement *sidecar.EvsStatement
	changes   []*sidecar.EvsCheckedChange
}

// One recompute's reads of u's ref.
type sweepRecompute struct {
	sweep   *Sweep
	ctx     context.Context
	cluster sidecar.BlobCluster
	target  *SweepTarget
	head    *protocol.EvsHead
	// u's path epoch, which every replaced version must be in
	pathEpoch uint64
	pushes    map[uint64]*sweepRecomputePush
}

// A change of u's whose replaced version the walk still looks for.
type sweepRecomputePending struct {
	index  int
	change *sidecar.EvsCheckedChange
}

// The candidates of target's marked list as step 5 would have listed them with no bound, and how many of the
// record's replacing changes replaced a version the recompute did not find. See the file header.
func (self *Sweep) recompute(ctx context.Context, cluster sidecar.BlobCluster, target *SweepTarget) (*protocol.EvsPurgeList, int, error) {
	if target.Record == nil || target.CommitVersion == 0 {
		return nil, 0, fmt.Errorf("%w: a marked list with no record to recompute it from", ErrEvsStatementMismatch)
	}
	head, err := self.heads.ReadCluster(ctx, cluster, target.RepoId, target.RefId)
	if err != nil {
		return nil, 0, err
	}
	if head.Absent() || head.Head.GetVersion() < target.CommitVersion {
		return nil, 0, fmt.Errorf("%w: a head below the record's version %d", ErrEvsStatementMismatch, target.CommitVersion)
	}
	run := &sweepRecompute{
		sweep:   self,
		ctx:     ctx,
		cluster: cluster,
		target:  target,
		head:    head.Head,
		pushes:  map[uint64]*sweepRecomputePush{},
	}
	u, err := run.pushAt(target.CommitVersion)
	if err != nil {
		return nil, 0, err
	}
	if sidecar.Id(u.statement.Push.GetPushId()) != target.Record.PushId {
		return nil, 0, fmt.Errorf("%w: the record's version names another push", ErrEvsStatementMismatch)
	}
	run.pathEpoch = max(1, u.statement.Push.GetPathEpoch())
	own, err := run.recordChanges(target.Record, u)
	if err != nil {
		return nil, 0, err
	}
	pushVersions := []*protocol.EvsEntryVersion{}
	for _, change := range u.changes {
		if !change.WritesEntry() {
			continue
		}
		entryVersion, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return nil, 0, err
		}
		pushVersions = append(pushVersions, entryVersion)
	}

	// each replacing change's version, in change order
	replacedVersions := make([]*protocol.EvsEntryVersion, len(own))
	pending := []*sweepRecomputePending{}
	for index, change := range own {
		if change.Change.GetBaseEntryVersion() == 0 {
			continue
		}
		version, err := run.byPrev(change)
		if err == nil && version == nil {
			version, err = run.byEntry(change)
		}
		if err != nil {
			return nil, 0, err
		}
		if version == nil {
			pending = append(pending, &sweepRecomputePending{index: index, change: change})
			continue
		}
		replacedVersions[index] = version
	}
	if err := run.walk(pending, replacedVersions); err != nil {
		return nil, 0, err
	}
	replaced := []*PurgeReplaced{}
	unfoundCount := 0
	for index, change := range own {
		if change.Change.GetBaseEntryVersion() == 0 {
			continue
		}
		if replacedVersions[index] == nil {
			unfoundCount += 1
			continue
		}
		replaced = append(replaced, &PurgeReplaced{TokenPath: change.TokenPath, Version: replacedVersions[index]})
	}
	list, _ := purgeCandidateList(replaced, pushVersions)
	return list, unfoundCount, nil
}

// The changes record carries of u's: a one-part push's or a reseed's, a part's, or for a seal every part's.
func (self *sweepRecompute) recordChanges(record *sidecar.EvsBatchRecord, u *sweepRecomputePush) ([]*sidecar.EvsCheckedChange, error) {
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED,
		protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		return u.changes, nil
	case protocol.EvsBatchRecordType_EVS_BATCH_PART:
		statementBytes, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(statementBytes, u.statement.Bytes) {
			return nil, fmt.Errorf("%w: a part of another statement", ErrEvsStatementMismatch)
		}
		checked, err := sidecar.EvsCheckStoredPart(u.statement, partBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		return checked.Changes, nil
	}
	return nil, fmt.Errorf("%w: a record of type %d", ErrEvsStatementMismatch, record.Type)
}

// The push committed at version, read once a recompute.
func (self *sweepRecompute) pushAt(version uint64) (*sweepRecomputePush, error) {
	if push, ok := self.pushes[version]; ok {
		return push, nil
	}
	entry, _, err := self.sweep.entryAt(self.ctx, self.cluster, self.target.RepoId, self.target.RefId, self.head, version)
	if err != nil {
		return nil, err
	}
	push, err := self.readPush(entry)
	if err != nil {
		return nil, err
	}
	self.pushes[version] = push
	return push, nil
}

// The record at entry's place, of either format, held to the entry, and its changes: a one-part push's, or a seal's
// parts' in order, each part held to the seal's root for it.
func (self *sweepRecompute) readPush(entry *sidecar.EvsWindowEntry) (*sweepRecomputePush, error) {
	repoId, refId := self.target.RepoId, self.target.RefId
	readRecord := func(place *protocol.EvsPlace) (*sidecar.EvsBatchRecord, error) {
		recordBytes, err := self.sweep.locator.ReadRecord(self.ctx, self.cluster, repoId, refId, place)
		if err != nil {
			return nil, err
		}
		record, _, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
		if err != nil {
			return nil, err
		}
		if record.PushId != entry.PushId || record.RepoId != repoId || record.RefId != refId {
			return nil, fmt.Errorf("%w: another push's record", ErrEvsStatementMismatch)
		}
		return record, nil
	}
	statementOf := func(statementBytes []byte) (*sidecar.EvsStatement, error) {
		statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		if !entry.Names(sidecar.Id(statement.Push.GetPushId()), statement.Sha256) {
			return nil, fmt.Errorf("%w: the statement's hash", ErrEvsStatementMismatch)
		}
		return statement, nil
	}
	if entry.Place == nil {
		return nil, fmt.Errorf("%w: a version with no place", ErrEvsStatementMismatch)
	}
	record, err := readRecord(entry.Place)
	if err != nil {
		return nil, err
	}
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		statement, err := statementOf(statementBytes)
		if err != nil {
			return nil, err
		}
		payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		return &sweepRecomputePush{statement: statement, changes: payload.Changes}, nil
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		statementBytes, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		statement, err := statementOf(statementBytes)
		if err != nil {
			return nil, err
		}
		push := &sweepRecomputePush{statement: statement}
		for _, sealPart := range parts {
			partRecord, err := readRecord(sealPart.Place)
			if err != nil {
				return nil, err
			}
			if partRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART {
				return nil, fmt.Errorf("%w: a seal's part place holds another record", ErrEvsStatementMismatch)
			}
			partStatementBytes, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(partRecord.Body)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(partStatementBytes, statement.Bytes) {
				return nil, fmt.Errorf("%w: a part of another statement", ErrEvsStatementMismatch)
			}
			checked, err := sidecar.EvsCheckStoredPart(statement, partBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
			}
			if checked.Root != sealPart.ChangesRoot {
				return nil, fmt.Errorf("%w: a part whose changes_root the seal does not name", ErrEvsStatementMismatch)
			}
			push.changes = append(push.changes, checked.Changes...)
		}
		return push, nil
	}
	return nil, fmt.Errorf("%w: a record of type %d at a version's place", ErrEvsStatementMismatch, record.Type)
}

// The entry version push writes at tokenPath numbered version, in u's path epoch; nil when it writes none such.
func (self *sweepRecompute) versionIn(push *sweepRecomputePush, tokenPath sidecar.EvsTokenPath, version uint64) (*protocol.EvsEntryVersion, error) {
	if max(1, push.statement.Push.GetPathEpoch()) != self.pathEpoch {
		return nil, nil
	}
	for _, change := range push.changes {
		if !change.WritesEntry() || !change.TokenPath.Equal(tokenPath) {
			continue
		}
		entryVersion, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return nil, err
		}
		if entryVersion.GetVersion() != version {
			return nil, nil
		}
		return entryVersion, nil
	}
	return nil, nil
}

// A write's replaced version by its own prev_push_id and prev_commit_version; nil for a removal, or when that push
// does not write the path at the base.
func (self *sweepRecompute) byPrev(change *sidecar.EvsCheckedChange) (*protocol.EvsEntryVersion, error) {
	if !change.WritesEntry() {
		return nil, nil
	}
	entryVersion, err := parseEvsEntryVersion(change.EntryVersion)
	if err != nil {
		return nil, err
	}
	prevVersion := entryVersion.GetPrevCommitVersion()
	if prevVersion == 0 || len(entryVersion.GetPrevPushId()) == 0 || self.target.CommitVersion <= prevVersion {
		return nil, nil
	}
	push, err := self.pushAt(prevVersion)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(push.statement.Push.GetPushId(), entryVersion.GetPrevPushId()) {
		return nil, nil
	}
	return self.versionIn(push, change.TokenPath, change.Change.GetBaseEntryVersion())
}

// The replaced version from the path's folded entry in u's epoch, which keeps the newest versions it folded, a
// removed path's beside its marker; nil when the entry holds none numbered as the base. An elided version has lost
// only its inline bodies, which name no candidate.
func (self *sweepRecompute) byEntry(change *sidecar.EvsCheckedChange) (*protocol.EvsEntryVersion, error) {
	read, err := ReadEntry(self.ctx, self.cluster, self.target.RepoId, self.target.RefId, self.pathEpoch, change.TokenPath, self.head.GetFoldedThrough())
	if err != nil {
		return nil, err
	}
	if read.Absent() {
		return nil, nil
	}
	for _, indexVersion := range read.Entry.GetVersions() {
		if self.target.CommitVersion <= indexVersion.GetCommitVersion() {
			continue
		}
		entryVersion, err := parseEvsEntryVersion(indexVersion.GetEntryVersion())
		if err != nil {
			return nil, err
		}
		if entryVersion.GetVersion() == change.Change.GetBaseEntryVersion() {
			return entryVersion, nil
		}
	}
	return nil, nil
}

// The pending changes' versions by one walk back from u's version: each version whose paths may change a pending
// path is read, and the newest change it makes to that path ends the search for it, found when it writes the base.
// A PATH_EPOCH push ends the walk, as does RecomputeVersionCount; what is left stays unfound.
func (self *sweepRecompute) walk(pending []*sweepRecomputePending, replacedVersions []*protocol.EvsEntryVersion) error {
	if len(pending) == 0 {
		return nil
	}
	keyPendings := map[string]*sweepRecomputePending{}
	for _, item := range pending {
		keyPendings[item.change.TokenPath.KeyString()] = item
	}
	commitVersion := self.target.CommitVersion
	for version := commitVersion - 1; 0 < version && 0 < len(keyPendings) &&
		commitVersion-version <= uint64(self.sweep.settings.RecomputeVersionCount); version -= 1 {
		entry, _, err := self.sweep.entryAt(self.ctx, self.cluster, self.target.RepoId, self.target.RefId, self.head, version)
		if err != nil {
			return err
		}
		if entry.PathEpoch() {
			// the versions below it hold their paths in another epoch
			return nil
		}
		mayChange := false
		for _, item := range keyPendings {
			if entry.PathsDigest.MayChange(item.change.TokenPath) {
				mayChange = true
				break
			}
		}
		if !mayChange {
			continue
		}
		push, err := self.pushAt(version)
		if err != nil {
			return err
		}
		for _, change := range push.changes {
			item, ok := keyPendings[change.TokenPath.KeyString()]
			if !ok {
				continue
			}
			delete(keyPendings, change.TokenPath.KeyString())
			entryVersion, err := self.versionIn(push, change.TokenPath, item.change.Change.GetBaseEntryVersion())
			if err != nil {
				return err
			}
			replacedVersions[item.index] = entryVersion
		}
	}
	return nil
}
