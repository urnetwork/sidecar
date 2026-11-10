// Evacuation's staged decisions (§11.13's staged row; D-EVS-36, D-EVS-37, FI-6, FI-16; EVSB-M10-02; DESIGN-DETAILS
// 2.7's note). A staged segment is a one-record versionless version that rode in its push's batch record, outside every
// hash (evs_staged.go). As evacuation takes a committed record of format 2 (an instance at format 2 reads batches of
// either format), it decides each staged segment the record carries:
//
//	written  to seg/<repo>/<id> on the segment cluster, create-only with its id as checksum, equal bytes on 412 a
//	         success (a rerun after a kill between this PUT and the batch's DELETE stores one object), before the
//	         batch's DELETE, when its version is still its path's newest committed version, when it was replaced
//	         under 60 s earlier, or when a hold covering the repo keeps it (its batch predates the hold's placement)
//	dropped  otherwise: it goes with its batch, never reaching seg/; except while §19.11's purge mode is observe, which
//	         keeps replaced content: such a segment is written too, and logged as a candidate, for the turn-on pass
//	         to delete (plan-EVS2-small-readings#6)
//
// The newest version is read from the cluster at the decision (PurgeNewestReader). A replacement whose time the head
// no longer shows, or a newest version that cannot be read for a reason other than the store's, writes the segment:
// keeping is the safe way to err, and the sweep of the replacing record deletes it at that record's evacuation
// (sweep.go). A store that does not answer leaves the minute waiting.
//
// The record goes to its pack or parcel without its staged bytes, its purge list kept (packs and parcels never hold
// staged bytes), and its pidx/ entry lists the staged segments it introduced, written or not, as the segments a
// committed push introduced, so orphan GC never takes one (DESIGN-DETAILS 2.2.4). Dead and duplicate records' staged
// bytes go with their batch. taskworker reports the staged content it drops, or writes only for a hold, as negative
// stored-byte deltas (producer taskworker, §20.6): what evacuation writes for a version still newest stays counted,
// at seg/ in place of the batch.

package evsservice

import (
	"crypto/sha256"
	"errors"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The series the staged decisions export, with no network or repo label (D-OPS-8; §19.8's versionless row).
const (
	versionlessStagedMetricName = "urnetwork_evs_versionless_staged_total"
	versionlessStagedDropped    = "dropped"
	versionlessStagedWritten    = "written"
)

// Where taskworker's stored-byte deltas go: *sidecar.QuotaUsageBatcher meets it, under producer taskworker.
type StoredDeltaSink interface {
	AddStoredDelta(networkId connect.Id, byteDelta int64) error
}

// A staged segment's introducing version: its path, in its push's path epoch.
type evacuateStagedVersion struct {
	tokenPath sidecar.EvsTokenPath
	pathEpoch uint64
}

// The paths of the versions in record that cite each staged id, from its payload's or part's changes as stored: a
// staged locator is cited only by its introducing version (D-EVS-36). A seal or reseed stages nothing.
func evacuateStagedVersions(record *sidecar.EvsBatchRecord) (map[string]*evacuateStagedVersion, error) {
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return nil, err
	}
	var changes []*sidecar.EvsCheckedChange
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH:
		_, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		checked, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return nil, err
		}
		changes = checked.Changes
	case protocol.EvsBatchRecordType_EVS_BATCH_PART:
		_, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		checked, err := sidecar.EvsCheckStoredPart(statement, partBytes)
		if err != nil {
			return nil, err
		}
		changes = checked.Changes
	default:
		return map[string]*evacuateStagedVersion{}, nil
	}
	versions := map[string]*evacuateStagedVersion{}
	for _, change := range changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return nil, err
		}
		for _, locator := range entry.GetChain() {
			if locator.GetStaged() && protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT {
				versions[string(locator.GetId())] = &evacuateStagedVersion{tokenPath: change.TokenPath, pathEpoch: statement.Push.GetPathEpoch()}
			}
		}
	}
	return versions, nil
}

// Decides each staged segment of a kept committed record: see the file header. A non-empty why leaves the minute
// waiting, with the error a step met.
func (self *evacuateRun) decideStaged(minute *evacuateMinute, place *protocol.EvsPlace, record *sidecar.EvsBatchRecord, tail *sidecar.EvsBatchRecordTail) (string, error) {
	stagedSegments, err := tail.StagedSegments()
	if err != nil {
		self.alarm("evacuate_staged_invalid", placeKey(place), "a committed record of batch minute %d on cluster %s carries staged bytes that do not parse: it stays", minute.minute, self.clusterId)
		return "staged unread", nil
	}
	if len(stagedSegments) == 0 {
		return "", nil
	}
	versions, err := evacuateStagedVersions(record)
	if err != nil {
		self.alarm("evacuate_staged_invalid", placeKey(place), "a committed record of batch minute %d on cluster %s has changes that do not parse: it stays", minute.minute, self.clusterId)
		return "staged changes unread", nil
	}
	segmentCluster, err := self.evacuator.blobs.SegmentCluster()
	if err != nil {
		return "no segment cluster", err
	}
	read, err := self.evacuator.repos.Read(self.ctx, self.cluster, record.RepoId)
	if err != nil {
		return "repo/ unread", err
	}
	networkId, networkErr := sidecar.IdFromBytes(read.Object.GetNetworkId())
	batchTime := batchMinuteTime(place.GetMinute())
	for _, segment := range stagedSegments {
		id := sha256.Sum256(segment)
		barrierKey := barrierSegmentKey(record.RepoId, id[:])
		testHookBarrier(BarrierEvacuateStagedBefore, barrierKey)
		if err := self.stop(BarrierEvacuateStagedBefore, barrierKey); err != nil {
			return "stopped", nil
		}
		version, ok := versions[string(id[:])]
		write := false
		heldOnly := false
		if !ok {
			// no version cites it: nothing can name it again
			self.alarm("evacuate_staged_uncited", barrierKey, "a staged segment no version of its record cites, batch minute %d on cluster %s: dropped", minute.minute, self.clusterId)
		} else {
			newest, err := self.evacuator.newest.NewestNames(self.ctx, self.cluster, record.RepoId, record.RefId, version.pathEpoch, version.tokenPath)
			switch {
			case err != nil && evacuateStoreError(err):
				return "staged newest unread", err
			case err != nil:
				// a newest version this reader cannot judge: keep, and the replacing record's sweep deletes it
				write = true
			case newest.Names[string(id[:])]:
				write = true
			case newest.CommitMinuteEnd.IsZero():
				// replaced by a version whose commit the head no longer shows: keep, as above
				write = true
			case self.now.Before(newest.CommitMinuteEnd.Add(evsPurgeMinAllowance)):
				// replaced under 60 s ago: readers may still be inside the allowance
				write = true
			}
			if !write {
				cover, err := self.evacuator.holds.CoveringRepo(self.ctx, record.RepoId, read.Object)
				if err != nil {
					cover = &sidecar.HoldCover{Unknown: true}
				}
				if cover.Keeps(batchTime) {
					write, heldOnly = true, true
				}
			}
			if !write && self.evacuator.format2.PurgeMode() != sidecar.Format2On {
				// observe mode keeps replaced content: written, and left to the turn-on pass
				self.evacuator.log.Infof("[evs] purge observe: a replaced staged segment of %s kept at seg/", barrierRefKey(record.RepoId, record.RefId))
				write = true
			}
		}
		if write {
			if _, err := sidecar.PutImmutable(self.ctx, segmentCluster, SegmentKey(record.RepoId, id), segment, &sidecar.BlobPutOptions{Sha256: id[:]}); err != nil {
				if errors.Is(err, sidecar.ErrBlobImmutableMismatch) {
					self.alarm("evacuate_staged_mismatch", barrierKey, "seg/ holds other bytes under a staged segment's id, batch minute %d on cluster %s: it stays", minute.minute, self.clusterId)
					return "staged seg/ mismatch", nil
				}
				return "staged not written", err
			}
			self.countStaged(versionlessStagedWritten)
			self.result.StagedWrittenCount += 1
		} else {
			self.countStaged(versionlessStagedDropped)
			self.result.StagedDroppedCount += 1
		}
		if !write || heldOnly {
			// dropped, or kept only for a hold: either way out of the stored count
			self.reportStoredDelta(networkId, networkErr, -int64(len(segment)))
		}
		testHookBarrier(BarrierEvacuateStagedAfter, barrierKey)
		if err := self.stop(BarrierEvacuateStagedAfter, barrierKey); err != nil {
			return "stopped", nil
		}
	}
	return "", nil
}

// Whether err is the store's, which a later run retries: a held key, a read that did not answer. A format the
// reader does not take, or bytes that do not parse, are not.
func evacuateStoreError(err error) bool {
	var unknown *sidecar.BlobUnknownError
	return errors.Is(err, sidecar.ErrBlobHeld) || errors.As(err, &unknown) || errors.Is(err, sidecar.ErrBlobClusterUnknown)
}

func (self *evacuateRun) countStaged(outcome string) {
	if counter := self.evacuator.stagedCounter; counter != nil {
		counter.Add(1, outcome)
	}
}

// A stored-byte delta of the repo's network to taskworker's usage batches. A repo/ with no network, or no sink,
// reports nothing and alarms, the nightly count correcting the drift.
func (self *evacuateRun) reportStoredDelta(networkId sidecar.Id, networkErr error, byteDelta int64) {
	sink := self.evacuator.deps.Usage
	if sink == nil || networkErr != nil {
		self.alarm("evacuate_usage", self.clusterId, "a staged segment's %d bytes reach no usage batch on cluster %s", byteDelta, self.clusterId)
		return
	}
	if err := sink.AddStoredDelta(connect.Id(networkId), byteDelta); err != nil {
		self.alarm("evacuate_usage", self.clusterId, "a staged segment's delta was not batched on cluster %s: %v", self.clusterId, err)
	}
}

// A kept format-2 record's tail settled before its batch goes: its staged segments decided, then its list swept
// (sweep.go) as P2 of evacuation's rank, funded by the push. A non-empty why leaves the minute waiting.
func (self *evacuateRun) settleFormat2(minute *evacuateMinute, place *protocol.EvsPlace, record *sidecar.EvsBatchRecord, tail *sidecar.EvsBatchRecordTail) (string, error) {
	if why, err := self.decideStaged(minute, place, record, tail); why != "" {
		return why, err
	}
	list, err := tail.PurgeListValue()
	if err != nil {
		self.alarm("evacuate_purge_list", placeKey(place), "a committed record of batch minute %d on cluster %s lists candidates that do not parse: it stays", minute.minute, self.clusterId)
		return "purge list unread", nil
	}
	if list == nil {
		return "", nil
	}
	read, err := self.evacuator.repos.Read(self.ctx, self.cluster, record.RepoId)
	if err != nil {
		return "repo/ unread", err
	}
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return "statement unread", err
	}
	swept, err := self.evacuator.sweep.SweepList(self.ctx, self.cluster, record.RepoId, record.RefId, read.Object,
		statement.Push.GetPathEpoch(), list, self.rank, self.funded, batchMinuteTime(minute.minute))
	self.result.Swept.add(swept)
	switch {
	case errors.Is(err, ErrSweepRetry):
		return "sweep", nil
	case err != nil:
		return "sweep", err
	}
	return "", nil
}
