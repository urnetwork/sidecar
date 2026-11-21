// The nightly pass's count (§11.13's bytes row, §20.7's count row; EVSB-M2-12): a repo's stored bytes are the sizes
// of its billable seg/, pack/ and hp/ objects as LIST returns them, plus the record lengths its head windows, log
// pages and committed seals give for versions still in batches, with no payload read. They are summed by the
// network its repo/ names (the answer to plan-EVSB-repo-network): a repo whose repo/ names none counts to no one.
//
// A version counts from its head's window while its batch may stand, and from the parcel or pack that holds it
// afterwards, so a record mid-evacuation counts twice only until its minute's batches are deleted, and the next
// pass corrects it (§20.7). A batch may stand while its minute starts at or after the cluster's horizon; with no
// horizon read, while it is under 26 h old.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Adds one repo's stored bytes to its network's in result: what it listed, less the containers the pass deleted.
func (self *NightlyPass) countRepo(ctx context.Context, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster, listing *nightlyListing, result *NightlyResult) error {
	repoId := listing.repoId
	read, err := self.repos.Read(ctx, cluster, repoId)
	if errors.Is(err, sidecar.ErrEvsRepoNotFound) {
		// deleted between the LIST and this read: nothing of it is counted
		return nil
	}
	if err != nil {
		return err
	}
	networkId, err := sidecar.IdFromBytes(read.Object.GetNetworkId())
	if err != nil {
		result.UnknownNetworkRepoCount += 1
		return nil
	}
	batchRecordByteCount, err := self.batchRecordByteCount(ctx, cluster, listing, result)
	if err != nil {
		return err
	}
	segmentByteCount, err := self.billableSegmentBytes(ctx, cluster, segmentCluster, listing)
	if err != nil {
		return err
	}
	networkBytes, ok := result.NetworkBytes[networkId]
	if !ok {
		networkBytes = &NightlyBytes{}
		result.NetworkBytes[networkId] = networkBytes
	}
	networkBytes.RepoCount += 1
	networkBytes.SegmentByteCount += segmentByteCount
	for _, pack := range listing.packs {
		if !listing.deletedKeys[pack.Key] {
			networkBytes.PackByteCount += pack.ByteCount
		}
	}
	for _, parcel := range listing.parcels {
		if !listing.deletedKeys[parcel.Key] {
			networkBytes.ParcelByteCount += parcel.ByteCount
		}
	}
	networkBytes.BatchRecordByteCount += batchRecordByteCount
	return nil
}

// A DROP's held ids survive a restart in the active or held job's immutable files. Only the listed segments
// those files name have already left billable usage; other segments under the same hold still count.
func (self *NightlyPass) billableSegmentBytes(ctx context.Context, cluster, segmentCluster sidecar.BlobCluster, listing *nightlyListing) (int64, error) {
	if len(listing.segments) == 0 {
		return 0, nil
	}
	repoId := listing.repoId
	table, err := self.drops.Read(ctx, cluster, repoId)
	if err != nil {
		return 0, err
	}
	held := map[string]bool{}
	for _, jobId := range table.State.JobIds() {
		files := NewDropFiles(segmentCluster, repoId, jobId, self.drops.Settings())
		heldFiles, err := files.ReadAll(ctx, DropFileHeld)
		if err != nil {
			return 0, err
		}
		for _, file := range heldFiles {
			for _, id := range file.Ids {
				if id.Kind == DropIdSegment {
					held[SegmentKey(repoId, id.Id)] = true
				}
			}
		}
	}
	var byteCount int64
	for _, segment := range listing.segments {
		if !held[segment.Key] {
			byteCount += segment.ByteCount
		}
	}
	return byteCount, nil
}

// The committed records still stored in batches for the repo's refs.
func (self *NightlyPass) batchRecordByteCount(ctx context.Context, cluster sidecar.BlobCluster, listing *nightlyListing, result *NightlyResult) (int64, error) {
	repoId := listing.repoId
	heads, err := self.listAll(ctx, cluster, HeadRepoPrefix(repoId))
	if err != nil {
		return 0, err
	}
	now := self.clock.Now()
	standing := now.Add(-self.settings.HeadWindowAge)
	if result.HasHorizon {
		standing = result.Horizon
	}
	count := &nightlyRecordCount{cluster: cluster, repoId: repoId, standing: standing, locator: self.evacuator.locator, batches: map[string]bool{}}
	if result.HasHorizon {
		count.tooYoungToEvacuate = now.Add(-evsEvacuateMinMinuteAge)
	}
	pagedThrough := map[sidecar.Id]uint64{}
	readAge := max(self.settings.HeadWindowAge, self.collectorSettings.HeadAge)
	for _, listed := range heads {
		if listed.LastModified.Before(now.Add(-readAge)) && listed.LastModified.Before(standing) {
			continue
		}
		headBytes, err := readBlob(ctx, cluster, listed.Key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			return 0, err
		}
		head, err := ParseEvsHead(headBytes)
		if err != nil {
			return 0, err
		}
		if err := self.queueCollection(ctx, cluster, repoId, listed.Key, head, result); err != nil {
			return 0, err
		}
		if listed.LastModified.Before(standing) {
			continue
		}
		refId, err := sidecar.ParseId(strings.TrimPrefix(listed.Key, HeadRepoPrefix(repoId)))
		if err != nil || HeadKey(repoId, refId) != listed.Key {
			return 0, fmt.Errorf("%w: head key %s", ErrEvsHeadInvalid, listed.Key)
		}
		if first := EvsHeadWindowFirstVersion(head); 1 < first {
			pagedThrough[refId] = first - 1
		}
		window, err := EvsHeadWindow(head)
		if err != nil {
			return 0, err
		}
		for _, entry := range window {
			if err := count.add(ctx, refId, entry); err != nil {
				return 0, err
			}
		}
	}
	if len(pagedThrough) != 0 {
		if err := self.countLogPages(ctx, count, listing, pagedThrough); err != nil {
			return 0, err
		}
	}
	return count.byteCount, nil
}

// Only the batch header's type byte and, for a seal, its place table are read. Part bodies, including staged
// ciphertext, are never fetched. A HEAD result is shared by every selected place in the same batch.
type nightlyRecordCount struct {
	cluster            sidecar.BlobCluster
	repoId             sidecar.Id
	standing           time.Time
	tooYoungToEvacuate time.Time
	locator            *RecordLocator
	batches            map[string]bool
	byteCount          int64
}

func (self *nightlyRecordCount) addPlace(ctx context.Context, place *protocol.EvsPlace) error {
	minute := batchMinuteTime(place.GetMinute())
	if place == nil {
		return nil
	}
	if !self.tooYoungToEvacuate.IsZero() {
		if minute.Before(self.standing) {
			return nil
		}
		// Before evacuation's floor the committed place itself proves these bytes are still in their batch.
		if minute.After(self.tooYoungToEvacuate) {
			self.byteCount += int64(place.GetLength())
			return nil
		}
	}
	key := PlaceBatchKey(place)
	exists, known := self.batches[key]
	if !known {
		_, err := self.cluster.Head(ctx, key)
		if err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
			return err
		}
		exists = err == nil
		self.batches[key] = exists
	}
	if exists {
		self.byteCount += int64(place.GetLength())
	}
	return nil
}

func (self *nightlyRecordCount) add(ctx context.Context, refId sidecar.Id, entry *sidecar.EvsWindowEntry) error {
	place := entry.Place
	if place == nil {
		return nil
	}
	if !entry.ChangesInPayload() {
		return self.addPlace(ctx, place)
	}
	key := PlaceBatchKey(place)
	// The minute is when a batch opened. A part and its seal can be appended on different processes, so
	// determine each selected place independently, even when the seal's batch has already moved.
	var kind []byte
	err := sidecar.ErrBlobNotFound
	if self.tooYoungToEvacuate.IsZero() || !batchMinuteTime(place.GetMinute()).Before(self.standing) {
		kind, err = readBlobRange(ctx, self.cluster, key, int64(place.GetOffset()), 1)
	}
	var recordBytes []byte
	switch {
	case err == nil:
		self.batches[key] = true
		self.byteCount += int64(place.GetLength())
		switch protocol.EvsBatchRecordType(kind[0]) {
		case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
			return nil
		case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		default:
			return sidecar.ErrEvsPushInvalid
		}
		if place.GetLength() > sidecar.EvsBatchMaxRecordByteCount {
			return sidecar.ErrEvsPushInvalid
		}
		// Read through the locator in case evacuation moved the seal between these reads.
		recordBytes, err = self.locator.ReadRecord(ctx, self.cluster, self.repoId, refId, place)
	case errors.Is(err, sidecar.ErrBlobNotFound):
		self.batches[key] = false
		// A different batch may still hold one of this seal's parts. The container index gives the record
		// type without fetching an ordinary push payload.
		for attempt := range 2 {
			ref, lookupErr := self.locator.ref(ctx, self.cluster, PidxRefPrefix(self.repoId, refId), attempt != 0)
			if lookupErr != nil {
				return lookupErr
			}
			container, record := locateRecord(ref, place)
			if record == nil {
				continue
			}
			if record.GetType() != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
				return nil
			}
			recordBytes, err = self.locator.readContainer(ctx, self.cluster, self.repoId, container, int64(record.GetOffset()), int64(record.GetLength()))
			if !errors.Is(err, sidecar.ErrBlobNotFound) {
				break
			}
		}
	default:
		return err
	}
	if err != nil {
		return err
	}
	record, _, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		return err
	}
	if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL || record.RepoId != self.repoId || record.RefId != refId || record.PushId != entry.PushId {
		return fmt.Errorf("%w: committed seal identity", sidecar.ErrEvsPushInvalid)
	}
	_, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
	if err != nil {
		return err
	}
	for _, part := range parts {
		if err := self.addPlace(ctx, part.Place); err != nil {
			return err
		}
	}
	return nil
}

// A page can be written before a head publishes its page-out; only versions removed from the current window
// count here. Pages created before the oldest standing batch cannot name records in it. The same holds for
// an older pack index; a newer one can name a recent page even after the packer unlinks its log/ object.
func (self *NightlyPass) countLogPages(ctx context.Context, count *nightlyRecordCount, listing *nightlyListing, pagedThrough map[sidecar.Id]uint64) error {
	repoId := listing.repoId
	counted := map[string]bool{}
	countPage := func(refId sidecar.Id, page uint64) error {
		first, _ := EvsLogPageVersions(page)
		key := LogPageKey(repoId, refId, page)
		if pagedThrough[refId] < first || counted[key] {
			return nil
		}
		logPage, err := self.evacuator.readLogPage(ctx, count.cluster, repoId, refId, page)
		if err != nil {
			return err
		}
		for i, entry := range logPage.Entries {
			if first+uint64(i) > pagedThrough[refId] {
				break
			}
			if err := count.add(ctx, refId, entry); err != nil {
				return err
			}
		}
		counted[key] = true
		return nil
	}
	logPrefix := logKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	for _, listed := range listing.logPages {
		if listed.LastModified.Before(count.standing) {
			continue
		}
		refId, page, ok := parseLogPageKey(logPrefix, listed.Key)
		if !ok {
			return ErrEvsLogPageInvalid
		}
		if err := countPage(refId, page); err != nil {
			return err
		}
	}
	if len(listing.packs) == 0 {
		return nil
	}
	pidxPrefix := pidxKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	for _, listed := range listing.pidxEntries {
		if listed.LastModified.Before(count.standing) {
			continue
		}
		refText, _, _ := strings.Cut(strings.TrimPrefix(listed.Key, pidxPrefix), "/")
		refId, err := sidecar.ParseId(refText)
		if err != nil {
			return ErrEvsPidxInvalid
		}
		first, _, ok := parsePidxKey(PidxRefPrefix(repoId, refId), listed.Key)
		if !ok {
			return ErrEvsPidxInvalid
		}
		if pagedThrough[refId] < first {
			continue
		}
		encoded, err := readBlob(ctx, count.cluster, listed.Key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		index, err := DecodeEvsPidxEntry(encoded)
		if err != nil {
			return err
		}
		for _, page := range index.GetLogPages() {
			if err := countPage(refId, page.GetPage()); err != nil {
				return err
			}
		}
	}
	return nil
}

// Queues the ref's marker collection (EVSB-M2-14) when its head is due one: the fold has passed a removal after its
// last window by a base range, and the cluster and the clock would let a window open. One run per ref, once-keyed.
func (self *NightlyPass) queueCollection(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, headKey string, head *protocol.EvsHead, result *NightlyResult) error {
	if self.host.Tasks == nil || !MarkerCollectionDue(head) || !self.clockSure() || !cluster.SettlePassed() {
		return nil
	}
	refText := strings.TrimPrefix(headKey, HeadRepoPrefix(repoId))
	refId, err := sidecar.ParseId(refText)
	if err != nil || HeadKey(repoId, refId) != headKey {
		return nil
	}
	request := EvsCollectTaskRequest(cluster.ClusterId(), repoId, refId, self.clock.Now(), self.collectorSettings)
	if err := self.host.Tasks.Schedule(ctx, request); err != nil {
		return err
	}
	result.CollectQueuedCount += 1
	return nil
}
