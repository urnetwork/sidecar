// Evacuation's move step (§11.13's move, index, skip and resume rows; D-EVS-32, I-EVS-7; plan-EVSB-pack-put,
// plan-EVSB-parcel-log-pages): one pack or parcel per repo a run, across every minute directory the run evacuates.
//
//	aged     the repo's aged material is this run's kept records, its parcels' records and its log pages over 24 h
//	         old still at log/, less what a pack already holds
//	pack     once that reaches 256 KiB, or its oldest (a parcel's record by its batch minute, a log page by its
//	         LastModified) would pass 7 d before the next run: one pack/<repo>/<pack_id> on the segment cluster
//	         holds all of it, a streamed PUT with its SHA-256, cancelled 8 min after issue
//	parcel   below that: one hp/<repo>/<parcel_id> on the repo's metadata cluster holds the kept records; log pages
//	         wait at log/ for a pack
//	order    the container, then one create-only pidx/ entry per ref, then, for a pack, the delete of each parcel
//	         it replaced, that parcel's entries first, and of each log page it holds. A minute's batches go only
//	         after every repo of that minute is through this (evacuate.go)
//	resume   before anything is built, the run lists each ref's pidx/ entries and moves only what no container
//	         holds, from a parcel what no pack holds; a container with equal bytes on 412 is reused and entries are
//	         create-only, so a run killed at any write is finished by the next, and one killed between a pack's
//	         entries and its deletes has those deletes made then
//	skip     every write rereads repo/ and hold/ as it issues, each cached at most 5 s: a create only while repo/
//	         shows active or deleted, or shredding under a hold covering the repo; a delete never under a hold, so a
//	         held repo's records are packed as usual and nothing of it is deleted while the hold stands
//
// A parcel is read through the pidx/ entries that name it. Records of a ref whose entry is missing are ones no
// reader can reach there: a run killed between a parcel's entries left them in their batch, to be moved again, so a
// pack takes only what an entry names, and the parcel goes once a pack holds all of that. A parcel no entry names is
// left alone, the nightly pass's to delete after 25 h, as is one whose bytes or entries do not parse.

package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One log page at log/ that has aged.
type evacuateLogPage struct {
	refId        sidecar.Id
	page         uint64
	key          string
	byteCount    int64
	lastModified time.Time
}

// One parcel of a repo, read whole with its pidx/ entries.
type evacuateParcel struct {
	key string
	id  sidecar.Id
	// its pidx/ entries' keys, deleted before it
	entryKeys []string
	// the records its entries name
	records []*ContainerRecord
	// it parsed, and an entry names it: false leaves the parcel alone
	usable bool
}

// What containers already hold of one ref, from its pidx/ entries.
type evacuateRefHeld struct {
	// records by place, with the kind and id of a container holding each, a pack over a parcel
	placeKinds     map[string]protocol.EvsContainerKind
	placeParcelIds map[string]sidecar.Id
	// log pages a pack holds
	logPages map[uint64]bool
}

// The versions of one ref a run asks pidx/ about.
type evacuateRefRange struct {
	first uint64
	last  uint64
	set   bool
}

// Widens the range to hold first..last.
func (self *evacuateRefRange) add(first uint64, last uint64) {
	if !self.set {
		self.first, self.last, self.set = first, last, true
		return
	}
	self.first = min(self.first, first)
	self.last = max(self.last, last)
}

// The ref and page a log/<repo>/<ref>/<n> key names.
func parseLogPageKey(repoPrefix string, key string) (sidecar.Id, uint64, bool) {
	rest, ok := strings.CutPrefix(key, repoPrefix)
	if !ok || len(rest) != 32+1+20 || rest[32] != '/' {
		return sidecar.Id{}, 0, false
	}
	refId, err := sidecar.ParseId(rest[:32])
	if err != nil || sidecar.EvsKeyId(refId) != rest[:32] {
		return sidecar.Id{}, 0, false
	}
	page, err := strconv.ParseUint(rest[33:], 10, 64)
	if err != nil {
		return sidecar.Id{}, 0, false
	}
	return refId, page, true
}

// Every object under keyPrefix on the run's cluster.
func (self *evacuateRun) listAll(keyPrefix string) ([]*sidecar.BlobInfo, error) {
	all := []*sidecar.BlobInfo{}
	startAfter := ""
	for {
		objects, more, err := self.cluster.List(self.ctx, keyPrefix, startAfter, self.evacuator.settings.ListLimit)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			all = append(all, object)
			startAfter = object.Key
		}
		if !more {
			return all, nil
		}
	}
}

// The whole object at key, within the bound a repo's container is built under.
func (self *evacuateRun) readObject(key string) ([]byte, error) {
	object, err := self.cluster.Get(self.ctx, key)
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	limit := self.evacuator.settings.RepoMoveByteCount + EvsPidxEntryMaxByteCount
	objectBytes, err := io.ReadAll(io.LimitReader(object.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if limit < int64(len(objectBytes)) {
		return nil, fmt.Errorf("%w: %s is past %d bytes", ErrEvsContainerInvalid, key, limit)
	}
	return objectBytes, nil
}

// The repo's log pages still at log/ whose LastModified is over 24 h before the run's start.
func (self *evacuateRun) agedLogPages(repoId sidecar.Id) ([]*evacuateLogPage, error) {
	repoPrefix := logKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	objects, err := self.listAll(repoPrefix)
	if err != nil {
		return nil, err
	}
	agedBefore := self.now.Add(-self.evacuator.settings.LogPageAge)
	pages := []*evacuateLogPage{}
	for _, object := range objects {
		refId, page, ok := parseLogPageKey(repoPrefix, object.Key)
		if !ok || !object.LastModified.Before(agedBefore) {
			continue
		}
		pages = append(pages, &evacuateLogPage{refId: refId, page: page, key: object.Key, byteCount: object.ByteCount, lastModified: object.LastModified})
	}
	return pages, nil
}

// The repo's parcels, each read whole with the pidx/ entry of each ref it holds, which give its records their
// places and the segments they introduce.
func (self *evacuateRun) readParcels(repoId sidecar.Id) ([]*evacuateParcel, error) {
	repoPrefix := parcelKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	objects, err := self.listAll(repoPrefix)
	if err != nil {
		return nil, err
	}
	parcels := []*evacuateParcel{}
	for _, object := range objects {
		idText := strings.TrimPrefix(object.Key, repoPrefix)
		parcelId, err := sidecar.ParseId(idText)
		if err != nil || sidecar.EvsKeyId(parcelId) != idText {
			continue
		}
		parcel := &evacuateParcel{key: object.Key, id: parcelId}
		parcelBytes, err := self.readObject(object.Key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// deleted since the LIST, by a pack that replaced it
			continue
		}
		if err != nil {
			return nil, err
		}
		kind, items, err := ParseContainer(parcelBytes)
		if err != nil || kind != protocol.EvsContainerKind_EVS_CONTAINER_PARCEL {
			self.alarm("evacuate_parcel_invalid", object.Key, "%s on cluster %s is no parcel: it stays", object.Key, self.clusterId)
			parcels = append(parcels, parcel)
			continue
		}
		// each ref's entry is keyed by the first version the parcel holds of it
		refFirstVersions := map[sidecar.Id]uint64{}
		refIds := []sidecar.Id{}
		for _, item := range items {
			first, ok := refFirstVersions[item.RefId]
			if !ok {
				refIds = append(refIds, item.RefId)
			}
			if !ok || item.Number < first {
				refFirstVersions[item.RefId] = item.Number
			}
		}
		invalid := false
		for _, refId := range refIds {
			entryKey := PidxKey(repoId, refId, refFirstVersions[refId], parcelId)
			entryBytes, err := self.readObject(entryKey)
			if errors.Is(err, sidecar.ErrBlobNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			entry, err := DecodeEvsPidxEntry(entryBytes)
			if err != nil || !bytes.Equal(entry.GetContainerId(), parcelId[:]) {
				self.alarm("evacuate_pidx_invalid", entryKey, "%s on cluster %s is not its parcel's entry: the parcel stays", entryKey, self.clusterId)
				invalid = true
				continue
			}
			parcel.entryKeys = append(parcel.entryKeys, entryKey)
			for i, record := range entry.GetRecords() {
				end := record.GetOffset() + uint64(record.GetLength())
				if uint64(len(parcelBytes)) < end {
					self.alarm("evacuate_pidx_invalid", entryKey, "%s on cluster %s names bytes past its parcel: the parcel stays", entryKey, self.clusterId)
					invalid = true
					break
				}
				containerRecord := &ContainerRecord{
					RefId: refId, Version: record.GetVersion(), Place: record.GetPlace(),
					Bytes: parcelBytes[record.GetOffset():end],
				}
				if i == 0 {
					// an entry lists its ref's introduced segments once, so one record carries them on
					for _, segmentId := range entry.GetSegmentIds() {
						containerRecord.SegmentIds = append(containerRecord.SegmentIds, [32]byte(segmentId))
					}
				}
				parcel.records = append(parcel.records, containerRecord)
			}
		}
		parcel.usable = !invalid && 0 < len(parcel.records)
		parcels = append(parcels, parcel)
	}
	return parcels, nil
}

// What containers already hold of one ref within versions: its pidx/ keys listed, and the entries that may name
// those versions read newest first, at most ResumeEntryCount of them and none past the first that ends below
// the range. An entry not reached costs a record moved twice, never one lost.
func (self *evacuateRun) refHeld(repoId sidecar.Id, refId sidecar.Id, versions *evacuateRefRange) (*evacuateRefHeld, error) {
	held := &evacuateRefHeld{
		placeKinds:     map[string]protocol.EvsContainerKind{},
		placeParcelIds: map[string]sidecar.Id{},
		logPages:       map[uint64]bool{},
	}
	refPrefix := PidxRefPrefix(repoId, refId)
	objects, err := self.listAll(refPrefix)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		key          string
		firstVersion uint64
		containerId  sidecar.Id
	}
	candidates := []*candidate{}
	for _, object := range objects {
		firstVersion, containerId, ok := parsePidxKey(refPrefix, object.Key)
		if ok && firstVersion <= versions.last {
			candidates = append(candidates, &candidate{key: object.Key, firstVersion: firstVersion, containerId: containerId})
		}
	}
	slices.SortFunc(candidates, func(a *candidate, b *candidate) int {
		switch {
		case a.firstVersion > b.firstVersion:
			return -1
		case a.firstVersion < b.firstVersion:
			return 1
		}
		return strings.Compare(a.key, b.key)
	})
	for i, candidate := range candidates {
		if self.evacuator.settings.ResumeEntryCount <= i {
			break
		}
		entryBytes, err := self.readObject(candidate.key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		entry, err := DecodeEvsPidxEntry(entryBytes)
		if err != nil || !bytes.Equal(entry.GetContainerId(), candidate.containerId[:]) {
			// it names nothing this run can trust, so what it may hold is moved again
			self.alarm("evacuate_pidx_invalid", candidate.key, "%s on cluster %s is no entry of its key's container", candidate.key, self.clusterId)
			continue
		}
		kind := entry.GetContainerKind()
		for _, record := range entry.GetRecords() {
			key := placeKey(record.GetPlace())
			if held.placeKinds[key] == protocol.EvsContainerKind_EVS_CONTAINER_PACK {
				continue
			}
			held.placeKinds[key] = kind
			if kind == protocol.EvsContainerKind_EVS_CONTAINER_PARCEL {
				held.placeParcelIds[key] = candidate.containerId
			} else {
				delete(held.placeParcelIds, key)
			}
		}
		for _, logPage := range entry.GetLogPages() {
			held.logPages[logPage.GetPage()] = true
		}
		if entry.GetLastVersion() < versions.first {
			break
		}
	}
	return held, nil
}

// Moves one repo's aged material: see the file header. errEvacuateRepoWaits when repo/ lets no write issue, which
// leaves the repo's records in their batches.
func (self *evacuateRun) moveRepo(repo *evacuateRepo) error {
	settings := self.evacuator.settings
	repoId := repo.repoId
	state, err := self.repoState(repoId)
	if err != nil {
		return err
	}
	if state.action != evacuateRepoMove {
		return fmt.Errorf("%w: %s", errEvacuateRepoWaits, state.why)
	}

	pages, err := self.agedLogPages(repoId)
	if err != nil {
		return err
	}
	parcels, err := self.readParcels(repoId)
	if err != nil {
		return err
	}
	parcelIds := map[sidecar.Id]bool{}
	for _, parcel := range parcels {
		parcelIds[parcel.id] = true
	}

	// resume: what containers already hold of each ref this run touches
	refRanges := map[sidecar.Id]*evacuateRefRange{}
	rangeOf := func(refId sidecar.Id) *evacuateRefRange {
		versions, ok := refRanges[refId]
		if !ok {
			versions = &evacuateRefRange{}
			refRanges[refId] = versions
		}
		return versions
	}
	for _, kept := range repo.kept {
		rangeOf(kept.refId).add(kept.version, kept.version)
	}
	for _, parcel := range parcels {
		if !parcel.usable {
			continue
		}
		for _, record := range parcel.records {
			rangeOf(record.RefId).add(record.Version, record.Version)
		}
	}
	for _, page := range pages {
		first, last := EvsLogPageVersions(page.page)
		rangeOf(page.refId).add(first, last)
	}
	refHelds := map[sidecar.Id]*evacuateRefHeld{}
	for refId, versions := range refRanges {
		held, err := self.refHeld(repoId, refId, versions)
		if err != nil {
			return err
		}
		refHelds[refId] = held
	}
	packHolds := func(refId sidecar.Id, place *protocol.EvsPlace) bool {
		return refHelds[refId].placeKinds[placeKey(place)] == protocol.EvsContainerKind_EVS_CONTAINER_PACK
	}

	// this run's kept records no container holds; a parcel's entry counts only while its parcel stands
	fresh := []*evacuateKept{}
	freshPlaces := map[string]bool{}
	for _, kept := range repo.kept {
		key := placeKey(kept.place)
		held := refHelds[kept.refId]
		switch held.placeKinds[key] {
		case protocol.EvsContainerKind_EVS_CONTAINER_PACK:
			continue
		case protocol.EvsContainerKind_EVS_CONTAINER_PARCEL:
			if parcelIds[held.placeParcelIds[key]] {
				continue
			}
		}
		if !freshPlaces[key] {
			freshPlaces[key] = true
			fresh = append(fresh, kept)
		}
	}
	// parcels' records no pack holds, and the parcels a pack can replace
	parcelRecords := []*ContainerRecord{}
	replaceable := []*evacuateParcel{}
	for _, parcel := range parcels {
		if !parcel.usable {
			continue
		}
		replaceable = append(replaceable, parcel)
		for _, record := range parcel.records {
			key := placeKey(record.Place)
			if packHolds(record.RefId, record.Place) || freshPlaces[key] {
				continue
			}
			freshPlaces[key] = true
			parcelRecords = append(parcelRecords, record)
		}
	}
	unpackedPages := []*evacuateLogPage{}
	packedPages := []*evacuateLogPage{}
	for _, page := range pages {
		if refHelds[page.refId].logPages[page.page] {
			packedPages = append(packedPages, page)
		} else {
			unpackedPages = append(unpackedPages, page)
		}
	}

	// the aged material's size as a container holds it, and its oldest
	var agedByteCount int64
	var oldest time.Time
	older := func(at time.Time) {
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	for _, kept := range fresh {
		agedByteCount += int64(kept.place.GetLength()) + containerItemHeaderByteCount
	}
	for _, record := range parcelRecords {
		agedByteCount += int64(len(record.Bytes)) + containerItemHeaderByteCount
		older(batchMinuteTime(record.Place.GetMinute()))
	}
	for _, page := range unpackedPages {
		agedByteCount += page.byteCount + containerItemHeaderByteCount
		older(page.lastModified)
	}
	pack := settings.PackByteCount <= agedByteCount ||
		(!oldest.IsZero() && !oldest.Add(settings.PackAge).After(self.now.Add(settings.RunInterval)))

	freshRecords := make([]*ContainerRecord, 0, len(fresh))
	for _, kept := range fresh {
		recordBytes, err := self.spool.read(kept.spoolOffset, int(kept.place.GetLength()))
		if err != nil {
			return err
		}
		freshRecords = append(freshRecords, &ContainerRecord{
			RefId: kept.refId, Version: kept.version, Place: kept.place, Bytes: recordBytes, SegmentIds: kept.segmentIds,
		})
	}

	if !pack {
		if 0 < len(freshRecords) {
			container, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PARCEL, freshRecords, nil)
			if err != nil {
				return err
			}
			if err := self.writeContainer(repo, container); err != nil {
				return err
			}
			self.result.ParcelCount += 1
		}
		// what an earlier run's pack already holds still goes, as that run would have had it
		return self.deleteReplaced(repo, self.packedParcels(replaceable, packHolds), packedPages)
	}

	records := append(freshRecords, parcelRecords...)
	logPages := make([]*ContainerLogPage, 0, len(unpackedPages))
	for _, page := range unpackedPages {
		pageBytes, err := self.readObject(page.key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// packed and deleted since the LIST
			continue
		}
		if err != nil {
			return err
		}
		logPages = append(logPages, &ContainerLogPage{RefId: page.refId, Page: page.page, Bytes: pageBytes})
		packedPages = append(packedPages, page)
	}
	if 0 < len(records) || 0 < len(logPages) {
		container, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, records, logPages)
		if err != nil {
			return err
		}
		if err := self.writeContainer(repo, container); err != nil {
			return err
		}
		self.result.PackCount += 1
		self.result.PackedLogPageCount += len(logPages)
	}
	// every replaceable parcel's records are now in a pack: this one, or an earlier run's
	return self.deleteReplaced(repo, replaceable, packedPages)
}

// The parcels whose every record a pack already holds.
func (self *evacuateRun) packedParcels(parcels []*evacuateParcel, packHolds func(refId sidecar.Id, place *protocol.EvsPlace) bool) []*evacuateParcel {
	packed := []*evacuateParcel{}
	for _, parcel := range parcels {
		all := 0 < len(parcel.records)
		for _, record := range parcel.records {
			all = all && packHolds(record.RefId, record.Place)
		}
		if all {
			packed = append(packed, parcel)
		}
	}
	return packed
}

// Writes a container, then one create-only pidx/ entry per ref, in that order (I-EVS-7). A pack is a streamed PUT
// to the segment cluster, cancelled PackPutTimeout after issue; a parcel and every entry are P2 writes on the
// repo's cluster. Equal bytes already there are reused.
func (self *evacuateRun) writeContainer(repo *evacuateRepo, container *Container) error {
	evacuator := self.evacuator
	repoId := repo.repoId
	repoKey := barrierRepoKey(repoId)
	recheck := func(ctx context.Context) error { return self.recheckMove(ctx, repoId) }
	sum := sha256.Sum256(container.Bytes)
	key := container.Key(repoId)

	testHookBarrier(BarrierEvacuateContainerPutBefore, repoKey)
	if err := self.stop(BarrierEvacuateContainerPutBefore, repoKey); err != nil {
		return err
	}
	if container.Kind == protocol.EvsContainerKind_EVS_CONTAINER_PACK {
		segmentCluster, err := evacuator.blobs.SegmentCluster()
		if err != nil {
			return err
		}
		// the segment cluster spends no NVMe budget, so the skip row's reread is made here
		if err := recheck(self.ctx); err != nil {
			return err
		}
		putCtx, cancel := context.WithCancel(self.ctx)
		stop := evacuator.clock.AfterFunc(evacuator.settings.PackPutTimeout, cancel)
		_, err = segmentCluster.PutStream(putCtx, key, bytes.NewReader(container.Bytes), int64(len(container.Bytes)), sum[:])
		stop()
		cancel()
		// a 412 is the pack itself: its key names its bytes
		if err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
			return err
		}
	} else {
		grant, err := self.acquire(repo.firstMinute, WriteOperation{Kind: WriteOperationCreate, ObjectByteCount: int64(len(container.Bytes)), Count: 1}, recheck)
		if err != nil {
			return err
		}
		_, err = sidecar.PutImmutable(grant.Context(), self.cluster, key, container.Bytes, &sidecar.BlobPutOptions{Sha256: sum[:]})
		grant.Close()
		if err != nil {
			return self.immutableFault(key, err)
		}
	}
	testHookBarrier(BarrierEvacuateContainerPutAfter, repoKey)
	if err := self.stop(BarrierEvacuateContainerPutAfter, repoKey); err != nil {
		return err
	}

	refIds := make([]sidecar.Id, 0, len(container.RefEntries))
	for refId := range container.RefEntries {
		refIds = append(refIds, refId)
	}
	slices.SortFunc(refIds, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
	for _, refId := range refIds {
		refEntry := container.RefEntries[refId]
		entryBytes, err := encodeEvsPidxEntry(refEntry)
		if err != nil {
			return err
		}
		entryKey := PidxKey(repoId, refId, refEntry.GetFirstVersion(), container.Id)
		refKey := barrierRefKey(repoId, refId)
		testHookBarrier(BarrierEvacuatePidxPutBefore, refKey)
		if err := self.stop(BarrierEvacuatePidxPutBefore, refKey); err != nil {
			return err
		}
		grant, err := self.acquire(repo.firstMinute, WriteOperation{Kind: WriteOperationCreate, ObjectByteCount: int64(len(entryBytes)), Count: 1}, recheck)
		if err != nil {
			return err
		}
		_, err = sidecar.PutImmutable(grant.Context(), self.cluster, entryKey, entryBytes, nil)
		grant.Close()
		if err != nil {
			return self.immutableFault(entryKey, err)
		}
		testHookBarrier(BarrierEvacuatePidxPutAfter, refKey)
		if err := self.stop(BarrierEvacuatePidxPutAfter, refKey); err != nil {
			return err
		}
	}
	return nil
}

// Alarms an immutable key found holding other bytes, and gives the error back.
func (self *evacuateRun) immutableFault(key string, err error) error {
	if errors.Is(err, sidecar.ErrBlobImmutableMismatch) {
		self.alarm("evacuate_immutable_mismatch", key, "%s on cluster %s holds other bytes than evacuation built for it", key, self.clusterId)
	}
	return err
}

// Deletes what a pack replaced, after the pack and its entries stand: each parcel's pidx/ entries, then the parcel,
// then each packed log page. A hold covering the repo keeps all of it (§21.9), and a repo/ that lets no write
// issue leaves it for a later run.
func (self *evacuateRun) deleteReplaced(repo *evacuateRepo, parcels []*evacuateParcel, pages []*evacuateLogPage) error {
	if len(parcels) == 0 && len(pages) == 0 {
		return nil
	}
	repoId := repo.repoId
	repoKey := barrierRepoKey(repoId)
	recheck := func(ctx context.Context) error { return self.recheckDelete(ctx, repoId) }
	// read once before the first delete, so a held repo costs no budget wait; each delete rereads as it issues
	if err := recheck(self.ctx); err != nil {
		if errors.Is(err, errEvacuateHeld) || errors.Is(err, errEvacuateRepoWaits) {
			return nil
		}
		return err
	}
	kept := func(err error) bool {
		return errors.Is(err, errEvacuateHeld) || errors.Is(err, errEvacuateRepoWaits)
	}
	for _, parcel := range parcels {
		testHookBarrier(BarrierEvacuateParcelDeleteBefore, repoKey)
		if err := self.stop(BarrierEvacuateParcelDeleteBefore, repoKey); err != nil {
			return err
		}
		for _, key := range append(slices.Clone(parcel.entryKeys), parcel.key) {
			if err := self.deleteKey(repo.firstMinute, key, recheck); err != nil {
				if kept(err) {
					return nil
				}
				return err
			}
		}
		self.result.ReplacedParcelCount += 1
		testHookBarrier(BarrierEvacuateParcelDeleteAfter, repoKey)
		if err := self.stop(BarrierEvacuateParcelDeleteAfter, repoKey); err != nil {
			return err
		}
	}
	for _, page := range pages {
		if err := self.deleteKey(repo.firstMinute, page.key, recheck); err != nil {
			if kept(err) {
				return nil
			}
			return err
		}
	}
	return nil
}
