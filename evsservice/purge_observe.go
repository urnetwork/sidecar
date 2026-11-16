// D-TEST-12's checker (§11.13's purge and sweep rows, §19.11's purge: observe; R-TEST-10, D-PHASE-10, D-PHASE-12, FI-16;
// EVS2-M10-33): "logging candidates and deleting nothing while taskworker checks that no retained version names one".
// Under purge: observe, evacuation's sweep hands each committed record's candidate list here before it keeps the list
// (sweep.go), and the check reads every retained version of the repo that could name a candidate id, comparing
// locators and slot ids and decrypting nothing:
//
//	own ref    every version of the record's ref after the record's own, newest first, at most VersionCount (64 log
//	           pages): the path's later versions and the rename targets of later pushes among them
//	other refs every version in each other ref's window: the reuse sources a cross-ref copy cites from a repo's other
//	           refs, which a copy made within the record's ~26 h before evacuation finds there
//	verdict    each candidate id that some version names is retained, which pages as storage integrity
//	           (purge_observe_retained, opaque ids only: repo, ref and segment or slot id); every other one is clean.
//	           urnetwork_evs_versionless_observe_total{result} counts each, with no network or repo label
//
// A marked list names no ids; it is counted unchecked and its content stays, as observe keeps everything. A record the
// check cannot read leaves its candidates unchecked, logged, and the sweep goes on: nothing is decided on it, and
// observe deletes nothing whatever the check says. Its reads are its own, sharing no scan code with the purge or the
// sweep, so a bug in theirs cannot hide here (D-EVS-64's reason); the turn-on pass (EVSB-M10-02) deletes only what
// observe kept, once an operator sets purge: on.
//
// Safe for concurrent use: a check keeps its own state.

package evsservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The checker's series (§19.8's versionless rows), with no network or repo label.
const (
	purgeObserveMetricName = "urnetwork_evs_versionless_observe_total"
	purgeObserveClean      = "clean"
	purgeObserveRetained   = "retained"
	purgeObserveUnchecked  = "unchecked"
)

// Settings a check cannot work with.
var ErrPurgeObserveSettings = errors.New("evs purge observe settings invalid")

// Tunables of the check.
type PurgeObserveSettings struct {
	// Versions of the record's ref after it that one check reads, newest first: 4,096, 64 log pages, a day's
	// pushes on a busy ref.
	VersionCount int
	// LIST pages of head/<repo>/ ask for this many keys.
	ListLimit int
}

func DefaultPurgeObserveSettings() *PurgeObserveSettings {
	return &PurgeObserveSettings{VersionCount: 4096, ListLimit: 1000}
}

// ErrPurgeObserveSettings for a bound that is not positive.
func (self *PurgeObserveSettings) Validate() error {
	if self.VersionCount <= 0 || self.ListLimit <= 0 {
		return fmt.Errorf("%w: a bound that is not positive", ErrPurgeObserveSettings)
	}
	return nil
}

// What a check runs on beyond its host.
type PurgeObserveDeps struct {
	// nil: the defaults.
	Settings    *PurgeObserveSettings
	EvsSettings *EvsSettings
	// The page a retained candidate raises. nil discards.
	Log sidecar.Logger
}

// What one check found, in counts with no id (I-13).
type PurgeObserveResult struct {
	CleanCount     int
	RetainedCount  int
	UncheckedCount int
}

// See the file header.
type PurgeObserveCheck struct {
	settings    *PurgeObserveSettings
	evsSettings *EvsSettings
	log         sidecar.Logger
	heads       *HeadStore
	records     *RecordCache
	logPages    *LogPageCache
	locator     *RecordLocator
	counter     sidecar.MetricsCounter
}

// A check on host, which needs Blobs.
func NewPurgeObserveCheck(host *sidecar.ServiceHost, deps *PurgeObserveDeps) (*PurgeObserveCheck, error) {
	if host == nil || host.Blobs == nil {
		return nil, errors.New("evs's purge observe check needs a host with Blobs")
	}
	if deps == nil {
		deps = &PurgeObserveDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultPurgeObserveSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	evsSettings := deps.EvsSettings
	if evsSettings == nil {
		evsSettings = DefaultEvsSettings()
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	clock := host.ClockOrReal()
	self := &PurgeObserveCheck{
		settings:    settings,
		evsSettings: evsSettings,
		log:         log,
		heads:       NewHeadStore(clock, host.ClockCheck, nil, evsSettings, log),
		records:     NewRecordCache(evsSettings),
		logPages:    NewLogPageCache(evsSettings),
		locator:     NewRecordLocator(host.Blobs, nil),
	}
	if host.Metrics != nil {
		self.counter = host.Metrics.Counter(purgeObserveMetricName, "Purge candidates observe mode checked against every retained version, by verdict (D-TEST-12).", "result")
	}
	return self, nil
}

// The candidate ids a list names, by what they are: a segment's or a staged segment's 32 B id, a slot's 16 B.
type purgeObserveId struct {
	id   [sha256.Size]byte
	slot bool
}

// Checks target's list: see the file header.
func (self *PurgeObserveCheck) Check(ctx context.Context, cluster sidecar.BlobCluster, target *SweepTarget) *PurgeObserveResult {
	result := &PurgeObserveResult{}
	list := target.List
	if list == nil || list.GetReplaced() {
		return result
	}
	if list.GetMarked() {
		result.UncheckedCount += 1
		self.count(purgeObserveUnchecked, 1)
		return result
	}
	ids := map[purgeObserveId]bool{}
	for _, candidate := range list.GetCandidates() {
		for _, segmentId := range append(append([][]byte{}, candidate.GetSegmentIds()...), candidate.GetStagedSegmentIds()...) {
			if len(segmentId) == sha256.Size {
				ids[purgeObserveId{id: [sha256.Size]byte(segmentId)}] = false
			}
		}
		for _, slotId := range candidate.GetSlotIds() {
			key := purgeObserveId{slot: true}
			copy(key.id[:], slotId)
			ids[key] = false
		}
	}
	if len(ids) == 0 {
		return result
	}
	refKey := barrierRefKey(target.RepoId, target.RefId)
	if err := self.scan(ctx, cluster, target, ids); err != nil {
		self.log.Warningf("[evs] purge observe: %d candidates of %s unchecked: %v", len(ids), refKey, err)
		result.UncheckedCount += len(ids)
		self.count(purgeObserveUnchecked, len(ids))
		return result
	}
	for id, named := range ids {
		if !named {
			result.CleanCount += 1
			continue
		}
		result.RetainedCount += 1
		kind := "segment"
		if id.slot {
			kind = "slot"
		}
		self.log.Errorf("[evs] alarm purge_observe_retained: a purge candidate of %s, %s %s, is named by a retained version", refKey, kind, hex.EncodeToString(id.id[:]))
	}
	self.count(purgeObserveClean, result.CleanCount)
	self.count(purgeObserveRetained, result.RetainedCount)
	return result
}

// Adds count to the verdict's series.
func (self *PurgeObserveCheck) count(verdict string, count int) {
	if self.counter != nil && 0 < count {
		self.counter.Add(float64(count), verdict)
	}
}

// Marks in ids each id a retained version names: the record's ref after it, then each other ref's window.
func (self *PurgeObserveCheck) scan(ctx context.Context, cluster sidecar.BlobCluster, target *SweepTarget, ids map[purgeObserveId]bool) error {
	head, err := self.heads.ReadCluster(ctx, cluster, target.RepoId, target.RefId)
	if err != nil {
		return err
	}
	if !head.Absent() {
		first := target.CommitVersion + 1
		if newest := head.Version(); self.settings.VersionCount < int(newest-min(newest, target.CommitVersion)) {
			first = newest - uint64(self.settings.VersionCount) + 1
		}
		if err := self.scanRef(ctx, cluster, target.RepoId, target.RefId, head.Head, first, ids); err != nil {
			return err
		}
	}
	prefix := HeadRepoPrefix(target.RepoId)
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, prefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return err
		}
		for _, object := range objects {
			refId, err := parseEvsHexId(object.Key[len(prefix):])
			if err != nil || refId == target.RefId {
				continue
			}
			other, err := self.heads.ReadCluster(ctx, cluster, target.RepoId, refId)
			if err != nil {
				return err
			}
			if other.Absent() || other.Version() == 0 {
				continue
			}
			if err := self.scanRef(ctx, cluster, target.RepoId, refId, other.Head, EvsHeadWindowFirstVersion(other.Head), ids); err != nil {
				return err
			}
		}
		if !more || len(objects) == 0 {
			return nil
		}
		startAfter = objects[len(objects)-1].Key
	}
}

// Marks what each version of refId from first through head's names.
func (self *PurgeObserveCheck) scanRef(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *protocol.EvsHead, first uint64, ids map[purgeObserveId]bool) error {
	window, err := EvsHeadWindow(head)
	if err != nil {
		return err
	}
	windowFirst := EvsHeadWindowFirstVersion(head)
	for version := head.GetVersion(); first <= version && 0 < version; version -= 1 {
		var entry *sidecar.EvsWindowEntry
		if windowFirst <= version {
			entry = window[version-windowFirst]
		} else {
			page, err := self.readLogPage(ctx, cluster, repoId, refId, EvsLogPageOf(version))
			if err != nil {
				return err
			}
			var found bool
			if entry, _, found = page.At(version); !found {
				return fmt.Errorf("%w: log page %d lacks version %d", ErrEvsStatementMismatch, page.Page, version)
			}
		}
		entries, err := self.entryVersionsAt(ctx, cluster, repoId, refId, entry)
		if err != nil {
			return err
		}
		for _, entryBytes := range entries {
			entryVersion, err := parseEvsEntryVersion(entryBytes)
			if err != nil {
				continue
			}
			for _, locator := range entryVersion.GetChain() {
				switch protocol.EvsLocatorKind(locator.GetKind()) {
				case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT, protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
					if len(locator.GetId()) == sha256.Size {
						key := purgeObserveId{id: [sha256.Size]byte(locator.GetId())}
						if _, ok := ids[key]; ok {
							ids[key] = true
						}
					}
				}
			}
			for _, slotId := range entryVersion.GetSlotIds() {
				key := purgeObserveId{slot: true}
				copy(key.id[:], slotId)
				if _, ok := ids[key]; ok {
					ids[key] = true
				}
			}
		}
	}
	return nil
}

// The entry versions the push at entry's place wrote: a one-part push's, or each part's of a seal.
func (self *PurgeObserveCheck) entryVersionsAt(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, entry *sidecar.EvsWindowEntry) ([][]byte, error) {
	record, err := ReadRecordLocated(ctx, self.records, self.locator, cluster, repoId, refId, entry.Place)
	if err != nil {
		return nil, err
	}
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return nil, err
	}
	collect := func(changes []*sidecar.EvsCheckedChange) [][]byte {
		entries := [][]byte{}
		for _, change := range changes {
			if change.WritesEntry() {
				entries = append(entries, change.EntryVersion)
			}
		}
		return entries
	}
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH:
		_, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return nil, err
		}
		return collect(payload.Changes), nil
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		_, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		entries := [][]byte{}
		for _, part := range parts {
			if part.Changeless {
				continue
			}
			partRecord, err := ReadRecordLocated(ctx, self.records, self.locator, cluster, repoId, refId, part.Place)
			if err != nil {
				return nil, err
			}
			_, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(partRecord.Body)
			if err != nil {
				return nil, err
			}
			checked, err := sidecar.EvsCheckStoredPart(statement, partBytes)
			if err != nil {
				return nil, err
			}
			entries = append(entries, collect(checked.Changes)...)
		}
		return entries, nil
	}
	return nil, nil
}

// A log page of a ref, from log/ or, once packed, its container.
func (self *PurgeObserveCheck) readLogPage(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, page uint64) (*LogPage, error) {
	logPage, err := ReadLogPage(ctx, self.logPages, cluster, repoId, refId, page)
	if !errors.Is(err, ErrEvsRecordEvacuated) {
		return logPage, err
	}
	pageBytes, err := self.locator.ReadLogPage(ctx, cluster, repoId, refId, page)
	if err != nil {
		return nil, err
	}
	return ParseLogPage(repoId, refId, page, pageBytes)
}
