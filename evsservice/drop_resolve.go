// The drop job's resolve (§11.13's resolve row; D-EVS-63, D-EVS-64, I-EVS-15, FI-27, FS-93; DESIGN-DETAILS 10.2.8's
// resolve and 10.2.9's listed index, 8.3's G11; EVSB-M10-04): for each covered drop, it proves the DROP's lists exact
// against the ref's own history and writes what the job may delete.
//
//	scan     per ref holding a covered drop, its head read from the cluster, versions 1 to the head's: each
//	         statement from the head's window (its record) or the ref's log page; a PATH_EPOCH's new epoch noted with
//	         its map's hash and its window entry; every other push in a lineage entry's epoch whose changes may touch
//	         a lineage token path (inline, or under changes_root once its window digest matches the path or a prefix
//	         and a changed_prefix covers it) read from its record, each change on the path, or a removal of a
//	         directory holding it, a hit; a hit writing an entry carries its entry version, whose version is k
//	links    each older lineage entry is a source of the newer in the newer epoch's committed map part map_parts
//	         names (pmap/, the part's own repo, ref, epoch and part checked) or, at 0, its PATH_EPOCH's tail moves;
//	         else refused {mismatch}
//	exact    S, every hit writing an entry on a lineage token path in its epoch, below the DROP's version and below
//	         through_version, by count and the SHA-256 of its entry hashes ascending, equal to count and
//	         listed_sha256; section 10 is read only to describe a mismatch, which pages
//	bound    written: the DROP's own statement writes the lineage's newest token path at through_version - 1, and
//	         no hit below it reaches through_version; removed: the newest hit below the DROP is a removal, of the path
//	         or of a directory holding it, whose version (one past the path's last) is through_version
//	cand     every segment id a kind-1 locator of a version in S names and every slot id it names, and nothing else:
//	         kind-5 ids are the purge's, inline records stay, and nothing here lists seg/, so a git-mode push's
//	         history segments, which no entry version names, are never candidates (G11)
//	files    the list files first (dropscan/<repo>/<job>/list-<n>, the listed index kept for the repo's life), then
//	         the cand files, each If-None-Match with equal bytes success, so a resolve killed anywhere runs again
//	         whole and writes the same bytes
//
// Each covered drop is judged alone: one refused {mismatch} leaves the others, and the candidates are the union over
// those resolved. A store read that fails is an error, never a mismatch, and the job's resolve runs again; only what
// the ref's committed history shows refuses a drop. Reads are paced to the job's 32 MB/s and renew its lease.
//
// A dry run's resolve (Preview) makes the same scan at a snapshot of its request ref, its head's version: per path its
// links, found by a binary search over the committed map's parts and then the tail when the request names no part,
// its resolved count and list_match; its candidates go to cand files under the dry run's id, and its listed versions'
// entry hashes back to the caller for mark, since a dry run writes no list file a reader would take as a drop.
//
// The list file (DESIGN-DETAILS 10.2.9), within the common envelope of drop_files.go, integers big-endian:
//
//	header   drop count u16 | 2 zero bytes | per drop: drop_id 16 | ref_id 16 | version u64 | push_id 16, ascending
//	         by drop_id
//	rows     entry_sha256 32 | drop u16, an index into the header's drops | flags u8 (1: its chain holds an inline
//	         record): ascending by entry_sha256 then drop, at most FileRowCount a file
//	index    the entry_sha256 of every 128th row, from the first
//	bloom    10 bits a row, rounded up to a byte; 7 probes at (a + i x b) mod bits in unsigned 64-bit arithmetic, a
//	         and b the first and second 8 B of the entry_sha256 big-endian, i = 0 to 6; bit n is byte n/8's bit n mod
//	         8, counted from the least significant
//	tail     index offset u32 | bloom offset u32, each from the file's first byte; then the envelope's SHA-256
//
// Safe for concurrent use: each call holds its own state; the caches beneath are.

package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The list file's layout (DESIGN-DETAILS 10.2.9). Format values a reader needs to parse a file, not tunables.
const (
	dropListDropByteCount   = 56
	dropListRowByteCount    = 35
	dropListTailByteCount   = 8
	dropListIndexStride     = 128
	dropListBloomBitsPerRow = 10
	dropListBloomProbeCount = 7
	dropListFlagInline      = 1
)

// EvsDropHistory.action's drop (§11.7's action row), beside fold_format2.go's boundaries.
const evsDropActionDrop = 1

// What a resolve runs on beyond its host.
type DropResolveDeps struct {
	// nil: the defaults.
	Settings    *DropSettings
	EvsSettings *EvsSettings
	// Pages and what a run did. nil discards.
	Log sidecar.Logger
}

// See the file header.
type DropResolve struct {
	host        *sidecar.ServiceHost
	settings    *DropSettings
	evsSettings *EvsSettings
	log         sidecar.Logger
	records     *RecordCache
	locator     *RecordLocator
	logPages    *LogPageCache
}

// A resolve on host, which needs Blobs.
func NewDropResolve(host *sidecar.ServiceHost, deps *DropResolveDeps) (*DropResolve, error) {
	if host == nil || host.Blobs == nil {
		return nil, errors.New("evs's drop resolve needs a host with Blobs")
	}
	if deps == nil {
		deps = &DropResolveDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultDropSettings()
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
	return &DropResolve{
		host:        host,
		settings:    settings,
		evsSettings: evsSettings,
		log:         log,
		records:     NewRecordCache(evsSettings),
		locator:     NewRecordLocator(host.Blobs, nil),
		logPages:    NewLogPageCache(evsSettings),
	}, nil
}

// One lineage entry: a path epoch and the path's token path in it.
type dropLineageKey struct {
	epoch     uint64
	tokenPath string
}

// The key of a lineage entry.
func dropKeyOf(epoch uint64, tokenPath sidecar.EvsTokenPath) dropLineageKey {
	return dropLineageKey{epoch: epoch, tokenPath: tokenPath.KeyString()}
}

// One lineage entry, parsed.
type dropLineageEntry struct {
	epoch     uint64
	tokenPath sidecar.EvsTokenPath
}

// A lineage's entries parsed from an EvsDropPath, newest first; an entry that does not parse is the path's error.
func parseDropLineage(path *protocol.EvsDropPath) ([]*dropLineageEntry, error) {
	entries := make([]*dropLineageEntry, 0, len(path.GetLineage()))
	for _, source := range path.GetLineage() {
		tokenPath, err := sidecar.ParseEvsChangedTokenPath(source.GetTokenPath())
		if err != nil {
			return nil, err
		}
		entries = append(entries, &dropLineageEntry{epoch: source.GetEpoch(), tokenPath: tokenPath})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: a lineage with no entry", sidecar.ErrEvsPushInvalid)
	}
	return entries, nil
}

// One change of a ref's history on a lineage token path or on a directory holding it.
type dropHit struct {
	version uint64
	key     dropLineageKey
	// a removal, of the path itself or, prefix, of a directory holding it
	removal bool
	prefix  bool
	// the change's base, the version it names
	baseEntryVersion uint64
	// a write's entry hash and entry version, which names k
	entrySha256 [32]byte
	entry       *protocol.EvsEntryVersion
}

// A PATH_EPOCH of the ref: its new epoch's map hash, and where its statement is.
type dropEpoch struct {
	mapSha256 []byte
	version   uint64
	entry     *sidecar.EvsWindowEntry
}

// What one scan of a ref's history gathered for a set of lineage entries.
type dropRefHistory struct {
	reader *dropRefReader
	// each PATH_EPOCH's, by its new epoch
	epochs map[uint64]*dropEpoch
	// each lineage entry's hits, ascending by version
	hits map[dropLineageKey][]*dropHit
	// the window entries of the versions asked for
	entries map[uint64]*sidecar.EvsWindowEntry
}

// What a pass reads one ref's history with: its head as read, each version's window entry from that head's window or
// the ref's log pages, statements from log pages or records, and records through the process's cache, the batches or,
// once evacuated, their containers. Every read is counted and paced. Not safe for concurrent use.
type dropRefReader struct {
	ctx         context.Context
	cluster     sidecar.BlobCluster
	repoId      sidecar.Id
	refId       sidecar.Id
	head        *protocol.EvsHead
	window      []*sidecar.EvsWindowEntry
	windowFirst uint64
	source      *RecordPushSource
	records     *RecordCache
	locator     *RecordLocator
	logPages    *LogPageCache
	page        *LogPage
	// records read once, by version
	readVersions map[uint64]bool
	pace         func(ctx context.Context, byteCount int64) error
	byteCount    int64
}

// A reader of head's history, which a read from the cluster gave.
func newDropRefReader(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *protocol.EvsHead, records *RecordCache, locator *RecordLocator, logPages *LogPageCache, pace func(ctx context.Context, byteCount int64) error) (*dropRefReader, error) {
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, err
	}
	if pace == nil {
		pace = func(ctx context.Context, byteCount int64) error { return nil }
	}
	return &dropRefReader{
		ctx: ctx, cluster: cluster, repoId: repoId, refId: refId, head: head, window: window,
		windowFirst: EvsHeadWindowFirstVersion(head), source: NewRecordPushSource(records, locator, cluster, repoId, refId),
		records: records, locator: locator, logPages: logPages, readVersions: map[uint64]bool{}, pace: pace,
	}, nil
}

// Counts and paces byteCount bytes read.
func (self *dropRefReader) read(byteCount int64) error {
	self.byteCount += byteCount
	return self.pace(self.ctx, byteCount)
}

// Counts the record of version once, by its place's length.
func (self *dropRefReader) readRecordOf(version uint64, entry *sidecar.EvsWindowEntry) error {
	if self.readVersions[version] {
		return nil
	}
	self.readVersions[version] = true
	return self.read(int64(entry.Place.GetLength()))
}

// The window entry of version, and its statement's bytes when a log page holds them; nil bytes from the window.
func (self *dropRefReader) entryAt(version uint64) (*sidecar.EvsWindowEntry, []byte, error) {
	if self.windowFirst <= version && version-self.windowFirst < uint64(len(self.window)) {
		return self.window[version-self.windowFirst], nil, nil
	}
	number := EvsLogPageOf(version)
	if self.page == nil || self.page.Page != number {
		page, err := dropReadLogPage(self.ctx, self.logPages, self.locator, self.cluster, self.repoId, self.refId, number)
		if err != nil {
			return nil, nil, err
		}
		self.page = page
		if err := self.read(int64(len(page.Bytes))); err != nil {
			return nil, nil, err
		}
	}
	entry, statementBytes, ok := self.page.At(version)
	if !ok {
		return nil, nil, fmt.Errorf("%w: log page %d lacks version %d", ErrDropJobState, number, version)
	}
	return entry, statementBytes, nil
}

// The statement committed at version: from statementBytes a log page gave, held to the window entry's push id and
// hash prefix, else from its record.
func (self *dropRefReader) statementAt(version uint64, entry *sidecar.EvsWindowEntry, statementBytes []byte) (*sidecar.EvsStatement, error) {
	if statementBytes == nil {
		if err := self.readRecordOf(version, entry); err != nil {
			return nil, err
		}
		return self.source.statementAt(self.ctx, version, entry)
	}
	return self.source.statementOf(entry, statementBytes)
}

// The changes of the push at version on tokenPath or on a directory holding it, each writing one with its entry
// version (RecordPushSource.ChangesAt).
func (self *dropRefReader) changesAt(version uint64, entry *sidecar.EvsWindowEntry, tokenPath sidecar.EvsTokenPath) ([]*EvsCommittedChange, error) {
	if err := self.readRecordOf(version, entry); err != nil {
		return nil, err
	}
	return self.source.ChangesAt(self.ctx, version, entry, tokenPath)
}

// The push committed at version whole: its statement and its payload checked as stored, a one-part push's from its
// record and a sealed push's from every part (EvsCheckStoredSeal), each part matched to the root its seal names.
func (self *dropRefReader) pushAt(version uint64, entry *sidecar.EvsWindowEntry) (*sidecar.EvsStatement, *sidecar.EvsCheckedPayload, error) {
	if err := self.readRecordOf(version, entry); err != nil {
		return nil, nil, err
	}
	record, err := ReadRecordLocated(self.ctx, self.records, self.locator, self.cluster, self.repoId, self.refId, entry.Place)
	if err != nil {
		return nil, nil, err
	}
	if record.PushId != entry.PushId || record.RepoId != self.repoId || record.RefId != self.refId {
		return nil, nil, fmt.Errorf("%w: another push's record", ErrEvsStatementMismatch)
	}
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, nil, err
		}
		statement, err := self.source.statementOf(entry, statementBytes)
		if err != nil {
			return nil, nil, err
		}
		checked, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		return statement, checked, nil
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		statementBytes, sealParts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, nil, err
		}
		statement, err := self.source.statementOf(entry, statementBytes)
		if err != nil {
			return nil, nil, err
		}
		partBytes, err := self.partsOf(statement, sealParts)
		if err != nil {
			return nil, nil, err
		}
		checked, checkedParts, err := sidecar.EvsCheckStoredSeal(statement, partBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		for i, checkedPart := range checkedParts {
			if checkedPart.HoldsChanges() && checkedPart.Root != sealParts[i].ChangesRoot {
				return nil, nil, fmt.Errorf("%w: a part whose changes_root the seal does not name", ErrEvsStatementMismatch)
			}
		}
		return statement, checked, nil
	}
	return nil, nil, fmt.Errorf("%w: a record of type %d at a version's place", ErrEvsStatementMismatch, record.Type)
}

// The bytes of each part a seal names, each read from its place and held to the statement, counted as read.
func (self *dropRefReader) partsOf(statement *sidecar.EvsStatement, sealParts []*sidecar.EvsSealPart) ([][]byte, error) {
	partBytes := make([][]byte, len(sealParts))
	for i, sealPart := range sealParts {
		if err := self.read(int64(sealPart.Place.GetLength())); err != nil {
			return nil, err
		}
		record, err := ReadRecordLocated(self.ctx, self.records, self.locator, self.cluster, self.repoId, self.refId, sealPart.Place)
		if err != nil {
			return nil, err
		}
		if record.PushId != sidecar.Id(statement.Push.GetPushId()) {
			return nil, fmt.Errorf("%w: a seal's part place holds another record", ErrEvsStatementMismatch)
		}
		// a part record, or a re-seeded push's part, a reseed record holding a part's body (QD-818)
		statementBytes, part, _, _, err := sidecar.ParseEvsSealPartRecord(record)
		if err != nil {
			return nil, fmt.Errorf("%w: a seal's part place holds another record: %w", ErrEvsStatementMismatch, err)
		}
		if !bytes.Equal(statementBytes, statement.Bytes) {
			return nil, fmt.Errorf("%w: a part of another statement", ErrEvsStatementMismatch)
		}
		partBytes[i] = part
	}
	return partBytes, nil
}

// A log page of a ref, from log/ or, once packed, its container.
func dropReadLogPage(ctx context.Context, cache *LogPageCache, locator *RecordLocator, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, page uint64) (*LogPage, error) {
	logPage, err := ReadLogPage(ctx, cache, cluster, repoId, refId, page)
	if !errors.Is(err, ErrEvsRecordEvacuated) {
		return logPage, err
	}
	pageBytes, err := locator.ReadLogPage(ctx, cluster, repoId, refId, page)
	if err != nil {
		return nil, err
	}
	return ParseLogPage(repoId, refId, page, pageBytes)
}

// A ref's head from the cluster: nil when the ref has none. A held key is the store's ErrBlobHeld, which the caller's
// phase waits out: a scan never skips a ref.
func dropReadHead(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id) (*protocol.EvsHead, error) {
	object, err := cluster.Get(ctx, HeadKey(repoId, refId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	headBytes, err := io.ReadAll(io.LimitReader(object.Body, EvsHeadMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	return ParseEvsHead(headBytes)
}

// Scans versions 1 to through of the ref reader holds, gathering every PATH_EPOCH and each hit on keys, the lineage
// entries asked for, and the window entries of wantVersions. renew is called after each version.
func scanDropRef(reader *dropRefReader, keys map[dropLineageKey]*dropLineageEntry, through uint64, wantVersions map[uint64]bool, renew func(ctx context.Context) error) (*dropRefHistory, error) {
	history := &dropRefHistory{
		reader:  reader,
		epochs:  map[uint64]*dropEpoch{},
		hits:    map[dropLineageKey][]*dropHit{},
		entries: map[uint64]*sidecar.EvsWindowEntry{},
	}
	// the lineage token paths of each epoch
	epochPaths := map[uint64][]sidecar.EvsTokenPath{}
	for key, lineageEntry := range keys {
		epochPaths[key.epoch] = append(epochPaths[key.epoch], lineageEntry.tokenPath)
	}
	for epoch := range epochPaths {
		slices.SortFunc(epochPaths[epoch], func(a sidecar.EvsTokenPath, b sidecar.EvsTokenPath) int { return a.Compare(b) })
	}
	for version := uint64(1); version <= through; version += 1 {
		entry, statementBytes, err := reader.entryAt(version)
		if err != nil {
			return nil, err
		}
		if wantVersions[version] {
			history.entries[version] = entry
		}
		statement, err := reader.statementAt(version, entry, statementBytes)
		if err != nil {
			return nil, fmt.Errorf("version %d of ref %s: %w", version, sidecar.EvsKeyId(reader.refId), err)
		}
		push := statement.Push
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			history.epochs[push.GetPathEpoch()] = &dropEpoch{mapSha256: bytes.Clone(push.GetPathMapSha256()), version: version, entry: entry}
		} else if paths := epochPaths[push.GetPathEpoch()]; 0 < len(paths) {
			for _, tokenPath := range paths {
				if !dropMayTouch(statement, entry, tokenPath) {
					continue
				}
				changes, err := reader.changesAt(version, entry, tokenPath)
				if err != nil {
					return nil, fmt.Errorf("version %d of ref %s: %w", version, sidecar.EvsKeyId(reader.refId), err)
				}
				key := dropKeyOf(push.GetPathEpoch(), tokenPath)
				for _, change := range changes {
					hit, err := dropHitOf(version, key, tokenPath, change)
					if err != nil {
						return nil, fmt.Errorf("version %d of ref %s: %w", version, sidecar.EvsKeyId(reader.refId), err)
					}
					if hit != nil {
						history.hits[key] = append(history.hits[key], hit)
					}
				}
			}
		}
		if renew != nil {
			if err := renew(reader.ctx); err != nil {
				return nil, err
			}
		}
	}
	return history, nil
}

// Whether the statement may change tokenPath or remove a directory holding it: an inline change list says so
// exactly, and one under changes_root may when the window entry's digest matches the path or a prefix of it and a
// changed_prefix covers it (§11.8's digest row).
func dropMayTouch(statement *sidecar.EvsStatement, entry *sidecar.EvsWindowEntry, tokenPath sidecar.EvsTokenPath) bool {
	if len(statement.Push.GetChangesRoot()) == 0 {
		for _, change := range statement.Changes {
			if tokenPath.HasPrefix(change.TokenPath) {
				return true
			}
		}
		return false
	}
	if !entry.PathsDigest.MayChange(tokenPath) {
		return false
	}
	for _, prefix := range statement.ChangedPrefixes {
		if tokenPath.HasPrefix(prefix) {
			return true
		}
	}
	return false
}

// The hit a change makes on the lineage entry key at tokenPath: a write or removal of the path itself, or a removal
// of a directory holding it; nil for a directory's delta above it, which changes no file.
func dropHitOf(version uint64, key dropLineageKey, tokenPath sidecar.EvsTokenPath, change *EvsCommittedChange) (*dropHit, error) {
	if !change.TokenPath.Equal(tokenPath) {
		if !change.Removes() {
			return nil, nil
		}
		return &dropHit{version: version, key: key, removal: true, prefix: true, baseEntryVersion: change.BaseEntryVersion}, nil
	}
	if change.Removes() {
		return &dropHit{version: version, key: key, removal: true, baseEntryVersion: change.BaseEntryVersion}, nil
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
		return nil, fmt.Errorf("%w: an entry version that does not parse", ErrEvsStatementMismatch)
	}
	hit := &dropHit{version: version, key: key, baseEntryVersion: change.BaseEntryVersion, entry: entry}
	copy(hit.entrySha256[:], change.EntrySha256)
	return hit, nil
}

// A covered drop's or a dry run's path, judged: its listed set S and what its links found.
type dropPathVerdict struct {
	// S, ascending by entry hash
	listed []*dropHit
	// per older lineage entry, the map part holding its move (0 the tail), as far as the links held
	mapParts []uint32
	linked   bool
	// why the path refuses its drop, "" when it holds
	mismatch string
}

// S for path over the hits history holds, below below and below the path's through_version: every hit writing an
// entry on a lineage token path in its epoch, ascending by entry hash.
func dropListedSet(history *dropRefHistory, lineage []*dropLineageEntry, path *protocol.EvsDropPath, below uint64) []*dropHit {
	listed := []*dropHit{}
	for _, lineageEntry := range lineage {
		for _, hit := range history.hits[dropKeyOf(lineageEntry.epoch, lineageEntry.tokenPath)] {
			if hit.entry == nil || below <= hit.version || path.GetThroughVersion() <= hit.entry.GetVersion() {
				continue
			}
			listed = append(listed, hit)
		}
	}
	slices.SortFunc(listed, func(a *dropHit, b *dropHit) int { return bytes.Compare(a.entrySha256[:], b.entrySha256[:]) })
	return listed
}

// Whether listed's entry hashes, ascending, have path's count and listed_sha256; two equal hashes never match.
func dropListMatches(listed []*dropHit, path *protocol.EvsDropPath) bool {
	if uint64(len(listed)) != uint64(path.GetCount()) {
		return false
	}
	digest := sha256.New()
	for i, hit := range listed {
		if 0 < i && bytes.Equal(listed[i-1].entrySha256[:], hit.entrySha256[:]) {
			return false
		}
		digest.Write(hit.entrySha256[:])
	}
	return bytes.Equal(digest.Sum(nil), path.GetListedSha256())
}

// A committed map part's moves, read once a resolve.
type dropMapParts struct {
	parts map[string]*protocol.EvsPathMap
}

// Whether moves hold a move to newer whose sources name older.
func dropMovesLink(moves []*protocol.EvsPathMove, newer *dropLineageEntry, older *dropLineageEntry) bool {
	for _, move := range moves {
		newPath, err := sidecar.ParseEvsTokenPath(move.GetNewTokenPath())
		if err != nil || !newPath.Equal(newer.tokenPath) {
			continue
		}
		for _, source := range move.GetSources() {
			if source.GetEpoch() != older.epoch {
				continue
			}
			sourcePath, err := sidecar.ParseEvsTokenPath(source.GetTokenPath())
			if err == nil && sourcePath.Equal(older.tokenPath) {
				return true
			}
		}
	}
	return false
}

// Part part of epoch's committed map on the reader's ref, nil when the store holds no such part or it is not this
// map's: its own repo, ref, epoch and part, as the copy holds each part (the commit checked the parts against the
// map's hash, and the keys are immutable).
func (self *DropResolve) mapPart(reader *dropRefReader, cache *dropMapParts, epochNumber uint64, epoch *dropEpoch, part uint32) (*protocol.EvsPathMap, error) {
	key := PathMapKey(reader.repoId, reader.refId, epochNumber, epoch.mapSha256, part)
	if pathMap, ok := cache.parts[key]; ok {
		return pathMap, nil
	}
	object, err := reader.cluster.Get(reader.ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		cache.parts[key] = nil
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	partBytes, err := readAllLimited(object, int64(sidecar.DefaultEvsFormatSettings().PathMapMaxByteCount))
	object.Body.Close()
	if err != nil {
		return nil, err
	}
	if err := reader.read(int64(len(partBytes))); err != nil {
		return nil, err
	}
	_, pathMap, err := sidecar.ParseEvsPathMap(partBytes)
	if err != nil || sidecar.Id(pathMap.GetRepoId()) != reader.repoId || sidecar.Id(pathMap.GetRefId()) != reader.refId ||
		pathMap.GetPathEpoch() != epochNumber || pathMap.GetPart() != part {
		pathMap = nil
	}
	cache.parts[key] = pathMap
	return pathMap, nil
}

// The tail moves of the PATH_EPOCH that made epoch current.
func (self *DropResolve) tailMoves(reader *dropRefReader, epoch *dropEpoch) ([]*protocol.EvsPathMove, error) {
	_, payload, err := reader.pushAt(epoch.version, epoch.entry)
	if err != nil {
		return nil, err
	}
	moves := make([]*protocol.EvsPathMove, 0, len(payload.TailMoves))
	for _, item := range payload.TailMoves {
		move := &protocol.EvsPathMove{}
		if err := proto.Unmarshal(item, move); err != nil {
			return nil, fmt.Errorf("%w: a tail move that does not parse", ErrEvsStatementMismatch)
		}
		moves = append(moves, move)
	}
	return moves, nil
}

// Whether the link from older to newer holds at part (0 the tail) of newer's epoch.
func (self *DropResolve) linkAt(reader *dropRefReader, history *dropRefHistory, cache *dropMapParts, newer *dropLineageEntry, older *dropLineageEntry, part uint32) (bool, error) {
	epoch := history.epochs[newer.epoch]
	if epoch == nil {
		return false, nil
	}
	if part == 0 {
		moves, err := self.tailMoves(reader, epoch)
		if err != nil {
			return false, err
		}
		return dropMovesLink(moves, newer, older), nil
	}
	pathMap, err := self.mapPart(reader, cache, newer.epoch, epoch, part)
	if err != nil || pathMap == nil {
		return false, err
	}
	return dropMovesLink(pathMap.GetMoves(), newer, older), nil
}

// The part of newer's epoch's committed map whose run holds newer's move to older, by a binary search over the parts,
// which are runs ascending by new token path (DESIGN-DETAILS 9.2.2), else 0 when the tail links it; found false when
// neither does.
func (self *DropResolve) findLink(reader *dropRefReader, history *dropRefHistory, cache *dropMapParts, newer *dropLineageEntry, older *dropLineageEntry) (uint32, bool, error) {
	epoch := history.epochs[newer.epoch]
	if epoch == nil {
		return 0, false, nil
	}
	first, err := self.mapPart(reader, cache, newer.epoch, epoch, 1)
	if err != nil {
		return 0, false, err
	}
	if first != nil {
		low, high := uint32(1), max(1, first.GetParts())
		for low <= high {
			middle := low + (high-low)/2
			pathMap, err := self.mapPart(reader, cache, newer.epoch, epoch, middle)
			if err != nil {
				return 0, false, err
			}
			moves := pathMap.GetMoves()
			if len(moves) == 0 {
				break
			}
			firstPath, firstErr := sidecar.ParseEvsTokenPath(moves[0].GetNewTokenPath())
			lastPath, lastErr := sidecar.ParseEvsTokenPath(moves[len(moves)-1].GetNewTokenPath())
			if firstErr != nil || lastErr != nil {
				break
			}
			switch {
			case newer.tokenPath.Compare(firstPath) < 0:
				high = middle - 1
			case 0 < newer.tokenPath.Compare(lastPath):
				low = middle + 1
			default:
				if dropMovesLink(moves, newer, older) {
					return middle, true, nil
				}
				// the run that would hold the move does not: the map does not link it
				low = high + 1
			}
		}
	}
	moves, err := self.tailMoves(reader, epoch)
	if err != nil {
		return 0, false, err
	}
	if dropMovesLink(moves, newer, older) {
		return 0, true, nil
	}
	return 0, false, nil
}

// The links of lineage: the parts mapParts names when it names one per older entry, else each found by search. The
// map parts as far as the links held, and whether every one did.
func (self *DropResolve) links(reader *dropRefReader, history *dropRefHistory, cache *dropMapParts, lineage []*dropLineageEntry, mapParts []uint32) ([]uint32, bool, error) {
	found := []uint32{}
	for i := 1; i < len(lineage); i += 1 {
		newer, older := lineage[i-1], lineage[i]
		if newer.epoch <= older.epoch {
			return found, false, nil
		}
		if len(mapParts) == len(lineage)-1 {
			ok, err := self.linkAt(reader, history, cache, newer, older, mapParts[i-1])
			if err != nil || !ok {
				return found, false, err
			}
			found = append(found, mapParts[i-1])
			continue
		}
		if 0 < len(mapParts) {
			return found, false, nil
		}
		part, ok, err := self.findLink(reader, history, cache, newer, older)
		if err != nil || !ok {
			return found, false, err
		}
		found = append(found, part)
	}
	return found, true, nil
}

// A covered drop resolved: its statement's place and body, and each path's verdict.
type dropResolved struct {
	drop     *DropCovered
	mismatch string
	listed   []*dropHit
}

// Resolve (EVSB-M10-04): see the file header.
func (self *DropResolve) Resolve(ctx context.Context, request *DropResolveRequest) (*DropResolveResult, error) {
	result := &DropResolveResult{}
	if request.Cluster == nil || request.SegmentCluster == nil {
		return result, fmt.Errorf("%w: a resolve with no clusters", ErrDropJobState)
	}
	refDrops := map[sidecar.Id][]*DropCovered{}
	refIds := []sidecar.Id{}
	for _, drop := range request.Drops {
		if _, ok := refDrops[drop.RefId]; !ok {
			refIds = append(refIds, drop.RefId)
		}
		refDrops[drop.RefId] = append(refDrops[drop.RefId], drop)
	}
	slices.SortFunc(refIds, func(a sidecar.Id, b sidecar.Id) int { return bytes.Compare(a[:], b[:]) })
	resolved := []*dropResolved{}
	for _, refId := range refIds {
		refResolved, byteCount, err := self.resolveRef(ctx, request, refId, refDrops[refId])
		result.ScanByteCount += byteCount
		if err != nil {
			return result, err
		}
		for _, one := range refResolved {
			if one.mismatch != "" {
				self.log.Errorf("[evs] drop_mismatch: repo %s drop %s: %s", sidecar.EvsKeyId(request.RepoId), sidecar.EvsKeyId(one.drop.DropId), one.mismatch)
				result.Mismatch = append(result.Mismatch, one.drop.DropId)
				continue
			}
			resolved = append(resolved, one)
		}
	}
	if len(resolved) == 0 {
		return result, nil
	}
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.JobId, self.settings)
	listFiles, err := EncodeDropListFiles(request.RepoId, request.JobId, dropListInputs(resolved), self.settings)
	if err != nil {
		return result, err
	}
	for sequence, encoded := range listFiles {
		if err := files.Put(ctx, DropFileList, uint32(sequence), encoded); err != nil {
			return result, err
		}
	}
	candidates := map[DropScanId]bool{}
	for _, one := range resolved {
		for _, hit := range one.listed {
			dropCandidatesOf(hit.entry, candidates)
		}
	}
	if err := putDropCandFiles(ctx, files, request.RepoId, request.JobId, candidates, self.settings); err != nil {
		return result, err
	}
	return result, nil
}

// Every candidate an entry version names: each segment id of a kind-1 locator, and each slot id. A kind-5 locator's
// is the purge's, and an inline record stays, so neither is one (§11.13's resolve row).
func dropCandidatesOf(entry *protocol.EvsEntryVersion, candidates map[DropScanId]bool) {
	for _, locator := range entry.GetChain() {
		if locator.GetKind() == uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT) && len(locator.GetId()) == 32 {
			candidates[DropSegmentId([32]byte(locator.GetId()))] = true
		}
	}
	for _, slotId := range entry.GetSlotIds() {
		if len(slotId) == 16 {
			candidates[DropSlotId(sidecar.Id(slotId))] = true
		}
	}
}

// Whether an entry version's chain holds an inline record.
func dropEntryInline(entry *protocol.EvsEntryVersion) bool {
	for _, locator := range entry.GetChain() {
		if locator.GetKind() == uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE) {
			return true
		}
	}
	return false
}

// The cand files of candidates, ascending in cand order, FileRowCount a file, always at least cand-0.
func putDropCandFiles(ctx context.Context, files *DropFiles, repoId sidecar.Id, jobId sidecar.Id, candidates map[DropScanId]bool, settings *DropSettings) error {
	sorted := make([]DropScanId, 0, len(candidates))
	for scanId := range candidates {
		sorted = append(sorted, scanId)
	}
	slices.SortFunc(sorted, CompareDropScanIds)
	sequence := uint32(0)
	for {
		chunk := sorted[:min(len(sorted), settings.FileRowCount)]
		sorted = sorted[len(chunk):]
		encoded, err := EncodeDropIdFile(DropFileCand, repoId, jobId, sequence, chunk)
		if err != nil {
			return err
		}
		if err := files.Put(ctx, DropFileCand, sequence, encoded); err != nil {
			return err
		}
		sequence += 1
		if len(sorted) == 0 {
			return nil
		}
	}
}

// One ref's covered drops resolved over one scan of its history.
func (self *DropResolve) resolveRef(ctx context.Context, request *DropResolveRequest, refId sidecar.Id, drops []*DropCovered) ([]*dropResolved, int64, error) {
	head, err := dropReadHead(ctx, request.Cluster, request.RepoId, refId)
	if err != nil {
		return nil, 0, err
	}
	resolved := make([]*dropResolved, len(drops))
	for i, drop := range drops {
		resolved[i] = &dropResolved{drop: drop}
	}
	if head == nil || head.GetVersion() == 0 {
		for _, one := range resolved {
			one.mismatch = "its ref has no committed head"
		}
		return resolved, 0, nil
	}
	reader, err := newDropRefReader(ctx, request.Cluster, request.RepoId, refId, head, self.records, self.locator, self.logPages, request.Pace)
	if err != nil {
		return nil, 0, err
	}
	// each covered drop's body, from the record its own version's window entry names
	bodies := make([]*protocol.EvsDropHistory, len(drops))
	keys := map[dropLineageKey]*dropLineageEntry{}
	wantVersions := map[uint64]bool{}
	for i, drop := range drops {
		if drop.Version == 0 || head.GetVersion() < drop.Version {
			resolved[i].mismatch = fmt.Sprintf("its version %d is not on its ref's history, which ends at %d", drop.Version, head.GetVersion())
			continue
		}
		entry, _, err := reader.entryAt(drop.Version)
		if err != nil {
			return nil, reader.byteCount, err
		}
		if entry.PushId != drop.PushId || !entry.Drop() {
			resolved[i].mismatch = fmt.Sprintf("version %d is not its DROP push", drop.Version)
			continue
		}
		statement, payload, err := reader.pushAt(drop.Version, entry)
		if err != nil {
			return nil, reader.byteCount, err
		}
		if payload.Drop == nil || payload.Drop.History.GetAction() != evsDropActionDrop || !bytes.Equal(payload.Drop.History.GetDropId(), drop.DropId[:]) ||
			statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 {
			resolved[i].mismatch = fmt.Sprintf("version %d holds no drop of this id", drop.Version)
			continue
		}
		bodies[i] = payload.Drop.History
		wantVersions[drop.Version] = true
		for _, path := range bodies[i].GetPaths() {
			lineage, err := parseDropLineage(path)
			if err != nil {
				resolved[i].mismatch = fmt.Sprintf("a lineage that does not parse: %v", err)
				break
			}
			for _, lineageEntry := range lineage {
				keys[dropKeyOf(lineageEntry.epoch, lineageEntry.tokenPath)] = lineageEntry
			}
		}
	}
	history, err := scanDropRef(reader, keys, head.GetVersion(), wantVersions, request.Renew)
	if err != nil {
		return nil, reader.byteCount, err
	}
	cache := &dropMapParts{parts: map[string]*protocol.EvsPathMap{}}
	for i, one := range resolved {
		if one.mismatch != "" || bodies[i] == nil {
			continue
		}
		for pathIndex, path := range bodies[i].GetPaths() {
			verdict, err := self.judgePath(reader, history, cache, one.drop, path)
			if err != nil {
				return nil, reader.byteCount, err
			}
			if verdict.mismatch != "" {
				one.mismatch = fmt.Sprintf("path %d: %s", pathIndex, verdict.mismatch)
				if detail := self.describeMismatch(reader, one.drop, pathIndex, bodies[i], verdict.listed); detail != "" {
					one.mismatch += "; " + detail
				}
				one.listed = nil
				break
			}
			one.listed = append(one.listed, verdict.listed...)
		}
	}
	return resolved, reader.byteCount, nil
}

// One path of a covered drop judged against the ref's history: its links at the parts it names, its list exact, and
// its boundary.
func (self *DropResolve) judgePath(reader *dropRefReader, history *dropRefHistory, cache *dropMapParts, drop *DropCovered, path *protocol.EvsDropPath) (*dropPathVerdict, error) {
	verdict := &dropPathVerdict{}
	lineage, err := parseDropLineage(path)
	if err != nil {
		verdict.mismatch = fmt.Sprintf("a lineage that does not parse: %v", err)
		return verdict, nil
	}
	if len(path.GetMapParts()) != len(lineage)-1 {
		verdict.mismatch = fmt.Sprintf("%d map parts for %d older lineage entries", len(path.GetMapParts()), len(lineage)-1)
		return verdict, nil
	}
	verdict.mapParts, verdict.linked, err = self.links(reader, history, cache, lineage, path.GetMapParts())
	if err != nil {
		return nil, err
	}
	if !verdict.linked {
		verdict.mismatch = fmt.Sprintf("lineage entry %d is linked by no committed map part or tail it names", len(verdict.mapParts)+1)
		return verdict, nil
	}
	verdict.listed = dropListedSet(history, lineage, path, drop.Version)
	if !dropListMatches(verdict.listed, path) {
		verdict.mismatch = fmt.Sprintf("history lists %d versions where the DROP lists %d, or other versions", len(verdict.listed), path.GetCount())
		return verdict, nil
	}
	if why := dropBoundaryHolds(history, lineage, path, drop.Version); why != "" {
		verdict.mismatch = why
	}
	return verdict, nil
}

// "" when the path's boundary holds over the history: written, the DROP's own statement writes the lineage's newest
// token path at through_version - 1 and no earlier hit reaches through_version; removed, the newest hit before the
// DROP is a removal, of the path or a directory holding it, at through_version. Else why not.
func dropBoundaryHolds(history *dropRefHistory, lineage []*dropLineageEntry, path *protocol.EvsDropPath, dropVersion uint64) string {
	through := path.GetThroughVersion()
	all := []*dropHit{}
	for _, lineageEntry := range lineage {
		all = append(all, history.hits[dropKeyOf(lineageEntry.epoch, lineageEntry.tokenPath)]...)
	}
	slices.SortStableFunc(all, func(a *dropHit, b *dropHit) int {
		switch {
		case a.version < b.version:
			return -1
		case b.version < a.version:
			return 1
		}
		return 0
	})
	switch path.GetBoundary() {
	case evsDropBoundaryWritten:
		newestKey := dropKeyOf(lineage[0].epoch, lineage[0].tokenPath)
		writes := false
		for _, hit := range all {
			switch {
			case hit.version < dropVersion:
				if hit.entry != nil && through <= hit.entry.GetVersion() {
					return fmt.Sprintf("version %d at ref version %d is not below through_version %d", hit.entry.GetVersion(), hit.version, through)
				}
			case hit.version == dropVersion:
				if hit.key == newestKey && !hit.removal && hit.entry != nil && hit.baseEntryVersion+1 == through && hit.entry.GetVersion() == through {
					writes = true
				}
			}
		}
		if !writes {
			return fmt.Sprintf("the DROP does not write the lineage's newest token path at through_version %d", through)
		}
		return ""
	case evsDropBoundaryRemoved:
		var newest *dropHit
		lastVersion := uint64(0)
		removalVersion := uint64(0)
		for _, hit := range all {
			if dropVersion <= hit.version {
				break
			}
			newest = hit
			switch {
			case hit.entry != nil:
				lastVersion = max(lastVersion, hit.entry.GetVersion())
				removalVersion = 0
			case hit.prefix:
				// a directory's removal ends the path one past its last version (§11.7's versions row)
				removalVersion = lastVersion + 1
			default:
				removalVersion = hit.baseEntryVersion + 1
			}
		}
		if newest == nil || !newest.removal || lastVersion == 0 || removalVersion != through {
			return fmt.Sprintf("no standing removal at through_version %d precedes the DROP", through)
		}
		return ""
	}
	return fmt.Sprintf("boundary %d", path.GetBoundary())
}

// What a mismatch's page names: how many of S the DROP's section 10 lacks and how many it adds, with the first of
// each; "" when its lists cannot be read, the page then naming counts alone.
func (self *DropResolve) describeMismatch(reader *dropRefReader, drop *DropCovered, pathIndex int, body *protocol.EvsDropHistory, listed []*dropHit) string {
	lists, err := self.dropLists(reader, drop)
	if err != nil {
		return ""
	}
	offset := 0
	for i := 0; i < pathIndex; i += 1 {
		offset += int(body.GetPaths()[i].GetCount()) * sha256.Size
	}
	count := int(body.GetPaths()[pathIndex].GetCount())
	if len(lists) < offset+count*sha256.Size {
		return ""
	}
	values := map[[32]byte]bool{}
	for at := offset; at < offset+count*sha256.Size; at += sha256.Size {
		values[[32]byte(lists[at:at+sha256.Size])] = true
	}
	lacking, adding := 0, 0
	var firstLacking, firstAdding [32]byte
	inHistory := map[[32]byte]bool{}
	for _, hit := range listed {
		inHistory[hit.entrySha256] = true
		if !values[hit.entrySha256] {
			if lacking == 0 {
				firstLacking = hit.entrySha256
			}
			lacking += 1
		}
	}
	for at := offset; at < offset+count*sha256.Size; at += sha256.Size {
		value := [32]byte(lists[at : at+sha256.Size])
		if !inHistory[value] {
			if adding == 0 {
				firstAdding = value
			}
			adding += 1
		}
	}
	return fmt.Sprintf("its list lacks %d versions of history (first %x) and adds %d (first %x)", lacking, firstLacking[:8], adding, firstAdding[:8])
}

// The DROP's section 10 whole: a one-part push's from its payload, a sealed push's joined from its parts' slices.
func (self *DropResolve) dropLists(reader *dropRefReader, drop *DropCovered) ([]byte, error) {
	entry, _, err := reader.entryAt(drop.Version)
	if err != nil {
		return nil, err
	}
	record, err := ReadRecordLocated(reader.ctx, reader.records, reader.locator, reader.cluster, reader.repoId, reader.refId, entry.Place)
	if err != nil {
		return nil, err
	}
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		_, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		payload, err := sidecar.ParseEvsPayloadFormat2(payloadBytes)
		if err != nil {
			return nil, err
		}
		return payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS), nil
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		statementBytes, sealParts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			return nil, err
		}
		partBytes, err := reader.partsOf(statement, sealParts)
		if err != nil {
			return nil, err
		}
		lists := []byte{}
		for _, part := range partBytes {
			message := &protocol.EvsPushPart{}
			if err := proto.Unmarshal(part, message); err != nil {
				return nil, err
			}
			sections, err := sidecar.ParseEvsPayloadFormat2(message.GetSections())
			if err != nil {
				return nil, err
			}
			lists = append(lists, sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS)...)
		}
		return lists, nil
	}
	return nil, fmt.Errorf("%w: a DROP at a record of type %d", ErrDropJobState, record.Type)
}

// A dry run's resolve (EVSB-M10-04): see the file header.
func (self *DropResolve) Preview(ctx context.Context, request *DropPreviewResolveRequest) (*DropPreviewResolveResult, error) {
	result := &DropPreviewResolveResult{}
	if request.Cluster == nil || request.SegmentCluster == nil || request.Request == nil {
		return result, fmt.Errorf("%w: a dry run with no clusters or request", ErrDropJobState)
	}
	refId, err := sidecar.IdFromBytes(request.Request.GetRefId())
	if err != nil {
		return result, err
	}
	head, err := dropReadHead(ctx, request.Cluster, request.RepoId, refId)
	if err != nil {
		return result, err
	}
	if head == nil || head.GetVersion() == 0 {
		return result, fmt.Errorf("%w: a dry run of a ref with no committed head", ErrDropJobState)
	}
	result.SnapshotVersion = head.GetVersion()
	reader, err := newDropRefReader(ctx, request.Cluster, request.RepoId, refId, head, self.records, self.locator, self.logPages, request.Pace)
	if err != nil {
		return result, err
	}
	lineages := make([][]*dropLineageEntry, len(request.Request.GetPaths()))
	keys := map[dropLineageKey]*dropLineageEntry{}
	for i, path := range request.Request.GetPaths() {
		lineage, err := parseDropLineage(path)
		if err != nil {
			continue
		}
		lineages[i] = lineage
		for _, lineageEntry := range lineage {
			keys[dropKeyOf(lineageEntry.epoch, lineageEntry.tokenPath)] = lineageEntry
		}
	}
	history, err := scanDropRef(reader, keys, head.GetVersion(), nil, nil)
	if err != nil {
		result.ScanByteCount = reader.byteCount
		return result, err
	}
	result.VersionCount = head.GetVersion()
	cache := &dropMapParts{parts: map[string]*protocol.EvsPathMap{}}
	candidates := map[DropScanId]bool{}
	listed := map[[32]byte]bool{}
	for i, path := range request.Request.GetPaths() {
		answer := &protocol.EvsDropPreviewPath{}
		result.Paths = append(result.Paths, answer)
		lineage := lineages[i]
		if lineage == nil {
			continue
		}
		mapParts, linked, err := self.links(reader, history, cache, lineage, path.GetMapParts())
		if err != nil {
			result.ScanByteCount = reader.byteCount
			return result, err
		}
		answer.MapParts, answer.Linked = mapParts, linked
		pathListed := dropListedSet(history, lineage, path, head.GetVersion()+1)
		answer.Count = uint32(len(pathListed))
		answer.ListMatch = dropListMatches(pathListed, path)
		for _, hit := range pathListed {
			listed[hit.entrySha256] = true
			dropCandidatesOf(hit.entry, candidates)
			for _, locator := range hit.entry.GetChain() {
				if locator.GetKind() == uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE) {
					result.InlineByteCount += uint64(max(uint32(len(locator.GetInline())), locator.GetLength()))
				}
			}
		}
	}
	result.ScanByteCount = reader.byteCount
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.PreviewId, self.settings)
	if err := putDropCandFiles(ctx, files, request.RepoId, request.PreviewId, candidates, self.settings); err != nil {
		return result, err
	}
	result.Listed = listed
	return result, nil
}

// One drop a list file names.
type DropListDrop struct {
	DropId  sidecar.Id
	RefId   sidecar.Id
	Version uint64
	PushId  sidecar.Id
}

// One row of a list file: a listed version's entry hash, the drop listing it by its index in the file's drops, and
// whether its chain holds an inline record.
type DropListRow struct {
	EntrySha256 [32]byte
	Drop        uint16
	Inline      bool
}

// A list file as parsed.
type DropListFile struct {
	RepoId   sidecar.Id
	JobId    sidecar.Id
	Sequence uint32
	Drops    []*DropListDrop
	Rows     []DropListRow
	// every 128th row's entry hash, from the first
	Index [][32]byte
	Bloom []byte
}

// What a resolve's list files hold: the resolved drops, and per drop its listed versions.
type dropListInput struct {
	drop *DropListDrop
	rows []*dropHit
}

// The list files' input from what a resolve kept, drops ascending by id.
func dropListInputs(resolved []*dropResolved) []*dropListInput {
	inputs := make([]*dropListInput, 0, len(resolved))
	for _, one := range resolved {
		inputs = append(inputs, &dropListInput{
			drop: &DropListDrop{DropId: one.drop.DropId, RefId: one.drop.RefId, Version: one.drop.Version, PushId: one.drop.PushId},
			rows: one.listed,
		})
	}
	slices.SortFunc(inputs, func(a *dropListInput, b *dropListInput) int { return bytes.Compare(a.drop.DropId[:], b.drop.DropId[:]) })
	return inputs
}

// The list files of a job's resolved drops, in sequence order: every file names every drop, and its rows, ascending by
// entry hash then drop, hold at most FileRowCount. Deterministic, so a resolve run again writes equal bytes.
func EncodeDropListFiles(repoId sidecar.Id, jobId sidecar.Id, inputs []*dropListInput, settings *DropSettings) ([][]byte, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if math.MaxUint16 < len(inputs) {
		return nil, fmt.Errorf("%w: %d drops in one list file", ErrDropFileInvalid, len(inputs))
	}
	drops := make([]*DropListDrop, len(inputs))
	rows := []DropListRow{}
	for i, input := range inputs {
		drops[i] = input.drop
		for _, hit := range input.rows {
			rows = append(rows, DropListRow{EntrySha256: hit.entrySha256, Drop: uint16(i), Inline: dropEntryInline(hit.entry)})
		}
	}
	slices.SortFunc(rows, compareDropListRows)
	files := [][]byte{}
	for sequence := uint32(0); len(rows) != 0 || sequence == 0; sequence += 1 {
		chunk := rows[:min(len(rows), settings.FileRowCount)]
		rows = rows[len(chunk):]
		files = append(files, EncodeDropListFile(repoId, jobId, sequence, drops, chunk))
	}
	return files, nil
}

// Ascending by entry hash, then drop.
func compareDropListRows(a DropListRow, b DropListRow) int {
	if c := bytes.Compare(a.EntrySha256[:], b.EntrySha256[:]); c != 0 {
		return c
	}
	return int(a.Drop) - int(b.Drop)
}

// The bloom's bits for row count rows, a whole number of bytes.
func dropListBloomByteCount(rowCount int) int {
	return (rowCount*dropListBloomBitsPerRow + 7) / 8
}

// The bits a bloom of bitCount bits sets for an entry hash.
func dropListBloomBits(entrySha256 [32]byte, bitCount uint64) [dropListBloomProbeCount]uint64 {
	var bits [dropListBloomProbeCount]uint64
	a, b := binary.BigEndian.Uint64(entrySha256[0:8]), binary.BigEndian.Uint64(entrySha256[8:16])
	for i := range uint64(dropListBloomProbeCount) {
		bits[i] = (a + i*b) % bitCount
	}
	return bits
}

// One list file: its drops, its rows already sorted, their index and bloom, and its tail (see the file header).
func EncodeDropListFile(repoId sidecar.Id, jobId sidecar.Id, sequence uint32, drops []*DropListDrop, rows []DropListRow) []byte {
	encoded := encodeDropFileHeader(DropFileList, repoId, jobId, sequence, len(rows))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(drops)))
	encoded = append(encoded, 0, 0)
	for _, drop := range drops {
		encoded = append(encoded, drop.DropId[:]...)
		encoded = append(encoded, drop.RefId[:]...)
		encoded = binary.BigEndian.AppendUint64(encoded, drop.Version)
		encoded = append(encoded, drop.PushId[:]...)
	}
	for _, row := range rows {
		encoded = append(encoded, row.EntrySha256[:]...)
		encoded = binary.BigEndian.AppendUint16(encoded, row.Drop)
		flags := byte(0)
		if row.Inline {
			flags |= dropListFlagInline
		}
		encoded = append(encoded, flags)
	}
	indexOffset := len(encoded)
	for i := 0; i < len(rows); i += dropListIndexStride {
		encoded = append(encoded, rows[i].EntrySha256[:]...)
	}
	bloomOffset := len(encoded)
	bloom := make([]byte, dropListBloomByteCount(len(rows)))
	if bitCount := uint64(len(bloom) * 8); 0 < bitCount {
		for _, row := range rows {
			for _, bit := range dropListBloomBits(row.EntrySha256, bitCount) {
				bloom[bit/8] |= 1 << (bit % 8)
			}
		}
	}
	encoded = append(encoded, bloom...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(indexOffset))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(bloomOffset))
	return sealDropFile(encoded)
}

// A list file from its bytes, held to its key's repo, job and sequence, to its trailer, and to its own layout: rows
// ascending, each naming a drop the header holds, and an index and bloom of the sizes its rows give.
func DecodeDropListFile(encoded []byte, repoId sidecar.Id, jobId sidecar.Id, sequence uint32) (*DropListFile, error) {
	invalid := func(why string) error {
		return fmt.Errorf("%w: list %d: %s", ErrDropFileInvalid, sequence, why)
	}
	if len(encoded) < dropFileHeaderByteCount+4+dropListTailByteCount+dropFileTrailerByteCount {
		return nil, invalid("short")
	}
	body := encoded[:len(encoded)-dropFileTrailerByteCount]
	if trailer := sha256.Sum256(body); !bytes.Equal(trailer[:], encoded[len(body):]) {
		return nil, invalid("trailer")
	}
	if string(body[0:4]) != dropFileMagic || body[4] != dropFileFormat1 || DropFileKind(body[5]) != DropFileList || body[6] != 0 || body[7] != 0 ||
		sidecar.Id(body[8:24]) != repoId || sidecar.Id(body[24:40]) != jobId || binary.BigEndian.Uint32(body[40:44]) != sequence {
		return nil, invalid("not the file its key names")
	}
	rowCount := int(binary.BigEndian.Uint32(body[44:48]))
	file := &DropListFile{RepoId: repoId, JobId: jobId, Sequence: sequence}
	at := dropFileHeaderByteCount
	dropCount := int(binary.BigEndian.Uint16(body[at : at+2]))
	if body[at+2] != 0 || body[at+3] != 0 {
		return nil, invalid("drop header")
	}
	at += 4
	indexByteCount := (rowCount + dropListIndexStride - 1) / dropListIndexStride * sha256.Size
	bloomByteCount := dropListBloomByteCount(rowCount)
	want := at + dropCount*dropListDropByteCount + rowCount*dropListRowByteCount + indexByteCount + bloomByteCount + dropListTailByteCount
	if len(body) != want {
		return nil, invalid(fmt.Sprintf("%d bytes where its counts give %d", len(body), want))
	}
	for range dropCount {
		row := body[at : at+dropListDropByteCount]
		file.Drops = append(file.Drops, &DropListDrop{
			DropId: sidecar.Id(row[0:16]), RefId: sidecar.Id(row[16:32]), Version: binary.BigEndian.Uint64(row[32:40]), PushId: sidecar.Id(row[40:56]),
		})
		at += dropListDropByteCount
	}
	file.Rows = make([]DropListRow, 0, rowCount)
	for i := range rowCount {
		row := body[at : at+dropListRowByteCount]
		listRow := DropListRow{EntrySha256: [32]byte(row[0:32]), Drop: binary.BigEndian.Uint16(row[32:34]), Inline: row[34]&dropListFlagInline != 0}
		if dropCount <= int(listRow.Drop) || row[34]&^dropListFlagInline != 0 {
			return nil, invalid("a row's drop or flags")
		}
		if 0 < i && 0 <= compareDropListRows(file.Rows[i-1], listRow) {
			return nil, invalid("rows out of order")
		}
		file.Rows = append(file.Rows, listRow)
		at += dropListRowByteCount
	}
	indexOffset := at
	for i := 0; i < rowCount; i += dropListIndexStride {
		entrySha256 := [32]byte(body[at : at+sha256.Size])
		if entrySha256 != file.Rows[i].EntrySha256 {
			return nil, invalid("index")
		}
		file.Index = append(file.Index, entrySha256)
		at += sha256.Size
	}
	bloomOffset := at
	file.Bloom = bytes.Clone(body[at : at+bloomByteCount])
	at += bloomByteCount
	if int(binary.BigEndian.Uint32(body[at:at+4])) != indexOffset || int(binary.BigEndian.Uint32(body[at+4:at+8])) != bloomOffset {
		return nil, invalid("tail")
	}
	for _, row := range file.Rows {
		if !file.MayHold(row.EntrySha256) {
			return nil, invalid("bloom")
		}
	}
	return file, nil
}

// Whether the file's bloom may hold entrySha256: false proves no row does.
func (self *DropListFile) MayHold(entrySha256 [32]byte) bool {
	bitCount := uint64(len(self.Bloom) * 8)
	if bitCount == 0 {
		return false
	}
	for _, bit := range dropListBloomBits(entrySha256, bitCount) {
		if self.Bloom[bit/8]&(1<<(bit%8)) == 0 {
			return false
		}
	}
	return true
}

// The most bytes a list file of settings may hold.
func dropListFileMaxByteCount(settings *DropSettings) int64 {
	rows := int64(settings.FileRowCount)
	return int64(dropFileHeaderByteCount+4+dropListTailByteCount+dropFileTrailerByteCount) + (math.MaxUint16+1)*dropListDropByteCount +
		rows*dropListRowByteCount + (rows/dropListIndexStride+1)*sha256.Size + int64(dropListBloomByteCount(int(rows)))
}

// Every list file of the repo, any job's, on the segment cluster, each read whole and held to its layout.
func ReadDropListFiles(ctx context.Context, segmentCluster sidecar.BlobCluster, repoId sidecar.Id, settings *DropSettings) ([]*DropListFile, int64, error) {
	prefix := dropscanKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	files := []*DropListFile{}
	byteCount := int64(0)
	startAfter := ""
	for {
		objects, more, err := segmentCluster.List(ctx, prefix, startAfter, settings.ListLimit)
		if err != nil {
			return nil, byteCount, err
		}
		for _, object := range objects {
			rest := object.Key[len(prefix):]
			jobText, name, ok := strings.Cut(rest, "/")
			if !ok {
				continue
			}
			jobId, err := parseEvsHexId(jobText)
			if err != nil {
				continue
			}
			sequence, ok := dropFileSequence(DropFileList.String()+"-", name)
			if !ok {
				continue
			}
			reader, err := segmentCluster.Get(ctx, object.Key)
			if err != nil {
				return nil, byteCount, err
			}
			encoded, err := readAllLimited(reader, dropListFileMaxByteCount(settings))
			reader.Body.Close()
			if err != nil {
				return nil, byteCount, err
			}
			byteCount += int64(len(encoded))
			file, err := DecodeDropListFile(encoded, repoId, jobId, sequence)
			if err != nil {
				return nil, byteCount, err
			}
			files = append(files, file)
		}
		if !more || len(objects) == 0 {
			return files, byteCount, nil
		}
		startAfter = objects[len(objects)-1].Key
	}
}

// What a reindex is asked: one job's list files to write again (DESIGN-DETAILS 10.5's corrupt row).
type DropReindexRequest struct {
	Cluster        sidecar.BlobCluster
	SegmentCluster sidecar.BlobCluster
	RepoId         sidecar.Id
	JobId          sidecar.Id
	// The job's drops, as its list files name them. nil takes them from the first of the job's list files that reads
	// whole.
	Drops []*DropListDrop
	Pace  func(ctx context.Context, byteCount int64) error
}

// What a reindex did.
type DropReindexResult struct {
	// The sequences of the list files deleted and written again, and of those written where none stood.
	Rewritten []uint32
	Written   []uint32
	// Files of the job past the sequences its drops give, left as they are for the operator to look at.
	Stray         []uint32
	ScanByteCount int64
}

// The listed index of a job written again (DESIGN-DETAILS 10.5's corrupt list file row, 10.7's EVSB-M10-04 note):
// its list files computed anew from its drops' bodies and their refs' history, as resolve computes them, then each of
// the job's list files that does not read whole, or holds other bytes, deleted by a DELETE naming its LastModified and
// written again, equal bytes to what resolve wrote. A drop that no longer resolves is an error, and nothing is
// written. What sidecarctl's evs drop-reindex calls, after drop_index_corrupt pages; it deletes nothing while the
// segment cluster has not passed the settle cases.
func (self *DropResolve) Reindex(ctx context.Context, request *DropReindexRequest) (*DropReindexResult, error) {
	result := &DropReindexResult{}
	if request.Cluster == nil || request.SegmentCluster == nil {
		return result, fmt.Errorf("%w: a reindex with no clusters", ErrDropJobState)
	}
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.JobId, self.settings)
	sequences, err := files.Sequences(ctx, DropFileList)
	if err != nil {
		return result, err
	}
	readFile := func(sequence uint32) ([]byte, *sidecar.BlobInfo, error) {
		object, err := request.SegmentCluster.Get(ctx, DropFileKey(request.RepoId, request.JobId, DropFileList, sequence))
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		defer object.Body.Close()
		encoded, err := readAllLimited(object, dropListFileMaxByteCount(self.settings))
		return encoded, &object.BlobInfo, err
	}
	drops := request.Drops
	for _, sequence := range sequences {
		if drops != nil {
			break
		}
		encoded, _, err := readFile(sequence)
		if err != nil {
			return result, err
		}
		if file, err := DecodeDropListFile(encoded, request.RepoId, request.JobId, sequence); err == nil {
			drops = file.Drops
		}
	}
	if len(drops) == 0 {
		return result, fmt.Errorf("%w: no list file of job %s reads whole; name its drops", ErrDropJobState, sidecar.EvsKeyId(request.JobId))
	}
	covered := make([]*DropCovered, 0, len(drops))
	for _, drop := range drops {
		covered = append(covered, &DropCovered{DropId: drop.DropId, RefId: drop.RefId, Version: drop.Version, PushId: drop.PushId})
	}
	resolveRequest := &DropResolveRequest{Cluster: request.Cluster, SegmentCluster: request.SegmentCluster, RepoId: request.RepoId, JobId: request.JobId, Drops: covered, Pace: request.Pace}
	refDrops := map[sidecar.Id][]*DropCovered{}
	for _, drop := range covered {
		refDrops[drop.RefId] = append(refDrops[drop.RefId], drop)
	}
	resolved := []*dropResolved{}
	for refId, refCovered := range refDrops {
		refResolved, byteCount, err := self.resolveRef(ctx, resolveRequest, refId, refCovered)
		result.ScanByteCount += byteCount
		if err != nil {
			return result, err
		}
		for _, one := range refResolved {
			if one.mismatch != "" {
				return result, fmt.Errorf("%w: drop %s no longer resolves: %s", ErrDropJobState, sidecar.EvsKeyId(one.drop.DropId), one.mismatch)
			}
			resolved = append(resolved, one)
		}
	}
	listFiles, err := EncodeDropListFiles(request.RepoId, request.JobId, dropListInputs(resolved), self.settings)
	if err != nil {
		return result, err
	}
	for i, encoded := range listFiles {
		sequence := uint32(i)
		stored, info, err := readFile(sequence)
		if err != nil {
			return result, err
		}
		if stored != nil && bytes.Equal(stored, encoded) {
			continue
		}
		if stored != nil {
			if !request.SegmentCluster.SettlePassed() {
				return result, fmt.Errorf("%w: the segment cluster has not passed the settle cases", ErrDropJobState)
			}
			if err := request.SegmentCluster.Delete(sidecar.WithBlobUnmodified(ctx, info.LastModified), info.Key); err != nil {
				return result, err
			}
			result.Rewritten = append(result.Rewritten, sequence)
		} else {
			result.Written = append(result.Written, sequence)
		}
		if err := files.Put(ctx, DropFileList, sequence, encoded); err != nil {
			return result, err
		}
	}
	for _, sequence := range sequences {
		if uint32(len(listFiles)) <= sequence {
			result.Stray = append(result.Stray, sequence)
		}
	}
	return result, nil
}
