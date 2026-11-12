//go:build !ios_extension

// Masks (§11.14's newest row; §16.10's merge row; D-EVS-52, D-EVS-53; FI-18; FS-108, FS-109; SEARCH-M10-24): whether
// a candidate counts. Per doc key the entry with the highest version over every partition this device holds,
// tombstones included, is current. A candidate from partition X counts only if X holds that entry, it is no tombstone,
// no ref tombstone of its ref (its row's ref_id) is above its version, and no ERASE names its key; equal versions in
// two partitions, as during a roll-up, are the same content. Keys an ERASE names stay masked in every partition until
// the rewritten files are cached, and each document the ref's erasure set lists is masked at or below its listed
// version from the CUT on, the version table holding both as erased. Entries past their log's searchable_days are
// masked (§16.8). A branch's search adds its base ref's documents for paths the branch has not changed (§11.7's
// overlays), probing the table for the branch's own key of each such path.
//
// Each candidate is answered by §5.9's version table (CORE-M10-02's SearchVersionTable.Probe), one probe a candidate
// as the ranker walks it in rank order, through the table's page cache, never by collecting a partition's keys at
// search time: FS-109 fails a build that does, and D-EVS-52 is why it must not come back, since a phone's buckets
// alone hold hundreds of thousands of keys. So a search's mask state is its pending candidates and the few refs they
// name, whatever the partitions hold. Every all row being older than each bucket entry of its key (the roll-up keeps
// one row), a device keeping only the buckets masks exactly too.
//
// The local layer (SEARCH-M10-25) joins newest-wins: a version this host indexed from its own text past what the
// index covers supersedes the index's older entries, and is itself superseded once the index holds it or newer. The
// table must cover every file of the snapshot it was built with; a candidate above anything it holds says the two
// disagree, and is not shown, so coverage reads that document not yet searchable rather than no match.

package sidecar

import (
	"errors"
	"math"
)

// The table is not there to mask with: no candidate is shown without one.
var errSearchMaskNoTable = errors.New("search mask: no version table")

// One key's record in §5.9's version table at a search's snapshot.
type searchVersionRecord struct {
	// Some partition this device keeps holds the key.
	found bool
	// The highest version any of them holds, and whether that entry is a tombstone. A ref id's record is its ref
	// tombstone's (ur/index).
	version   uint64
	tombstone bool
	// Versions at or below this are erased: the ref's erasure set lists the document at it, from its CUT on, or, at
	// searchErasedAll, an ERASE names the key until the rewritten files are cached. 0 masks none.
	erasedThrough uint64
}

// An ERASE's mask: every version of the key.
const searchErasedAll uint64 = math.MaxUint64

// The version table as the mask reads it: one key, a doc_key or a ref_id, through the table's page cache at the
// search's snapshot (CORE-M10-02's SearchVersionTable.Probe).
type searchVersionProbe func(key [indexIdByteCount]byte) (searchVersionRecord, error)

// The local layer's newest entry of a key, a tombstone included: SearchLocalLayer.newest.
type searchLocalNewestFunc func(key [indexIdByteCount]byte) (version uint64, tombstone bool, ok bool)

// Why a candidate does not count, or that it does.
type searchMaskVerdict int

const (
	// It counts.
	searchMaskCurrent searchMaskVerdict = iota + 1
	// A newer version or a tombstone of its key is held, in a partition or in this host's local layer.
	searchMaskSuperseded
	// A ref tombstone of its ref is above its version (FS-108's ref DELETE).
	searchMaskRefDeleted
	// An ERASE names its key, or its ref's erasure set lists it at or above its version.
	searchMaskErased
	// Older than its log's searchable_days.
	searchMaskExpired
	// A base ref's document whose path the branch searched has changed or removed.
	searchMaskOverlaid
	// The table holds nothing at or above its version, or a base document's path is not exact enough to probe the
	// branch's key: not shown, and read not yet searchable.
	searchMaskUnknown
	// A ur/index row of a ref this search does not read: out of scope, not counted as masked.
	searchMaskOtherRef
)

// Whether the verdict is a mask §16.10's counts report, rather than a document out of scope.
func (self searchMaskVerdict) masked() bool {
	return self != searchMaskCurrent && self != searchMaskOtherRef
}

// What one (repo, index root)'s mask reads.
type searchMaskArgs struct {
	probe searchVersionProbe
	// ur/index, whose rows carry their ref_id: refId is the ref searched, and baseRefId, when set, the base of the
	// branch searched. An in-ref index's rows carry none, every row being its own ref's.
	companion bool
	refId     Id
	baseRefId *Id
	// The branch's own key of a base row's document, from K_ref, the row's locator and its chunk; false where the
	// locator is not the exact path.
	branchKey func(row *indexRow) ([indexIdByteCount]byte, bool)
	// The local layer, nil where this host keeps none.
	local searchLocalNewestFunc
	// §16.8's searchable_days as a time: entries before it are masked. 0 masks none.
	searchableSinceSeconds uint64
}

// One (repo, index root)'s mask over a search's snapshot. Not safe for concurrent use: one search walks it.
type searchMask struct {
	args *searchMaskArgs
	// Ref tombstones probed, by ref id: one probe a ref a search, and a search names a few refs.
	refRecords map[[indexIdByteCount]byte]searchVersionRecord
	// Probes made, which FS-109's test holds to one a candidate and one a ref.
	probeCount int
}

// A mask over args, refusing one with no table.
func newSearchMask(args *searchMaskArgs) (*searchMask, error) {
	if args == nil || args.probe == nil {
		return nil, errSearchMaskNoTable
	}
	return &searchMask{args: args, refRecords: map[[indexIdByteCount]byte]searchVersionRecord{}}, nil
}

// One candidate as the mask reads it.
type searchMaskCandidate struct {
	key         [indexIdByteCount]byte
	version     uint64
	timeSeconds uint64
	row         *indexRow
	// From this host's local layer rather than an index file.
	local bool
}

// Whether the candidate counts, and if not why.
func (self *searchMask) judge(candidate *searchMaskCandidate) (searchMaskVerdict, error) {
	base := false
	if self.args.companion {
		refId, err := IdFromBytes(candidate.row.refId)
		switch {
		case err != nil:
			return searchMaskOtherRef, nil
		case refId == self.args.refId:
		case self.args.baseRefId != nil && refId == *self.args.baseRefId:
			base = true
		default:
			return searchMaskOtherRef, nil
		}
	}
	if candidate.timeSeconds < self.args.searchableSinceSeconds {
		return searchMaskExpired, nil
	}

	record, err := self.probe(candidate.key)
	if err != nil {
		return 0, err
	}
	if candidate.version <= record.erasedThrough {
		return searchMaskErased, nil
	}
	if self.args.local != nil && !candidate.local {
		if version, _, ok := self.args.local(candidate.key); ok && candidate.version < version {
			return searchMaskSuperseded, nil
		}
	}
	switch {
	case candidate.local:
		// The local layer holds what the index does not cover yet: once a partition holds its version or newer, the
		// index's copy answers and this one goes at the next swap.
		if record.found && candidate.version <= record.version {
			return searchMaskSuperseded, nil
		}
	case !record.found || record.version < candidate.version:
		return searchMaskUnknown, nil
	case candidate.version < record.version || record.tombstone:
		return searchMaskSuperseded, nil
	}

	if self.args.companion {
		refRecord, err := self.refRecord(candidate.row.refId)
		if err != nil {
			return 0, err
		}
		if refRecord.found && refRecord.tombstone && candidate.version < refRecord.version {
			return searchMaskRefDeleted, nil
		}
	}
	if base {
		if self.args.branchKey == nil {
			return searchMaskUnknown, nil
		}
		branchKey, ok := self.args.branchKey(candidate.row)
		if !ok {
			return searchMaskUnknown, nil
		}
		branchRecord, err := self.probe(branchKey)
		if err != nil {
			return 0, err
		}
		if branchRecord.found || 0 < branchRecord.erasedThrough {
			return searchMaskOverlaid, nil
		}
		if self.args.local != nil {
			if _, _, ok := self.args.local(branchKey); ok {
				return searchMaskOverlaid, nil
			}
		}
	}
	return searchMaskCurrent, nil
}

// One probe, counted.
func (self *searchMask) probe(key [indexIdByteCount]byte) (searchVersionRecord, error) {
	self.probeCount += 1
	return self.args.probe(key)
}

// A ref's tombstone record, probed once a search.
func (self *searchMask) refRecord(refIdBytes []byte) (searchVersionRecord, error) {
	refKey := [indexIdByteCount]byte(refIdBytes)
	if record, ok := self.refRecords[refKey]; ok {
		return record, nil
	}
	record, err := self.probe(refKey)
	if err != nil {
		return searchVersionRecord{}, err
	}
	self.refRecords[refKey] = record
	return record, nil
}
