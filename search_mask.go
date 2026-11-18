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
//
// Prefix write rules (DESIGN-DETAILS 16.2.5's search row; 16.7's note for SEARCH-M10-24): a hit whose (path, version)
// the searching device ignores is masked with the rest, and as lazily. A candidate that passes scope, searchable_days
// and the erasures asks the device's prefix judge once, about its own version and every version held of its key above
// it, and newest-wins counts only the versions the device does not ignore: a breach's hit is masked, and the accepted
// version's hit shows though the breach's newer version, or its removal, is held over it. The judge answers from the
// verdicts EVS1-M6-04 already left on this device, never a read of evs, since a read a query chose would show evs what
// was searched (I-19): a head reader's read record of the path, in which effective's walk kept the accepted version and
// the newest version it ignored, every version between them ignored; and the mirror's journal of ignored events. A
// version the device holds no verdict on is not ignored: the index's rows are reproduction's to check, as every
// writer's rows are (§11.14), and opening the hit reads it through effective. A repo whose rows hold no rule set asks
// nothing, and masks nothing more.

package sidecar

import (
	"errors"
	"math"
	"slices"
)

var (
	// The table is not there to mask with: no candidate is shown without one.
	errSearchMaskNoTable = errors.New("search mask: no version table")
	// A prefix judge's answer that names no version at or above its candidate's.
	errSearchMaskPrefixAnswer = errors.New("search mask: prefix answer out of range")
)

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

// The searching device's prefix judge as the mask asks it (see the file header): once a candidate, from verdicts the
// device already holds, never a fetch. searchPrefixJudgeOf builds one over an evs client.
type searchPrefixJudgeFunc func(ask *searchPrefixAsk) (searchPrefixAnswer, error)

// One candidate as the prefix judge is asked about it.
type searchPrefixAsk struct {
	// The ref its document is on, and its path: the row's exact locator, raw names joined by /.
	refId Id
	path  string
	// The candidate's version, and the newest version a partition or the local layer holds of its key, at or above it.
	version uint64
	newest  uint64
}

// What the prefix judge holds of one candidate's versions.
type searchPrefixAnswer struct {
	// The newest version from the candidate's through newest that the device does not ignore, 0 where it ignores every
	// one. A version it holds no verdict on counts as not ignored.
	allowed uint64
	// Not shown, and read not yet searchable: the device can judge nothing of the repo (a ruled repo on a client no
	// composition enabled the rules on, whose every read is refused), or its own reads show a version of the path newer
	// than any held, which the index has not reached and under which the candidate may be a version it ignored.
	unsearchable bool
}

// Why a candidate does not count, or that it does.
type searchMaskVerdict int

const (
	// It counts.
	searchMaskCurrent searchMaskVerdict = iota + 1
	// A newer version or a tombstone of its key is held, in a partition or in this host's local layer, and the device
	// does not ignore it.
	searchMaskSuperseded
	// A ref tombstone of its ref is above its version (FS-108's ref DELETE).
	searchMaskRefDeleted
	// An ERASE names its key, or its ref's erasure set lists it at or above its version.
	searchMaskErased
	// Older than its log's searchable_days.
	searchMaskExpired
	// A base ref's document whose path the branch searched has changed or removed.
	searchMaskOverlaid
	// The device ignores its version under the repo's prefix rules, and every version held of its key above it
	// (DESIGN-DETAILS 16.2.5).
	searchMaskIgnored
	// The table holds nothing at or above its version; or a base document's path is not exact enough to probe the
	// branch's key; or, under prefix rules, the device cannot judge it, its row's path not being exact or the answer
	// unsearchable: not shown, and read not yet searchable.
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
	// The device's prefix judge over the repo, one a search (searchPrefixJudgeOf); nil where the repo's rows hold no
	// rule set, which asks nothing and masks nothing more.
	prefix searchPrefixJudgeFunc
}

// One (repo, index root)'s mask over a search's snapshot. Not safe for concurrent use: one search walks it.
type searchMask struct {
	args *searchMaskArgs
	// Ref tombstones probed, by ref id: one probe a ref a search, and a search names a few refs.
	refRecords map[[indexIdByteCount]byte]searchVersionRecord
	// Probes made, which FS-109's test holds to one a candidate and one a ref.
	probeCount int
	// Prefix judge calls made, at most one a candidate.
	prefixCallCount int
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
	refId := self.args.refId
	base := false
	if self.args.companion {
		rowRefId, err := IdFromBytes(candidate.row.refId)
		switch {
		case err != nil:
			return searchMaskOtherRef, nil
		case rowRefId == self.args.refId:
		case self.args.baseRefId != nil && rowRefId == *self.args.baseRefId:
			base = true
		default:
			return searchMaskOtherRef, nil
		}
		refId = rowRefId
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
	// the newest version held of the key, at or above the candidate's: in a partition, and over an index candidate in
	// this host's local layer
	newest := candidate.version
	if record.found {
		newest = max(newest, record.version)
	}
	if self.args.local != nil && !candidate.local {
		if version, _, ok := self.args.local(candidate.key); ok {
			newest = max(newest, version)
		}
	}
	// the newest of them that counts: under prefix rules, the newest the device does not ignore
	counted := newest
	if self.args.prefix != nil {
		answer, err := self.askPrefix(refId, candidate, newest)
		if err != nil {
			return 0, err
		}
		switch {
		case answer.unsearchable:
			return searchMaskUnknown, nil
		case answer.allowed == 0:
			return searchMaskIgnored, nil
		}
		counted = answer.allowed
	}
	if candidate.version < counted {
		return searchMaskSuperseded, nil
	}
	if candidate.local {
		// the local layer holds what the index does not cover yet: once a partition holds its version, the index's copy
		// answers and this one goes at the next swap
		if record.found && record.version == candidate.version {
			return searchMaskSuperseded, nil
		}
	} else {
		if !record.found || record.version < candidate.version {
			return searchMaskUnknown, nil
		}
		// a tombstone at the candidate's own version; one above it counted only where the device does not ignore it
		if record.version == candidate.version && record.tombstone {
			return searchMaskSuperseded, nil
		}
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

// The prefix judge's one call for a candidate on refId, newest the newest version held of its key. A row whose
// locator is not the exact path names no path to ask about, so its candidate is unsearchable with no call.
func (self *searchMask) askPrefix(refId Id, candidate *searchMaskCandidate, newest uint64) (searchPrefixAnswer, error) {
	if candidate.row.flags&indexRowInexact != 0 {
		return searchPrefixAnswer{unsearchable: true}, nil
	}
	self.prefixCallCount += 1
	answer, err := self.args.prefix(&searchPrefixAsk{refId: refId, path: candidate.row.locator, version: candidate.version, newest: newest})
	if err != nil {
		return searchPrefixAnswer{}, err
	}
	if !answer.unsearchable && answer.allowed != 0 && (answer.allowed < candidate.version || newest < answer.allowed) {
		return searchPrefixAnswer{}, errSearchMaskPrefixAnswer
	}
	return answer, nil
}

// One path of one ref, as the mirror's journal is looked up by.
type searchPrefixPathKey struct {
	refId Id
	path  string
}

// EVS1-M6-04's judge over one repo as its masks ask it (see the file header), from the verdicts this device holds and
// never a read of evs. Nil where the repo's rows hold no rule set, and on a client whose rules are dark, the launch
// default (QD-1032), whatever its rows hold. A ruled repo on a client running the rules that no composition gave a
// judge answers every candidate unsearchable, as every read of it is refused (EvsRepo.prefixRuled). Else a version is
// ignored where the head reader's record of its path holds it above the accepted version and at or below
// IgnoredThrough, or where the mirror's journal holds an ignored write, creation or removal of the path at it. The
// journal is read once, at the first ask, and held as each path's ignored versions: the events no repair has settled
// yet, which a breach's size bounds, never the partitions' keys. A record is read from the pin store's memory and
// touches nothing, so a search persists nothing of what it asked (I-13). One a search, as a mask is: not safe for
// concurrent use.
func searchPrefixJudgeOf(client *EvsClient, repoId Id) (searchPrefixJudgeFunc, error) {
	ruled, err := client.Repo(repoId).prefixRuled()
	switch {
	case errors.Is(err, ErrEvsPrefixRule):
		return func(ask *searchPrefixAsk) (searchPrefixAnswer, error) {
			return searchPrefixAnswer{unsearchable: true}, nil
		}, nil
	case err != nil:
		return nil, err
	case ruled == nil:
		return nil, nil
	}
	var journalVersions map[searchPrefixPathKey][]uint64
	return func(ask *searchPrefixAsk) (searchPrefixAnswer, error) {
		if journalVersions == nil {
			units, err := client.PrefixIgnored(&repoId)
			if err != nil {
				return searchPrefixAnswer{}, err
			}
			journalVersions = map[searchPrefixPathKey][]uint64{}
			for _, unit := range units {
				if !unit.Named || unit.Kind == EvsPrefixIgnoredNames {
					// an unnamed unit names no path, and a directory's delta no document
					continue
				}
				key := searchPrefixPathKey{refId: unit.RefId, path: unit.Path}
				journalVersions[key] = append(journalVersions[key], unit.Version)
			}
			for _, versions := range journalVersions {
				slices.Sort(versions)
			}
		}
		record, _, err := client.pins.ReadRecord(repoId, ask.refId, ask.path)
		if err != nil {
			return searchPrefixAnswer{}, err
		}
		return searchPrefixAnswerOf(record, journalVersions[searchPrefixPathKey{refId: ask.refId, path: ask.path}], ask), nil
	}, nil
}

// What a head reader's record of one path, nil for none, and the mirror's ignored versions of it, ascending, say of
// ask's versions. The record's walk ignored every version above its accepted one through IgnoredThrough, an absent
// path's accepted version being 0. An accepted version newer than any held means the index has not reached what the
// device shows; a version below it may be one the device ignored before an allowed version was written over it, which
// the record no longer says, so the candidate is unsearchable. The walk down from newest steps past the record's span
// at once and past each journal version, so it is as long as the path's journal.
func searchPrefixAnswerOf(record *EvsReadRecord, ignoredVersions []uint64, ask *searchPrefixAsk) searchPrefixAnswer {
	spanFrom, spanThrough := uint64(0), uint64(0)
	if record != nil && record.Accepted != nil {
		if !record.Accepted.Absent && ask.newest < record.Accepted.Version {
			return searchPrefixAnswer{unsearchable: true}
		}
		if record.Accepted.Version < record.IgnoredThrough {
			spanFrom, spanThrough = record.Accepted.Version, record.IgnoredThrough
		}
	}
	version := ask.newest
	for ask.version <= version && 0 < version {
		if spanFrom < version && version <= spanThrough {
			version = spanFrom
			continue
		}
		if _, found := slices.BinarySearch(ignoredVersions, version); found {
			version -= 1
			continue
		}
		return searchPrefixAnswer{allowed: version}
	}
	return searchPrefixAnswer{}
}
