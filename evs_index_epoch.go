//go:build !ios_extension

// The epoch guard (§11.14's epoch row; §11.12's cut row; I-EVS-17; FS-111; SEARCH-M10-16): the rule every index push
// builder but a CLOSURE shares, so no push built before an erasure's CUT publishes what that CUT lists.
//
//	name     every push but a CLOSURE that creates or replaces an index file version (a head, slot, large entry,
//	         shard, manifest, lock or the erasure set) names the index_epoch of the head its view was read at, so evs
//	         refuses it 409 INDEX_EPOCH once a CUT has moved the epoch since (evs's step 5d); a CUT names it too, and
//	         evs moves the epoch to the CUT's own version
//	write    no file a push writes holds an entry, posting, row or tombstone of a document the ref's erasure set lists
//	         at or below its listed version; the builders leave those documents out themselves, from the view, and
//	         the guard checks each file before it is sent, so a builder that did not is refused here rather than at a
//	         reader
//	rebuild  on 409 INDEX_EPOCH a builder reads the head and the set again, drops the listed documents from its pending
//	         entries and inputs and builds again under a new push id (each builder's loop, as on a 409 for a path);
//	         work begun at an epoch below the set's listed_since cannot tell which complete erasures the set has since
//	         dropped, so it is rebuilt from content at the head, which an erased document's destroyed keys no longer
//	         open, or left to backfill: a journal's units begun there lose their key sets (rebuildJournal), which the
//	         companion then extracts again from the text or drops
//
// Every entry is full or a tombstone (owner decision 584), so no surviving version rests on a listed one and the rule
// is per entry. Hints only speed this: the guard reads the set of the view, so a lost hint publishes nothing, and no
// indexer takes part.
//
// Off the ios_extension leg, as every index builder is. Not safe for concurrent use: one build holds one guard.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A push would publish what the erasure set lists: a builder's bug, never sent.
	errIndexEpochListed = errors.New("index push holds a document the erasure set lists")
	// A CLOSURE names no epoch and goes through the eraser, never through the guard.
	errIndexEpochClosure = errors.New("index CLOSURE built through the epoch guard")
	// Only a CUT writes the erasure set (§11.12's cut row).
	errIndexEpochErasureSet = errors.New("index push other than a CUT writes the erasure set")
)

// The rule one build holds to, read from the view its push is built at.
type indexEpochGuard struct {
	view *indexView
	// L(k): the highest version at which the set lists each doc_key.
	listed      map[[indexIdByteCount]byte]uint64
	listedSince uint64
}

// The guard of a build at view. A set that was written and does not read, or that no one who may erase signed, leaves
// no builder knowing what it may not write: errIndexErasureSetUnreadable, and nothing is written (fail closed).
func indexNewEpochGuard(view *indexView) (*indexEpochGuard, error) {
	if view.erasureSetUnreadable {
		return nil, errIndexErasureSetUnreadable
	}
	guard := &indexEpochGuard{view: view, listed: indexErasureSetListed(view.erasureSet)}
	if view.erasureSet != nil {
		guard.listedSince = view.erasureSet.ListedSince
	}
	return guard, nil
}

// L(k) of every doc_key a set lists: its highest listed version over the set's erasures.
func indexErasureSetListed(erasureSet *protocol.IndexErasureSet) map[[indexIdByteCount]byte]uint64 {
	listed := map[[indexIdByteCount]byte]uint64{}
	if erasureSet == nil {
		return listed
	}
	for _, erasure := range erasureSet.Erasures {
		for _, erased := range erasure.Docs {
			if len(erased.DocKey) != indexIdByteCount {
				continue
			}
			key := [indexIdByteCount]byte(erased.DocKey)
			listed[key] = max(listed[key], erased.Version)
		}
	}
	return listed
}

// The epoch the build's push names: the head's, as the view read it.
func (self *indexEpochGuard) epoch() uint64 {
	return self.view.head.indexEpoch
}

// Whether the set lists key at or above version.
func (self *indexEpochGuard) erased(key [indexIdByteCount]byte, version uint64) bool {
	listed, ok := self.listed[key]
	return ok && version <= listed
}

// Whether work begun at begunEpoch began below the set's listed_since: the set may since have dropped a complete
// erasure that work could still hold, so it is rebuilt from content or dropped to backfill.
func (self *indexEpochGuard) stale(begunEpoch uint64) bool {
	return begunEpoch < self.listedSince
}

// The push of files and removals a build sends: a fresh push id, the view's base and epoch, its signed time, each file
// checked against the set first. A CLOSURE is refused: it names no epoch.
func (self *indexEpochGuard) push(kind indexPushKind, signedTimeMs int64, files []*indexPushFile, removals []*indexPushRemoval) (*indexPush, error) {
	if kind == indexPushClosure {
		return nil, errIndexEpochClosure
	}
	if err := self.checkFiles(files, kind == indexPushCut); err != nil {
		return nil, err
	}
	return &indexPush{
		pushId:       NewId(),
		kind:         kind,
		baseVersion:  self.view.head.version,
		indexEpoch:   self.view.head.indexEpoch,
		signedTimeMs: signedTimeMs,
		files:        files,
		removals:     removals,
	}, nil
}

// Refuses a file the push may not write: the erasure set from any push but a CUT, and any slot, large entry or shard
// holding a listed document at or below its listed version. Manifests, the lock and the settings hold no document.
func (self *indexEpochGuard) checkFiles(files []*indexPushFile, cut bool) error {
	companion := self.view.companion
	settings := self.view.settings
	for _, file := range files {
		parsed, ok := indexParsePath(file.path, companion)
		if !ok {
			return fmt.Errorf("%w: a file outside the index", errIndexEpochListed)
		}
		switch parsed.kind {
		case indexPathErasureSet:
			if !cut {
				return errIndexEpochErasureSet
			}
		case indexPathSlot, indexPathLargeEntry:
			sum := sha256.Sum256(file.plaintext)
			slot, err := indexDecodeSlot(file.plaintext, sum[:], companion, settings)
			if err != nil {
				return err
			}
			for _, entry := range slot.entries {
				if entry.kind == indexEntryRefTombstone {
					continue
				}
				if self.erased(entry.key, entry.version) {
					return errIndexEpochListed
				}
			}
		case indexPathBucketShard, indexPathAllShard:
			if len(self.listed) == 0 {
				continue
			}
			reader, err := indexOpenShard(indexBytesFrames(file.plaintext), companion)
			if err != nil {
				return err
			}
			listed := false
			err = reader.walk(indexShardVisitor{
				document: func(docId uint32, document *indexShardDocument) error {
					listed = listed || self.erased(document.key, document.version)
					return nil
				},
				tombstone: func(tombstone *indexShardTombstone) error {
					listed = listed || tombstone.kind == indexEntryTombstone && self.erased(tombstone.key, tombstone.version)
					return nil
				},
			})
			if err != nil {
				return err
			}
			if listed {
				return errIndexEpochListed
			}
		}
	}
	return nil
}

// Strips the key sets of every journal unit begun below the set's listed_since, so the companion extracts each again
// from the text at its pin, where an erased document's destroyed keys no longer open, or drops it to backfill (§11.14's
// epoch row). Then the journal takes the head's epoch as what it has seen, which units journaled from now are begun at.
func (self *indexEpochGuard) rebuildJournal(journal *IndexJournal) (int, error) {
	stripped, err := journal.stripBelow(self.listedSince)
	if err != nil {
		return stripped, err
	}
	return stripped, journal.observe(self.epoch())
}
