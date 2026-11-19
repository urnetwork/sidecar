// FI-19, index erasure (§22.8; §11.14's erase and cut rows; I-EVS-13, I-EVS-17; TEST-M10-02), over each index source's
// replay (fi_search.go) and the searches its devices ran:
//
//	the CUT     an erasure is the erasure set's (.ur-index/x, or x on ur/index) from the push that first lists it, its
//	            CUT; from the next push on, no push writes a file holding a listed document's postings or display fields
//	            at or below its listed version, whatever index pushes were prepared before the CUT, delayed, resealed or
//	            retried: a CLOSURE's clean takes the listed entries out (protocol/INDEX-FORMAT.md's Erasure), and with
//	            full entries only no CLOSURE has a reason to keep one (QD-1036)
//	completion  once the erasure set stops listing an erasure, which drops only complete ones, or a schedule records it
//	            complete (SearchRecord.CompleteErasure), no file at the head holds a listed document's postings or display
//	            fields at or below its version
//	searches    a device whose sync reached the CUT's ref version returns no listed document at or below its version from
//	            a search
//
// Readings and gaps, each in TEST-M10-02's report: a source's files are what current keys open, so "every stored
// version that held them shares a key its ERASEs destroyed", the CLOSURE's re-keying and the ERASE's key destruction are
// read on evs's store by FI-1's slot clause, not here; "finishes from evs's state on a device that may erase it" is the
// eraser's resume (SEARCH-M10-17), which a schedule shows by recording the completion; a cache's return of an erased
// document is read through the device's searches alone.

package fault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
)

var _ = RegisterInvariant(19, func(ctx context.Context, oracle *Oracle) error {
	return checkFi19(ctx, oracle)
})

func checkFi19(ctx context.Context, oracle *Oracle) error {
	errs := []error{}
	record := SearchRecordOf(oracle.Net)
	replays := searchReplaysOf(ctx, oracle)
	_, searches, _, _ := record.snapshot()
	for _, replay := range replays {
		if replay.readErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", replay.name, replay.readErr))
			continue
		}
		errs = append(errs, replay.fi19Findings...)
		for _, run := range searches {
			synced, ok := run.SyncedVersions[replay.name]
			if !ok {
				continue
			}
			for _, id := range slices.Sorted(maps.Keys(replay.erasures)) {
				erasure := replay.erasures[id]
				if synced < erasure.cutVersion {
					continue
				}
				for index := range run.Hits {
					found := &run.Hits[index]
					if listed, ok := erasure.docs[found.DocKey]; ok && found.Version <= listed {
						errs = append(errs, fmt.Errorf("%s, synced through %s's ref version %d, returned %s at %d, which erasure %s's CUT at %d listed through %d",
							run.Label, replay.name, synced, found.Path, found.Version, id, erasure.cutVersion, listed))
					}
				}
			}
		}
	}
	return errors.Join(errs...)
}

// FI-19's clauses on one push, after the replay's head moved to it: written is what it wrote, nil where a file did not
// decode. A complete erasure is held at the head once, at the first push that finds it complete.
func (self *searchReplay) fi19Apply(push *SearchIndexPush, written map[string]*oracleIndexFile, completed map[string]bool) {
	ids := slices.Sorted(maps.Keys(self.erasures))
	for _, path := range slices.Sorted(maps.Keys(written)) {
		file := written[path]
		if file == nil {
			continue
		}
		for _, entry := range file.keyedEntries() {
			if !entry.live() {
				continue
			}
			for _, id := range ids {
				erasure := self.erasures[id]
				if listed, ok := erasure.docs[entry.key]; ok && erasure.cutVersion < push.RefVersion && entry.version <= listed {
					self.fi19Findings = append(self.fi19Findings, fmt.Errorf("%s: ref version %d writes %s holding doc_key %x at %d, which erasure %s's CUT at %d listed through %d",
						self.name, push.RefVersion, path, entry.key, entry.version, id, erasure.cutVersion, listed))
				}
			}
		}
	}
	setWritten := false
	for _, path := range slices.Sorted(maps.Keys(written)) {
		file := written[path]
		if file == nil || file.path.kind != oracleIndexPathErasureSet {
			continue
		}
		setWritten = true
		listed := map[string]bool{}
		for _, erasure := range file.erasureSet.Erasures {
			id := hex.EncodeToString(erasure.ErasureId)
			listed[id] = true
			seen := self.erasures[id]
			if seen == nil {
				seen = &searchErasureSeen{id: id, cutVersion: push.RefVersion, docs: map[[16]byte]uint64{}}
				self.erasures[id] = seen
			}
			for _, doc := range erasure.Docs {
				var key [16]byte
				copy(key[:], doc.DocKey)
				seen.docs[key] = max(seen.docs[key], doc.Version)
				self.erased[key] = max(self.erased[key], doc.Version)
			}
		}
		for id, seen := range self.erasures {
			if !listed[id] {
				seen.dropped = true
			}
		}
	}
	if !setWritten {
		for _, removed := range push.Removed {
			if parsed, ok := oracleIndexParsePath(removed, DefaultOracleIndexFormatSettings()); ok && parsed.kind == oracleIndexPathErasureSet {
				for _, seen := range self.erasures {
					seen.dropped = true
				}
			}
		}
	}
	for _, id := range slices.Sorted(maps.Keys(self.erasures)) {
		erasure := self.erasures[id]
		if erasure.completionChecked || (!erasure.dropped && !completed[id]) {
			continue
		}
		erasure.completionChecked = true
		for rootKey, paths := range self.keyPaths {
			listed, ok := erasure.docs[rootKey.key]
			if !ok {
				continue
			}
			for _, path := range slices.Sorted(maps.Keys(paths)) {
				file := self.files[path]
				if file == nil {
					continue
				}
				for _, entry := range file.keyedEntries() {
					if entry.key == rootKey.key && entry.live() && entry.version <= listed {
						self.fi19Findings = append(self.fi19Findings, fmt.Errorf("%s: after ref version %d, erasure %s is complete and %s still holds doc_key %x at %d",
							self.name, push.RefVersion, id, path, entry.key, entry.version))
					}
				}
			}
		}
	}
}
