// `collected` on the read route (§11.7's reads and history rows, §11.9's collected row; R-EVS-8, D-EVS-38, I-EVS-1,
// I-EVS-4, FI-16, FS-64, FS-66; EVS2-M10-08), by the time rule the owner decided (plan-EVS2-small-readings#5, QD-219).
//
// Head reads are unchanged: a path's newest version has its content (I-EVS-1), and this file never marks one. A read
// that names an older version by number answers that version's signed entry version, its statement and its proof as
// before; when the version is versionless (versioning 1 or 2) and replaced, it also answers `collected` from
//
//	T = the end of the UTC minute in the replacing record's EvsPlace + ReadCollectedAfter (60 s)
//
// by this process's checked clock, whether or not the version's bytes remain: staged in a batch that evacuation has
// not reached, kept by purge: observe, or kept by a hold. Before T the version reads as any older version does, so a
// reader paused mid-read still finds its content for at least ReadCollectedAfter after the replacement commits, and
// at most a minute more. The rule never reads time_ms, which may trail a commit by 10 minutes.
//
// The replacing record is the one that committed the path's next version or its removal. evs finds it among the
// entry's folded versions and marker, then among the window's changes of the path after the version's own commit;
// where neither holds the next version itself (a version below the entry's four, asked for by its commit_version),
// the oldest newer version evs holds stands in, whose minute is no earlier, so the answer errs towards serving.
// Nothing above the head being served is read for it.
//
// A process whose clock §19.6 finds unsure cannot tell either side of T, so the read answers 503, as a route that
// may CAS does.
//
// A raw range read names a segment, not a version, so it takes no part in this rule: purged content answers missing
// there and the reader decides (read_frame.go). A reader with a stale cached head can name a replaced version as the
// newest; its own fresh reread settles that, and evs raises nothing.

package evsservice

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A read that must place the clock against a version's T while the clock is unsure.
var errReadClockUnsure = errors.New("evs: clock unsure for a collected verdict")

// From when a version replaced by the record at place reads `collected`: the end of the place's UTC minute plus after.
func collectedFrom(place *protocol.EvsPlace, after time.Duration) time.Time {
	return time.Unix((int64(place.GetMinute())+1)*60, 0).UTC().Add(after)
}

// The place of the record that committed version, a seal's for a push in parts: its window entry's, else its log
// page's entry's.
func (self *readPushes) placeAt(version uint64) (*protocol.EvsPlace, error) {
	if push, ok := self.pushes[version]; ok {
		return push.entry.Place, nil
	}
	if entry := windowEntryAt(self.head, version); entry != nil {
		return entry.Place, nil
	}
	push, err := self.at(version)
	if err != nil {
		return nil, err
	}
	return push.entry.Place, nil
}

// The ref version that committed the replacement of the path's version pathVersion, which committed at
// commitVersion: see the file header. false for a version nothing replaced.
func (self *readAttempt) replacingCommit(path *readPath, pathVersion uint64, commitVersion uint64) (uint64, bool, error) {
	head := self.head.Head
	// the nearest newer version among what the entry folded
	nearest, nearestCommit := uint64(0), uint64(0)
	note := func(version uint64, commit uint64) {
		if pathVersion < version && commit <= head.GetVersion() && (nearest == 0 || version < nearest) {
			nearest, nearestCommit = version, commit
		}
	}
	if entry := path.read.Entry; entry != nil {
		for _, folded := range entry.GetVersions() {
			entryVersion, err := parseEvsEntryVersion(folded.GetEntryVersion())
			if err != nil {
				continue
			}
			note(entryVersion.GetVersion(), folded.GetCommitVersion())
		}
		if marker := entry.GetMarker(); marker != nil {
			note(marker.GetPathVersion(), marker.GetRemovalVersion())
		}
	}
	if nearest != 0 {
		return nearestCommit, true, nil
	}
	// the window's first change of the path after the version's own commit
	tokenPath := path.tokens.Current
	first := max(EvsHeadWindowFirstVersion(head), path.read.FoldedThrough+1, commitVersion+1)
	for version := first; version <= head.GetVersion(); version += 1 {
		entry := windowEntryAt(head, version)
		if entry == nil || !entry.PathsDigest.MayChange(tokenPath) {
			continue
		}
		push, err := self.pushes.at(version)
		if err != nil {
			return 0, false, err
		}
		change, _, _, err := self.pushes.changeOf(push, tokenPath)
		if err != nil {
			return 0, false, err
		}
		if change == nil {
			continue
		}
		if !change.WritesEntry() {
			return version, true, nil
		}
		if entryVersion, err := parseEvsEntryVersion(change.EntryVersion); err == nil && pathVersion < entryVersion.GetVersion() {
			return version, true, nil
		}
	}
	// what the newest rule found: a prefix's removal, or a newer version the scan could not place
	if newest := path.newest; newest != nil && newest.CommitVersion <= head.GetVersion() {
		switch {
		case newest.Exists && !newest.Directory && pathVersion < newest.Version:
			return newest.CommitVersion, true, nil
		case !newest.Exists && pathVersion < newest.RemovalVersion:
			return newest.CommitVersion, true, nil
		}
	}
	return 0, false, nil
}

// Marks reply `collected` when the older version it serves is a replaced versionless one past its T: see the file
// header. The version's entry version, statement and proof stay as served.
func (self *readAttempt) answerCollected(path *readPath, reply *protocol.EvsReadPathReply) error {
	served := reply.GetVersion()
	if served == nil {
		return nil
	}
	entryVersion, err := parseEvsEntryVersion(served.GetEntryVersion())
	if err != nil || entryVersion.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		// a kept version's content is never collected; bytes that do not parse are served as stored, for the reader
		// to refuse
		return nil
	}
	replacedAt, replaced, err := self.replacingCommit(path, entryVersion.GetVersion(), served.GetCommitVersion())
	if err != nil || !replaced {
		return err
	}
	place, err := self.pushes.placeAt(replacedAt)
	if err != nil {
		return err
	}
	if !self.engine.clockSure() {
		return errReadClockUnsure
	}
	testHookBarrier(BarrierReadCollected, barrierRefKey(self.repoId, self.refId))
	if !self.engine.clock.Now().Before(collectedFrom(place, self.settings.ReadCollectedAfter)) {
		reply.State = protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED
	}
	return nil
}

// Whether reply serves a version evs answered `collected`.
func readReplyCollected(reply *protocol.EvsReadPathReply) bool {
	return reply.GetState() == protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED
}

// The staged segments the version reply serves names, each a kind-5 locator its own push staged (D-EVS-36).
func readReplyStagedIds(reply *protocol.EvsReadPathReply) [][sha256.Size]byte {
	served := reply.GetVersion()
	if served == nil {
		return nil
	}
	entryVersion, err := parseEvsEntryVersion(served.GetEntryVersion())
	if err != nil {
		return nil
	}
	ids := [][sha256.Size]byte{}
	for _, locator := range entryVersion.GetChain() {
		if locator.GetStaged() && protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT &&
			len(locator.GetId()) == sha256.Size {
			ids = append(ids, [sha256.Size]byte(locator.GetId()))
		}
	}
	return ids
}
