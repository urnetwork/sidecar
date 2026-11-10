// Removal markers (§11.7's removal and collect rows; owner decision 148): a fold never deletes a current-epoch entry,
// only, while sources stand, the source copies a current entry supersedes (fold_sources.go). A removal at r gives
// its path a marker {removing push id, r, the path's version, one past its last} (fold.go), then gives every
// current-epoch entry below the path, which a LIST finds, a marker of its own: by PUT If-Match on the entry read, only
// while that entry holds a version older than r, a marker staying as it is, and on a 412 read again. The path's own
// marker goes first (writeRange), so while sources stand no read or copy falls back to a source at or below it. A
// path the fold changes itself takes its marker from its own events, the LIST passing it by, and a path that was a
// file just before its removal has nothing below it to LIST.
//
// A marker leaves only at a collection window (EVSB-M2-14): once folded_through passes r by a base range, taskworker
// opens a window by a head CAS {through, until_ms}, waits out every fold write planned on an older head (the stale
// rule), and deletes the markers at or below through. So a fold that read a head whose window is open writes over
// none of them until FoldCollectMargin (150 ms) past until_ms by its own clock, and none at all on an unsure clock; a
// 404 needs no wait, a window deleting a key once.
//
// Carried ids (a versionless file's kind-5 segments and slots; D-EVS-40): a marker written below a removed directory,
// by this LIST or by a planned path's own merge, over a versionless file the removing push did not list carries
// that file's newest version's ids, with an alarm, for its collection to delete (fold_format2.go). Format 1 has no
// versionless file, so its markers carry none, and a marker read with them keeps them.

package evsservice

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Holds a write over the marker read holds while the head the fold relies on has a collection window covering it:
// until FoldCollectMargin past until_ms by this process's clock, after which it answers waited, so the caller reads
// the head and the entry again. A page-out's fold never waits, and no fold writes on an unsure clock: both answer
// ErrEvsFoldDeferred.
func (self *foldRun) waitOverMarker(read *EvsEntryRead) (bool, error) {
	marker := read.Entry.GetMarker()
	collect := self.head.Head.GetCollect()
	if marker == nil || collect.GetUntilMs() == 0 || collect.GetThrough() < marker.GetRemovalVersion() {
		return false, nil
	}
	if !self.folder.clockSure() {
		return false, fmt.Errorf("%w: an unsure clock writes over no marker a collection window covers", ErrEvsFoldDeferred)
	}
	writableAt := time.UnixMilli(collect.GetUntilMs()).Add(self.folder.settings.FoldCollectMargin)
	now := self.folder.clock.Now()
	if !now.Before(writableAt) {
		return false, nil
	}
	if self.request.NoWait {
		return false, fmt.Errorf("%w: a collection window covers the marker", ErrEvsFoldDeferred)
	}
	select {
	case <-self.folder.clock.After(writableAt.Sub(now)):
	case <-self.ctx.Done():
		return false, self.ctx.Err()
	}
	// the head this fold relies on is older than the window now: the next write reads it again
	self.staleDeadline = time.Time{}
	return true, nil
}

// The markers of removal on every current-epoch entry below its path, page by page of a LIST, the paths the fold
// plans itself passed by.
func (self *foldRun) markBelow(removal *foldRemoval) error {
	epochPrefix := IndexEpochPrefix(self.request.RepoId, self.request.RefId, self.epoch)
	keyPrefix := IndexChildrenPrefix(self.request.RepoId, self.request.RefId, self.epoch, removal.tokenPath)
	startAfter := ""
	for {
		if err := self.ready(); err != nil {
			return err
		}
		testHookBarrier(BarrierFoldListBefore, self.barrierKey)
		objects, more, err := self.cluster.List(self.ctx, keyPrefix, startAfter, self.folder.settings.FoldListPageCount)
		testHookBarrier(BarrierFoldListAfter, self.barrierKey)
		if err != nil {
			return err
		}
		for _, object := range objects {
			startAfter = object.Key
			if !strings.HasSuffix(object.Key, indexEntryKeySuffix) {
				continue
			}
			tokenPath, err := IndexEntryTokenPath(epochPrefix, object.Key)
			if err != nil {
				self.folder.log.Errorf("[evs] alarm index_key: a key below a removed path names no entry: %v", err)
				continue
			}
			if _, planned := self.paths[string(tokenPath.Bytes())]; planned {
				continue
			}
			if err := self.markEntry(tokenPath, removal); err != nil {
				return err
			}
		}
		if !more || len(objects) == 0 {
			return nil
		}
	}
}

// One entry below a removed path: its marker, while it holds a version older than the removal; nothing for an entry
// gone, already holding the removal or something newer, or holding a marker of its own.
func (self *foldRun) markEntry(tokenPath sidecar.EvsTokenPath, removal *foldRemoval) error {
	for attempt := 0; attempt < self.folder.settings.FoldEntryRetryCount; attempt += 1 {
		if err := self.ready(); err != nil {
			return err
		}
		read, err := ReadEntry(self.ctx, self.cluster, self.request.RepoId, self.request.RefId, self.epoch, tokenPath, self.head.Head.GetFoldedThrough())
		if err != nil {
			return err
		}
		if read.Absent() || removal.commitVersion <= evsIndexEntryNewestCommit(read.Entry) {
			return nil
		}
		standing, ok := evsIndexEntryStanding(read.Entry, 0)
		if !ok {
			return nil
		}
		marked := proto.Clone(read.Entry).(*protocol.EvsIndexEntry)
		marked.Marker = &protocol.EvsRemovalMarker{
			PushId:         removal.pushId.Bytes(),
			RemovalVersion: removal.commitVersion,
			PathVersion:    standing + 1,
			LeafPart:       removal.leaf.part,
			LeafIndex:      removal.leaf.index,
		}
		// no change of the range names the path, the removing push's included: a versionless file here is one that
		// push did not list (fold_format2.go)
		carryUnlistedIds(marked.Marker, read.Entry, self.folder.log, "a removed directory's LIST")
		state := EvsEntryStateValue{}
		if self.sources {
			state = EvsEntryStateValue{State: EvsEntryStateRemoved}
		}
		err = self.put(tokenPath, read, marked, state)
		if retryEntryWrite(err) {
			continue
		}
		if err != nil {
			return err
		}
		self.result.EntryWriteCount += 1
		self.result.MarkerWriteCount += 1
		return nil
	}
	return fmt.Errorf("%w: %d tries on one entry below a removal", ErrEvsFoldBusy, self.folder.settings.FoldEntryRetryCount)
}
