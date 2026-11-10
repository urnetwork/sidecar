// The fold's source deletes (DESIGN-DETAILS 9.2.6's "the fold deletes what it supersedes"; §11.7's epochs row;
// question details-9-fold-deletes-sources, option 1): while the head lists source epochs, a path's entry lives in
// exactly one of the listed epochs, so a source holds only what still has to move and the copy for the newest map
// and its tail always drains.
//
//	path       once a path's current-epoch entry holds its changes in the fold's range, written by this fold or found
//	           holding them already, the source copies its changes' source paths name, in epochs the head still
//	           lists, are deleted: DELETE idx/<repo>/<ref>/<s>/<tp(X, s)>.e, unconditional, a key already gone being
//	           done
//	directory  below each directory the range removes, once the current epoch's markers stand (markBelow), every key
//	           under the directory in those named sources is LISTed and deleted
//
// The order is the copy's own: the current entry stands before a source copy goes, so §11.6's read rule ("if every
// GET of the path returned 404 it GETs the current one again") covers a fold's delete as it covers a move's, and under
// a removed directory the marker stands, below which no read falls back to a source. Each delete is paid as the
// fold's entry writes are and carries the stale rule's deadline. The deletes are part of the fold: its range is
// finished, so its process may raise folded_through over it, only once they have answered, and a fold killed between
// a PUT and its DELETE leaves the range to another, which finds the entry holding the change and still deletes.
//
// A reading, named in the report: the directory rule runs for every directory removal in the range, where 9.2.6 names
// the path's newest change, so a directory removed and created again within one range still empties its named
// sources, whose copies below it the removal left dead.

package evsservice

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Whether the head the fold relies on lists epoch among its sources.
func (self *foldRun) listsSource(epoch uint64) bool {
	for _, source := range self.head.Head.GetPathEpoch().GetSources() {
		if source.GetEpoch() == epoch {
			return true
		}
	}
	return false
}

// The source paths the path's changes in the range name, each once, in epochs the head lists: never the current
// epoch, which the head lists as no source. A source path that does not parse names nothing (5b held each to its
// shape).
func (self *foldRun) namedSourcePaths(path *foldPath) []*EvsSourceTokenPath {
	named := []*EvsSourceTokenPath{}
	seen := map[string]bool{}
	for _, encoded := range path.sourcePaths() {
		sourcePath := &protocol.EvsSourcePath{}
		if err := proto.Unmarshal(encoded, sourcePath); err != nil || !self.listsSource(sourcePath.GetEpoch()) {
			continue
		}
		tokenPath, err := sidecar.ParseEvsChangedTokenPath(sourcePath.GetTokenPath())
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%d/%s", sourcePath.GetEpoch(), tokenPath.KeyString())
		if seen[key] {
			continue
		}
		seen[key] = true
		named = append(named, &EvsSourceTokenPath{Epoch: sourcePath.GetEpoch(), TokenPath: tokenPath})
	}
	return named
}

// The path rule: see the file header. Called once the path's current entry holds its changes.
func (self *foldRun) deleteSourceCopies(path *foldPath) error {
	if !self.sources || self.folder.keepSourceCopies {
		return nil
	}
	for _, source := range self.namedSourcePaths(path) {
		key := IndexEntryKey(self.request.RepoId, self.request.RefId, source.Epoch, source.TokenPath)
		if err := self.deleteSourceKey(source.Epoch, key); err != nil {
			return err
		}
	}
	return nil
}

// The directory rule: see the file header. Called after markBelow for a removal of what may have been a directory.
func (self *foldRun) emptySourcesBelow(removal *foldRemoval) error {
	path := self.paths[string(removal.tokenPath.Bytes())]
	if !self.sources || self.folder.keepSourceCopies || path == nil {
		return nil
	}
	for _, source := range self.namedSourcePaths(path) {
		keyPrefix := IndexChildrenPrefix(self.request.RepoId, self.request.RefId, source.Epoch, source.TokenPath)
		startAfter := ""
		for {
			if err := self.ready(); err != nil {
				return err
			}
			objects, more, err := self.cluster.List(self.ctx, keyPrefix, startAfter, self.folder.settings.FoldListPageCount)
			if err != nil {
				return err
			}
			for _, object := range objects {
				startAfter = object.Key
				if err := self.deleteSourceKey(source.Epoch, object.Key); err != nil {
					return err
				}
			}
			if !more || len(objects) == 0 {
				break
			}
		}
	}
	return nil
}

// One source key's DELETE, paid as an entry write is and under the stale rule's deadline, while the head still lists
// its epoch; an unknown outcome or a held key tries again, a DELETE being idempotent.
func (self *foldRun) deleteSourceKey(epoch uint64, key string) error {
	for attempt := 0; attempt < self.folder.settings.FoldEntryRetryCount; attempt += 1 {
		if err := self.ready(); err != nil {
			return err
		}
		if !self.listsSource(epoch) {
			// the copy drained and dropped it: nothing of it is left to delete
			return nil
		}
		err := self.deleteKey(key)
		if retryEntryWrite(err) && !errors.Is(err, sidecar.ErrBlobPrecondition) {
			continue
		}
		if err != nil {
			return err
		}
		self.result.SourceDeleteCount += 1
		return nil
	}
	return fmt.Errorf("%w: %d tries on one source delete", ErrEvsFoldBusy, self.folder.settings.FoldEntryRetryCount)
}

// One DELETE, paid for, between the source-delete barriers.
func (self *foldRun) deleteKey(key string) error {
	price, err := self.folder.priceTable.Price(WriteOperation{Kind: WriteOperationDelete, Count: 1})
	if err != nil {
		return err
	}
	grant, err := self.acquire(price)
	if err != nil {
		return err
	}
	defer grant.Close()
	deleteCtx := sidecar.WithBlobDeadline(grant.Context(), self.staleDeadline)
	if !self.request.Deadline.IsZero() {
		// a page-out's delete that would land past step 7's window is worth nothing to it
		deleteCtx = sidecar.WithBlobDeadline(deleteCtx, self.request.Deadline)
	}
	testHookBarrier(BarrierFoldSourceDeleteBefore, self.barrierKey)
	err = self.cluster.Delete(deleteCtx, key)
	testHookBarrier(BarrierFoldSourceDeleteAfter, self.barrierKey)
	return err
}
