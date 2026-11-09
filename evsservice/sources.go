// §11.6's read row: the entry that stands for a path while its head lists source epochs (§11.6's commit and copy
// rows). Clients send each path's token path in the current epoch and in each listed source that may hold it; evs
// GETs them, and HEADs each prefix's current entry, whose state rides in object metadata, all in one round, then
// settles by §11.7's states:
//
//   - under a removed prefix the path is absent;
//   - under a fresh prefix it is absent too, unless its own current entry is fresh;
//   - else the current entry, else the newest source's;
//   - and if every GET of the path returned 404, the current one again, since a copy PUTs the current entry before it
//     deletes a source copy.
//
// While the head lists no source this is one GET of the current entry. The read keeps the folded_through of the head
// read before it, which only Newest combines it with.

package evsservice

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A path's token path in one source epoch.
type EvsSourceTokenPath struct {
	Epoch     uint64
	TokenPath sidecar.EvsTokenPath
}

// One path as a client names it: its token path in the head's current epoch, and in each listed source that may hold
// it, newest first or in any order.
type EvsPathTokens struct {
	Current sidecar.EvsTokenPath
	Sources []*EvsSourceTokenPath
}

// The head's current path epoch: 1 for a ref whose head names none yet.
func EvsHeadCurrentEpoch(head *protocol.EvsHead) uint64 {
	return max(1, head.GetPathEpoch().GetCurrent())
}

// Why ReadPathEntry found the path absent despite an entry somewhere: a prefix removed, or fresh with the path's own
// entry not.
type EvsPrefixVerdict int

const (
	// No prefix decided it.
	EvsPrefixVerdictNone EvsPrefixVerdict = iota
	// A prefix's current entry is removed.
	EvsPrefixVerdictRemoved
	// A prefix's current entry is fresh and the path's own is not.
	EvsPrefixVerdictFresh
)

// The entry that stands for a path, by §11.6's read rule, and what decided it.
type EvsPathRead struct {
	*EvsEntryRead
	// Set when a prefix made the path absent: Entry is then nil.
	Prefix EvsPrefixVerdict
	// The source epoch the entry came from, 0 for the current epoch.
	SourceEpoch uint64
}

// The path's entry by §11.6's read rule against head, the head evs read before it. tokens names the path in the
// current epoch and in each listed source; a source token path for an epoch the head does not list is not read.
func ReadPathEntry(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *protocol.EvsHead, tokens *EvsPathTokens) (*EvsPathRead, error) {
	epoch := EvsHeadCurrentEpoch(head)
	foldedThrough := head.GetFoldedThrough()
	listedEpochs := []uint64{}
	for _, source := range head.GetPathEpoch().GetSources() {
		listedEpochs = append(listedEpochs, source.GetEpoch())
	}
	if len(listedEpochs) == 0 {
		read, err := ReadEntry(ctx, cluster, repoId, refId, epoch, tokens.Current, foldedThrough)
		if err != nil {
			return nil, err
		}
		return &EvsPathRead{EvsEntryRead: read}, nil
	}

	// the sources the client named that the head lists, newest first as the head lists them
	sourcePaths := []*EvsSourceTokenPath{}
	for _, listedEpoch := range listedEpochs {
		for _, source := range tokens.Sources {
			if source.Epoch == listedEpoch && len(source.TokenPath) != 0 {
				sourcePaths = append(sourcePaths, source)
				break
			}
		}
	}

	// one round: the current entry, each source's, and each prefix's state
	var waitGroup sync.WaitGroup
	var currentRead *EvsEntryRead
	var currentErr error
	sourceReads := make([]*EvsEntryRead, len(sourcePaths))
	sourceErrs := make([]error, len(sourcePaths))
	prefixCount := len(tokens.Current) - 1
	prefixStates := make([]EvsEntryStateValue, max(0, prefixCount))
	prefixErrs := make([]error, max(0, prefixCount))
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		currentRead, currentErr = ReadEntry(ctx, cluster, repoId, refId, epoch, tokens.Current, foldedThrough)
	}()
	for i, source := range sourcePaths {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			sourceReads[i], sourceErrs[i] = ReadEntry(ctx, cluster, repoId, refId, source.Epoch, source.TokenPath, foldedThrough)
		}()
	}
	barrierKey := barrierRefKey(repoId, refId)
	testHookBarrier(BarrierEntryStateBefore, barrierKey)
	for length := 1; length <= prefixCount; length += 1 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			prefixStates[length-1], _, prefixErrs[length-1] = HeadEntryState(ctx, cluster, repoId, refId, epoch, tokens.Current[:length])
		}()
	}
	waitGroup.Wait()
	testHookBarrier(BarrierEntryStateAfter, barrierKey)
	if currentErr != nil {
		return nil, currentErr
	}
	if err := errors.Join(prefixErrs...); err != nil {
		return nil, err
	}

	// a removed prefix, or a fresh one over a path whose own entry is not fresh, makes it absent
	for _, state := range prefixStates {
		if state.State == EvsEntryStateRemoved {
			return absentPathRead(tokens.Current, epoch, foldedThrough, EvsPrefixVerdictRemoved), nil
		}
	}
	if slices.ContainsFunc(prefixStates, func(state EvsEntryStateValue) bool { return state.State == EvsEntryStateFresh }) {
		if !currentRead.Absent() && currentRead.State.State == EvsEntryStateFresh {
			return &EvsPathRead{EvsEntryRead: currentRead}, nil
		}
		return absentPathRead(tokens.Current, epoch, foldedThrough, EvsPrefixVerdictFresh), nil
	}
	if !currentRead.Absent() {
		return &EvsPathRead{EvsEntryRead: currentRead}, nil
	}
	for i, sourceRead := range sourceReads {
		if sourceErrs[i] != nil {
			return nil, sourceErrs[i]
		}
		if !sourceRead.Absent() {
			// the window after h names the path in the current epoch, since a PATH_EPOCH commit sets
			// folded_through to its own version (§11.7's when row (4)), so the rule scans it by the current path
			sourceRead.TokenPath = tokens.Current
			return &EvsPathRead{EvsEntryRead: sourceRead, SourceEpoch: sourcePaths[i].Epoch}, nil
		}
	}
	// every GET 404'd: the copy PUTs the current entry before it deletes a source copy, so the current one again
	read, err := ReadEntry(ctx, cluster, repoId, refId, epoch, tokens.Current, foldedThrough)
	if err != nil {
		return nil, err
	}
	return &EvsPathRead{EvsEntryRead: read}, nil
}

// A path a prefix made absent.
func absentPathRead(tokenPath sidecar.EvsTokenPath, epoch uint64, foldedThrough uint64, verdict EvsPrefixVerdict) *EvsPathRead {
	return &EvsPathRead{
		EvsEntryRead: &EvsEntryRead{TokenPath: tokenPath, Epoch: epoch, FoldedThrough: foldedThrough},
		Prefix:       verdict,
	}
}
