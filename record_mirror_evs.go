//go:build !ios_extension

// RecordMirrorView over a network's verified config and this device's EvsMirrors (RECORD-M3-10; EVSB-M2-19's
// EvsMirror and its designation rule): the indexers an IndexerSet designates for mirror, the network's `record`
// repos, and each mirror's coverage as §11.13's status row reads it. EvsMirror's own coverage already takes a ref
// behind under its HeadLag as mirrored, so what crosses here is its reasons whole and no BehindSince.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// What the view reads.
type RecordEvsMirrorViewArgs struct {
	// The newest verified config state; nil, or a nil answer, reads as unknown.
	State func() *ConfigState
	// Opens an indexer's sealed services.
	Services EvsMirrorServicesFunction
	// The mirror this device keeps of a repo, nil for one it keeps none of.
	Mirror func(repoId Id) *EvsMirror
}

// The config's indexers and this device's mirrors, as the record reads them.
type RecordEvsMirrorView struct {
	args *RecordEvsMirrorViewArgs
}

// A view over args, reading the state and the mirrors anew at each call.
func NewRecordEvsMirrorView(args *RecordEvsMirrorViewArgs) *RecordEvsMirrorView {
	return &RecordEvsMirrorView{args: args}
}

// The state now, nil for none.
func (self *RecordEvsMirrorView) state() *ConfigState {
	if self.args == nil || self.args.State == nil {
		return nil
	}
	return self.args.State()
}

// The subjects of the designations that hold, serve and name the mirror among their services, ascending.
func (self *RecordEvsMirrorView) Indexers() ([]Id, bool) {
	state := self.state()
	if state == nil {
		return nil, false
	}
	indexerIds := []Id{}
	for _, indexer := range state.Indexers() {
		if evsMirrorDesignated(indexer, self.args.Services) && !slices.Contains(indexerIds, indexer.SidecarId) {
			indexerIds = append(indexerIds, indexer.SidecarId)
		}
	}
	slices.SortFunc(indexerIds, func(a Id, b Id) int { return a.Cmp(b) })
	return indexerIds, true
}

// The `record` repos the projection holds at the state.
func (self *RecordEvsMirrorView) Ledgers() []Id {
	ledgerIds := []Id{}
	for _, repo := range evsMirrorProjectedRepos(self.state()) {
		if repo.GetKind() != protocol.RepoKind_REPO_KIND_RECORD {
			continue
		}
		if repoId, err := IdFromBytes(repo.GetRepoId()); err == nil {
			ledgerIds = append(ledgerIds, repoId)
		}
	}
	return ledgerIds
}

// This device's mirror of logId, read fresh against evs's heads; nil when it keeps none.
func (self *RecordEvsMirrorView) Coverage(ctx context.Context, logId Id) (*RecordMirrorCoverage, error) {
	if self.args == nil || self.args.Mirror == nil {
		return nil, nil
	}
	mirror := self.args.Mirror(logId)
	if mirror == nil {
		return nil, nil
	}
	coverage, err := mirror.Coverage(ctx)
	if err != nil {
		return nil, err
	}
	return &RecordMirrorCoverage{Reasons: slices.Clone(coverage.Reasons)}, nil
}
