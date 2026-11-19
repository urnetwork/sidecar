//go:build sidecar_testhooks && !ios_extension && !js

// An erasure's eraser on real engines, for FS-111's registered case on sidecartest/fault's evs world (SEARCH-M10-37):
// the index's eraser (SEARCH-M10-16, SEARCH-M10-17) over EvsRepo's index store and its eraser seam
// (evs_index_store_evs.go), as a composition will build one for mail's and the record's erasures (MAIL-M10-02,
// RECORD-M10-01; none is wired yet). Only the sidecar_testhooks build has it, which no release leg is (§22.4).

package sidecar

import (
	"context"
)

// An eraser of repo's file-mode ref refName (nil: main), signing as the device of repo's client, on that client's
// clock: its CUT, CLOSUREs and ERASEs go through EvsRepo, and which erasures are complete is read from the repo's
// erasure ref. isAdmin judges an erasure set or settings version's signer, as the composition's AclState does. A fresh
// one each call, as a device starting holds none of its memory.
func NewSearchTestEvsEraser(ctx context.Context, repo *EvsRepo, refName []byte, isAdmin func(signer Id) bool) (*IndexEraser, error) {
	store := newIndexEvsStore(repo, refName, false)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, err
	}
	kind, err := repo.repoKind()
	if err != nil {
		return nil, err
	}
	repoKey, err := repo.client.args.Gkm.CurrentRepoKey(ctx, repo.repoId)
	if err != nil {
		return nil, err
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return nil, err
	}
	padKey, err := indexNewPadKey(repoKey)
	if err != nil {
		return nil, err
	}
	return indexNewEraser(&indexEraserArgs{
		store: store, eraseStore: store, repoId: repo.repoId, refId: refId, repoKind: kind,
		isAdmin: func(file *indexFileVersion) bool { return isAdmin(file.signerSidecarId) },
		format:  DefaultIndexFormatSettings(), eraser: repo.client.args.Identity().SidecarId,
		complete: func(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
			erasures, err := repo.ReadErasures(ctx, 0)
			if err != nil {
				return nil, err
			}
			complete := map[Id]bool{}
			for _, erasure := range erasures {
				if erasure.Complete {
					complete[erasure.ErasureId] = true
				}
			}
			return complete, nil
		},
		refKey: refKey, tables: indexLinkedTables(), mayMerge: func() bool { return true },
		padKey: func(ctx context.Context) (*indexPadKey, error) { return padKey, nil },
		clock:  repo.client.clock, log: repo.client.log,
	})
}

// The committed CLOSUREs of erasureId on repo's file-mode ref refName (nil: main), as evs's state holds them: what a
// resume reads (§11.12's reconcile row).
func SearchTestEvsClosureCount(ctx context.Context, repo *EvsRepo, refName []byte, erasureId Id) (int, error) {
	if refName == nil {
		refName = EvsMainRefName
	}
	closures, err := repo.ReadClosures(ctx, refName, 0)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, closure := range closures {
		if closure.ErasureId == erasureId {
			count += 1
		}
	}
	return count, nil
}

// The head's index_epoch of repo's file-mode ref refName (nil: main), read through EvsRepo's verifying reader.
func SearchTestEvsIndexEpoch(ctx context.Context, repo *EvsRepo, refName []byte) (uint64, error) {
	head, err := newIndexEvsStore(repo, refName, false).Head(ctx)
	if err != nil {
		return 0, err
	}
	return head.indexEpoch, nil
}
