//go:build sidecar_testhooks && !ios_extension && !js

// The eraser's history walk over EvsRepo on real engines, for the seam's tests (QD-1110; question
// mail-m10-04-index-eraser-history-reads; SEARCH-M10-17's indexEvsStore.Retained and Read): what the store names
// beside each live index path's newest version, and what its Read gives for each one evs still serves, as
// IndexEraser.history reads them; and the files at the head holding any one document by its doc_key, every chunk of a
// message as an erasure's CUT lists it, for MAIL-M10-04's rows. Only the sidecar_testhooks build has it, which no
// release leg is (§22.4).

package sidecar

import (
	"context"
)

// One version of an index file indexEvsStore.Retained names beside its path's newest.
type SearchTestEvsRetained struct {
	Path          string
	Version       uint64
	CommitVersion uint64
	// Whether evs still serves its content, so the eraser's walk reads it; and that read's plaintext or error.
	Readable  bool
	Plaintext []byte
	ReadErr   error
}

// Every version indexEvsStore.Retained names on repo's file-mode ref refName (nil: main), each readable one read
// through the store's Read as the eraser's walk reads it, and whether the store answered its list complete.
func SearchTestEvsRetainedVersions(ctx context.Context, repo *EvsRepo, refName []byte) ([]*SearchTestEvsRetained, bool, error) {
	store := newIndexEvsStore(repo, refName, false)
	retained, err := store.Retained(ctx)
	if err != nil {
		return nil, false, err
	}
	versions := []*SearchTestEvsRetained{}
	for _, version := range retained.versions {
		listed := &SearchTestEvsRetained{
			Path: version.file.path, Version: version.file.version, CommitVersion: version.file.commitVersion,
			Readable: version.readable,
		}
		if version.readable {
			listed.Plaintext, listed.ReadErr = store.Read(ctx, version.file)
		}
		versions = append(versions, listed)
	}
	return versions, retained.complete, nil
}

// Every index file of repo's file-mode ref refName (nil: main) at its head holding an entry, row or tombstone of the
// document docKey names, read through EvsRepo as every index builder reads it: SearchTestEvsFilesHolding for any chunk,
// the doc_key as SearchOracle derives it.
func SearchTestEvsFilesHoldingKey(ctx context.Context, repo *EvsRepo, refName []byte, docKey [indexIdByteCount]byte) ([]SearchTestHeld, error) {
	return searchTestFilesHolding(ctx, newIndexEvsStore(repo, refName, false), docKey, DefaultIndexFormatSettings())
}
