//go:build sidecar_testhooks && !ios_extension && !js

// The in-ref index writer as §22.8's index row counts it (SEARCH-M10-40; D-TEST-13; sidecartest/bench/index_load.go):
// the writer search_evs_testhooks.go installs, whose plan hook says after each content push's plan whether the writer
// put an index file or removal in it, so the row counts indexed pushes as the pushes that carried index writes, never
// a push the writer left unindexed (one that must merge first, or whose replaced version it could not read), which a
// backfill covers. Only the sidecar_testhooks build has it, which no release leg is (§22.4).

package sidecar

import (
	"context"
	"errors"
	"slices"
)

// Installs an in-ref index writer on client as InstallSearchTestIndexWriter does, telling planned, after each plan the
// writer saw, whether the plan holds an index write. The function returned removes it.
func InstallSearchTestIndexWriterCounting(client *EvsClient, args *SearchTestIndexWriterArgs, planned func(indexed bool)) (func(), error) {
	if client == nil || args == nil || args.IsAdmin == nil || planned == nil {
		return nil, errors.New("search test index writer: a client, an admin judge and a count")
	}
	writer, err := newIndexWriter(&indexWriterArgs{
		client: client,
		store: func(repo *EvsRepo, refName []byte) indexRefStore {
			return newIndexEvsStore(repo, refName, false)
		},
		isAdmin: func(repoId Id) func(file *indexFileVersion) bool {
			return func(file *indexFileVersion) bool { return args.IsAdmin(file.signerSidecarId) }
		},
		mayMerge: args.MayMerge,
		settings: DefaultIndexFormatSettings(),
		clock:    client.clock,
		log:      client.log,
	})
	if err != nil {
		return nil, err
	}
	client.SetWritePlanHook(func(ctx context.Context, plan *EvsWritePlan) error {
		if err := writer.Prepare(ctx, plan); err != nil {
			return err
		}
		// the writer's files and removals go in beside the content as the plan's index writes (evs_plan.go's hook)
		planned(slices.ContainsFunc(plan.indexWrites, evsIsIndexWrite))
		return nil
	})
	return func() { client.SetWritePlanHook(nil) }, nil
}
