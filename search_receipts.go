//go:build !ios_extension

// Search's read receipts (§16.10's owner-bound row; D-MCP-18, D-ACL-14, R-MCP-14; SEARCH-M10-26): an owner-bound repo
// is searched only by its readers, and a reader that is not its writer deposits a read receipt of purpose search
// naming the index objects it is about to decrypt, and awaits evs's 200, before it first decrypts them. The objects an
// index file's read decrypts are named by the file's 32-byte content_sha256 (RECORD.md's ReadBody, §11.14), at most
// 64 to a receipt, which RecordReceipts batches; one already receipted for search this UTC day takes none. A
// receipt that cannot land refuses the round's fetch, so the repo holds no snapshot and coverage names it skipped.
//
// The sync engine deposits through searchReceiptDepositor before each round's first fetch of such a repo, and spaces
// those rounds Search.NonWriterSyncInterval apart, so a non-writer's receipts stay near 100 a day; a search reads the
// cache it fetched and decrypts kept records again with no further receipt, as every cache of decrypted index bytes
// does (§5.9). Opening a hit is the open tool's read, which evs's read gate receipts. A search writes nothing to evs
// but receipts.
//
// On every leg but ios_extension. Safe for concurrent use as the deposit is.

package sidecar

import (
	"context"
	"fmt"
)

// RecordReceipts.Deposit's shape: deposits the receipt request names and returns once evs committed each, or why not.
type SearchReceiptDeposit func(ctx context.Context, request *RecordReceiptRequest) error

// The sync engine's depositReceipt for an owner-bound repo this sidecar reads and does not write: one request of
// purpose search naming each wanted file's content_sha256, outside any run or session. A nil deposit refuses, so the
// round fetches nothing (fail closed).
func searchReceiptDepositor(deposit SearchReceiptDeposit, repoId Id) func(ctx context.Context, wanted []*SearchSyncWanted) error {
	return func(ctx context.Context, wanted []*SearchSyncWanted) error {
		if deposit == nil {
			return fmt.Errorf("%w: no receipt depositor", ErrRecordReceiptRefused)
		}
		if len(wanted) == 0 {
			return nil
		}
		objectIds := make([][]byte, 0, len(wanted))
		for _, file := range wanted {
			sum := file.ContentSha256
			objectIds = append(objectIds, sum[:])
		}
		return deposit(ctx, &RecordReceiptRequest{RepoId: repoId, Purpose: RecordReadPurposeSearch, ObjectIds: objectIds, NoSession: true})
	}
}

// What a sync engine follows a scoped ref with, for receipts: whether its reader is a non-writer of an owner-bound
// repo, and the depositor its rounds call.
func searchReceiptFollowArgs(repo *SearchScopeRepo, deposit SearchReceiptDeposit) (bool, func(ctx context.Context, wanted []*SearchSyncWanted) error) {
	if !repo.ReceiptRequired {
		return false, nil
	}
	return true, searchReceiptDepositor(deposit, repo.RepoId)
}
