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
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
			if file == nil || file.ContentSha256 == ([sha256.Size]byte{}) {
				return fmt.Errorf("%w: missing signed index digest", ErrRecordReceiptRefused)
			}
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

// The sealed admission window and whether queries must skip the ref while its receipt is outstanding.
type searchReceiptRoundWire struct {
	NextMs  int64 `json:"next_ms"`
	Skipped bool  `json:"skipped,omitempty"`
}

// A manual sync, a background trigger and a restarted member all use the same reservation.
var errSearchReceiptInterval = errors.New("search sync: the non-writer sync interval has not elapsed")

// The local receipt schedule is keyed by the encrypted index's ref, shared by its content streams.
func searchReceiptRoundKey(repo, ref Id) string {
	return hex.EncodeToString(repo[:]) + "/" + hex.EncodeToString(ref[:])
}

// Reserves the interval before the first remote read. An interrupted round leaves the ref skipped.
func (self *SidecarSearchState) beginReceiptRound(key string) (int64, error) {
	now := self.clock.Now()
	next := now.Add(self.settings.NonWriterSyncInterval).UnixMilli()
	var refused error
	err := self.change(func(wire *searchStateWire) {
		if wire.ReceiptRounds[key].NextMs > now.UnixMilli() {
			refused = errSearchReceiptInterval
			return
		}
		if wire.ReceiptRounds == nil {
			wire.ReceiptRounds = make(map[string]searchReceiptRoundWire)
		}
		wire.ReceiptRounds[key] = searchReceiptRoundWire{NextMs: next, Skipped: true}
	}, func(*searchStateWire) error { return refused })
	return next, err
}

// Makes a completed, receipted snapshot available. Until this write succeeds a restart still skips it.
func (self *SidecarSearchState) finishReceiptRound(key string, next int64) error {
	return self.change(func(wire *searchStateWire) {
		row, ok := wire.ReceiptRounds[key]
		if !ok || row.NextMs != next {
			return
		}
		row.Skipped = false
		wire.ReceiptRounds[key] = row
	}, nil)
}

// Reads the most recent durable outcome, including an interrupted round.
func (self *SidecarSearchState) receiptRoundSkipped(key string) bool {
	wire, err := self.current()
	return err != nil || wire.ReceiptRounds[key].Skipped
}

// Covers held files from an older writer manifest, and any surviving partial plan, before it can be reused.
func (self *SearchSync) receiptHeld(ctx context.Context, ref *searchSyncRef) error {
	manifest, plan := self.state(ref)
	var files []*SearchSyncWanted
	add := func(held []*SearchManifestFile) {
		for _, f := range held {
			if f.State == SearchManifestHeld {
				files = append(files, &SearchSyncWanted{ContentSha256: f.ContentSha256})
			}
		}
	}
	if manifest != nil && !manifest.Receipted {
		add(manifest.Files)
	}
	if plan != nil {
		add(plan.Staged)
	}
	if len(files) != 0 {
		if ref.args.depositReceipt == nil {
			return errSearchSyncReceipt
		}
		if err := ref.args.depositReceipt(ctx, files); err != nil {
			return fmt.Errorf("%w: %w", errSearchSyncReceipt, err)
		}
	}
	return nil
}

// Both an unacknowledged round and a writer-only cached snapshot keep the protected ref out of a page.
func (self *SearchSync) receiptSkipped(repo, index Id) bool {
	self.stateLock.Lock()
	ref := self.refs[[2]Id{repo, index}]
	skipped := ref == nil || (ref.manifest != nil && !ref.manifest.Receipted) || errors.Is(ref.lastErr, errSearchSyncReceipt)
	self.stateLock.Unlock()
	return skipped || self.args.receiptState != nil && self.args.receiptState.receiptRoundSkipped(searchReceiptRoundKey(repo, index))
}
