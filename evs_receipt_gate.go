//go:build !ios_extension

// §16.8's read-receipt gate (D-MCP-18, R-TRUST-7; §11.12's deposits row; EVS1-M2-29): a reader of an owner-bound repo
// (vault, mailbox, secret) that is not its writer deposits a read entry naming the objects a read decrypts, and
// awaits evs's 200, before it decrypts any of them. A first read that cannot deposit is refused, and so is every
// read while no depositor is installed: the gate fails closed, which is §8.19's owner-bound shares staying closed
// until RECORD's receipts are bound to evs (RECORD-M3-12, EVS1-M3-01's read gate).
//
// The receipt itself is the record's: its entry, its seq in the reader's log, its journal and its day's budget are
// RecordReceipts' (record_receipt.go), which deposits through its RecordStreams, which RECORD-M3-12 binds to
// EvsRepo.Deposit. This file is evs's side alone: which reads need one, and that none decrypts before it lands.
//
// On every leg. Safe for concurrent use as its depositor is.

package sidecar

import (
	"context"
	"fmt"
	"slices"
)

// Deposits a read receipt naming objectIds of a read of repoId's refId and returns once evs committed it, or with why
// it did not: RecordReceipts.Deposit's shape, which the binding adapts.
type EvsReceiptDepositFunction func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error

// The gate over deposit as an EvsPreDecryptFunction: a read of an owner-bound repo this sidecar does not write deposits
// its receipt first; every other read passes. A nil deposit refuses those reads with ErrEvsReceiptGate.
func NewEvsReceiptGate(client *EvsClient, deposit EvsReceiptDepositFunction) EvsPreDecryptFunction {
	return func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
		needs, err := client.needsReceipt(repoId)
		if err != nil || !needs {
			return err
		}
		if deposit == nil {
			return ErrEvsReceiptGate
		}
		if err := deposit(ctx, repoId, refId, objectIds); err != nil {
			return fmt.Errorf("%w: %w", ErrEvsReceiptGate, err)
		}
		return nil
	}
}

// Installs the receipt gate over deposit (SetPreDecrypt).
func (self *EvsClient) SetReceiptDepositor(deposit EvsReceiptDepositFunction) {
	self.SetPreDecrypt(NewEvsReceiptGate(self, deposit))
}

// Whether a read of repoId by this sidecar needs a receipt: an owner-bound repo it does not write, by the newest
// verified state.
func (self *EvsClient) needsReceipt(repoId Id) (bool, error) {
	state, err := self.verifier.config()
	if err != nil {
		return false, err
	}
	repo := state.Repo(repoId)
	if repo == nil {
		return false, fmt.Errorf("%w: a repo the state does not hold", ErrEvsNoConfig)
	}
	return aclRepoKindOwnerBound(repo.GetKind()) && !slices.Contains(state.RepoWriters(repoId), self.args.Identity().SidecarId), nil
}
