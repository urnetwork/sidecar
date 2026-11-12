//go:build !ios_extension

// §16.8's read-receipt gate (D-MCP-18, R-TRUST-7; §11.12's deposits row; EVS1-M2-29): a reader of an owner-bound repo
// (vault, mailbox, secret) that is not its writer deposits a read entry naming the objects a read decrypts, and
// awaits evs's 200, before it decrypts any of them. A first read that cannot deposit is refused, and so is every
// read while no depositor is installed: the gate fails closed, which is §8.19's owner-bound shares staying closed
// until RECORD's receipts are bound to evs (RECORD-M3-12, EVS1-M3-01's read gate).
//
// The receipt itself is the record's: its entry, its seq in the reader's log, its journal and its day's budget are
// RecordReceipts' (record_receipt.go), which deposits through its RecordStreams, which RECORD-M3-12 binds to
// EvsRepo.Deposit. This file is evs's side: which reads need one, that none decrypts before it lands, and the binding
// that opens the gate (EVS1-M3-01; owner-bound shares open at M3, §8.19): NewEvsRecordReceiptDepositor puts each read's
// objects to RecordReceipts.Deposit as §16.8's RecordHeader kind read, source observed, ReadBody{object ids, at most 64
// a receipt, purpose}, and the read decrypts only once evs answered 200 for every receipt it needs.
//
//	purpose  the read's purpose and the run it serves ride its context (WithEvsReadContext): §16.5's evs_read and
//	         ur://evs read, search's more, export and disclosure set theirs; a read whose context names none is purpose
//	         read, bound to no run and no session, whose receipt seals tainted by section 5.3's unbound row, the
//	         closed side
//	re-reads a receipt committed for an object this UTC day covers every later read of it for that purpose
//	         (RecordReceipts' day), so a re-read deposits nothing; this client keeps no plaintext, and whatever caches
//	         decrypted bytes (§5.9's caches) reads them without reaching the gate again
//	objects  what the read decrypts: each chain's segments and slots; a listing names none, since a name table is no
//	         object a receipt can name, and passes with no receipt (EVS1-M2-29's reading)
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

// What a read's receipt says of it beside its objects: §16.8's ReadBody purpose, and the run whose taint the receipt
// takes (RecordReceiptRequest's RunId and NoSession).
type EvsReadContext struct {
	Purpose   RecordReadPurpose
	RunId     *Id
	NoSession bool
}

// The context key of an EvsReadContext.
type evsReadContextKey struct{}

// ctx carrying read, a copy: what the receipt gate deposits a read under.
func WithEvsReadContext(ctx context.Context, read *EvsReadContext) context.Context {
	copied := *read
	if read.RunId != nil {
		runId := *read.RunId
		copied.RunId = &runId
	}
	return context.WithValue(ctx, evsReadContextKey{}, &copied)
}

// The read's context, or purpose read bound to no run and no session.
func evsReadContextOf(ctx context.Context) *EvsReadContext {
	if read, ok := ctx.Value(evsReadContextKey{}).(*EvsReadContext); ok && read != nil {
		return read
	}
	return &EvsReadContext{Purpose: RecordReadPurposeRead}
}

// The receipt gate's depositor over the record's receipts: see the file header. A nil receipts gives a nil depositor,
// which keeps the gate refusing.
func NewEvsRecordReceiptDepositor(receipts *RecordReceipts) EvsReceiptDepositFunction {
	if receipts == nil {
		return nil
	}
	return func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
		read := evsReadContextOf(ctx)
		return receipts.Deposit(ctx, &RecordReceiptRequest{
			RepoId: repoId, Purpose: read.Purpose, ObjectIds: objectIds, RunId: read.RunId, NoSession: read.NoSession,
		})
	}
}

// Opens §8.19's owner-bound shares on this client: its receipt gate deposits through receipts (SetReceiptDepositor).
func (self *EvsClient) SetRecordReceipts(receipts *RecordReceipts) {
	self.SetReceiptDepositor(NewEvsRecordReceiptDepositor(receipts))
}
