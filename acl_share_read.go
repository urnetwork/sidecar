//go:build !ios_extension

// §8.19's owner-bound reads (R-ACL-11, D-MCP-18, I-4, FS-30): an EvsShare, and from M6 the audit reader, open an
// owner-bound repo (vault, mailbox, secret) only behind §16.8's read receipts. A reader of such a repo that does not
// write it deposits a read entry naming what it is about to decrypt, and awaits evs's commit, before anything is
// decrypted; a first read that cannot deposit fails closed. The repo's owner need not be online: the receipt lands in
// evs, where the owner's devices read it when they next sync (FS-30).
//
// Each read is judged at its own time against the installed state, never from a cached open. An EvsShare ends at its
// expires with no device online to file anything, so a read past it is refused before any receipt is filed and
// nothing reaches evs. A writer of the repo, a consented device of its owner, reads with no receipt. The engine allows
// AclEngineSettings.ClockSkew past an expiry, as every check of it does, and evs's own gate holds the scope to server
// time (D-ACL-21).
//
// The receipt's entry, its seq in the reader's log and its day's budget are RECORD's (record_receipt.go), and the
// deposit's scope is AclExchangeScopes' repo:<id>:deposit, which EvsAccess gives every such reader (acl_evs.go). evs's
// read path calls the gate through EvsClient.SetPreDecrypt (evs_read.go): NewAclShareReadGate is the gate to install
// there, judging each read on the engine and then depositing through RECORD's binding.
//
// Safe for concurrent use. The deposit is the read's linearization point, between the acl_share_read.deposit barriers.
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The installed state does not let this sidecar read the repo at the read's time: a share past its expires, a revoked
// or suspended reader, a repo deleted or held by no row. Nothing was deposited.
var ErrAclShareReadRefused = errors.New("acl: the read is refused")

// One read's admission at the reader.
type AclShareRead struct {
	// Whether this sidecar reads the repo at the read's time.
	Allowed bool
	// Whether that read must land a read receipt before anything is decrypted: an owner-bound repo this sidecar reads
	// and does not write.
	RequiresReceipt bool
	// What gave the read, an EvsShare with the position of the entry that carried it among them, or why there is none.
	AclDecision
}

// Whether this sidecar's read of a repo at now needs a read receipt first, and whether it may read at all: a reader of
// an owner-bound repo who is not its writer, its EvsShares' subjects and the audit reader, needs one; a writer and a
// reader of any other kind need none. Judged on the installed state at each call.
func (self *AclEngine) ReadRequiresReceipt(repoId Id, now time.Time) AclShareRead {
	installed := self.installed.Load()
	if installed == nil {
		return AclShareRead{AclDecision: aclDeny(AclReasonNoState)}
	}
	state := installed.state
	access := state.EvsAccess(installed.self, repoId, AclTokenAudienceEvs, time.UnixMilli(self.checkMs(now)))
	if !access.Rights.Has(AclEvsRead) {
		// a deposit alone reads nothing; with no rights the access says why
		decision := access.AclDecision
		if access.Rights != 0 || decision.Reason == 0 {
			decision = aclDeny(AclReasonNoGrant)
		}
		return AclShareRead{AclDecision: decision}
	}
	repo := state.Repo(repoId)
	return AclShareRead{
		Allowed:         true,
		RequiresReceipt: repo != nil && aclRepoKindOwnerBound(repo.GetKind()) && !access.Rights.Has(AclEvsWrite),
		AclDecision:     access.AclDecision,
	}
}

// The read gate evs's read path calls before it decrypts a read's objects (EvsClient.SetPreDecrypt): each read judged
// on engine at clock's now; a read the state refuses answers ErrAclShareReadRefused before any deposit; one that needs
// a receipt deposits it and returns only once deposit has, wrapping its refusal in ErrEvsReceiptGate; every other read
// passes. A nil deposit refuses every read that needs a receipt, and a nil clock reads real time.
func NewAclShareReadGate(engine *AclEngine, clock Clock, deposit EvsReceiptDepositFunction) EvsPreDecryptFunction {
	if clock == nil {
		clock = RealClock{}
	}
	return func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
		if engine == nil {
			return fmt.Errorf("%w: %s", ErrAclShareReadRefused, AclReasonNoState)
		}
		read := engine.ReadRequiresReceipt(repoId, clock.Now())
		if !read.Allowed {
			return fmt.Errorf("%w: %s", ErrAclShareReadRefused, read.Reason)
		}
		if !read.RequiresReceipt {
			return nil
		}
		if deposit == nil {
			return ErrEvsReceiptGate
		}
		testHookBarrier("acl_share_read.deposit.before", repoId.String())
		err := deposit(ctx, repoId, refId, objectIds)
		testHookBarrier("acl_share_read.deposit.after", repoId.String())
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEvsReceiptGate, err)
		}
		return nil
	}
}
