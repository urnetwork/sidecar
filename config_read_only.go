// §7.9's read_only row (D-TEAM-24): page Workers are admitted read_only, and every verifier, api's, members'
// devices, gkm and evs, accepts from such a device only its own SidecarRevoke (sign-out), its own key upkeep under
// its r scopes at gkm (its ReaderKeys, its KeyPackages, its leaf's path-only commits, resyncs and acks), leaving,
// `read` record entries and receipt deposits (§16.8), and HeadCheck replies, and refuses everything else. It is never a
// writer, approver, counted signer, consent signer, indexer, key deliverer or committer of another's Add or Remove.
//
// ReadOnlyAllows is the one list every verifier asks, so none refuses what another accepts. The log's part,
// configReadOnlyCheck, runs on every statement before its type's rule; the counted, consent and config-writer rules
// leave read_only devices out on their own.
//
// On every leg, the sidecar_http page Worker's included. Package-level functions are safe for concurrent use.

package sidecar

import (
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One kind of act a read_only device may attempt at a verifier. The device's ownership of what it acts on (its own
// sidecar, its own keys, its own leaf) is the caller's to check; this says only whether such an act is one D-TEAM-24
// leaves a read_only device.
type ReadOnlyAct int

const (
	// its own SidecarRevoke: signing out
	ReadOnlyActSignOut ReadOnlyAct = iota + 1
	// its own ReaderKeys, signed reader-key (§10.6's r scopes)
	ReadOnlyActReaderKey
	// its own KeyPackages, whose credentials it signs mls-credential
	ReadOnlyActKeyPackage
	// its leaf's path-only commit
	ReadOnlyActPathCommit
	// its resync of a group it reads (KF5)
	ReadOnlyActResync
	// its ack of a group epoch
	ReadOnlyActAck
	// leaving a group it holds a leaf of
	ReadOnlyActLeave
	// a `read` record entry (§16.8)
	ReadOnlyActReadEntry
	// a receipt deposit (§16.8)
	ReadOnlyActReceiptDeposit
	// a HeadCheck reply (§6.4)
	ReadOnlyActHeadCheckReply

	// any log statement other than its own sign-out: admissions of every kind, OwnerConfirm, EvsShare,
	// KeyRegister, KeyRevoke, IndexerSet, RecoveryBind, RecoveryRebind, and every authority, acl and bridge statement
	ReadOnlyActStatement
	// an ApprovalDecision (§16.6)
	ReadOnlyActApprovalDecision
	// a ReaderWrap or DelegationWrap: delivering a key
	ReadOnlyActWrap
	// a GenRotate
	ReadOnlyActGenRotate
	// a Welcome
	ReadOnlyActWelcome
	// a group-info write (§10.6's info row)
	ReadOnlyActGroupInfoWrite
	// a commit adding or removing another's leaf
	ReadOnlyActAddOrRemove
	// an evs head
	ReadOnlyActEvsHead
	// a socket registration (§9)
	ReadOnlyActSocketRegistration
	// a DNS, TLS or mail write
	ReadOnlyActServiceWrite
)

// Whether a read_only device may do act (D-TEAM-24). An act this list does not know is refused.
func ReadOnlyAllows(act ReadOnlyAct) bool {
	switch act {
	case ReadOnlyActSignOut, ReadOnlyActReaderKey, ReadOnlyActKeyPackage, ReadOnlyActPathCommit, ReadOnlyActResync,
		ReadOnlyActAck, ReadOnlyActLeave, ReadOnlyActReadEntry, ReadOnlyActReceiptDeposit, ReadOnlyActHeadCheckReply:
		return true
	}
	return false
}

// Whether the sidecar's admission at this state carries read_only. A sidecar this state never admitted is no
// read_only device, and every rule refuses it as no signer at all.
func (self *ConfigState) ReadOnly(sidecarId Id) bool {
	row := self.sidecars[sidecarId]
	return row != nil && configRowReadOnly(row)
}

// The act a log statement is, for a read_only signer: its own SidecarRevoke is signing out, and anything else a
// statement.
func configReadOnlyStatementAct(signerId Id, signedType bridge.SignedType, body any) ReadOnlyAct {
	if revoke, ok := body.(*bridge.SidecarRevoke); ok && signedType == bridge.SignedType_SIGNED_SIDECAR_REVOKE {
		if sidecarId, err := IdFromBytes(revoke.GetSidecarId()); err == nil && sidecarId == signerId {
			return ReadOnlyActSignOut
		}
	}
	return ReadOnlyActStatement
}

// The log's read_only rule: a statement any read_only device signs is refused unless ReadOnlyAllows its act, which
// for a statement is its own sign-out alone.
func configReadOnlyCheck(state *ConfigState, statement *configStatement) error {
	for _, signer := range statement.signers {
		if signer.Kind != ConfigSignerSidecar || !state.ReadOnly(signer.SidecarId) {
			continue
		}
		if !ReadOnlyAllows(configReadOnlyStatementAct(signer.SidecarId, statement.signedType, statement.body)) {
			return fmt.Errorf("%w: %s from a read_only device", ErrConfigReadOnly, statement.signedType)
		}
	}
	return nil
}
