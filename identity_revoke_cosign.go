// The cosign side of §5.6's revocation at k > 1 (CORE-M3-04, D-CORE-20, D-CORE-13, I-4, FS-98, FS-124): another
// AdminSet member's device reads an open revocation proposal's plan and signs its AuthorityCosign, what
// `ur approve <proposal_id>` confirmed on /dev/tty and §18.5's Decide reach, never MCP.
//
//	preview   PreviewRevokeProposal reads the proposal's row at the newest verified state
//	          (SidecarAuthorityProposals.PendingProposal): only an open k-of-n proposal of a SidecarRevoke is one, any
//	          other, a closed or an expired one answering ErrSidecarRevokeProposalUnknown. The plan is the proposed
//	          statement's own: its target, reason and since_n, the cascade a compromise one runs from since_n as this
//	          device's state derives it, who signed so far, when it expires, and Presence, set from the log
//	          (SidecarAuthority.PresenceRequired over this device's cosign), never by the caller
//	cosign    CosignRevokeProposal reads the row again, so a proposal that closed or expired since the preview signs
//	          nothing, and signs AuthorityCosign{proposal_id} as an act: a person's confirmation alone reaches it
//	          (D-CORE-13), under one presence check where the log covers it, a failed, refused or missing check
//	          answering REVOKE_CANCELLED with nothing signed. The proposal's bytes cannot change under its id, so
//	          nothing is compared with the preview; the cascade's items are the tip's, as RevokeDevice's joined ones are
//	caller    a device approval-capable for its member and not suspended, never the target, which never counts, nor a
//	          device that signed the proposal already (REVOKE_NOT_CAPABLE). Whether its member is a further counted
//	          signer is the verifier's rule (§7.9's authority row): api refuses a cosign that is not at the tip
//	          (REVOKE_REFUSED), and this device does not judge it a second way
//	effects   the cosign that completes the proposal applies the revocation at its entry; this device, a writer leaf
//	          like any other, commits its Removes through the same seam the proposer's device does
//	          (SidecarRevokeEffects), from the entry it sees applied
//
// testHookBarrier brackets the signing point; each post has identity.post's.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// No open revocation proposal has that id at the newest verified state: it closed, expired, proposes something else
// or was never seen.
var ErrSidecarRevokeProposalUnknown = errors.New("no open revocation proposal has that id")

// An open revocation proposal as a cosigner reads it before deciding.
type DeviceRevokeProposal struct {
	// §7.9's 32-byte proposal_id.
	ProposalId []byte
	// The device the proposal revokes, and its config device name.
	SidecarId Id
	Name      string
	// The member the target's admission names.
	MemberId Id
	// "lost" or "compromise"; any other SidecarRevoke reason by its enum name.
	Reason string
	// compromise: where P starts, with its entry's time.
	SinceN    uint64
	SinceTime time.Time
	// compromise: §7.9's cascade from since_n at this device's state.
	Items []DeviceRevokeItem
	// The entry that carried the proposal, and when it expires unsigned.
	ProposedAt uint64
	NotAfter   time.Time
	// Who signed so far, the proposer first, in log order: each a sidecar_id's 16 bytes or a recovery key's hash.
	Signers [][]byte
	// Whether the target is suspended while cosigns are due.
	Suspended bool
	// Set from the log, never by the caller: this device's cosign needs its presence check.
	Presence bool
}

// The plan of the open revocation proposal proposalId names. ErrSidecarRevokeProposalUnknown for any other id;
// ErrSidecarDevicesPrecondition while Locked or Unenrolled; ErrSidecarActNoAuthority while no verified state is
// installed. Signs nothing.
func (self *Sidecar) PreviewRevokeProposal(proposalId []byte) (*DeviceRevokeProposal, error) {
	identity, err := self.devicesReady()
	if err != nil {
		return nil, err
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	return self.deriveRevokeProposal(authority, identity, proposalId)
}

// The proposal's plan at authority's newest state.
func (self *Sidecar) deriveRevokeProposal(authority SidecarAuthority, identity *SidecarIdentity, proposalId []byte) (*DeviceRevokeProposal, error) {
	proposals, ok := authority.(SidecarAuthorityProposals)
	if !ok || len(proposalId) != sha256.Size {
		return nil, ErrSidecarRevokeProposalUnknown
	}
	row := proposals.PendingProposal(proposalId)
	if row == nil || bridge.SignedType(row.GetStatementType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE ||
		bridge.ProposalKind(row.GetKind()) != bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY {
		return nil, ErrSidecarRevokeProposalUnknown
	}
	revoke := &bridge.SidecarRevoke{}
	if err := proto.Unmarshal(row.GetStatement(), revoke); err != nil {
		return nil, fmt.Errorf("%w: its statement does not parse", ErrSidecarRevokeProposalUnknown)
	}
	targetId, err := IdFromBytes(revoke.GetSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: it names no sidecar", ErrSidecarRevokeProposalUnknown)
	}
	plan := &DeviceRevokeProposal{
		ProposalId: bytes.Clone(row.GetProposalId()),
		SidecarId:  targetId,
		SinceN:     revoke.GetSinceN(),
		Items:      []DeviceRevokeItem{},
		ProposedAt: row.GetProposedAt(),
		NotAfter:   time.UnixMilli(row.GetNotAfterMs()),
	}
	switch revoke.GetReason() {
	case bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST:
		plan.Reason = DeviceRevokeLost
	case bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE:
		plan.Reason = DeviceRevokeCompromise
	default:
		plan.Reason = revoke.GetReason().String()
	}
	if target := authority.Admission(targetId); target != nil {
		plan.MemberId = target.MemberId
	}
	for _, signer := range row.GetSigners() {
		plan.Signers = append(plan.Signers, bytes.Clone(signer.GetSigner()))
	}
	if revokes, ok := authority.(SidecarRevokeAuthority); ok {
		plan.Suspended = revokes.Suspended(targetId)
		if sinceTime, found := revokes.EntryTime(plan.SinceN); found && plan.SinceN != 0 {
			plan.SinceTime = sinceTime
		}
	}
	if revoke.GetReason() == bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE {
		items, err := authority.Cascade(targetId, plan.SinceN)
		if err != nil {
			return nil, err
		}
		plan.Items = append(plan.Items, items...)
	}
	plan.Presence = authority.PresenceRequired(deviceRevokeStatement(identity.SidecarId, bridge.SignedType_SIGNED_AUTHORITY_COSIGN,
		&protocol.AuthorityCosign{ProposalId: bytes.Clone(row.GetProposalId())}))
	return plan, nil
}

// Signs this device's AuthorityCosign of the open revocation proposal proposalId names and answers its entry. origin
// says who asked: anything but a person's confirmation is ErrSidecarActMode with nothing signed (D-CORE-13). check is
// the presence check as an act takes it, nil only where the log does not cover the cosign. Every refusal of §5.6's is
// a *DeviceRevokeError with its code; ErrSidecarRevokeProposalUnknown for a proposal that is not open;
// ErrSidecarActPending means the cosign is signed and its post goes again.
func (self *Sidecar) CosignRevokeProposal(ctx context.Context, proposalId []byte, origin SidecarActOrigin, check SidecarPresenceCheck) (*bridge.AuthPin, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	identity, err := self.devicesReady()
	if err != nil {
		return nil, err
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	plan, err := self.deriveRevokeProposal(authority, identity, proposalId)
	if err != nil {
		return nil, err
	}
	// the caller row: approval-capable and not suspended, as the log says, never the target or a signer already
	revokes, ok := authority.(SidecarRevokeAuthority)
	if _, capable := self.approvalCapableAdmission(authority); !ok || !capable || !revokes.ApprovalCapable(identity.SidecarId) ||
		revokes.Suspended(identity.SidecarId) || plan.SidecarId == identity.SidecarId ||
		slices.ContainsFunc(plan.Signers, func(signer []byte) bool { return bytes.Equal(signer, identity.SidecarId.Bytes()) }) {
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeNotCapable}
	}
	if plan.Presence && check == nil {
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeCancelled}
	}
	act, err := self.newAct(origin)
	if err != nil {
		return nil, err
	}
	if err := act.Add(bridge.SignedType_SIGNED_AUTHORITY_COSIGN, &protocol.AuthorityCosign{ProposalId: bytes.Clone(plan.ProposalId)}); err != nil {
		return nil, err
	}
	// the act's own reading of the log decides the check, whatever the plan said
	if _, covered, err := act.CountersignedBytes(); err != nil {
		return nil, err
	} else if covered && check == nil {
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeCancelled}
	}
	// watched before the post, so the completing entry runs the effects whichever of the post's answer and the
	// follower's apply comes first
	watch := &sidecarRevokeWatch{proposalId: bytes.Clone(plan.ProposalId), sidecarId: plan.SidecarId}
	func() {
		self.revokePlans.stateLock.Lock()
		defer self.revokePlans.stateLock.Unlock()
		self.revokeWatches.watches = append(self.revokeWatches.watches, watch)
	}()
	unwatch := func() {
		self.revokePlans.stateLock.Lock()
		defer self.revokePlans.stateLock.Unlock()
		self.revokeWatches.watches = slices.DeleteFunc(self.revokeWatches.watches, func(each *sidecarRevokeWatch) bool { return each == watch })
	}

	testHookBarrier("identity.revoke.cosign.before", plan.SidecarId.String())
	pins, runErr := act.Run(ctx, check)
	testHookBarrier("identity.revoke.cosign.after", plan.SidecarId.String())
	switch {
	case errors.Is(runErr, ErrSidecarActPresence):
		// nothing was signed
		unwatch()
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeCancelled}
	case errors.Is(runErr, ErrSidecarActRefused):
		unwatch()
		return nil, fmt.Errorf("%w: %w", &DeviceRevokeError{Code: DeviceRevokeCodeRefused}, runErr)
	case errors.Is(runErr, ErrSidecarActPending):
		// signed and kept: the same bytes go again, and the watch stands for the entry they land at
		return nil, runErr
	case runErr != nil:
		unwatch()
		return nil, runErr
	}
	if len(pins) == 0 || pins[0] == nil {
		return nil, nil
	}
	return pins[0], nil
}
