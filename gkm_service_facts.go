//go:build !ios_extension

// What gkm's service asks of one verified state beyond the gate's rights (§10.6's rows; QD-718): a sidecar's standing
// as its row gives it, and who a late delivery's ask is widened to. Members apply the same row rules to every commit,
// rotation and delivery they judge (gkm_verify_*.go), so the service reads them here, from the one place they live,
// and gkmservice's state over §8.9's gate cache only carries the answers.
//
//	GkmSidecarStandingAt  the identity key the log admits, revoked, parked, read_only, member device, its member,
//	                      recovery-admitted (§10.8), and the live Delegation that admitted it
//	GkmLateHolders        §10.6's late wraps row: the sidecars that may sign a LATE delivery of the repo's key at a
//	                      time (§10.9's late row: standing, not read_only, reading the repo as a holder or under a
//	                      holding Delegation), the recipient's member's devices first, then by identity bytes
//
// A Suspend is ACL's fold, not a row's field, so the standing carries none: gkmservice reads it from the state's acl
// part.
//
// Pure, on every leg. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What one state's row says of a sidecar, as §10.6's rows ask it.
type GkmSidecarStanding struct {
	// The identity key its admission names, a SidecarAdmit's or, for a network's first device, the Genesis's.
	IdentityPublicKey []byte
	// Revoked, which a tombstone keeps.
	Revoked bool
	// Parked by a compromise cascade, until its lift (§7.9).
	Parked bool
	// The read_only capability (D-TEAM-24).
	ReadOnly bool
	// Untagged, naming a member, and not ephemeral: a member device (§7.9's leaves row).
	MemberDevice bool
	// The member an untagged admission names; nil for a tagged one.
	MemberId *Id
	// Admitted by one of its member's recovery bindings (§10.8).
	RecoveryAdmitted bool
	// The Delegation that admitted it, while that Delegation is live at the time asked (§10.5's live(d)); nil for
	// none, and for one that ended, dropped its key, expired or rests on what a cascade voids.
	CoveringDelegationId []byte
}

// A sidecar's standing at a state and a time, nil for one the state never admitted.
func GkmSidecarStandingAt(view GkmAuthView, sidecarId Id, at time.Time) *GkmSidecarStanding {
	if view == nil {
		return nil
	}
	row := view.SidecarRow(sidecarId)
	if row == nil {
		return nil
	}
	standing := &GkmSidecarStanding{
		IdentityPublicKey: view.IdentityKey(sidecarId),
		Revoked:           row.GetRevokedAt() != 0,
		Parked:            row.GetParkedAt() != 0,
		ReadOnly:          gkmRowReadOnly(row),
		MemberDevice:      gkmRowMemberDevice(row),
		RecoveryAdmitted:  gkmRecoveryAdmitted(view, row),
	}
	if len(row.GetTagIds()) == 0 {
		if memberId, err := IdFromBytes(row.GetMemberId()); err == nil && memberId != (Id{}) {
			standing.MemberId = &memberId
		}
	}
	if delegationId := row.GetDelegationId(); 0 < len(delegationId) {
		for _, delegation := range view.Delegations() {
			if bytes.Equal(delegation.GetDelegationId(), delegationId) {
				if GkmDelegationLive(view, delegation, at) {
					standing.CoveringDelegationId = bytes.Clone(delegationId)
				}
				break
			}
		}
	}
	return standing
}

// The member a sidecar's row answers to: an untagged row's own, a tagged row's sponsor while that member stands
// (owner decision 83). False for neither.
func gkmRowAnswersTo(view GkmAuthView, row *bridge.SidecarRow) (Id, bool) {
	if row == nil {
		return Id{}, false
	}
	memberBytes := row.GetMemberId()
	if 0 < len(row.GetTagIds()) {
		memberBytes = row.GetSponsor()
	}
	memberId, err := IdFromBytes(memberBytes)
	if err != nil || memberId == (Id{}) || view.Member(memberId) == nil {
		return Id{}, false
	}
	return memberId, true
}

// §10.6's late wraps row: who a late delivery's ask is widened to. recipient is the ask's, as its wrap path writes it,
// s:<sidecar_id> or d:<delegation_id> in hex. The answer is every sidecar reading the repo at the view's state and
// the time given that may sign a LATE delivery there (§10.9's late row), so standing and not read_only, the recipient
// left out: first the member devices of the member the recipient answers to, a sidecar's own member, an agent's
// sponsor, or a Delegation's signer's, then the rest, each part member devices before agents and then by id, the
// order of their §10.5 identities. ErrGkmNoRepo for a repo the state does not hold, ErrGkmMalformed for a recipient
// that names nothing.
func GkmLateHolders(view GkmAuthView, repoId Id, recipient string, at time.Time) ([]Id, error) {
	if view == nil || view.Repo(repoId) == nil {
		return nil, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, repoId)
	}
	wrapType, recipientBytes, err := gkmParseHintRecipient(recipient)
	if err != nil {
		return nil, err
	}
	var recipientSidecarId Id
	var answersTo *bridge.SidecarRow
	switch wrapType {
	case GkmWrapTypeReader:
		recipientSidecarId, err = IdFromBytes(recipientBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: a hint's recipient", ErrGkmMalformed)
		}
		answersTo = view.SidecarRow(recipientSidecarId)
	case GkmWrapTypeDelegation:
		for _, delegation := range view.Delegations() {
			if bytes.Equal(delegation.GetDelegationId(), recipientBytes) {
				if signerId, err := IdFromBytes(delegation.GetSigner()); err == nil {
					answersTo = view.SidecarRow(signerId)
				}
				break
			}
		}
	}
	firstMemberId, hasFirstMember := gkmRowAnswersTo(view, answersTo)

	type lateHolder struct {
		sidecarId Id
		// the recipient's member's device
		first bool
		// a member device, §10.5's leaf identity, which sorts before an agent's
		memberDevice bool
	}
	holders := []lateHolder{}
	for _, readerId := range view.RepoReadersAt(repoId, at) {
		if wrapType == GkmWrapTypeReader && readerId == recipientSidecarId {
			continue
		}
		row := view.SidecarRow(readerId)
		if !gkmRowStanding(row) || gkmRowReadOnly(row) {
			continue
		}
		holder := lateHolder{sidecarId: readerId, memberDevice: gkmRowMemberDevice(row)}
		if holder.memberDevice && hasFirstMember {
			memberId, err := IdFromBytes(row.GetMemberId())
			holder.first = err == nil && memberId == firstMemberId
		}
		holders = append(holders, holder)
	}
	slices.SortFunc(holders, func(a lateHolder, b lateHolder) int {
		switch {
		case a.first != b.first:
			if a.first {
				return -1
			}
			return 1
		case a.memberDevice != b.memberDevice:
			if a.memberDevice {
				return -1
			}
			return 1
		}
		return a.sidecarId.Cmp(b.sidecarId)
	})
	holderIds := make([]Id, 0, len(holders))
	for _, holder := range holders {
		holderIds = append(holderIds, holder.sidecarId)
	}
	return holderIds, nil
}
