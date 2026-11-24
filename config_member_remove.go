// A member's removal on the device (TEAM-M6-11; R-TEAM-11, D-TEAM-10, I-15, FS-87, FI-19, FI-25, Q-TEAM-8; §7.10): the
// MemberRevoke an admin device signs, what readers mask from its position, and which server denials still owe one.
//
//	plan     MemberRevokePlan reads, at one verified state, what the MemberRevoke does: the member's untagged devices it
//	         revokes at its position n', its tagged agents it leaves, which keep their tags' grants with
//	         autogroup:admin standing in as their sponsor until an admin's SponsorSet (owner decision 83), whether it
//	         is an authority statement (an AdminSet member: k of n, the member never counting), and the repos whose
//	         key holders it shrinks, where a write needs a generation covering n' (§7.10's gate). A plan is derived,
//	         never stored: the act re-reads it at the newest state before it signs
//	sign     SignMemberRevoke, on a person's confirmation only (D-CORE-13): the MemberRevoke, or where k > 1 its
//	         AuthorityProposal, through CORE's sidecarAct, so each statement is kept before it is posted and a kill
//	         or a lost answer retries the same bytes; with the presence countersignature where §7.9's presence row
//	         asks (D-TEAM-32), the act's own reading deciding
//	effects  from the entry where it takes effect, the completing cosign's at k > 1: this device commits a Remove of
//	         each revoked device's leaves first (KEYS's SidecarRevokeEffects.CommitRevocation, the config and directory
//	         groups by rotation alone where this device is wrapped), then shows the revocation unwitnessed until a
//	         HeadCheck peer holds its position (§7.10's confirm row, TrackRevocation)
//	mask     MaskedInDirectory: from n' every reader masks the cards, notices and pending requests of each sidecar a
//	         removal revoked, a member's devices and never its tagged agents (§7.10's cards row, §16.11's member and
//	         device rows); the directory's view asks this (directory_auth.go)
//	owed     UnsignedMemberRemovals: the members the config holds and api no longer lists, which api denied at once
//	         (POST /network/member-remove, SCIM's active=false) and whose MemberRevoke no device has signed; the server
//	         list only proposes, and nothing here signs from it
//
// The signed statement is the removal: until it lands no reader changes, whatever api denied (owner decisions 5, 59).
// Nothing here creates, derives or unwraps a key. On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The member named is no member of this state: unknown, or already removed.
	ErrMemberPlanNoMember = errors.New("no such member")
	// No verified log is installed to plan from.
	ErrMemberPlanNoState = errors.New("no verified log to plan from")
)

// What a MemberRevoke does, at one state.
type MemberRevokePlan struct {
	// The state the plan was read at.
	Pin      *bridge.AuthPin
	MemberId Id
	Role     bridge.MemberRole
	// The member is in the AdminSet (§7.5's first four roles): the MemberRevoke is an authority statement.
	AdminSet bool
	// The distinct counted members it needs: k of the AdminSet's n for an AdminSet member, else one Owner's or Admin's
	// device. More than one goes as an AuthorityProposal its cosigns complete.
	Signatures int
	// The member's untagged devices it revokes at its position, those not revoked already, in id order.
	DeviceIds []Id
	// The tagged agents the member sponsors, which stay: they keep their tags' grants, and autogroup:sponsor resolves
	// to autogroup:admin for them until an admin's SponsorSet, which their directory cards show (owner decision 83).
	// In id order.
	AgentIds []Id
	// The repos whose key holders the removal shrinks, the config among them: from its position a push or deposit
	// there needs a generation covering it, and receivers answer 451 until one is claimed (§7.10's gate). In id order.
	ReposRotating []Id
}

// The plan of a MemberRevoke of memberId at this state.
func (self *ConfigState) MemberRevokePlan(memberId Id) (*MemberRevokePlan, error) {
	member := self.members[memberId]
	if member == nil {
		return nil, ErrMemberPlanNoMember
	}
	plan := &MemberRevokePlan{
		Pin:        self.Pin(),
		MemberId:   memberId,
		Role:       member.GetRole(),
		AdminSet:   configRoleInAdminSet(member.GetRole()),
		Signatures: 1,
	}
	if plan.AdminSet {
		plan.Signatures, _ = self.Threshold()
	}
	for _, sidecarId := range self.SidecarIds() {
		row := self.sidecars[sidecarId]
		if row.GetRevokedAt() != 0 {
			continue
		}
		if rowMemberId, untagged := configRowMember(row); untagged {
			if rowMemberId == memberId {
				plan.DeviceIds = append(plan.DeviceIds, sidecarId)
			}
			continue
		}
		if sponsorId, ok := self.Sponsor(sidecarId); ok && sponsorId == memberId {
			plan.AgentIds = append(plan.AgentIds, sidecarId)
		}
	}
	at := time.UnixMilli(self.timeMs)
	for _, repoId := range configShrinkRepoIds(self) {
		holders, err := KeyHolders(self, repoId, at)
		if err != nil {
			continue
		}
		held := holders.Contains(GkmHolderRecovery, memberId.Bytes())
		for _, deviceId := range plan.DeviceIds {
			held = held || holders.Contains(GkmHolderLeaf, deviceId.Bytes())
		}
		if held {
			plan.ReposRotating = append(plan.ReposRotating, repoId)
		}
	}
	slices.SortFunc(plan.ReposRotating, Id.Cmp)
	return plan, nil
}

// Whether every reader masks the sidecar's cards, notices and pending requests in the team directory at this state
// (§7.10's cards row; §16.11's member and device rows): its row revoked at or before this position, by a
// SidecarRevoke, a reap at its tick's position, or its member's MemberRevoke, which revokes the member's untagged
// devices and leaves its tagged agents. False for a sidecar this state never admitted, which the directory's standing
// rule judges, and for a parked or suspended one, which no removal names. Rows-only readers answer alike.
func (self *ConfigState) MaskedInDirectory(sidecarId Id) bool {
	row := self.sidecars[sidecarId]
	return row != nil && row.GetRevokedAt() != 0 && row.GetRevokedAt() <= self.n
}

// The members this state holds that serverMemberIds, the team's whole member list as api answers it (GET
// /network/members), lacks: removals api denied at once whose MemberRevoke no device has signed yet, so members still
// encrypt to their devices (§7.6, §7.10). An unsigned list only proposes: a person confirms each MemberRevoke. In id
// order.
func (self *ConfigState) UnsignedMemberRemovals(serverMemberIds []Id) []Id {
	listed := map[Id]bool{}
	for _, memberId := range serverMemberIds {
		listed[memberId] = true
	}
	owed := []Id{}
	for _, memberId := range self.MemberIds() {
		if !listed[memberId] {
			owed = append(owed, memberId)
		}
	}
	return owed
}

// What SignMemberRevoke did.
type MemberRevocation struct {
	// The plan as signed, re-read at the newest state.
	Plan *MemberRevokePlan
	// The MemberRevoke's entry (n', A_n'); nil while a proposal pends or a post's answer is lost.
	Entry *bridge.AuthPin
	// §7.9's 32-byte proposal_id while k > 1 pends.
	ProposalId []byte
	// The statements are signed and kept, and a post's answer was lost: they go again with the same bytes.
	Pending bool
}

// The plan of a MemberRevoke at the newest verified state, for `ur admin members remove` to print before the person
// confirms.
func (self *Sidecar) PlanMemberRevoke(memberId Id) (*MemberRevokePlan, error) {
	state, err := self.memberRevokeState()
	if err != nil {
		return nil, err
	}
	return state.MemberRevokePlan(memberId)
}

// The verified state a member's removal reads: the installed ConfigAuthority's, or that of an installed authority
// that holds one itself. ErrMemberPlanNoState with none.
func (self *Sidecar) memberRevokeState() (*ConfigState, error) {
	if state, err := self.configState(); err == nil {
		return state, nil
	}
	if holder, ok := self.authority().(interface{ State() *ConfigState }); ok {
		if state := holder.State(); state != nil {
			return state, nil
		}
	}
	return nil, ErrMemberPlanNoState
}

// Signs and posts a MemberRevoke of memberId as the person confirmed it (origin), re-planned at the newest verified
// state; at k > 1 its AuthorityProposal, whose cosigns other admin devices give. Refused through MCP, a hook or an
// unconfirmed call (D-CORE-13), and with the presence check the log asks run by check, nil for none: a covered act with
// none is ErrSidecarActPresence, nothing signed. ErrSidecarActPending means the statements are signed and their post
// goes again; ErrSidecarActRefused that api or a verifier refused them at the tip.
func (self *Sidecar) SignMemberRevoke(ctx context.Context, memberId Id, origin SidecarActOrigin, check SidecarPresenceCheck) (*MemberRevocation, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	return self.signMemberRevoke(ctx, memberId, check)
}

// The MemberRevoke's act at the newest state, on a confirmation the caller has established: a person's, or for the
// indexer ServiceSettings.scim_signer names, that designation (config_scim_signer.go).
func (self *Sidecar) signMemberRevoke(ctx context.Context, memberId Id, check SidecarPresenceCheck) (*MemberRevocation, error) {
	plan, err := self.PlanMemberRevoke(memberId)
	if err != nil {
		return nil, err
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	act, err := self.newAct(SidecarActConfirmed)
	if err != nil {
		return nil, err
	}
	// k > 1 goes as an AuthorityProposal this device signs as the first counted signer, the plan's reading of the log,
	// as RevokeDevicePlan decides its own
	revoke := &bridge.MemberRevoke{MemberId: memberId.Bytes()}
	proposal := 1 < plan.Signatures
	if proposal {
		proposedBytes, err := act.proposedStatementBytes(revoke)
		if err != nil {
			return nil, err
		}
		if err := act.Add(bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, &protocol.AuthorityProposal{
			StatementType: uint32(bridge.SignedType_SIGNED_MEMBER_REVOKE),
			Statement:     proposedBytes,
		}); err != nil {
			return nil, err
		}
	} else if err := act.Add(bridge.SignedType_SIGNED_MEMBER_REVOKE, revoke); err != nil {
		return nil, err
	}
	// the act's own reading of the log decides the check, whatever the caller expected
	if _, covered, err := act.CountersignedBytes(); err != nil {
		return nil, err
	} else if covered && check == nil {
		return nil, ErrSidecarActPresence
	}
	revocation := &MemberRevocation{Plan: plan}
	if proposal {
		revocation.ProposalId = act.proposalId(0)
	}
	notAfterMs := act.notAfterMs()

	testHookBarrier("config.member_remove.sign.before", memberId.String())
	pins, runErr := act.Run(ctx, check)
	testHookBarrier("config.member_remove.sign.after", memberId.String())
	switch {
	case errors.Is(runErr, ErrSidecarActPending):
		revocation.Pending = true
	case runErr != nil:
		return revocation, runErr
	}
	landed := 0 < len(pins) && pins[0] != nil
	if !proposal && landed {
		revocation.Entry = pins[0]
		self.runMemberRevokeEffects(ctx, memberId, pins[0])
		return revocation, nil
	}
	// the effects wait for the entry this device sees applied: the completing cosign's, or the retried post's
	self.watchMemberRevoke(authority, memberId, revocation.ProposalId, notAfterMs)
	return revocation, runErr
}

// Runs a landed MemberRevoke's effects at entry: this device's Removes of each device the entry revoked, then the
// revoker's tracking of its position (§7.10's commit and confirm rows), then the bridge block's head where the removal
// left its signer no longer standing (Sidecar.saveBridgeBlockAfter; QD-1205). With no effects installed the revocation
// still stands, and any writer leaf commits the Removes.
func (self *Sidecar) runMemberRevokeEffects(ctx context.Context, memberId Id, entry *bridge.AuthPin) {
	effects := func() SidecarRevokeEffects {
		self.revokePlans.stateLock.Lock()
		defer self.revokePlans.stateLock.Unlock()
		return self.revokePlans.effects
	}()
	testHookBarrier("config.member_remove.effects.before", memberId.String())
	defer testHookBarrier("config.member_remove.effects.after", memberId.String())
	// last, whatever returns first
	defer self.saveBridgeBlockAfter(ctx, entry)
	if effects == nil {
		self.log.Infof("[config]the MemberRevoke at %d landed with no committer installed: a writer leaf commits its Removes", entry.GetVersion())
		return
	}
	state, err := self.memberRevokeState()
	if err != nil {
		self.log.Warningf("[config]the MemberRevoke at %d: no state to read its devices from: %s", entry.GetVersion(), err)
		return
	}
	for _, sidecarId := range state.SidecarIds() {
		row := state.SidecarRow(sidecarId)
		if rowMemberId, untagged := configRowMember(row); !untagged || rowMemberId != memberId || row.GetRevokedAt() != entry.GetVersion() {
			continue
		}
		if err := effects.CommitRevocation(ctx, sidecarId, entry); err != nil {
			self.log.Warningf("[config]this device's Removes of %s for the MemberRevoke at %d were not committed: %s", sidecarId, entry.GetVersion(), err)
		}
	}
	effects.TrackRevocation(entry.GetVersion())
}

// Watches the log for the entry where this device's MemberRevoke of memberId takes effect, a proposal's completing
// cosign or a pending post's retry, and runs the effects there; the watch ends there, or once the statement's not_after
// passes in the log's time. In memory: a restart drops it, and any writer leaf commits the Removes.
func (self *Sidecar) watchMemberRevoke(authority SidecarAuthority, memberId Id, proposalId []byte, notAfterMs int64) {
	proposals, _ := authority.(SidecarAuthorityProposals)
	var remove func()
	var removeLock sync.Mutex
	done := false
	end := func() {
		removeLock.Lock()
		defer removeLock.Unlock()
		done = true
		if remove != nil {
			// off the follower's goroutine, which runs this callback
			go remove()
		}
	}
	callback := func(entry *SidecarAuthorityEntry) {
		if entry == nil || entry.Pin == nil {
			return
		}
		// inert once it ended: its removal runs off this goroutine, and may come after another entry
		ended := func() bool {
			removeLock.Lock()
			defer removeLock.Unlock()
			return done
		}()
		if ended {
			return
		}
		for _, effect := range entry.Effects {
			if effect.Type != bridge.SignedType_SIGNED_MEMBER_REVOKE {
				continue
			}
			revoke := &bridge.MemberRevoke{}
			if proto.Unmarshal(effect.Body, revoke) != nil || !bytes.Equal(revoke.GetMemberId(), memberId.Bytes()) {
				continue
			}
			if proposalId != nil && proposals != nil && proposals.PendingProposal(proposalId) != nil {
				// another removal of the member landed; this proposal still pends
				continue
			}
			end()
			pin := proto.Clone(entry.Pin).(*bridge.AuthPin)
			// the follower's goroutine must not block on a commit, which ends with the Sidecar's context
			go self.runMemberRevokeEffects(self.ctx, memberId, pin)
			return
		}
		if notAfterMs < entry.TimeMs {
			end()
		}
	}
	added := authority.AddEntryCallback(callback)
	removeLock.Lock()
	defer removeLock.Unlock()
	remove = added
	if done {
		go remove()
	}
}
