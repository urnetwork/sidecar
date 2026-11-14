// AgentRevokePlan (TEAM-M2-18; D-TEAM-27, D-TEAM-31, R-CTX-33): what revoking, suspending or unsuspending an agent
// does, read from the verified state, which `ur admin agents` prints before the person confirms on /dev/tty and §18.5
// shows alike. For an agent a Delegation admitted it names three capabilities apart:
//
//	the agent          its admission, tags and not_after, and whether it is parked, suspended or revoked now
//	the shared key     the Delegation's reader key, which a Suspend or any revocation of one of its agents drops
//	                   (§10.5's key_dropped_at): the agents that then read by their own ReaderWraps, and the repos that
//	                   rotate, those the Delegation holds a key of
//	the authority      the Delegation's admission authority, its not_after and the admissions left, which only a
//	                   compromise revocation of one of its agents ends; any other act leaves it admitting and offers
//	                   `ur admin delegations revoke <delegation_id> [--leaked --since <time|position>]`, since revoking
//	                   an auth key at api stops only its bearer (D-TEAM-31)
//
// A plan is derived, never stored: the act re-reads it at the newest state before it signs. The statements a plan
// signs go through CORE's sidecarAct, confirmed on /dev/tty, with the presence countersignature the log asks for a
// revocation or a Suspend (§7.9's presence row); MCP and hooks sign none of them (D-CORE-13).
//
// Nothing here creates, derives or unwraps a key. On every leg.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What an agent act does.
type AgentAct string

const (
	AgentActRevoke    AgentAct = "revoke"
	AgentActSuspend   AgentAct = "suspend"
	AgentActUnsuspend AgentAct = "unsuspend"
)

var (
	// The sidecar named is no agent this state admits: unknown, or a member's own device, which `ur admin agents`
	// does not act on.
	ErrAgentPlanNoAgent = errors.New("no such agent")
	// The act does nothing at this state: a revocation of a revoked agent, a Suspend of a suspended one, an
	// Unsuspend of one no Suspend names.
	ErrAgentPlanNothing = errors.New("the act changes nothing")
	// No verified log is installed to plan from.
	ErrAgentPlanNoState = errors.New("no verified log to plan from")
)

// What an act on an agent does, at one state.
type AgentRevokePlan struct {
	Act AgentAct
	// The state the plan was read at.
	Pin *bridge.AuthPin
	// The agent: its sidecar, tags, ephemeral flag and not_after, and what holds it now.
	AgentId   Id
	TagIds    []Id
	Ephemeral bool
	NotAfter  time.Time
	Revoked   bool
	Parked    bool
	Suspended bool
	// A revocation for compromise (--compromise), whose P starts at SinceN (--since), 0 for a plain revocation.
	Compromise bool
	SinceN     uint64
	// The Delegation that admitted the agent; nil for an agent a device admitted.
	Delegation *AgentDelegationPlan
	// The command offered when the act leaves the Delegation admitting, empty for none.
	Offer string

	statements []agentPlanStatement
}

// The Delegation part of a plan.
type AgentDelegationPlan struct {
	DelegationId []byte
	// The shared reader key: whether this act retires it, the agents that then read by their own ReaderWraps, and the
	// repos that rotate.
	KeyRetires       bool
	AgentsOnOwnWraps []Id
	ReposRotating    []Id
	// The admission authority: its not_after, the admissions left, and whether this act ends it.
	NotAfter       time.Time
	AdmissionsLeft uint32
	AuthorityEnds  bool
	// The agents of the Delegation parked now, and the confirmations that lifted a park (who lifted what, at which
	// position), from rows that survive any fold (DESIGN-DETAILS 5.7's TEAM-M2-18 note).
	ParkedAgents []Id
	Lifts        []AgentPlanLift
}

// One confirmation that lifted an agent's park.
type AgentPlanLift struct {
	AgentId Id
	// a sidecar_id, a recovery key's hash or a delegation_id, as rows name a signer
	Signer   []byte
	Position uint64
}

// One statement a plan signs.
type agentPlanStatement struct {
	signedType bridge.SignedType
	statement  proto.Message
}

// A Delegation's state as `ur admin delegations` lists it: its keys and its admission authority.
type DelegationState struct {
	DelegationId []byte
	TagIds       []Id
	// The sidecar that declared it, and its entry.
	Signer []byte
	At     uint64
	// Its shared reader key's state: live, or dropped at a position.
	KeyDroppedAt uint64
	// Its admission authority: ended at a position, or admitting until NotAfter with AdmissionsLeft.
	EndedAt        uint64
	NotAfter       time.Time
	AdmissionsLeft uint32
	// Its agents, revoked ones included.
	AgentIds []Id
	// For a forwarding Delegation (§7.9's forwarding row), the sidecar it forwards for, else nil: it has no tags, no
	// agents and no admission authority, and its NotAfter is zero.
	ForwardSidecarId []byte
	// The position of that sidecar's newer forwarding Delegation, which superseded this one; 0 for none.
	SupersededAt uint64
}

// The plan of an act on agentId at this state; for a revocation, compromise asks a cascade from sinceN (0 for the
// agent's own admission).
func (self *ConfigState) AgentRevokePlan(agentId Id, act AgentAct, compromise bool, sinceN uint64) (*AgentRevokePlan, error) {
	row := self.SidecarRow(agentId)
	if row == nil || len(row.GetTagIds()) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrAgentPlanNoAgent, agentId)
	}
	if compromise && act != AgentActRevoke {
		return nil, errors.New("only a revocation is for compromise")
	}
	plan := &AgentRevokePlan{
		Act:        act,
		Pin:        self.Pin(),
		AgentId:    agentId,
		Ephemeral:  row.GetEphemeral(),
		Revoked:    row.GetRevokedAt() != 0,
		Parked:     row.GetParkedAt() != 0,
		Suspended:  self.Suspended(agentId),
		Compromise: compromise,
		SinceN:     sinceN,
	}
	if row.GetNotAfter() != 0 {
		plan.NotAfter = time.UnixMilli(row.GetNotAfter())
	}
	for _, tagBytes := range row.GetTagIds() {
		if tagId, err := IdFromBytes(tagBytes); err == nil {
			plan.TagIds = append(plan.TagIds, tagId)
		}
	}
	switch act {
	case AgentActRevoke:
		if plan.Revoked {
			return nil, ErrAgentPlanNothing
		}
		reason := bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED
		if compromise {
			reason = bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE
			if sinceN == 0 {
				plan.SinceN = row.GetAdmittedAt()
			}
		}
		revoke := &bridge.SidecarRevoke{SidecarId: agentId.Bytes(), Reason: reason}
		if compromise {
			revoke.SinceN = plan.SinceN
		}
		plan.statements = append(plan.statements, agentPlanStatement{signedType: bridge.SignedType_SIGNED_SIDECAR_REVOKE, statement: revoke})
	case AgentActSuspend:
		if plan.Revoked || plan.Suspended {
			return nil, ErrAgentPlanNothing
		}
		suspendId := make([]byte, aclSuspendIdByteCount)
		if _, err := rand.Read(suspendId); err != nil {
			return nil, err
		}
		plan.statements = append(plan.statements, agentPlanStatement{signedType: bridge.SignedType_SIGNED_SUSPEND,
			statement: &bridge.Suspend{Subject: agentId.Bytes(), SuspendId: suspendId}})
	case AgentActUnsuspend:
		if !plan.Suspended {
			return nil, ErrAgentPlanNothing
		}
		for _, suspension := range self.aclRows.GetSuspensions() {
			if bytes.Equal(suspension.GetSubject(), agentId.Bytes()) {
				plan.statements = append(plan.statements, agentPlanStatement{signedType: bridge.SignedType_SIGNED_UNSUSPEND,
					statement: &bridge.Unsuspend{Subject: agentId.Bytes(), SuspendId: bytes.Clone(suspension.GetSuspendId())}})
			}
		}
	default:
		return nil, fmt.Errorf("no act %q", act)
	}

	if delegationId := row.GetDelegationId(); 0 < len(delegationId) {
		delegation := self.Delegation(delegationId)
		if delegation == nil {
			return nil, fmt.Errorf("the agent's Delegation %x is not in this state", delegationId)
		}
		part := &AgentDelegationPlan{DelegationId: bytes.Clone(delegationId)}
		if delegation.GetNotAfter() != 0 {
			part.NotAfter = time.UnixMilli(delegation.GetNotAfter())
		}
		if delegation.GetAdmissions() < delegation.GetMaxAdmits() {
			part.AdmissionsLeft = delegation.GetMaxAdmits() - delegation.GetAdmissions()
		}
		live := delegation.GetEndedAt() == 0 && delegation.GetKeyDroppedAt() == 0
		part.KeyRetires = act != AgentActUnsuspend && live
		part.AuthorityEnds = act == AgentActRevoke && compromise && delegation.GetEndedAt() == 0
		at := time.UnixMilli(self.timeMs)
		for _, sidecarId := range self.SidecarIds() {
			other := self.SidecarRow(sidecarId)
			if !bytes.Equal(other.GetDelegationId(), delegationId) {
				continue
			}
			if other.GetParkedAt() != 0 {
				part.ParkedAgents = append(part.ParkedAgents, sidecarId)
			}
			for _, confirmation := range other.GetConfirmations() {
				if confirmation.GetLiftedPark() {
					part.Lifts = append(part.Lifts, AgentPlanLift{AgentId: sidecarId, Signer: bytes.Clone(confirmation.GetSigner()), Position: confirmation.GetAt()})
				}
			}
			if part.KeyRetires && sidecarId != agentId && other.GetRevokedAt() == 0 {
				part.AgentsOnOwnWraps = append(part.AgentsOnOwnWraps, sidecarId)
			}
		}
		if part.KeyRetires {
			// the rows' repos and the config beside them, which a live Delegation always reaches though the rows hold
			// its row only from its first shrink (QD-762)
			for _, repoId := range configShrinkRepoIds(self) {
				holders, err := KeyHolders(self, repoId, at)
				if err == nil && holders.Contains(GkmHolderDelegation, delegationId) {
					part.ReposRotating = append(part.ReposRotating, repoId)
				}
			}
		}
		plan.Delegation = part
		if !part.AuthorityEnds && delegation.GetEndedAt() == 0 {
			plan.Offer = fmt.Sprintf("ur admin delegations revoke %s [--leaked --since <time|position>]", hex.EncodeToString(delegationId))
		}
	}
	return plan, nil
}

// The Delegations this state holds, ended ones included, as `ur admin delegations` lists them.
func (self *ConfigState) DelegationStates() []*DelegationState {
	states := []*DelegationState{}
	for _, delegation := range self.Delegations() {
		state := &DelegationState{
			DelegationId: bytes.Clone(delegation.GetDelegationId()),
			Signer:       bytes.Clone(delegation.GetSigner()),
			At:           delegation.GetAt(),
			KeyDroppedAt: delegation.GetKeyDroppedAt(),
			EndedAt:      delegation.GetEndedAt(),
			SupersededAt: delegation.GetSupersededAt(),
		}
		if ConfigDelegationRowForwards(delegation) {
			state.ForwardSidecarId = bytes.Clone(delegation.GetForwardSidecarId())
		}
		if delegation.GetNotAfter() != 0 {
			state.NotAfter = time.UnixMilli(delegation.GetNotAfter())
		}
		if delegation.GetAdmissions() < delegation.GetMaxAdmits() {
			state.AdmissionsLeft = delegation.GetMaxAdmits() - delegation.GetAdmissions()
		}
		for _, atom := range delegation.GetTagAtoms() {
			if tagId, err := IdFromBytes(atom); err == nil {
				state.TagIds = append(state.TagIds, tagId)
			}
		}
		for _, sidecarId := range self.SidecarIds() {
			if bytes.Equal(self.SidecarRow(sidecarId).GetDelegationId(), delegation.GetDelegationId()) {
				state.AgentIds = append(state.AgentIds, sidecarId)
			}
		}
		states = append(states, state)
	}
	return states
}

// The DelegationRevoke `ur admin delegations revoke` signs: the Delegation's end, and for a leaked bundle (--leaked)
// a park of what its key admitted from sinceN on (§7.9's cascade). Refuses one this state does not hold or that ended,
// and leaked for a forwarding Delegation, whose revocation carries since_n 0 alone.
func (self *ConfigState) DelegationRevokeStatement(delegationId []byte, leaked bool, sinceN uint64) (*protocol.DelegationRevoke, error) {
	delegation := self.Delegation(delegationId)
	if delegation == nil {
		return nil, fmt.Errorf("no Delegation %x in this state", delegationId)
	}
	if delegation.GetEndedAt() != 0 {
		return nil, ErrAgentPlanNothing
	}
	revoke := &protocol.DelegationRevoke{DelegationId: bytes.Clone(delegationId)}
	if leaked {
		if ConfigDelegationRowForwards(delegation) {
			// it admitted nothing to park, and the log refuses its revocation with a since_n (D-TEAM-33)
			return nil, fmt.Errorf("Delegation %x is a forwarding Delegation, which a revocation ends with no since_n", delegationId)
		}
		revoke.SinceN = max(sinceN, delegation.GetAt())
	}
	return revoke, nil
}

// The position of the first entry this state retains at or after at, for a --since given as a time; false when none.
func (self *ConfigState) positionSince(at time.Time) (uint64, bool) {
	if self.history == nil {
		return 0, false
	}
	view := self.history.view.Load()
	if view == nil {
		return 0, false
	}
	for _, kept := range view.entries {
		if kept != nil && at.UnixMilli() <= kept.entry.GetTimeMs() {
			return kept.n, true
		}
	}
	return 0, false
}

// The verified state of this Sidecar's installed authority, when it is a ConfigClient's: what the agent plans read.
func (self *Sidecar) configState() (*ConfigState, error) {
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok {
		return nil, ErrAgentPlanNoState
	}
	state := authority.client.State()
	if state == nil {
		return nil, ErrAgentPlanNoState
	}
	return state, nil
}

// The plan of an act on an agent at the newest verified state, for `ur admin agents` to print before the person
// confirms.
func (self *Sidecar) PlanAgentAct(agentId Id, act AgentAct, compromise bool, sinceN uint64) (*AgentRevokePlan, error) {
	state, err := self.configState()
	if err != nil {
		return nil, err
	}
	return state.AgentRevokePlan(agentId, act, compromise, sinceN)
}

// Signs and posts an act on an agent as the person confirmed it (origin), re-planned at the newest verified state so
// what is signed is what the log says now; refused through MCP or a hook (D-CORE-13), and with the presence check the
// log asks run by check. Answers the entries' pins.
func (self *Sidecar) SignAgentAct(ctx context.Context, agentId Id, act AgentAct, compromise bool, sinceN uint64, origin SidecarActOrigin, check SidecarPresenceCheck) (*AgentRevokePlan, []*bridge.AuthPin, error) {
	plan, err := self.PlanAgentAct(agentId, act, compromise, sinceN)
	if err != nil {
		return nil, nil, err
	}
	sidecarAct, err := self.newAct(origin)
	if err != nil {
		return nil, nil, err
	}
	for _, statement := range plan.statements {
		if err := sidecarAct.Add(statement.signedType, statement.statement); err != nil {
			return nil, nil, err
		}
	}
	pins, err := sidecarAct.Run(ctx, check)
	return plan, pins, err
}

// The Delegations at the newest verified state, for `ur admin delegations`.
func (self *Sidecar) DelegationStates() ([]*DelegationState, error) {
	state, err := self.configState()
	if err != nil {
		return nil, err
	}
	return state.DelegationStates(), nil
}

// Signs and posts a DelegationRevoke as the person confirmed it (origin): the Delegation ends, and with leaked what its
// key admitted from sinceN, or from the time since, parks. Refused through MCP or a hook.
func (self *Sidecar) SignDelegationRevoke(ctx context.Context, delegationId []byte, leaked bool, sinceN uint64, since time.Time, origin SidecarActOrigin, check SidecarPresenceCheck) ([]*bridge.AuthPin, error) {
	state, err := self.configState()
	if err != nil {
		return nil, err
	}
	if leaked && sinceN == 0 && !since.IsZero() {
		position, ok := state.positionSince(since)
		if !ok {
			return nil, fmt.Errorf("no retained entry at or after %s: name a position", since.UTC().Format(time.RFC3339))
		}
		sinceN = position
	}
	revoke, err := state.DelegationRevokeStatement(delegationId, leaked, sinceN)
	if err != nil {
		return nil, err
	}
	sidecarAct, err := self.newAct(origin)
	if err != nil {
		return nil, err
	}
	if err := sidecarAct.Add(bridge.SignedType_SIGNED_DELEGATION_REVOKE, revoke); err != nil {
		return nil, err
	}
	return sidecarAct.Run(ctx, check)
}

// The agent a name or sidecar_id names at the newest verified state: a sidecar_id's text, else a tagged sidecar whose
// config device name (ConfigNames) is name.
func (self *Sidecar) ResolveAgent(nameOrId string) (Id, error) {
	if agentId, err := ParseId(nameOrId); err == nil {
		return agentId, nil
	}
	return Id{}, fmt.Errorf("%w: %q is no sidecar_id, and names resolve through the config head's names file, which a draft does not read yet", ErrAgentPlanNoAgent, nameOrId)
}
