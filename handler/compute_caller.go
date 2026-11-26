// Who calls an api/compute route (DESIGN-COMPUTE §9.10, §14.3; BAL-M12-06): ComputeApiCaller, which CSRV's mount of
// the routes (C§14.3) fills from the session and the api's verified config state, never from the request, and the
// rights §9.10's table gives it:
//
//	role (DESIGN §7.5)      buy, redeem, set auto-renew       see charges and the spend view
//	Owner                   yes                               all
//	Billing admin           yes                               all
//	Admin                   no                                all
//	Network admin           no                                all
//	IT admin                no                                all
//	Auditor                 no                                all
//	Member                  only with the policy's            their own and their agents'
//	                        compute:buy grant
//	agent, tagged sidecar,  never                             none (an agent on its person's consented device
//	enclave                                                   reads that person's spend view through compute_spend,
//	                                                          on the person's surface's rights)
//
// A person's surface is an untagged member device, admitted under its member, neither an enclave nor admitted by a
// Delegation, or the network's own credential, the account's login as Pro's routes take it, which is the network's
// and never a sidecar's token; an agent's or MCP's scoped token (DESIGN §7.8) is never one. The spend view asks more of
// a device: the person's consented device, untagged and neither ephemeral nor Delegation-admitted (DESIGN §8.5, owner
// decision 126; Q-BAL-11).
//
// compute:buy is CACL's grant check (C§16.2), which RegisterComputeBuyGrant takes; until CACL registers it, Owners and
// Billing admins alone buy, and a Member's grant is never read (fails closed).

package handler

import (
	"errors"
	"fmt"

	operator "github.com/urnetwork/operator-core"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What credential a call came with.
type ComputeApiCredential int

const (
	// A sidecar's token (DESIGN §7.8): the calling device, by its verified row.
	ComputeApiCredentialSidecar ComputeApiCredential = 1
	// The network's own credential, the account's login as Pro's routes take it.
	ComputeApiCredentialNetwork ComputeApiCredential = 2
	// A token scoped to an agent or an MCP session (DESIGN §7.8): never a person's surface.
	ComputeApiCredentialAgent ComputeApiCredential = 3
)

// Who calls a route, as the mount verified it. The zero value is no one: every right refuses.
type ComputeApiCaller struct {
	Credential ComputeApiCredential
	NetworkId  operator.Id
	// The calling sidecar; nil for the network's credential.
	SidecarId *operator.Id
	// The member the sidecar's admission names, or the network credential's member; nil for a tagged sidecar.
	MemberId *operator.Id
	// The member's role (DESIGN §7.5): for a sidecar, its member's in the verified config; for the network's
	// credential, its user's in the network, the Owner of a personal network.
	Role bridge.MemberRole
	// Admitted with tags: a server, a CI runner, a cloud agent.
	Tagged bool
	// An agents' enclave's incarnation (SIDECAR_CAPABILITY_ENCLAVE).
	Enclave   bool
	Ephemeral bool
	// Admitted by a Delegation (an auth key's agent).
	DelegationAdmitted bool
	// Consented for its member (DESIGN §8.5's consented(d, M)).
	Consented bool
}

// The roles that see the network's charges and spend view (§9.10).
var computeApiNetworkViewRoles = []bridge.MemberRole{
	bridge.MemberRole_MEMBER_ROLE_OWNER,
	bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN,
	bridge.MemberRole_MEMBER_ROLE_ADMIN,
	bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN,
	bridge.MemberRole_MEMBER_ROLE_IT_ADMIN,
	bridge.MemberRole_MEMBER_ROLE_AUDITOR,
}

// CACL's compute:buy check for a caller (C§16.2), nil until CACL registers it.
var computeBuyGrant func(caller *ComputeApiCaller) bool

// Registers CACL's compute:buy check from an init function in its own file. A second registration, or a nil one, is
// a build error, which panics.
func RegisterComputeBuyGrant(grant func(caller *ComputeApiCaller) bool) {
	if grant == nil || computeBuyGrant != nil {
		panic("compute: the compute:buy grant is registered once")
	}
	computeBuyGrant = grant
}

// Whether the call comes from a person's surface: an untagged member device, neither an enclave nor admitted by a
// Delegation, or the network's own credential.
func (self *ComputeApiCaller) personSurface() bool {
	switch self.Credential {
	case ComputeApiCredentialNetwork:
		return true
	case ComputeApiCredentialSidecar:
		return self.SidecarId != nil && self.MemberId != nil && !self.Tagged && !self.Enclave && !self.DelegationAdmitted
	}
	return false
}

// Whether the caller may buy credits, redeem a promotion code and set auto-renew (§9.10): an Owner or a Billing admin,
// or a member the policy grants compute:buy, from a person's surface; never an agent, MCP, a tagged sidecar or an
// enclave.
func (self *ComputeApiCaller) MayBuy() bool {
	if !self.personSurface() {
		return false
	}
	switch self.Role {
	case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN:
		return true
	case bridge.MemberRole_MEMBER_ROLE_UNSPECIFIED:
		return false
	}
	return computeBuyGrant != nil && computeBuyGrant(self)
}

// Whether the caller sees the network's charges, statements and spend view: an Owner, Billing admin, Admin, Network
// admin, IT admin or Auditor, from a person's surface.
func (self *ComputeApiCaller) SeesNetwork() bool {
	if !self.personSurface() {
		return false
	}
	for _, role := range computeApiNetworkViewRoles {
		if self.Role == role {
			return true
		}
	}
	return false
}

// The member whose charges a Member sees, what counts to them and their agents (§9.10, §9.13); false for a caller who
// sees the network's, or none.
func (self *ComputeApiCaller) SeesMember() (operator.Id, bool) {
	if !self.personSurface() || self.SeesNetwork() || self.MemberId == nil || self.Role != bridge.MemberRole_MEMBER_ROLE_MEMBER {
		return operator.Id{}, false
	}
	return *self.MemberId, true
}

// Whether the call comes from the person's consented device: a sidecar, untagged, neither an enclave nor ephemeral nor
// Delegation-admitted, consented for its member (DESIGN §8.5, owner decision 126). What the spend view asks (§14.3).
func (self *ComputeApiCaller) ConsentedDevice() bool {
	return self.Credential == ComputeApiCredentialSidecar && self.SidecarId != nil && self.MemberId != nil &&
		!self.Tagged && !self.Enclave && !self.Ephemeral && !self.DelegationAdmitted && self.Consented
}

// Whether the caller holds one of roles, from a person's surface.
func (self *ComputeApiCaller) hasRole(roles ...bridge.MemberRole) bool {
	if !self.personSurface() {
		return false
	}
	for _, role := range roles {
		if self.Role == role {
			return true
		}
	}
	return false
}

// The verified facts a sidecar's rights come from, as the api's gate cache holds them (sidecar/acl_gate.go): its row,
// its member's row and whether it is consented. ComputeApiStateOf gives the real one; a test gives its own.
type ComputeApiVerifiedState interface {
	SidecarRow(sidecarId sidecar.Id) *bridge.SidecarRow
	Member(memberId sidecar.Id) *bridge.MemberRow
	Consented(sidecarId sidecar.Id) bool
}

// A sidecar whose row the verified state lacks, revoked or parked: no caller.
var ErrComputeApiCallerUnknown = errors.New("compute api: the sidecar is not admitted in the verified state")

// A gate snapshot's config and acl parts as one verified state.
type computeApiGateState struct {
	config *sidecar.ConfigState
	acl    *sidecar.AclState
}

func (self *computeApiGateState) SidecarRow(sidecarId sidecar.Id) *bridge.SidecarRow {
	return self.config.SidecarRow(sidecarId)
}

func (self *computeApiGateState) Member(memberId sidecar.Id) *bridge.MemberRow {
	return self.config.Member(memberId)
}

func (self *computeApiGateState) Consented(sidecarId sidecar.Id) bool {
	return self.acl.Consented(sidecarId)
}

// The verified state of a network the gate cache loaded; an error where the snapshot holds none.
func ComputeApiStateOf(snapshot *sidecar.AclGateSnapshot) (ComputeApiVerifiedState, error) {
	if snapshot == nil || snapshot.Config == nil || snapshot.Acl == nil {
		return nil, fmt.Errorf("%w: no verified state is loaded", ErrComputeApiCallerUnknown)
	}
	return &computeApiGateState{config: snapshot.Config, acl: snapshot.Acl}, nil
}

// The caller a sidecar's token makes, every right from state: its row's member, tags, ephemeral mark, Delegation and
// enclave capability, its member's role and its consent. A sidecar state lacks, revoked or parked, is refused.
func NewComputeApiSidecarCaller(state ComputeApiVerifiedState, networkId operator.Id, sidecarId operator.Id) (*ComputeApiCaller, error) {
	row := state.SidecarRow(sidecarId)
	if row == nil || row.GetRevokedAt() != 0 || row.GetParkedAt() != 0 {
		return nil, ErrComputeApiCallerUnknown
	}
	caller := &ComputeApiCaller{
		Credential:         ComputeApiCredentialSidecar,
		NetworkId:          networkId,
		SidecarId:          &sidecarId,
		Tagged:             0 < len(row.GetTagIds()),
		Enclave:            row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_ENCLAVE) != 0,
		Ephemeral:          row.GetEphemeral(),
		DelegationAdmitted: 0 < len(row.GetDelegationId()),
		Consented:          state.Consented(sidecarId),
	}
	if !caller.Tagged && len(row.GetMemberId()) != 0 {
		memberId, err := sidecar.IdFromBytes(row.GetMemberId())
		if err != nil {
			return nil, fmt.Errorf("%w: its member id: %w", ErrComputeApiCallerUnknown, err)
		}
		member := state.Member(memberId)
		if member == nil {
			return nil, fmt.Errorf("%w: its member is not in the verified state", ErrComputeApiCallerUnknown)
		}
		memberIdCopy := operator.Id(memberId)
		caller.MemberId = &memberIdCopy
		caller.Role = member.GetRole()
	}
	return caller, nil
}
