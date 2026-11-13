//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's team and acl views (D-MCP-3, D-MCP-17, I-7, X10; MCP-M3-14): team_members, team_agents, acl_grants and
// acl_check, R tools, and the only views of the config an agent gets, since MCP never reads the config repo (QD-205):
//
//	team_members  each member: its id and role, and each of its devices' sidecar id and standing (read_only,
//	              ephemeral, revoked, parked, consented, approval-capable, config writer)
//	team_agents   each agent sidecar, tagged or admitted under a Delegation, with its tag ids, sponsor, Delegation,
//	              expiry and standing, and each Delegation with its signer, tags, expiry, end and admissions
//	acl_grants    each rule and activated grant in force for this sidecar (AclEngine.Grants): its id, the requests
//	              rule an activated one came from, its actions by name, its targets as rows carry them (ids, token
//	              paths and public names, never a prefix or a port) and its expiry
//	acl_check     §8.9's local check of one action on one resource for this sidecar: allowed, the grant's id and the
//	              reason by name
//
// Ids and names alone: never a key, K_sock, a ShareSigner seed, an identity, reader or Delegation key, which the rows
// hold beside them (I-7), and the framework's secret check holds every result to that. Each result names the config
// version it was read at, so it is version-aware (D-MCP-13). The rows are the network's, written by its members, so
// a view's trust is member. The same data serves ur://acl/grants (resources.go).

package mcp

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One network as the views read it: its verified config and its grants.
type McpTeamNetwork interface {
	McpToolNetwork
	// The network's verified config state, nil before one verifies.
	ConfigState() *sidecar.ConfigState
	// Every rule and activated grant in force for this sidecar at now: AclEngine.Grants.
	Grants(now time.Time) []sidecar.AclGrantInfo
}

// A hosted Sidecar with its engine and its config client, as the views read them.
type mcpSidecarTeamNetwork struct {
	*mcpSidecarNetwork
	config *sidecar.ConfigClient
}

// The view of hosted, its grants from engine and its config from config.
func McpTeamNetworkOf(hosted *sidecar.Sidecar, engine *sidecar.AclEngine, config *sidecar.ConfigClient) McpTeamNetwork {
	return &mcpSidecarTeamNetwork{mcpSidecarNetwork: &mcpSidecarNetwork{Sidecar: hosted, engine: engine}, config: config}
}

// The config client's verified state.
func (self *mcpSidecarTeamNetwork) ConfigState() *sidecar.ConfigState {
	if self.config == nil {
		return nil
	}
	return self.config.State()
}

// The engine's grants for the hosted sidecar.
func (self *mcpSidecarTeamNetwork) Grants(now time.Time) []sidecar.AclGrantInfo {
	identity := self.Identity()
	if self.engine == nil || identity == nil {
		return nil
	}
	return self.engine.Grants(sidecar.AclSidecarSubject(identity.SidecarId), now)
}

// The views' refusals, each constant.
var (
	errMcpTeamUnavailable = NewMcpError(McpCodeUnavailable, "this daemon has no verified config for the network yet: run ur status in your own terminal", true)
	errMcpAclAction       = NewMcpError(McpCodeInvalidArguments, "action is one of dial, listen, route, read, write, admin, deposit, publish and send", false)
	errMcpAclResource     = NewMcpError(McpCodeInvalidArguments, "resource is a policy's dst form: sock:, ip:, evs:, a subject or *", false)
	errMcpTeamFilter      = NewMcpError(McpCodeInvalidArguments, "a filter names an id", false)
)

// The views' network, refused where the daemon holds none.
func mcpTeamNetworkOf(call *McpCall) (McpTeamNetwork, *sidecar.ConfigState, error) {
	network, ok := call.Network.(McpTeamNetwork)
	if !ok {
		return nil, nil, errMcpTeamUnavailable
	}
	state := network.ConfigState()
	if state == nil {
		return nil, nil, errMcpTeamUnavailable
	}
	return network, state, nil
}

// The time a call reads at: its server's clock.
func mcpCallNow(call *McpCall) time.Time {
	if call == nil || call.Session == nil || call.Session.server == nil {
		return sidecar.RealClock{}.Now()
	}
	return call.Session.server.clock.Now()
}

// An id's text, or "" for bytes that are no id.
func mcpIdText(idBytes []byte) string {
	id, err := sidecar.IdFromBytes(idBytes)
	if err != nil {
		return ""
	}
	return id.String()
}

// An optional id filter, the zero id for none.
func mcpIdFilter(text string) (sidecar.Id, error) {
	if text == "" {
		return sidecar.Id{}, nil
	}
	id, err := sidecar.ParseId(text)
	if err != nil {
		return sidecar.Id{}, errMcpTeamFilter
	}
	return id, nil
}

// A role's name: owner, admin, network_admin, it_admin, billing_admin, auditor or member.
func mcpRoleName(role bridge.MemberRole) string {
	return strings.TrimPrefix(strings.ToLower(role.String()), "member_role_")
}

// team_members' arguments: an optional member to list alone.
type mcpTeamMembersIn struct {
	Member string `json:"member,omitempty"`
}

// One device of a member.
type mcpTeamDeviceOut struct {
	SidecarId       string `json:"sidecar_id"`
	ReadOnly        bool   `json:"read_only"`
	Ephemeral       bool   `json:"ephemeral"`
	Revoked         bool   `json:"revoked"`
	Parked          bool   `json:"parked"`
	Consented       bool   `json:"consented"`
	ApprovalCapable bool   `json:"approval_capable"`
	ConfigWriter    bool   `json:"config_writer"`
}

// One member.
type mcpTeamMemberOut struct {
	MemberId string              `json:"member_id"`
	Role     string              `json:"role"`
	Devices  []*mcpTeamDeviceOut `json:"devices"`
}

// team_members' data.
type mcpTeamMembersOut struct {
	// The config version it was read at.
	Version uint64              `json:"version"`
	Members []*mcpTeamMemberOut `json:"members"`
}

// team_agents' arguments: an optional sponsor whose agents alone are listed.
type mcpTeamAgentsIn struct {
	Sponsor string `json:"sponsor,omitempty"`
}

// One agent sidecar.
type mcpTeamAgentOut struct {
	SidecarId       string   `json:"sidecar_id"`
	TagIds          []string `json:"tag_ids"`
	SponsorMemberId string   `json:"sponsor_member_id,omitempty"`
	DelegationId    string   `json:"delegation_id,omitempty"`
	Ephemeral       bool     `json:"ephemeral"`
	Revoked         bool     `json:"revoked"`
	Parked          bool     `json:"parked"`
	// ms since the epoch, 0 for none
	NotAfterMillis int64 `json:"not_after_millis,omitempty"`
}

// One Delegation.
type mcpTeamDelegationOut struct {
	DelegationId string   `json:"delegation_id"`
	SignerId     string   `json:"signer_id"`
	TagIds       []string `json:"tag_ids"`
	// ms since the epoch, 0 for none
	NotAfterMillis int64  `json:"not_after_millis,omitempty"`
	Ended          bool   `json:"ended"`
	Admissions     uint32 `json:"admissions"`
	MaxAdmits      uint32 `json:"max_admits"`
	Forwarding     bool   `json:"forwarding"`
}

// team_agents' data.
type mcpTeamAgentsOut struct {
	Version     uint64                  `json:"version"`
	Agents      []*mcpTeamAgentOut      `json:"agents"`
	Delegations []*mcpTeamDelegationOut `json:"delegations"`
}

// acl_grants' arguments: an optional action whose grants alone are listed.
type mcpAclGrantsIn struct {
	Action string `json:"action,omitempty"`
}

// One grant.
type mcpAclGrantOut struct {
	GrantId      string   `json:"grant_id"`
	SourceRuleId string   `json:"source_rule_id,omitempty"`
	Actions      []string `json:"actions"`
	Targets      []string `json:"targets"`
	// ms since the epoch, 0 for none
	ExpiresMillis int64 `json:"expires_millis,omitempty"`
	PortsLimited  bool  `json:"ports_limited,omitempty"`
}

// acl_grants' data.
type mcpAclGrantsOut struct {
	Version uint64            `json:"version"`
	Grants  []*mcpAclGrantOut `json:"grants"`
}

// acl_check's arguments.
type mcpAclCheckIn struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// acl_check's data.
type mcpAclCheckOut struct {
	Allowed bool   `json:"allowed"`
	GrantId string `json:"grant_id,omitempty"`
	Reason  string `json:"reason"`
}

// A target as rows carry it: ids, token paths and public names.
func mcpAclTargetText(target *protocol.AclTarget) string {
	switch {
	case 0 < len(target.GetAtom()):
		return "atom:" + hex.EncodeToString(target.GetAtom())
	case 0 < len(target.GetSidecarId()):
		return "sidecar:" + mcpIdText(target.GetSidecarId())
	case 0 < len(target.GetNetworkId()):
		return "network:" + mcpIdText(target.GetNetworkId())
	case 0 < len(target.GetRepoId()):
		return "evs:" + mcpIdText(target.GetRepoId())
	case 0 < len(target.GetSocketTokens()):
		tokens := []string{}
		for _, token := range target.GetSocketTokens() {
			tokens = append(tokens, hex.EncodeToString(token))
		}
		text := "sock-token:" + strings.Join(tokens, "/")
		if target.GetSocketPrefix() {
			text += "/*"
		}
		return text
	case target.GetPublicName() != "":
		return "name:" + target.GetPublicName()
	case target.GetMailSend():
		return "mail:send"
	case 0 < len(target.GetClientId()):
		return "client:" + mcpIdText(target.GetClientId())
	}
	return "*"
}

// The members of state, filtered to one where memberFilter is set, each with its untagged devices.
func mcpTeamMembers(state *sidecar.ConfigState, memberFilter sidecar.Id) (*mcpTeamMembersOut, error) {
	acl, err := state.Acl()
	if err != nil {
		return nil, errMcpTeamUnavailable
	}
	out := &mcpTeamMembersOut{Version: state.Pin().GetVersion(), Members: []*mcpTeamMemberOut{}}
	sidecarIds := state.SidecarIds()
	slices.SortFunc(sidecarIds, sidecar.Id.Cmp)
	memberIds := state.MemberIds()
	slices.SortFunc(memberIds, sidecar.Id.Cmp)
	for _, memberId := range memberIds {
		if memberFilter != (sidecar.Id{}) && memberId != memberFilter {
			continue
		}
		row := state.Member(memberId)
		if row == nil {
			continue
		}
		member := &mcpTeamMemberOut{MemberId: memberId.String(), Role: mcpRoleName(row.GetRole()), Devices: []*mcpTeamDeviceOut{}}
		for _, sidecarId := range sidecarIds {
			facts := state.Sidecar(sidecarId)
			if facts == nil || facts.MemberId != memberId || 0 < len(facts.TagIds) {
				continue
			}
			member.Devices = append(member.Devices, &mcpTeamDeviceOut{
				SidecarId:       sidecarId.String(),
				ReadOnly:        state.ReadOnly(sidecarId),
				Ephemeral:       facts.Ephemeral,
				Revoked:         facts.Row.GetRevokedAt() != 0,
				Parked:          state.Parked(sidecarId),
				Consented:       acl.ConsentedFor(sidecarId, memberId),
				ApprovalCapable: acl.ApprovalCapable(sidecarId) && acl.ConsentedFor(sidecarId, memberId),
				ConfigWriter:    state.IsConfigWriter(sidecarId),
			})
		}
		out.Members = append(out.Members, member)
	}
	return out, nil
}

// The agent sidecars and Delegations of state, filtered to one sponsor's where sponsorFilter is set.
func mcpTeamAgents(state *sidecar.ConfigState, sponsorFilter sidecar.Id) *mcpTeamAgentsOut {
	out := &mcpTeamAgentsOut{Version: state.Pin().GetVersion(), Agents: []*mcpTeamAgentOut{}, Delegations: []*mcpTeamDelegationOut{}}
	sidecarIds := state.SidecarIds()
	slices.SortFunc(sidecarIds, sidecar.Id.Cmp)
	for _, sidecarId := range sidecarIds {
		facts := state.Sidecar(sidecarId)
		if facts == nil || (len(facts.TagIds) == 0 && len(facts.Row.GetDelegationId()) == 0) {
			continue
		}
		sponsor, sponsored := state.Sponsor(sidecarId)
		if sponsorFilter != (sidecar.Id{}) && (!sponsored || sponsor != sponsorFilter) {
			continue
		}
		agent := &mcpTeamAgentOut{
			SidecarId:      sidecarId.String(),
			TagIds:         []string{},
			Ephemeral:      facts.Ephemeral,
			Revoked:        facts.Row.GetRevokedAt() != 0,
			Parked:         state.Parked(sidecarId),
			NotAfterMillis: facts.Row.GetNotAfter(),
		}
		for _, tagId := range facts.TagIds {
			agent.TagIds = append(agent.TagIds, tagId.String())
		}
		if sponsored {
			agent.SponsorMemberId = sponsor.String()
		}
		if delegationId := facts.Row.GetDelegationId(); 0 < len(delegationId) {
			agent.DelegationId = hex.EncodeToString(delegationId)
		}
		out.Agents = append(out.Agents, agent)
	}
	for _, delegation := range state.Delegations() {
		if sponsorFilter != (sidecar.Id{}) {
			continue
		}
		listed := &mcpTeamDelegationOut{
			DelegationId:   hex.EncodeToString(delegation.GetDelegationId()),
			SignerId:       mcpIdText(delegation.GetSigner()),
			TagIds:         []string{},
			NotAfterMillis: delegation.GetNotAfter(),
			Ended:          delegation.GetEndedAt() != 0,
			Admissions:     delegation.GetAdmissions(),
			MaxAdmits:      delegation.GetMaxAdmits(),
			Forwarding:     0 < len(delegation.GetForwardSidecarId()),
		}
		for _, atom := range delegation.GetTagAtoms() {
			listed.TagIds = append(listed.TagIds, mcpIdText(atom))
		}
		out.Delegations = append(out.Delegations, listed)
	}
	return out
}

// The grants in force for this sidecar, filtered to one action where action is set.
func mcpAclGrants(network McpTeamNetwork, state *sidecar.ConfigState, action protocol.AclAction, now time.Time) *mcpAclGrantsOut {
	out := &mcpAclGrantsOut{Version: state.Pin().GetVersion(), Grants: []*mcpAclGrantOut{}}
	for _, grant := range network.Grants(now) {
		if action != protocol.AclAction_ACL_ACTION_UNSPECIFIED && !slices.Contains(grant.Actions, action) {
			continue
		}
		listed := &mcpAclGrantOut{
			GrantId:       hex.EncodeToString(grant.GrantId),
			Actions:       []string{},
			Targets:       []string{},
			ExpiresMillis: grant.ExpiresMs,
			PortsLimited:  grant.PortsLimited,
		}
		if 0 < len(grant.SourceRuleId) {
			listed.SourceRuleId = hex.EncodeToString(grant.SourceRuleId)
		}
		for _, granted := range grant.Actions {
			listed.Actions = append(listed.Actions, sidecar.AclActionName(granted))
		}
		for _, target := range grant.Targets {
			listed.Targets = append(listed.Targets, mcpAclTargetText(target))
		}
		out.Grants = append(out.Grants, listed)
	}
	return out
}

// ur://acl/grants' data: the grants, the members and the network's registered keys, ids only.
type mcpAclGrantsResourceOut struct {
	Version uint64              `json:"version"`
	Grants  []*mcpAclGrantOut   `json:"grants"`
	Members []*mcpTeamMemberOut `json:"members"`
	Keys    []*mcpAclKeyOut     `json:"keys"`
}

// One registered key, by its id: never the key.
type mcpAclKeyOut struct {
	KeyId    string `json:"key_id"`
	Purpose  string `json:"purpose"`
	MemberId string `json:"member_id"`
	Revoked  bool   `json:"revoked"`
	// ms since the epoch, 0 for none
	NotAfterMillis int64 `json:"not_after_millis,omitempty"`
}

// The data ur://acl/grants carries: grants, membership and key changes as ids.
func mcpAclGrantsView(call *McpCall, result *McpResult) (any, error) {
	network, state, err := mcpTeamNetworkOf(call)
	if err != nil {
		return nil, err
	}
	result.Member()
	result.SetSource("config:acl_grants")
	members, err := mcpTeamMembers(state, sidecar.Id{})
	if err != nil {
		return nil, err
	}
	out := &mcpAclGrantsResourceOut{
		Version: state.Pin().GetVersion(),
		Grants:  mcpAclGrants(network, state, protocol.AclAction_ACL_ACTION_UNSPECIFIED, time.UnixMilli(state.TimeMs())).Grants,
		Members: members.Members,
		Keys:    []*mcpAclKeyOut{},
	}
	for _, memberId := range state.MemberIds() {
		for _, key := range state.MemberKeys(memberId) {
			out.Keys = append(out.Keys, &mcpAclKeyOut{
				KeyId:          hex.EncodeToString(key.GetKeyId()),
				Purpose:        strings.TrimPrefix(strings.ToLower(key.GetPurpose().String()), "key_purpose_"),
				MemberId:       memberId.String(),
				Revoked:        key.GetRevokedAt() != 0,
				NotAfterMillis: key.GetNotAfter(),
			})
		}
	}
	slices.SortFunc(out.Keys, func(a *mcpAclKeyOut, b *mcpAclKeyOut) int { return strings.Compare(a.KeyId, b.KeyId) })
	return out, nil
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addTeamTools(catalog)
	})
}

// Registers the four views on catalog.
func addTeamTools(catalog *McpCatalog) {
	AddTool(catalog, &McpToolSpec[mcpTeamMembersIn]{
		Name:        "team_members",
		Tier:        McpTierRead,
		Description: "Lists the network's members by id and role, each with its devices' sidecar ids and standing, from the verified config.",
		Access:      func(call *McpCall, in *mcpTeamMembersIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpTeamMembersIn, result *McpResult) (*mcpTeamMembersOut, error) {
		memberFilter, err := mcpIdFilter(in.Member)
		if err != nil {
			return nil, err
		}
		_, state, err := mcpTeamNetworkOf(call)
		if err != nil {
			return nil, err
		}
		result.Member()
		result.SetSource("config:members")
		result.SetResource(McpAclGrantsUri)
		return mcpTeamMembers(state, memberFilter)
	})

	AddTool(catalog, &McpToolSpec[mcpTeamAgentsIn]{
		Name:        "team_agents",
		Tier:        McpTierRead,
		Description: "Lists the network's agent sidecars, tagged or admitted under a Delegation, and its Delegations, by id, from the verified config.",
		Access:      func(call *McpCall, in *mcpTeamAgentsIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpTeamAgentsIn, result *McpResult) (*mcpTeamAgentsOut, error) {
		sponsorFilter, err := mcpIdFilter(in.Sponsor)
		if err != nil {
			return nil, err
		}
		_, state, err := mcpTeamNetworkOf(call)
		if err != nil {
			return nil, err
		}
		result.Member()
		result.SetSource("config:agents")
		return mcpTeamAgents(state, sponsorFilter), nil
	})

	AddTool(catalog, &McpToolSpec[mcpAclGrantsIn]{
		Name:        "acl_grants",
		Tier:        McpTierRead,
		Description: "Lists the rules and activated grants in force for this sidecar: ids, actions, targets as ids, token paths and public names, and expiries.",
		Access:      func(call *McpCall, in *mcpAclGrantsIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpAclGrantsIn, result *McpResult) (*mcpAclGrantsOut, error) {
		action := protocol.AclAction_ACL_ACTION_UNSPECIFIED
		if in.Action != "" {
			parsed, err := sidecar.ParseAclAction(in.Action)
			if err != nil {
				return nil, errMcpAclAction
			}
			action = parsed
		}
		network, state, err := mcpTeamNetworkOf(call)
		if err != nil {
			return nil, err
		}
		result.Member()
		result.SetSource("config:acl_grants")
		result.SetResource(McpAclGrantsUri)
		return mcpAclGrants(network, state, action, mcpCallNow(call)), nil
	})

	AddTool(catalog, &McpToolSpec[mcpAclCheckIn]{
		Name:        "acl_check",
		Tier:        McpTierRead,
		Description: "Checks whether the network's policy lets this sidecar take one action on one resource now, naming the grant and the reason.",
		Access:      func(call *McpCall, in *mcpAclCheckIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpAclCheckIn, result *McpResult) (*mcpAclCheckOut, error) {
		action, err := sidecar.ParseAclAction(in.Action)
		if err != nil {
			return nil, errMcpAclAction
		}
		resource, err := sidecar.ParseAclResource(in.Resource)
		if err != nil {
			return nil, errMcpAclResource
		}
		network, ok := mcpToolNetworkOf(call)
		if !ok {
			return nil, errMcpNoToolNetwork
		}
		check, installed := network.Allow(action, resource, mcpCallNow(call))
		if !installed {
			return nil, errMcpNoPolicy
		}
		result.SetSource("acl:check")
		out := &mcpAclCheckOut{Allowed: check.Allowed, Reason: check.Reason.String()}
		if 0 < len(check.GrantId) {
			out.GrantId = hex.EncodeToString(check.GrantId)
		}
		return out, nil
	})
}
