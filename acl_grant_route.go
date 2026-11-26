// The one reader of an activated route grant's sealed detail, and its dial counterpart below (§8.8's folded grants
// and Saving, §17.8; owner decisions 220 and 679; QD-003, QD-740, QD-1164). A requested route grant keeps only ids in
// the clear: its prefixes and ports ride its CanonicalAction's sealed_detail. So every reader that judges what such a
// grant reaches opens the detail under the config keys it holds and reads it here, one way: the save's ip: tests
// (acl_tests.go), the bridge compile's sender table and host rows (bridge_compile_grants.go), and AclEngine's
// AllowRoute and Check (acl_engine.go), which ur bridge's previews and MCP's acl_check ask. An accept the save counts
// is then one the compile serves and the engine answers, at the same prefixes and ports:
//
//	prefixes   the detail's cidrs and its ip: destinations, masked, each once
//	ports      the ports its sidecar destinations name, taken together since rows mark ports for the rule whole, each
//	           once; none means every port
//	unsealed   a grant whose action seals no detail, one from before version 4 (record_action_rules.go's version-4
//	           grants always seal one), which its fold marks by limiting no ports (acl_grant.go): it names nothing any
//	           reader can read, so it reaches nothing anywhere, the closed direction QD-003 left every activated grant
//	           in, and no opener is asked
//	unread     a detail this reader cannot read gives nothing here either, with why: no opener, an action the state
//	           does not hold, a generation whose key it does not hold, a detail that does not open or does not hold
//	           to its action, a prefix or destination that does not read, or a target_port naming no protocol. What a
//	           reader makes of that is its own: the compile waits or alarms, the engine reaches nothing, and the save,
//	           which judges what a device holding the key may serve, holds the grant indeterminate (QD-1164)
//
// A grant whose detail reads but names no prefix routes by its subjects, as a document rule naming none does
// (aclRouteBySubject; owner decision 575). The opener over a state is aclStateGrantDetails: each grant's action as the
// state holds it, or as the base's head's folds hold it for a reader that joined after the grant landed
// (ConfigState.grantActionsAtHead), opened in the state's network under the config repo's key of the generation it
// names. testHookSecret runs where the detail's key derives, inside OpenConfigBody.
//
// Its dial counterpart reads the same detail for the ports a port-limited activated dial grant opens at each sidecar
// (aclGrantDialPortsOf, QD-740), one way for the bridge compile's host dial rows (bridge_compile_grants.go) and a
// forward's route (ConfigState.grantPortRule), and AclEngine's AllowInbound, Check and ActiveGrant (acl_engine.go,
// acl_grant_file.go), ActiveGrant reading a forward's own asked ports from its detail by it too:
//
//	ports      each sidecar:<id>:<protocol>:<port> of the detail's grant_dst, at that sidecar alone, a target_port
//	           keeping only the destinations whose port it is; none at a sidecar opens nothing there, and an ip:
//	           destination opens no port
//	unsealed   a dial grant whose action seals no detail limits no ports: its rows' reach stands at every port, as a
//	           document rule's with no ip port list does, and no opener is asked
//	unread     a detail that does not open here, for the reasons above, which aclOpenGrantDetail names, opens no port
//	           anywhere, the closed direction
//
// On every leg, the ios_extension legs' included, whose forwarding role compiles: root Id, no connect type.
// Package-level functions are safe for concurrent use; an opener is used by one reader at a time.

package sidecar

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// An activated grant's sealed detail did not open here: its action does not parse, or a reader's opener could not
	// read it. A reader holds such a grant to nothing, and a save's ip: check it may apply to is indeterminate.
	ErrAclGrantDetailUnread = errors.New("acl: an activated grant's detail did not open")
	// The state holds no action for an activated grant its rows name: neither the log it applied nor the base's head's
	// folds hold the GrantActivate, so the detail is not here to open.
	ErrAclGrantActionNotHeld = fmt.Errorf("%w: the state holds no action for the grant", ErrAclGrantDetailUnread)
)

// Opens an activated grant's sealed detail at the verified base a reader stands on (owner decision 220, QD-003,
// QD-1164): the CanonicalActionDetail its action's sealed_detail opens to under the device's config keys, held to that
// action. grantId is the grant's rule id in the rows. nil with no error for an action that seals none. An error says
// it did not open here: ErrAclGrantActionNotHeld, ErrAclGrantDetailUnread, or the opener's own
// (ErrConfigSealGenerationMissing, ErrConfigSealInvalid, ErrCanonicalActionDetailInvalid).
type AclGrantDetails interface {
	GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error)
}

// The details a verified state opens (the file's comment), each action by grant id, in the state's network under the
// config repo's key of the generation it names, which repoKeyAt answers, nil holding none.
type aclStateGrantDetails struct {
	actions   map[string][]byte
	networkId Id
	repoKeyAt func(generation uint64) *EvsRepoKey
}

// The details state opens at the base head stands on, head nil for one not read yet; nil for no state.
func newAclStateGrantDetails(state *ConfigState, head *ConfigHead, repoKeyAt func(generation uint64) *EvsRepoKey) AclGrantDetails {
	if state == nil {
		return nil
	}
	return &aclStateGrantDetails{actions: state.grantActionsAtHead(head), networkId: state.NetworkId(), repoKeyAt: repoKeyAt}
}

// See AclGrantDetails.
func (self *aclStateGrantDetails) GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error) {
	encoded := self.actions[string(grantId)]
	if len(encoded) == 0 {
		return nil, ErrAclGrantActionNotHeld
	}
	action, err := ParseStoredCanonicalAction(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAclGrantDetailUnread, err)
	}
	return OpenCanonicalActionDetail(action, self.networkId, self.repoKeyAt)
}

// The subject a grant's action names and the generation its detail is sealed under, which a reader names in its alarm
// or waits for; the zero id and 0 where the state holds no action for it or it does not parse.
func (self *aclStateGrantDetails) sealing(grantId []byte) (Id, uint64) {
	action, err := ParseStoredCanonicalAction(self.actions[string(grantId)])
	if err != nil {
		return Id{}, 0
	}
	subjectId, _ := IdFromBytes(action.Action.GetSubject())
	generation, _ := ConfigSealedGeneration(action.Action.GetSealedDetail())
	return subjectId, generation
}

// Why an activated route grant gives no route here (aclReadGrantRoute), none for one whose detail read.
type aclGrantRouteUnread int

const (
	aclGrantRouteUnreadNone aclGrantRouteUnread = iota
	// its action seals no detail: it reaches nothing anywhere
	aclGrantRouteUnreadUnsealed
	// the reader holds no opener
	aclGrantRouteUnreadNoOpener
	// the state holds no action for it
	aclGrantRouteUnreadNotHeld
	// sealed to a generation whose key the reader does not hold
	aclGrantRouteUnreadGeneration
	// rides an action that does not parse, or does not open under the key held, or does not hold to its action
	aclGrantRouteUnreadNotOpened
	// opens to no detail, its rule limiting ports
	aclGrantRouteUnreadMissing
	// holds a prefix that does not read
	aclGrantRouteUnreadPrefix
	// holds a destination that does not read
	aclGrantRouteUnreadDestination
	// names a target_port with no protocol, so its ports are not read whole
	aclGrantRouteUnreadPortProtocol
)

// What follows "its sealed detail" in an alarm or a failure, which names no prefix, port or key (I-13).
func (self aclGrantRouteUnread) String() string {
	switch self {
	case aclGrantRouteUnreadNone:
		return "reads"
	case aclGrantRouteUnreadUnsealed:
		return "is none: its action seals no detail"
	case aclGrantRouteUnreadNoOpener:
		return "has no opener here"
	case aclGrantRouteUnreadNotHeld:
		return "is not held here: the state keeps no action for it"
	case aclGrantRouteUnreadGeneration:
		return "needs a config key generation this device does not hold"
	case aclGrantRouteUnreadNotOpened:
		return "does not open here"
	case aclGrantRouteUnreadMissing:
		return "is missing"
	case aclGrantRouteUnreadPrefix:
		return "holds a prefix that does not read"
	case aclGrantRouteUnreadDestination:
		return "holds a destination that does not read"
	case aclGrantRouteUnreadPortProtocol:
		return "names a port with no protocol"
	}
	return "does not read"
}

// One activated route grant as every reader reads it: its detail's prefixes and ports, or nil and why not. The caller
// must not change local.
type aclGrantRoute struct {
	local  *AclLocalRule
	unread aclGrantRouteUnread
}

// Whether the grant may reach what this reader cannot see: a sealed detail it could not read, which a device holding
// the key, or a build reading more, may serve. A grant whose detail read, and one that seals none, are settled here.
func (self aclGrantRoute) indeterminate() bool {
	return self.unread != aclGrantRouteUnreadNone && self.unread != aclGrantRouteUnreadUnsealed
}

// Opens one activated grant's sealed detail for a reader (the file's comment): grantId its rule's id, portsLimited its
// rule's ports_limited, which the fold sets exactly where the action carries a sealed_detail, and details its opener,
// nil opening none. The detail, or nil and why it gives nothing here, which the route reader and its dial counterpart
// read alike.
func aclOpenGrantDetail(grantId []byte, portsLimited bool, details AclGrantDetails) (*protocol.CanonicalActionDetail, aclGrantRouteUnread) {
	if !portsLimited {
		return nil, aclGrantRouteUnreadUnsealed
	}
	if details == nil {
		return nil, aclGrantRouteUnreadNoOpener
	}
	detail, err := details.GrantDetail(grantId)
	switch {
	case errors.Is(err, ErrConfigSealGenerationMissing):
		return nil, aclGrantRouteUnreadGeneration
	case errors.Is(err, ErrAclGrantActionNotHeld):
		return nil, aclGrantRouteUnreadNotHeld
	case err != nil:
		return nil, aclGrantRouteUnreadNotOpened
	case detail == nil:
		return nil, aclGrantRouteUnreadMissing
	}
	return detail, aclGrantRouteUnreadNone
}

// Reads one activated grant's route (the file's comment), its detail opened by aclOpenGrantDetail.
func aclReadGrantRoute(grantId []byte, portsLimited bool, details AclGrantDetails) aclGrantRoute {
	detail, unread := aclOpenGrantDetail(grantId, portsLimited, details)
	if detail == nil {
		return aclGrantRoute{unread: unread}
	}
	local, unread := aclGrantRouteOfDetail(detail)
	return aclGrantRoute{local: local, unread: unread}
}

// An opened detail's prefixes and ports (the file's comment), each once, or why it does not read. The local rule
// names no rule id: a grant's id is no document rule's.
func aclGrantRouteOfDetail(detail *protocol.CanonicalActionDetail) (*AclLocalRule, aclGrantRouteUnread) {
	local := &AclLocalRule{}
	addPrefix := func(text string) bool {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return false
		}
		if prefix = prefix.Masked(); !slices.Contains(local.Cidrs, prefix) {
			local.Cidrs = append(local.Cidrs, prefix)
		}
		return true
	}
	for _, text := range detail.GetCidrs() {
		if !addPrefix(text) {
			return nil, aclGrantRouteUnreadPrefix
		}
	}
	for _, dst := range detail.GetGrantDst() {
		if text, isPrefix := strings.CutPrefix(dst, "ip:"); isPrefix {
			if !addPrefix(text) {
				return nil, aclGrantRouteUnreadPrefix
			}
			continue
		}
		_, ports, err := ParseAclGrantDst(dst)
		if err != nil || ports == nil {
			return nil, aclGrantRouteUnreadDestination
		}
		portRange := AclPortRange{Protocol: ports.GetProtocol(), First: ports.GetFirst(), Last: ports.GetLast()}
		if !slices.Contains(local.Ports, portRange) {
			local.Ports = append(local.Ports, portRange)
		}
	}
	if detail.GetTargetPort() != 0 && len(local.Ports) == 0 {
		return nil, aclGrantRouteUnreadPortProtocol
	}
	return local, aclGrantRouteUnreadNone
}

// One port range an activated dial grant's detail names at one sidecar.
type aclGrantDialPort struct {
	sidecarId Id
	ports     AclPortRange
}

// The ports an activated dial grant's opened detail names, each at its sidecar, in the detail's order (the file's
// comment's dial counterpart). The caller must not change it.
type aclGrantDialPorts []aclGrantDialPort

// An opened detail's dial ports: each grant_dst entry that is a sidecar's port, which a target_port keeps only where it
// is that port. Never infers a protocol from target_port, which alone names none.
func aclGrantDialPortsOf(detail *protocol.CanonicalActionDetail) aclGrantDialPorts {
	dialPorts := aclGrantDialPorts{}
	for _, destination := range detail.GetGrantDst() {
		recipient, ports, err := ParseAclGrantDst(destination)
		if err != nil || ports == nil || len(recipient.GetSidecarId()) != len(Id{}) {
			continue
		}
		if detail.GetTargetPort() != 0 && ports.GetFirst() != detail.GetTargetPort() {
			continue
		}
		dialPorts = append(dialPorts, aclGrantDialPort{
			sidecarId: Id(recipient.GetSidecarId()),
			ports:     AclPortRange{Protocol: ports.GetProtocol(), First: ports.GetFirst(), Last: ports.GetLast()},
		})
	}
	return dialPorts
}

// The ports at one sidecar as a rule's local detail, none for a sidecar the detail names no port at.
func (self aclGrantDialPorts) at(sidecarId Id) *AclLocalRule {
	local := &AclLocalRule{}
	for _, dialPort := range self {
		if dialPort.sidecarId == sidecarId {
			local.Ports = append(local.Ports, dialPort.ports)
		}
	}
	return local
}

// Whether a port at the sidecar takes the protocol and port, as aclLocalPortsMatch reads a rule's local ports.
// Allocates nothing.
func (self aclGrantDialPorts) takes(sidecarId Id, ipProtocol uint32, port uint32) bool {
	for i := range self {
		ports := &self[i].ports
		if self[i].sidecarId == sidecarId && (ports.Protocol == 0 || ports.Protocol == ipProtocol) && ports.First <= port && port <= ports.Last {
			return true
		}
	}
	return false
}

// Whether the detail names any port at the sidecar. Allocates nothing.
func (self aclGrantDialPorts) reaches(sidecarId Id) bool {
	for i := range self {
		if self[i].sidecarId == sidecarId {
			return true
		}
	}
	return false
}
