// §8.6's requests: which requests rule takes a grant a subject asks for, and how long the grant lasts (owner decisions
// 74, 75, 180). A daemon calls MatchAclRequest before it builds a CanonicalAction, to find the rule; api and every
// reader call it again on the action a GrantActivate carries, by the rule_id the action names (acl_grant.go).
//
// A rule takes an ask when the subject holds one of its src atoms, every action asked is one it allows, and every
// destination falls inside one of its targets. The grant lasts what the action asks, else the rule's expiresDefault (1
// h) from now, and never past its maxExpiry (30 days) from now; §13.9's tier caps on publishes are the publish gate's
// (TLS-M5-22, QUOTA), not this one's.
//
// A CanonicalAction shows api its grant fields in clear (QD-064), so grant_dst holds only ids and public names, one
// string per destination, in §8.4's resource grammar with every id 32 lowercase hex digits:
//
//	sidecar:<id>[:tcp|udp:<port>]  a sidecar, a port as plan-RECORD-small-readings #10 writes a worker's
//	client:<id>, network:<id>      a client no binding names, another network
//	evs:<repo_id>                  a repo
//	sock:<token path>              an application socket by §9.4's token path, in hex (plan-ACL-folded-grant-state #2)
//	sock:tls/..., sock:smtp/...    a tls/ or smtp/ socket name, in clear as rows carry it
//	dns:<host>                     a published name
//	mail:*                         send, all a server sees of mail (D-ACL-12)
//
// An ip: prefix is refused: a dial or route grant's prefixes and ports move to sealed_detail
// (plan-BRIDGE-gate-row-prefixes #2), which this build does not read, so such a grant fails closed. grant_allow holds
// §8.4's action names.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Why no requests rule takes an ask: no rule has its id, its subject holds no src atom, it asks an action or a
// destination outside the rule, or its expiry is past the rule's maximum or already gone.
var ErrAclRequestNoMatch = errors.New("no requests rule takes the grant")

// A grant_dst or grant_allow entry this build cannot read.
var ErrAclGrantFieldInvalid = errors.New("grant field invalid")

// §8.5's expiresDefault and maxExpiry, which compile writes into each AclRequestRule; a rule that leaves one 0 takes
// these, the format's defaults.
const (
	aclRequestDefaultExpiryMs = int64(60 * 60 * 1000)
	aclRequestMaxExpiryMs     = int64(30 * 24 * 60 * 60 * 1000)
)

// One grant a subject asks for, as a requests rule judges it.
type AclGrantAsk struct {
	// The sidecar the grant is for, CanonicalAction.subject.
	Subject Id
	// The destinations as rows carry them, and the ports grant_dst names, which apply to every destination.
	Dst   []*protocol.AclTarget
	Ports []*protocol.AclPortRange
	// The actions asked.
	Allow []protocol.AclAction
	// When the grant ends, ms since the epoch; 0 asks for the rule's default.
	ExpiresMs int64
	// The requests rule's id, or empty to take the first rule, in the rows' order, that takes the ask.
	RuleId []byte
}

// The rule that takes an ask, and the grant's end.
type AclRequestMatch struct {
	Rule *protocol.AclRequestRule
	// ms since the epoch.
	ExpiresMs int64
}

// 32 lowercase hex digits as an id.
func aclParseHexId(text string) (Id, error) {
	if len(text) != 2*len(Id{}) || strings.ToLower(text) != text {
		return Id{}, fmt.Errorf("%w: an id of %d characters", ErrAclGrantFieldInvalid, len(text))
	}
	idBytes, err := hex.DecodeString(text)
	if err != nil {
		return Id{}, fmt.Errorf("%w: an id not in hex", ErrAclGrantFieldInvalid)
	}
	return Id(idBytes), nil
}

// One grant_dst entry: its target, and the port it names, nil for none.
func ParseAclGrantDst(dst string) (*protocol.AclTarget, *protocol.AclPortRange, error) {
	kind, value, found := strings.Cut(dst, ":")
	if !found || value == "" {
		return nil, nil, fmt.Errorf("%w: grant_dst %q", ErrAclGrantFieldInvalid, kind)
	}
	switch kind {
	case "sidecar":
		idText, portText, hasPort := strings.Cut(value, ":")
		sidecarId, err := aclParseHexId(idText)
		if err != nil {
			return nil, nil, err
		}
		target := &protocol.AclTarget{SidecarId: sidecarId.Bytes()}
		if !hasPort {
			return target, nil, nil
		}
		protocolName, portDigits, found := strings.Cut(portText, ":")
		ipProtocol := map[string]uint32{"tcp": 6, "udp": 17}[protocolName]
		port, err := strconv.ParseUint(portDigits, 10, 16)
		if !found || ipProtocol == 0 || err != nil || port == 0 || strconv.FormatUint(port, 10) != portDigits {
			return nil, nil, fmt.Errorf("%w: a sidecar's port", ErrAclGrantFieldInvalid)
		}
		return target, &protocol.AclPortRange{Protocol: ipProtocol, First: uint32(port), Last: uint32(port)}, nil
	case "client", "network", "evs":
		id, err := aclParseHexId(value)
		if err != nil {
			return nil, nil, err
		}
		switch kind {
		case "client":
			return &protocol.AclTarget{ClientId: id.Bytes()}, nil, nil
		case "network":
			return &protocol.AclTarget{NetworkId: id.Bytes()}, nil, nil
		}
		if id == (Id{}) {
			return nil, nil, fmt.Errorf("%w: the wildcard repo is no grant's", ErrAclGrantFieldInvalid)
		}
		return &protocol.AclTarget{RepoId: id.Bytes()}, nil, nil
	case "sock":
		if strings.HasPrefix(value, "tls/") || strings.HasPrefix(value, "smtp/") {
			if strings.ContainsAny(value, " \t") {
				return nil, nil, fmt.Errorf("%w: a socket name", ErrAclGrantFieldInvalid)
			}
			return &protocol.AclTarget{PublicName: value}, nil, nil
		}
		tokenPath, err := hex.DecodeString(value)
		if err != nil || strings.ToLower(value) != value || len(tokenPath) == 0 || len(tokenPath)%aclSocketTokenByteCount != 0 {
			return nil, nil, fmt.Errorf("%w: a socket's token path", ErrAclGrantFieldInvalid)
		}
		return &protocol.AclTarget{SocketTokens: [][]byte{tokenPath}}, nil, nil
	case "dns":
		if strings.ContainsAny(value, "/ \t") {
			return nil, nil, fmt.Errorf("%w: a dns host", ErrAclGrantFieldInvalid)
		}
		return &protocol.AclTarget{PublicName: value}, nil, nil
	case "mail":
		if value != "*" {
			return nil, nil, fmt.Errorf("%w: mail aliases are the clients' to check", ErrAclGrantFieldInvalid)
		}
		return &protocol.AclTarget{MailSend: true}, nil, nil
	case "ip":
		return nil, nil, fmt.Errorf("%w: a prefix rides sealed_detail (plan-BRIDGE-gate-row-prefixes #2)", ErrAclGrantFieldInvalid)
	}
	return nil, nil, fmt.Errorf("%w: grant_dst kind %q", ErrAclGrantFieldInvalid, kind)
}

// One grant_allow entry: §8.4's action name.
func ParseAclGrantAllow(allow string) (protocol.AclAction, error) {
	for action := protocol.AclAction_ACL_ACTION_DIAL; action <= aclActionMax; action += 1 {
		if aclActionName(action) == allow {
			return action, nil
		}
	}
	return protocol.AclAction_ACL_ACTION_UNSPECIFIED, fmt.Errorf("%w: grant_allow %q", ErrAclGrantFieldInvalid, allow)
}

// §8.4's name of an action.
func aclActionName(action protocol.AclAction) string {
	switch action {
	case protocol.AclAction_ACL_ACTION_DIAL:
		return "dial"
	case protocol.AclAction_ACL_ACTION_LISTEN:
		return "listen"
	case protocol.AclAction_ACL_ACTION_ROUTE:
		return "route"
	case protocol.AclAction_ACL_ACTION_READ:
		return "read"
	case protocol.AclAction_ACL_ACTION_WRITE:
		return "write"
	case protocol.AclAction_ACL_ACTION_ADMIN:
		return "admin"
	case protocol.AclAction_ACL_ACTION_DEPOSIT:
		return "deposit"
	case protocol.AclAction_ACL_ACTION_PUBLISH:
		return "publish"
	case protocol.AclAction_ACL_ACTION_SEND:
		return "send"
	}
	return ""
}

// The grant a CanonicalAction carries (QD-064's fields 8, 10, 11, 28 and 29): subject, destinations, actions, expiry
// and rule. Each list must be non-empty and each entry readable.
func ParseAclGrantAction(action *protocol.CanonicalAction) (*AclGrantAsk, error) {
	subjectId, err := IdFromBytes(action.GetSubject())
	if err != nil {
		return nil, fmt.Errorf("%w: a subject of %d bytes", ErrAclGrantFieldInvalid, len(action.GetSubject()))
	}
	if len(action.GetRuleId()) != aclAtomByteCount {
		return nil, fmt.Errorf("%w: a rule_id of %d bytes", ErrAclGrantFieldInvalid, len(action.GetRuleId()))
	}
	if len(action.GetGrantDst()) == 0 || len(action.GetGrantAllow()) == 0 {
		return nil, fmt.Errorf("%w: a grant with no destination or no action", ErrAclGrantFieldInvalid)
	}
	ask := &AclGrantAsk{Subject: subjectId, ExpiresMs: action.GetExpiresMillis(), RuleId: bytes.Clone(action.GetRuleId())}
	if ask.ExpiresMs < 0 {
		return nil, fmt.Errorf("%w: a negative expiry", ErrAclGrantFieldInvalid)
	}
	for _, dst := range action.GetGrantDst() {
		target, ports, err := ParseAclGrantDst(dst)
		if err != nil {
			return nil, err
		}
		ask.Dst = append(ask.Dst, target)
		if ports != nil && !slices.ContainsFunc(ask.Ports, func(existing *protocol.AclPortRange) bool {
			return existing.GetProtocol() == ports.GetProtocol() && existing.GetFirst() == ports.GetFirst()
		}) {
			ask.Ports = append(ask.Ports, ports)
		}
	}
	for _, allow := range action.GetGrantAllow() {
		action, err := ParseAclGrantAllow(allow)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(ask.Allow, action) {
			ask.Allow = append(ask.Allow, action)
		}
	}
	return ask, nil
}

// The requests rule that takes an ask at state and now, and the grant's end (§8.6's requests).
func MatchAclRequest(state *AclState, ask *AclGrantAsk, now time.Time) (*AclRequestMatch, error) {
	if state == nil || ask == nil || len(ask.Dst) == 0 || len(ask.Allow) == 0 {
		return nil, fmt.Errorf("%w: an empty ask", ErrAclRequestNoMatch)
	}
	nowMs := now.UnixMilli()
	requester := state.sidecarState(ask.Subject)
	if requester == nil || requester.hardDeny(nowMs) != 0 {
		return nil, fmt.Errorf("%w: a subject that does not stand", ErrAclRequestNoMatch)
	}
	for _, rule := range state.rows.GetRequests() {
		if 0 < len(ask.RuleId) && !bytes.Equal(rule.GetRuleId(), ask.RuleId) {
			continue
		}
		if !state.requestTakes(rule, requester, ask) {
			continue
		}
		defaultMs, maxMs := aclRequestDefaultExpiryMs, aclRequestMaxExpiryMs
		if seconds := rule.GetDefaultExpirySeconds(); 0 < seconds {
			defaultMs = seconds * 1000
		}
		if seconds := rule.GetMaxExpirySeconds(); 0 < seconds {
			maxMs = seconds * 1000
		}
		expiresMs := ask.ExpiresMs
		if expiresMs == 0 {
			expiresMs = nowMs + min(defaultMs, maxMs)
		}
		switch {
		case expiresMs <= nowMs:
			return nil, fmt.Errorf("%w: a grant already expired", ErrAclRequestNoMatch)
		case nowMs+maxMs < expiresMs:
			return nil, fmt.Errorf("%w: a grant past the rule's maxExpiry", ErrAclRequestNoMatch)
		}
		return &AclRequestMatch{Rule: rule, ExpiresMs: expiresMs}, nil
	}
	return nil, ErrAclRequestNoMatch
}

// Whether a requests rule takes the ask: the requester in its src, every action among its own, every destination
// inside one of its targets.
func (self *AclState) requestTakes(rule *protocol.AclRequestRule, requester *aclSidecarState, ask *AclGrantAsk) bool {
	inSrc := false
	for _, atomBytes := range rule.GetSrcAtoms() {
		atom, err := IdFromBytes(atomBytes)
		if err != nil {
			continue
		}
		atomIndex, found := self.atomIndexes[atom]
		if !found {
			continue
		}
		if _, holds := slices.BinarySearch(requester.atoms, atomIndex); holds {
			inSrc = true
			break
		}
	}
	if !inSrc {
		return false
	}
	for _, action := range ask.Allow {
		if !slices.Contains(rule.GetActions(), uint32(action)) {
			return false
		}
	}
	for _, target := range ask.Dst {
		if !slices.ContainsFunc(rule.GetTargets(), func(ruleTarget *protocol.AclTarget) bool {
			return self.requestTargetCovers(ruleTarget, target, requester)
		}) {
			return false
		}
	}
	return true
}

// The id an id field holds, false for a field of any other size: request rules are no part of what NewAclState
// checks, and an ask's targets are its caller's, so neither is trusted to be well formed.
func aclTargetId(idBytes []byte) (Id, bool) {
	id, err := IdFromBytes(idBytes)
	return id, err == nil
}

// Whether a requests rule's target takes one destination of a grant, for the requester.
func (self *AclState) requestTargetCovers(ruleTarget *protocol.AclTarget, target *protocol.AclTarget, requester *aclSidecarState) bool {
	switch {
	case len(ruleTarget.GetAtom()) != 0:
		atom, err := IdFromBytes(ruleTarget.GetAtom())
		if err != nil {
			return false
		}
		if autogroup, isAutogroup := aclAtomAutogroup(atom); isAutogroup && autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_SELF {
			destinationId, ok := aclTargetId(target.GetSidecarId())
			destination := self.sidecarState(destinationId)
			return ok && destination != nil && destination.valid && destination.hasOwner && requester.hasOwner &&
				destination.owner == requester.owner
		}
		atomIndex, found := self.atomIndexes[atom]
		if !found {
			return false
		}
		switch {
		case bytes.Equal(target.GetAtom(), ruleTarget.GetAtom()):
			return true
		case len(target.GetSidecarId()) != 0:
			destinationId, ok := aclTargetId(target.GetSidecarId())
			destination := self.sidecarState(destinationId)
			if !ok || destination == nil {
				return false
			}
			_, holds := slices.BinarySearch(destination.atoms, atomIndex)
			return holds
		case len(target.GetNetworkId()) != 0:
			networkId, ok := aclTargetId(target.GetNetworkId())
			return ok && slices.Contains(self.networkAtoms[networkId], atomIndex)
		case len(target.GetClientId()) != 0:
			clientId, ok := aclTargetId(target.GetClientId())
			return ok && slices.Contains(self.clientAtoms[clientId], atomIndex)
		}
		return false
	case len(ruleTarget.GetSidecarId()) != 0:
		_, ok := aclTargetId(target.GetSidecarId())
		return ok && bytes.Equal(ruleTarget.GetSidecarId(), target.GetSidecarId())
	case len(ruleTarget.GetNetworkId()) != 0:
		_, ok := aclTargetId(target.GetNetworkId())
		return ok && bytes.Equal(ruleTarget.GetNetworkId(), target.GetNetworkId())
	case len(ruleTarget.GetClientId()) != 0:
		_, ok := aclTargetId(target.GetClientId())
		return ok && bytes.Equal(ruleTarget.GetClientId(), target.GetClientId())
	case len(ruleTarget.GetRepoId()) != 0:
		repoId, ok := aclTargetId(target.GetRepoId())
		ruleRepoId, ruleOk := aclTargetId(ruleTarget.GetRepoId())
		if !ok || !ruleOk {
			return false
		}
		if repoId == ruleRepoId {
			return true
		}
		repo := self.repos[repoId]
		return ruleRepoId == (Id{}) && repo != nil && aclRepoKindGeneral(repo.kind)
	case len(ruleTarget.GetSocketTokens()) != 0 || ruleTarget.GetSocketPrefix():
		if len(target.GetSocketTokens()) != 1 {
			return false
		}
		socket := aclSocketTarget{prefix: ruleTarget.GetSocketPrefix()}
		for _, tokenPath := range ruleTarget.GetSocketTokens() {
			if 0 < len(tokenPath) {
				socket.tokenPaths = append(socket.tokenPaths, tokenPath)
			}
		}
		return socket.covers(target.GetSocketTokens()[0])
	case ruleTarget.GetPublicName() != "":
		pattern, name := ruleTarget.GetPublicName(), target.GetPublicName()
		if name == "" || strings.Contains(pattern, "/") != strings.Contains(name, "/") {
			return false
		}
		if strings.Contains(pattern, "/") {
			return aclPublicSocketCovers(pattern, name)
		}
		return aclDnsHostCovers(pattern, name)
	case ruleTarget.GetMailSend():
		return target.GetMailSend()
	}
	return false
}
