// §8.6's evaluation over one AclState: allowed(s, a, r, t) = not hardDeny(s, a, r, t) and some rule in force
// at t has s in its src, r in its dst, a among its actions and matching ports, within the ceiling. Grants
// form a union over a deny base, with no deny grant and no precedence (D-ACL-2), so a check returns the
// first rule it finds and never weighs one against another.
//
// Rows hold no ports and no CIDRs (plan-BRIDGE-gate-row-prefixes #1), so these are the gates' checks, who
// reaches whom and who holds what: "ports match" and a route's address are the client's, which AclEngine
// adds from AclLocalPolicy through the accept hooks below, on the same candidate rules.
//
// hardDeny here is what the state shows: an unadmitted, revoked or parked sidecar, an admission past its
// not_after, a sidecar whose member left, and a suspended subject. A gate adds abuse halts, quota and an
// unapproved client through AclSubject.Deny. A destination subject hard denied is no destination either:
// a Suspend or a revocation removes its atoms, so no rule names it (§8.6's one switch).
//
// Each check takes now and allocates nothing: it intersects the state's bitsets and reads each candidate
// rule's expiry, so a rule stops at exactly its time.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"math/bits"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What allowed a check, or why it refused.
type AclReason int

const (
	// allowed by a rule of the rows: the network's document, the implicit one, or an activated grant
	AclReasonRule AclReason = iota + 1
	// allowed by §8.5's kind defaults, which the binary holds
	AclReasonKindDefault
	// allowed by the repo's folded RepoCreate and RepoAdmin rows
	AclReasonRepoAdmin
	// allowed by a RepoGrant in the repo's access log
	AclReasonRepoGrant
	// allowed by an EvsShare of an owner-bound repo
	AclReasonEvsShare
	// allowed by the audit block (owner decision 63)
	AclReasonAudit

	// refused: no admission, an admission naming neither a member nor tags, or a member who left
	AclReasonUnadmitted
	// refused: a revoked sidecar
	AclReasonRevoked
	// refused: an admission past its not_after
	AclReasonExpired
	// refused: parked by a compromise cascade or a leaked bundle's DelegationRevoke
	AclReasonParked
	// refused: an active Suspend names the subject
	AclReasonSuspended
	// refused: no rule or row in force allows it
	AclReasonNoGrant
	// refused: the rows hold no such repo
	AclReasonNoRepo
	// refused: the repo's newest RepoDelete has no RepoRestore
	AclReasonRepoDeleted
	// refused by the caller: an abuse halt (§21)
	AclReasonAbuseHalt
	// refused by the caller: quota (§20)
	AclReasonQuota
	// refused by the caller: an unapproved client (§7)
	AclReasonUnapproved

	// refused: a leaf of a group for a sidecar that is no member device, a tagged or ephemeral one, which reads by
	// wraps and never takes a seat (D-KEYS-11, §8.12)
	AclReasonNotMemberDevice
	// refused: a leaf of the config or a team directory's group for a device §7.9's leaves rule does not entitle,
	// which reads there by wraps (owner decisions 144, 182)
	AclReasonNotLeafEntitled
	// refused: a leaf past a group's 1,000 seats (D-KEYS-2)
	AclReasonSeatsFull
	// refused: a device of an owner-bound repo's owner without §8.5's consent there, which KF2 parks until the
	// owner's OwnerConfirm (owner decision 126)
	AclReasonUnconsented
)

// A short name for logs and refusals.
func (self AclReason) String() string {
	switch self {
	case AclReasonRule:
		return "rule"
	case AclReasonKindDefault:
		return "kind_default"
	case AclReasonRepoAdmin:
		return "repo_admin"
	case AclReasonRepoGrant:
		return "repo_grant"
	case AclReasonEvsShare:
		return "evs_share"
	case AclReasonAudit:
		return "audit"
	case AclReasonUnadmitted:
		return "unadmitted"
	case AclReasonRevoked:
		return "revoked"
	case AclReasonExpired:
		return "expired"
	case AclReasonParked:
		return "parked"
	case AclReasonSuspended:
		return "suspended"
	case AclReasonNoGrant:
		return "no_grant"
	case AclReasonNoRepo:
		return "no_repo"
	case AclReasonRepoDeleted:
		return "repo_deleted"
	case AclReasonAbuseHalt:
		return "abuse_halt"
	case AclReasonQuota:
		return "quota"
	case AclReasonUnapproved:
		return "unapproved"
	case AclReasonNotMemberDevice:
		return "not_member_device"
	case AclReasonNotLeafEntitled:
		return "not_leaf_entitled"
	case AclReasonSeatsFull:
		return "seats_full"
	case AclReasonUnconsented:
		return "unconsented"
	}
	return "unknown"
}

// One check's answer, naming the rule or delta that allowed it, or the reason it refused (§8.17). A value:
// returning it allocates nothing, and the rows it points into must not be changed.
type AclDecision struct {
	Allowed bool
	Reason  AclReason
	// The rule that allowed it, for AclReasonRule: its rule_id, and a publish's audience, app_mode and pin.
	Rule *protocol.AclRule
	// For an access-log row or an EvsShare, the position of the entry that carried it (§8.8).
	At uint64
}

// A refusal.
func aclDeny(reason AclReason) AclDecision {
	return AclDecision{Reason: reason}
}

// An allow by a rule.
func aclAllowRule(rule *aclRule) AclDecision {
	return AclDecision{Allowed: true, Reason: AclReasonRule, Rule: rule.row}
}

// One socket as a check names it: an application socket by §9.4's token path, t_1 || ... || t_n, or a
// tls/ or smtp/ name in clear. Exactly one is set.
type AclSocketName struct {
	NameToken  []byte
	PublicName string
}

// A subject resolved against the state once per check, on the caller's stack.
type aclResolved struct {
	subject *AclSubject
	// the indexed sidecar, or nil for every other kind
	sidecar *aclSidecarState
	deny    AclReason
	// for a subject that is no indexed sidecar: the autogroups it holds and its atoms by source
	autogroups     uint32
	idAtoms        []int32
	memberAtoms    []int32
	principalAtoms []int32
	// the member autogroup:self and approvers read
	owner    Id
	hasOwner bool
}

// Resolves a subject at nowMs: its hard denies and what it holds.
func (self *AclState) resolve(subject *AclSubject, nowMs int64) aclResolved {
	resolved := aclResolved{subject: subject}
	switch subject.Kind {
	case AclSubjectSidecar:
		sidecar := self.sidecarState(subject.Id)
		if sidecar == nil {
			resolved.deny = AclReasonUnadmitted
			break
		}
		resolved.sidecar = sidecar
		resolved.owner = sidecar.owner
		resolved.hasOwner = sidecar.hasOwner
		resolved.deny = sidecar.hardDeny(nowMs)
	case AclSubjectClient:
		resolved.autogroups = aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED) |
			aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK)
		resolved.idAtoms = self.clientAtoms[subject.Id]
		if subject.Principal != "" {
			resolved.principalAtoms = self.principalAtoms[subject.Principal]
		}
		if subject.MemberId != (Id{}) {
			member := self.view.Member(subject.MemberId)
			if member == nil {
				// an app device whose member left is no subject of this network
				resolved.deny = AclReasonUnadmitted
				break
			}
			resolved.memberAtoms = self.memberAtoms[subject.MemberId]
			resolved.autogroups |= aclRoleAutogroups(member.GetRole())
			resolved.owner = subject.MemberId
			resolved.hasOwner = true
		}
		if self.suspended[subject.Id] {
			resolved.deny = AclReasonSuspended
		}
	case AclSubjectRemote:
		resolved.idAtoms = self.networkAtoms[subject.Id]
	case AclSubjectPublic:
		resolved.autogroups = aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_PUBLIC)
	default:
		resolved.deny = AclReasonUnadmitted
	}
	if resolved.deny == 0 && subject.Deny != 0 {
		resolved.deny = subject.Deny
	}
	return resolved
}

// The hard deny the state shows for a sidecar at nowMs, or zero.
func (self *aclSidecarState) hardDeny(nowMs int64) AclReason {
	switch {
	case !self.valid || self.memberGone:
		return AclReasonUnadmitted
	case self.revoked:
		return AclReasonRevoked
	case self.notAfterMs != 0 && self.notAfterMs <= nowMs:
		return AclReasonExpired
	case self.parked:
		return AclReasonParked
	case self.suspended:
		return AclReasonSuspended
	}
	return 0
}

// Whether a subject that is no indexed sidecar holds an atom.
func (self *AclState) holdsAtom(resolved *aclResolved, atomIndex int32) bool {
	if atomIndex <= int32(aclAutogroupMax) {
		return resolved.autogroups&(1<<uint32(atomIndex)) != 0
	}
	if slices.Contains(resolved.idAtoms, atomIndex) || slices.Contains(resolved.memberAtoms, atomIndex) ||
		slices.Contains(resolved.principalAtoms, atomIndex) {
		return true
	}
	if resolved.subject.Kind == AclSubjectClient {
		for _, role := range resolved.subject.Roles {
			if slices.Contains(self.roleAtoms[role], atomIndex) {
				return true
			}
		}
	}
	return false
}

// Whether the subject is in the rule's src.
func (self *AclState) inSrc(resolved *aclResolved, rule *aclRule) bool {
	if resolved.sidecar != nil {
		return resolved.sidecar.srcRules.has(rule.index)
	}
	for _, atomIndex := range rule.srcAtoms {
		if self.holdsAtom(resolved, atomIndex) {
			return true
		}
	}
	return false
}

// Whether the rule's subject targets name the destination for this source: an atom it holds, its id, or
// autogroup:self where the two share an owner or sponsor (§8.4).
func (self *AclState) targetsSubject(source *aclResolved, destination *aclResolved, rule *aclRule) bool {
	if rule.selfTarget && source.hasOwner && destination.hasOwner && source.owner == destination.owner {
		return true
	}
	if destination.sidecar != nil {
		if rule.actions&aclReachActions != 0 {
			return destination.sidecar.reachRules.has(rule.index)
		}
		return self.sidecarIsSubjectTarget(destination.sidecar, rule)
	}
	for _, atomIndex := range rule.atomTargets {
		if self.holdsAtom(destination, atomIndex) {
			return true
		}
	}
	switch destination.subject.Kind {
	case AclSubjectClient:
		return slices.Contains(rule.clientTargets, destination.subject.Id)
	case AclSubjectRemote:
		return slices.Contains(rule.networkTargets, destination.subject.Id)
	}
	return false
}

// Whether a rule names any subject as a target, which makes its subjects a route's via subjects.
func (self *aclRule) hasSubjectTargets() bool {
	return self.selfTarget || 0 < len(self.atomTargets) || 0 < len(self.sidecarTargets) ||
		0 < len(self.clientTargets) || 0 < len(self.networkTargets)
}

// Whether the destination sidecar holds, at nowMs, a listen grant on a socket the dial rule names.
func (self *AclState) listensOn(destination *aclResolved, dialRule *aclRule, nowMs int64) bool {
	overlaps := self.listenOverlaps[dialRule.index]
	if destination.sidecar == nil || overlaps == nil {
		return false
	}
	for w, word := range overlaps {
		word &= destination.sidecar.listenRules[w]
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			word &= word - 1
			if self.rules[w*64+bit].activeAt(nowMs) {
				return true
			}
		}
	}
	return false
}

// The first rule in force allowing one of actions from source to destination that accept, when not nil, also
// takes, sockets expanding to their listeners when asked. accept is the client's narrowing: AclEngine's ports.
func (self *AclState) findSubjectRule(source *aclResolved, destination *aclResolved, nowMs int64, actions uint32,
	accept func(rule *aclRule) bool, expandSockets bool) *aclRule {
	for w := 0; w < self.ruleWordCount; w += 1 {
		var word uint64
		for action := protocol.AclAction_ACL_ACTION_DIAL; action <= aclActionMax; action += 1 {
			if actions&(1<<uint32(action)) != 0 {
				word |= self.actionRules[action][w]
			}
		}
		if source.sidecar != nil {
			word &= source.sidecar.srcRules[w]
		}
		if destination.sidecar != nil {
			candidates := destination.sidecar.reachRules[w] | self.selfReachRules[w]
			if expandSockets {
				candidates |= self.socketDialRules[w]
			}
			word &= candidates
		}
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			word &= word - 1
			rule := &self.rules[w*64+bit]
			if !rule.activeAt(nowMs) || (accept != nil && !accept(rule)) {
				continue
			}
			if source.sidecar == nil && !self.inSrc(source, rule) {
				continue
			}
			if self.targetsSubject(source, destination, rule) {
				return rule
			}
			if expandSockets && self.socketDialRules.has(rule.index) && self.listensOn(destination, rule, nowMs) {
				return rule
			}
		}
	}
	return nil
}

// reach(a, b) for §8.10's contract rule: an active dial or route grant from a to b, a socket dial
// expanding to the subjects that listen on it and an ip grant to its via subjects. Ports are not read:
// the contract gate is who talks to whom, and the endpoints check ports.
func (self *AclState) Reach(source AclSubject, destination AclSubject, now time.Time) AclDecision {
	nowMs := now.UnixMilli()
	sourceResolved := self.resolve(&source, nowMs)
	if sourceResolved.deny != 0 {
		return aclDeny(sourceResolved.deny)
	}
	destinationResolved := self.resolve(&destination, nowMs)
	if destinationResolved.deny != 0 {
		return aclDeny(destinationResolved.deny)
	}
	if rule := self.findSubjectRule(&sourceResolved, &destinationResolved, nowMs, aclReachActions, nil, true); rule != nil {
		return aclAllowRule(rule)
	}
	return aclDeny(AclReasonNoGrant)
}

// Whether source may dial destination: a dial grant naming the destination. The rule's ports are the
// destination's to check (AclEngine.AllowInbound), since rows carry only whether it limits them.
func (self *AclState) MayDial(source AclSubject, destination AclSubject, now time.Time) AclDecision {
	return self.mayDial(source, destination, now.UnixMilli(), nil)
}

// MayDial with a client's narrowing of each candidate rule.
func (self *AclState) mayDial(source AclSubject, destination AclSubject, nowMs int64, accept func(rule *aclRule) bool) AclDecision {
	sourceResolved := self.resolve(&source, nowMs)
	if sourceResolved.deny != 0 {
		return aclDeny(sourceResolved.deny)
	}
	destinationResolved := self.resolve(&destination, nowMs)
	if destinationResolved.deny != 0 {
		return aclDeny(destinationResolved.deny)
	}
	dial := uint32(1) << uint32(protocol.AclAction_ACL_ACTION_DIAL)
	if rule := self.findSubjectRule(&sourceResolved, &destinationResolved, nowMs, dial, accept, false); rule != nil {
		return aclAllowRule(rule)
	}
	return aclDeny(AclReasonNoGrant)
}

// The first rule in force allowing the action whose src holds the subject and whose resource targets pass
// match.
func (self *AclState) findResourceRule(resolved *aclResolved, nowMs int64, action protocol.AclAction, match func(rule *aclRule) bool) *aclRule {
	actionRules := self.actionRules[action]
	for w := 0; w < self.ruleWordCount; w += 1 {
		word := actionRules[w]
		if resolved.sidecar != nil {
			word &= resolved.sidecar.srcRules[w]
		}
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			word &= word - 1
			rule := &self.rules[w*64+bit]
			if !rule.activeAt(nowMs) || (resolved.sidecar == nil && !self.inSrc(resolved, rule)) {
				continue
			}
			if match(rule) {
				return rule
			}
		}
	}
	return nil
}

// A resource check's answer for a resolved subject.
func (self *AclState) resourceDecision(subject AclSubject, nowMs int64, action protocol.AclAction, match func(rule *aclRule) bool) AclDecision {
	resolved := self.resolve(&subject, nowMs)
	if resolved.deny != 0 {
		return aclDeny(resolved.deny)
	}
	if rule := self.findResourceRule(&resolved, nowMs, action, match); rule != nil {
		return aclAllowRule(rule)
	}
	return aclDeny(AclReasonNoGrant)
}

// Whether the subject may dial an application socket by its token path, as sockets checks a Find (§9.10).
func (self *AclState) MayDialSocket(subject AclSubject, nameToken []byte, now time.Time) AclDecision {
	return self.resourceDecision(subject, now.UnixMilli(), protocol.AclAction_ACL_ACTION_DIAL, func(rule *aclRule) bool {
		for i := range rule.sockets {
			if rule.sockets[i].covers(nameToken) {
				return true
			}
		}
		return false
	})
}

// Whether the subject may listen on a socket: an application one by token path, or a tls/ or smtp/ name
// in clear against public_name, where a last segment of * takes every name below its prefix
// (acl-policy-small-readings #1). A publish also needs MayPublish on the host (§8.6).
func (self *AclState) MayListen(subject AclSubject, socket AclSocketName, now time.Time) AclDecision {
	return self.resourceDecision(subject, now.UnixMilli(), protocol.AclAction_ACL_ACTION_LISTEN, func(rule *aclRule) bool {
		if 0 < len(socket.NameToken) {
			for i := range rule.sockets {
				if rule.sockets[i].covers(socket.NameToken) {
					return true
				}
			}
			return false
		}
		for _, pattern := range rule.publicNames {
			if strings.Contains(pattern, "/") && aclPublicSocketCovers(pattern, socket.PublicName) {
				return true
			}
		}
		return false
	})
}

// Whether the subject may route to an address via a subject: a route grant whose via subjects, its subject
// targets, hold the via subject, or whose autogroup:internet takes the address, a public one. The rule's
// prefixes and ports are the client's to check (AclEngine.AllowRoute): rows carry neither, and a route rule
// with no via names its advertisers only through BridgeRows, so it reaches no via here.
func (self *AclState) MayRoute(source AclSubject, address netip.Addr, via AclSubject, now time.Time) AclDecision {
	return self.mayRoute(source, address, via, now.UnixMilli(), nil)
}

// MayRoute with a client's narrowing of each candidate rule.
func (self *AclState) mayRoute(source AclSubject, address netip.Addr, via AclSubject, nowMs int64, accept func(rule *aclRule) bool) AclDecision {
	sourceResolved := self.resolve(&source, nowMs)
	if sourceResolved.deny != 0 {
		return aclDeny(sourceResolved.deny)
	}
	viaResolved := self.resolve(&via, nowMs)
	if viaResolved.deny != 0 {
		return aclDeny(viaResolved.deny)
	}
	address = address.Unmap()
	rule := self.findResourceRule(&sourceResolved, nowMs, protocol.AclAction_ACL_ACTION_ROUTE, func(rule *aclRule) bool {
		if accept != nil && !accept(rule) {
			return false
		}
		if rule.internetTarget && aclAddressPublic(address) {
			return true
		}
		return rule.hasSubjectTargets() && self.targetsSubject(&sourceResolved, &viaResolved, rule)
	})
	if rule != nil {
		return aclAllowRule(rule)
	}
	return aclDeny(AclReasonNoGrant)
}

// Whether an address is a public destination, which autogroup:internet takes (§8.4).
func aclAddressPublic(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate()
}

// Whether a cidr takes an address, 0.0.0.0/0 and ::/0 leaving out loopback and link-local (§8.4).
func aclCidrCovers(cidr netip.Prefix, address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	if cidr.Bits() == 0 && (address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast()) {
		return false
	}
	return cidr.Contains(address)
}

// Whether the subject may publish a dns host (§8.4's dns:<host>): a publish grant whose public_name, a host
// with its glob kept (plan-ACL-small-readings #10), takes it label by label. The decision's rule carries
// the grant's audience, app_mode and pin, which the listener's front enforces (§8.10).
func (self *AclState) MayPublish(subject AclSubject, host string, now time.Time) AclDecision {
	return self.resourceDecision(subject, now.UnixMilli(), protocol.AclAction_ACL_ACTION_PUBLISH, func(rule *aclRule) bool {
		for _, pattern := range rule.publicNames {
			if !strings.Contains(pattern, "/") && aclDnsHostCovers(pattern, host) {
				return true
			}
		}
		return false
	})
}

// Whether the subject may send mail: a send grant with mail_send, all a server sees of mail:<alias>
// (D-ACL-12). Aliases are the client's to check.
func (self *AclState) MaySend(subject AclSubject, now time.Time) AclDecision {
	return self.resourceDecision(subject, now.UnixMilli(), protocol.AclAction_ACL_ACTION_SEND, func(rule *aclRule) bool {
		return rule.mailSend
	})
}

// Whether a tls/ or smtp/ pattern takes a name segment by segment, * within a segment, and a last segment
// of * every name strictly below its prefix. Neither string is copied.
func aclPublicSocketCovers(pattern string, name string) bool {
	if name == "" || strings.Contains(name, "*") {
		return false
	}
	for {
		patternSegment, patternRest, patternMore := strings.Cut(pattern, "/")
		nameSegment, nameRest, nameMore := strings.Cut(name, "/")
		if !patternMore && patternSegment == "*" {
			return nameSegment != ""
		}
		if !aclGlobMatches(patternSegment, nameSegment) {
			return false
		}
		if !patternMore || !nameMore {
			return patternMore == nameMore
		}
		pattern = patternRest
		name = nameRest
	}
}

// Whether a dns pattern takes a host label by label, a bare * every host. Neither string is copied.
func aclDnsHostCovers(pattern string, host string) bool {
	if host == "" || strings.Contains(host, "*") {
		return false
	}
	if pattern == "*" {
		return true
	}
	for {
		patternLabel, patternRest, patternMore := strings.Cut(pattern, ".")
		hostLabel, hostRest, hostMore := strings.Cut(host, ".")
		if !aclGlobMatches(patternLabel, hostLabel) {
			return false
		}
		if !patternMore || !hostMore {
			return patternMore == hostMore
		}
		pattern = patternRest
		host = hostRest
	}
}
