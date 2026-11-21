//go:build !sidecar_http && !ios_extension

// §8.10's edge gates' view (ACL-M5-01; R-ACL-5, R-ACL-8, D-ACL-16, I-5, I-8, C9): what sockets' ValidateListen and
// Find, dns's record writes, certs, tlsedge and the issuer's edge login read of a network's policy. It wraps the
// process's one AclGateCache (C-09) for one service and folds in the hard denies only servers know, which rows cannot
// carry: an abuse halt (§21, ServiceHost.Abuse) and quota (§20, the over-limit list a host keeps).
//
//	unloaded       a network whose state the cache has not loaded is never allowed: the view asks the cache to load
//	               it and answers no_state, which a gate refuses or answers unavailable
//	halted         a network whose standing is suspended, or one this build does not know, is refused everything
//	               (abuse_halt); a network whose standing the host has not loaded is refused as unloaded
//	quota          a network over its storage limit or spent is refused where the service reads the list (quota)
//	publish        AclState.PublishGrant, below: a publish grant for a host whose bound socket the subject holds
//	               listen on, raw only under public or link and a raw link only with a pin (§13.9), by the
//	               agreement rule (aclPublishRules) that AclState.PublishedNames lists every name by (QD-770)
//	edge Find      AclState.MayEdgeFind, below: an edge Find runs as autogroup:public (§9.4) before any listener is
//	               picked, so a visitor's dial goes on wherever a sidecar of the network holds a publish grant for the
//	               name, whatever the grant's audience, and is refused where none does (QD-852)
//	dns admin      dns:<host>'s admin covers a host's zone records (§12.8)
//
// Only the listener's front enforces a grant's audience and a raw link's pin (§13.7, §21.4), so the view reports
// them in AclPublishGrant and judges neither. An outward action reaches a server gate under a standing grant, a
// delta-carried approval, or a decision sent with Idempotency-Key: <effect_key>; the third is §16.6's gate and
// approval_use, server's, and the view only reports that no grant holds. Application socket names reach the gate as
// §9.4's token paths alone, and ur/ names are their services' to authorize, never §8's. Each gate's wiring is its
// own area's task.
//
// A check reads the cache's snapshot with one map read and the host's facts from memory, and allocates nothing but
// PublishGrant's answer. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// The over-limit list as a gate reads it from memory: whether a network is over its storage limit or spent, and false
// for ok while the host has not loaded the list. No I/O.
type AclGateQuota interface {
	OverLimit(networkId Id) (over bool, ok bool)
}

// The edge gates' view of one service. Construct with NewAclGateView.
type AclGateView struct {
	// the process's AclGateCache (C-09)
	states AclContractStateSource
	abuse  AbuseGate
	// nil: the service reads no over-limit list, so quota refuses nothing here
	quota AclGateQuota
}

// A view over the process's gate cache for one service, reading abuse for halts and quota for over-limit networks. A
// nil abuse gate has loaded no network, so every check refuses; a nil quota refuses nothing for quota, for a service
// whose quota is a lease's or another gate's (§20).
func NewAclGateView(states AclContractStateSource, abuse AbuseGate, quota AclGateQuota) *AclGateView {
	if abuse == nil {
		abuse = UnloadedAbuseGate{}
	}
	return &AclGateView{states: states, abuse: abuse, quota: quota}
}

// The network's loaded state, or the refusal that stands before any rule: not loaded, halted or over its limit.
func (self *AclGateView) state(networkId Id) (*AclState, AclReason) {
	if self == nil || self.states == nil {
		return nil, AclReasonNoState
	}
	snapshot, status := self.states.State(networkId)
	if status != AclGateLoaded || snapshot == nil || snapshot.Acl == nil {
		self.states.Changed(networkId)
		return nil, AclReasonNoState
	}
	standing, ok := self.abuse.Standing(connect.Id(networkId))
	switch {
	case !ok:
		return nil, AclReasonNoState
	case !standing.Known() || standing == AbuseStandingSuspended:
		return nil, AclReasonAbuseHalt
	}
	if self.quota != nil {
		over, ok := self.quota.OverLimit(networkId)
		if !ok {
			return nil, AclReasonNoState
		}
		if over {
			return nil, AclReasonQuota
		}
	}
	return snapshot.Acl, 0
}

// Whether the subject may listen on a socket of the network: an application one by token path, or a tls/ or smtp/
// name in clear (§9.10's ValidateListen).
func (self *AclGateView) MayListen(networkId Id, subject AclSubject, socket AclSocketName, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	return state.MayListen(subject, socket, now)
}

// Whether the subject may dial an application socket of the network by its token path, as sockets checks a Find.
func (self *AclGateView) MayDialSocket(networkId Id, subject AclSubject, nameToken []byte, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	return state.MayDialSocket(subject, nameToken, now)
}

// Whether the subject may publish the host its tls/<port>/<host> socket names in the network: a publish grant for the
// host and listen on that bound socket (§8.6), raw only as §13.9 allows. With no allocation, for the gates' hot paths.
func (self *AclGateView) MayPublish(networkId Id, subject AclSubject, socketName string, appMode protocol.AclAppMode, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	return state.publishDecision(subject, socketName, appMode, now, nil)
}

// The subject's publish grant for the host its tls/<port>/<host> socket names, for ValidateListen, dns, certs, tlsedge
// and the issuer's edge login (§7.8): PublishGrant's answer behind the view's refusals.
func (self *AclGateView) PublishGrant(networkId Id, subject AclSubject, socketName string, appMode protocol.AclAppMode, now time.Time) (*AclPublishGrant, AclDecision) {
	state, deny := self.state(networkId)
	if deny != 0 {
		return nil, aclDeny(deny)
	}
	return state.PublishGrant(subject, socketName, appMode, now)
}

// Whether an edge Find for a visitor may go on to the listeners of a tls/<port>/<host> name of the network:
// AclState.MayEdgeFind behind the view's refusals, whatever the audience of the grant it stands on.
func (self *AclGateView) MayEdgeFind(networkId Id, socketName string, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	return state.MayEdgeFind(socketName, now)
}

// Whether the subject may write a host's zone records: dns:<host>'s admin (§12.8).
func (self *AclGateView) MayAdminDns(networkId Id, subject AclSubject, host string, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	return state.mayAdminDns(subject, host, now)
}

// The zone view exposes records covered by either grant, with standing and quota checked on the same snapshot.
func (self *AclGateView) MayViewDns(networkId Id, subject AclSubject, host string, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	if decision := state.mayAdminDns(subject, host, now); decision.Allowed {
		return decision
	}
	return state.MayPublish(subject, host, now)
}

func (self *AclState) mayAdminDns(subject AclSubject, host string, now time.Time) AclDecision {
	return self.resourceDecision(subject, now.UnixMilli(), protocol.AclAction_ACL_ACTION_ADMIN, func(rule *aclRule) bool {
		for _, pattern := range rule.publicNames {
			if !strings.Contains(pattern, "/") && aclDnsHostCovers(pattern, host) {
				return true
			}
		}
		return false
	})
}

// One publish grant as a gate reports it (§8.4): what the listener's front enforces, which the gate judges not.
type AclPublishGrant struct {
	// Every agreeing rule's id in rule order, a document rule's or an activated grant's grant_id; a link token names
	// one of them.
	GrantIds [][]byte
	// members, members-device, link or public; unspecified reads as members.
	Audience protocol.AclAudience
	// http or raw; unspecified reads as http.
	AppMode protocol.AclAppMode
	// A raw link's pin, 32 bytes, else nil.
	LinkSpkiSha256 []byte
	// When the last of its rules ends, ms since the epoch; 0 for none.
	ExpiresMs int64
}

// The name §13.9's system publish serves, and the receiver's listen grant that stands in for its grants.
const (
	aclSystemPublishName   = "tls/443/mta-sts"
	aclSystemPublishListen = "smtp/25/mx"
)

// The subject's publish grant for the host its tls/<port>/<host> socket names at now, appMode the mode the listener
// registers (§8.10, §13.9), nil with the refusal for none. The grant is the rules allowing publish that take the host
// and bind the socket for listen, or where none does, those that take the host and bind no socket, the listen then
// needed from a rule of its own: publish requires listen on the bound socket. Rules that disagree on audience, mode or
// pin give none, the closed direction; so does a mode other than the registration's, raw under any audience but public
// or link, and a raw link with no pin. The system publish, mta-sts on 443, stands on the receiver's smtp/25/mx listen
// grant, public and http, and ends with it. What tls_audience.go's interim reads answers the same.
func (self *AclState) PublishGrant(subject AclSubject, socketName string, appMode protocol.AclAppMode, now time.Time) (*AclPublishGrant, AclDecision) {
	grant := &AclPublishGrant{}
	decision := self.publishDecision(subject, socketName, appMode, now, grant)
	if !decision.Allowed {
		return nil, decision
	}
	return grant, decision
}

// An audience with unspecified read as members (§8.4's default).
func aclPublishAudience(audience protocol.AclAudience) protocol.AclAudience {
	if audience == protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED {
		return protocol.AclAudience_ACL_AUDIENCE_MEMBERS
	}
	return audience
}

// An app mode with unspecified read as http (§8.4's default).
func aclPublishAppMode(appMode protocol.AclAppMode) protocol.AclAppMode {
	if appMode == protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED {
		return protocol.AclAppMode_ACL_APP_MODE_HTTP
	}
	return appMode
}

// PublishGrant's decision, filling grant when it is not nil; with grant nil it allocates nothing.
func (self *AclState) publishDecision(subject AclSubject, socketName string, appMode protocol.AclAppMode, now time.Time, grant *AclPublishGrant) AclDecision {
	appMode = aclPublishAppMode(appMode)
	if socketName == aclSystemPublishName {
		decision := self.MayListen(subject, AclSocketName{PublicName: aclSystemPublishListen}, now)
		if !decision.Allowed || appMode != protocol.AclAppMode_ACL_APP_MODE_HTTP {
			return aclDeny(AclReasonNoGrant)
		}
		if grant != nil {
			grant.GrantIds = [][]byte{bytes.Clone(decision.Rule.GetRuleId())}
			grant.Audience = protocol.AclAudience_ACL_AUDIENCE_PUBLIC
			grant.AppMode = protocol.AclAppMode_ACL_APP_MODE_HTTP
			grant.ExpiresMs = decision.Rule.GetExpires()
		}
		return decision
	}
	host, ok := aclPublishSocketHost(socketName)
	if !ok {
		return aclDeny(AclReasonNoGrant)
	}
	nowMs := now.UnixMilli()
	resolved := self.resolve(&subject, nowMs)
	if resolved.deny != 0 {
		return aclDeny(resolved.deny)
	}
	rules := self.publishRules(&resolved, socketName, host, nowMs, false)
	if rules.first == nil || !rules.listens || !rules.agree {
		return aclDeny(AclReasonNoGrant)
	}
	audience, ruleMode, pin, valid := aclPublishGrantFields(rules.first)
	if ruleMode != appMode || !valid {
		return aclDeny(AclReasonNoGrant)
	}
	if grant != nil {
		grant.Audience, grant.AppMode, grant.LinkSpkiSha256 = audience, ruleMode, bytes.Clone(pin)
		self.publishClassRules(&resolved, socketName, host, nowMs, rules.class, false, func(rule *aclRule) {
			grant.GrantIds = append(grant.GrantIds, bytes.Clone(rule.row.GetRuleId()))
		})
		grant.ExpiresMs = rules.expiresMs
	}
	return aclAllowRule(rules.first)
}

// Whether an edge Find for a visitor may go on to the listeners of a tls/<port>/<host> name (§9.10, §13.5 step 4;
// QD-852). The Find runs as autogroup:public before any listener is picked, so no subject is the visitor's to name: it
// passes where a sidecar the state admits, under no hard deny at now, holds a publish grant for the name by the
// agreement rule, in the mode its own rules give and whatever its audience, members, members-device, link or public.
// Only the listener's front judges the audience and a raw link's pin, both from its own evaluation (§8.10, §13.7), so
// this reads neither: a members visitor with no session must reach the front for §7.8's edge login, and a link's
// token is traded there. No grant for the name refuses, and so does a name whose only grants no registration could
// take: a publish without listen, rules that disagree, raw under members, a raw link with no pin. The system publish
// passes where a receiver holds its smtp/25/mx listen grant (§13.9). The decision carries the first such sidecar's
// grant, in sidecar id order; each listener a Find then picks is still judged under its own sidecar (§9.6).
//
// It reads each sidecar's rules until one holds a grant, a sidecar's check each, and allocates nothing.
func (self *AclState) MayEdgeFind(socketName string, now time.Time) AclDecision {
	return self.edgeFindDecision(socketName, Id{}, now.UnixMilli())
}

// MayEdgeFind for a scope host's name (§13.8): a member scope's host stands only on a grant of its member's consented
// devices, as MayPublishInScope holds a registration; a tag scope's on any sidecar's.
func (self *AclState) MayEdgeFindInScope(socketName string, scope AclScope, now time.Time) AclDecision {
	if scope.MemberId == (Id{}) {
		return self.MayEdgeFind(socketName, now)
	}
	return self.edgeFindDecision(socketName, scope.MemberId, now.UnixMilli())
}

// MayEdgeFind's decision, over the consented devices of memberId alone when it is not zero.
func (self *AclState) edgeFindDecision(socketName string, memberId Id, nowMs int64) AclDecision {
	system := socketName == aclSystemPublishName
	host := ""
	if !system {
		publishHost, ok := aclPublishSocketHost(socketName)
		if !ok {
			return aclDeny(AclReasonNoGrant)
		}
		host = publishHost
	}
	for i := range self.sidecars {
		sidecar := &self.sidecars[i]
		if sidecar.hardDeny(nowMs) != 0 {
			continue
		}
		if memberId != (Id{}) && (sidecar.memberId != memberId || !self.sidecarConsented(sidecar)) {
			continue
		}
		subject := AclSidecarSubject(sidecar.id)
		resolved := self.resolve(&subject, nowMs)
		if resolved.deny != 0 {
			continue
		}
		if system {
			if rule := self.publicNameListenRule(&resolved, aclSystemPublishListen, nowMs, false); rule != nil {
				return aclAllowRule(rule)
			}
			continue
		}
		rules := self.publishRules(&resolved, socketName, host, nowMs, false)
		if rules.first == nil || !rules.listens || !rules.agree {
			continue
		}
		if _, _, _, valid := aclPublishGrantFields(rules.first); valid {
			return aclAllowRule(rules.first)
		}
	}
	return aclDeny(AclReasonNoGrant)
}

// The host of a tls/<port>/<host> name, the host one segment and the port a number below 65536, or false for any
// other name, which no publish grant takes.
func aclPublishSocketHost(socketName string) (string, bool) {
	namespace, rest, ok := strings.Cut(socketName, "/")
	portText, host, ok2 := strings.Cut(rest, "/")
	if !ok || !ok2 || namespace != "tls" || portText == "" || host == "" || strings.Contains(host, "/") {
		return "", false
	}
	if _, err := strconv.ParseUint(portText, 10, 16); err != nil {
		return "", false
	}
	return host, true
}

// The classes the agreement rule sorts a rule allowing publish into, for one tls/ name.
const (
	// takes neither: it does not take the host, or it binds sockets and not this one for listen
	aclPublishClassNone = iota
	// takes the host and binds the name for listen
	aclPublishClassBound
	// takes the host and binds no socket at all, so listen must come from a rule of its own
	aclPublishClassHostOnly
)

// The class a rule allowing publish falls in for a tls/ name and its host (§8.6, §13.9). Without patterns this is how
// a gate reads a registration, where a glob is no host. With patterns the host may be a glob, as PublishedNames lists
// a document's names, and a rule takes it only where it takes every host the glob names (acl_published_names.go): for
// a host with no glob the two read alike.
func aclPublishClass(rule *aclRule, socketName string, host string, patterns bool) int {
	coversHost, coversName, bindsSocket := false, false, false
	for _, pattern := range rule.publicNames {
		if strings.Contains(pattern, "/") {
			bindsSocket = true
			coversName = coversName || aclPublicSocketTakes(pattern, socketName, patterns)
		} else {
			coversHost = coversHost || aclDnsHostTakes(pattern, host, patterns)
		}
	}
	switch {
	case !coversHost:
		return aclPublishClassNone
	case coversName && rule.allows(protocol.AclAction_ACL_ACTION_LISTEN):
		return aclPublishClassBound
	case !bindsSocket:
		return aclPublishClassHostOnly
	}
	return aclPublishClassNone
}

// Whether two rules allowing publish agree on what the listener's front enforces: audience, mode and pin, each with
// §8.4's default read for unspecified.
func aclPublishRulesAgree(a *aclRule, b *aclRule) bool {
	return aclPublishAudience(a.row.GetAudience()) == aclPublishAudience(b.row.GetAudience()) &&
		aclPublishAppMode(a.row.GetAppMode()) == aclPublishAppMode(b.row.GetAppMode()) &&
		bytes.Equal(a.row.GetLinkSpkiSha256(), b.row.GetLinkSpkiSha256())
}

// One class's rules as the agreement rule reads them, in rule order.
type aclPublishClassRules struct {
	first *aclRule
	// whether every rule after first agrees with it
	agree bool
	// the latest expiry among the rules, ms since the epoch, and whether one has none
	expiresMs int64
	unbounded bool
}

// Reads the class's next rule.
func (self *aclPublishClassRules) add(rule *aclRule) {
	if self.first == nil {
		self.first = rule
		self.agree = true
	} else if !aclPublishRulesAgree(self.first, rule) {
		self.agree = false
	}
	if rule.expiresMs == 0 {
		self.unbounded = true
	} else if self.expiresMs < rule.expiresMs {
		self.expiresMs = rule.expiresMs
	}
}

// What the agreement rule (§8.4, §8.6, §13.9) gives one subject for one tls/ name, the one reading PublishGrant and
// PublishedNames share (QD-770): the subject's rules in force allowing publish that take the host and bind the name
// for listen, or where none does, those that take the host and bind no socket, the listen then needed from a rule of
// the subject's own. The class's rules agree when each matches the first on audience, mode and pin; they give a grant
// only then, which ends when the last of them does.
type aclPublishRules struct {
	// aclPublishClassBound or aclPublishClassHostOnly; aclPublishClassNone where no rule takes the name
	class int
	// the class's first rule in rule order, nil for none
	first *aclRule
	// whether the class's rules agree
	agree bool
	// whether the subject holds listen on the name: a bound class's rules grant it, and a host-only class needs it from
	// a rule of its own
	listens bool
	// when the last of the class's rules ends, ms since the epoch; 0 for none
	expiresMs int64
}

// The agreement rule's reading of the resolved subject's rules for a tls/ name, the name's host a glob only with
// patterns. Allocates nothing.
func (self *AclState) publishRules(resolved *aclResolved, socketName string, host string, nowMs int64, patterns bool) aclPublishRules {
	bound, hostOnly := aclPublishClassRules{}, aclPublishClassRules{}
	self.findResourceRule(resolved, nowMs, protocol.AclAction_ACL_ACTION_PUBLISH, func(rule *aclRule) bool {
		switch aclPublishClass(rule, socketName, host, patterns) {
		case aclPublishClassBound:
			bound.add(rule)
		case aclPublishClassHostOnly:
			hostOnly.add(rule)
		}
		// every rule is read, so each class is whole
		return false
	})
	rules := aclPublishRules{class: aclPublishClassBound, listens: true}
	classRules := &bound
	if bound.first == nil {
		if hostOnly.first == nil {
			return aclPublishRules{}
		}
		rules.class = aclPublishClassHostOnly
		classRules = &hostOnly
		// publish requires listen on the bound socket
		rules.listens = self.publicNameListenRule(resolved, socketName, nowMs, patterns) != nil
	}
	rules.first, rules.agree = classRules.first, classRules.agree
	if !classRules.unbounded {
		rules.expiresMs = classRules.expiresMs
	}
	return rules
}

// Visits the resolved subject's rules in force of one class for a tls/ name, in rule order: a grant's rule ids.
func (self *AclState) publishClassRules(resolved *aclResolved, socketName string, host string, nowMs int64, class int, patterns bool,
	visit func(rule *aclRule)) {
	self.findResourceRule(resolved, nowMs, protocol.AclAction_ACL_ACTION_PUBLISH, func(rule *aclRule) bool {
		if aclPublishClass(rule, socketName, host, patterns) == class {
			visit(rule)
		}
		return false
	})
}

// The first rule in force giving the resolved subject listen on a tls/ or smtp/ name in clear, MayListen's match, with
// the name's host a glob only with patterns.
func (self *AclState) publicNameListenRule(resolved *aclResolved, name string, nowMs int64, patterns bool) *aclRule {
	return self.findResourceRule(resolved, nowMs, protocol.AclAction_ACL_ACTION_LISTEN, func(rule *aclRule) bool {
		for _, pattern := range rule.publicNames {
			if strings.Contains(pattern, "/") && aclPublicSocketTakes(pattern, name, patterns) {
				return true
			}
		}
		return false
	})
}

// A grant's audience, mode and pin as its first rule gives them, unspecified read as §8.4's defaults, and whether
// §13.9 lets any registration take it: raw only under public or link, and a raw link only with its 32-byte pin.
func aclPublishGrantFields(first *aclRule) (audience protocol.AclAudience, appMode protocol.AclAppMode, pin []byte, valid bool) {
	audience, appMode, pin = aclPublishAudience(first.row.GetAudience()), aclPublishAppMode(first.row.GetAppMode()), first.row.GetLinkSpkiSha256()
	if appMode == protocol.AclAppMode_ACL_APP_MODE_RAW {
		switch {
		case audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC && audience != protocol.AclAudience_ACL_AUDIENCE_LINK:
			return audience, appMode, pin, false
		case audience == protocol.AclAudience_ACL_AUDIENCE_LINK && len(pin) != sha256.Size:
			return audience, appMode, pin, false
		}
	}
	return audience, appMode, pin, true
}
