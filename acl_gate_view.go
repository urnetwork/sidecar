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
//	               listen on, raw only under public or link and a raw link only with a pin (§13.9)
//	public Find    an edge Find runs as autogroup:public (§9.4), so a visitor's dial passes only under a public
//	               publish of the host by a subject that listens on its socket
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

// Whether an edge Find for a visitor may reach a listener's socket: the Find runs as autogroup:public (§9.4), so it
// passes only where the listener's publish grant for the socket's host is public.
func (self *AclGateView) MayFindPublic(networkId Id, listener AclSubject, socketName string, appMode protocol.AclAppMode, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	grant := AclPublishGrant{}
	decision := state.publishDecision(listener, socketName, appMode, now, &grant)
	if !decision.Allowed {
		return decision
	}
	if grant.Audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC {
		return aclDeny(AclReasonNoGrant)
	}
	return decision
}

// Whether the subject may write a host's zone records: dns:<host>'s admin (§12.8).
func (self *AclGateView) MayAdminDns(networkId Id, subject AclSubject, host string, now time.Time) AclDecision {
	state, deny := self.state(networkId)
	if deny != 0 {
		return aclDeny(deny)
	}
	return state.resourceDecision(subject, now.UnixMilli(), protocol.AclAction_ACL_ACTION_ADMIN, func(rule *aclRule) bool {
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
	// tls/<port>/<host>, the host one segment
	namespace, rest, ok := strings.Cut(socketName, "/")
	portText, host, ok2 := strings.Cut(rest, "/")
	if !ok || !ok2 || namespace != "tls" || portText == "" || host == "" || strings.Contains(host, "/") {
		return aclDeny(AclReasonNoGrant)
	}
	if _, err := strconv.ParseUint(portText, 10, 16); err != nil {
		return aclDeny(AclReasonNoGrant)
	}
	nowMs := now.UnixMilli()
	resolved := self.resolve(&subject, nowMs)
	if resolved.deny != 0 {
		return aclDeny(resolved.deny)
	}
	var bound, hostOnly *aclRule
	boundAgree, hostOnlyAgree := true, true
	agrees := func(first *aclRule, rule *aclRule) bool {
		return aclPublishAudience(first.row.GetAudience()) == aclPublishAudience(rule.row.GetAudience()) &&
			aclPublishAppMode(first.row.GetAppMode()) == aclPublishAppMode(rule.row.GetAppMode()) &&
			bytes.Equal(first.row.GetLinkSpkiSha256(), rule.row.GetLinkSpkiSha256())
	}
	// the class each rule falls in: 1 binds this socket for listen, 2 binds no socket, 0 neither
	classOf := func(rule *aclRule) int {
		coversHost, coversName, bindsSocket := false, false, false
		for _, pattern := range rule.publicNames {
			if strings.Contains(pattern, "/") {
				bindsSocket = true
				coversName = coversName || aclPublicSocketCovers(pattern, socketName)
			} else {
				coversHost = coversHost || aclDnsHostCovers(pattern, host)
			}
		}
		switch {
		case !coversHost:
			return 0
		case coversName && rule.allows(protocol.AclAction_ACL_ACTION_LISTEN):
			return 1
		case !bindsSocket:
			return 2
		}
		return 0
	}
	match := func(rule *aclRule) bool {
		switch classOf(rule) {
		case 1:
			if bound == nil {
				bound = rule
			} else if !agrees(bound, rule) {
				boundAgree = false
			}
		case 2:
			if hostOnly == nil {
				hostOnly = rule
			} else if !agrees(hostOnly, rule) {
				hostOnlyAgree = false
			}
		}
		// every rule is read, so each class is whole
		return false
	}
	self.findResourceRule(&resolved, nowMs, protocol.AclAction_ACL_ACTION_PUBLISH, match)
	first, class, agree := bound, 1, boundAgree
	if first == nil {
		first, class, agree = hostOnly, 2, hostOnlyAgree
		if first != nil && !self.MayListen(subject, AclSocketName{PublicName: socketName}, now).Allowed {
			// publish requires listen on the bound socket
			return aclDeny(AclReasonNoGrant)
		}
	}
	if first == nil || !agree {
		return aclDeny(AclReasonNoGrant)
	}
	audience, ruleMode, pin := aclPublishAudience(first.row.GetAudience()), aclPublishAppMode(first.row.GetAppMode()), first.row.GetLinkSpkiSha256()
	if ruleMode != appMode {
		return aclDeny(AclReasonNoGrant)
	}
	if ruleMode == protocol.AclAppMode_ACL_APP_MODE_RAW {
		switch {
		case audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC && audience != protocol.AclAudience_ACL_AUDIENCE_LINK:
			return aclDeny(AclReasonNoGrant)
		case audience == protocol.AclAudience_ACL_AUDIENCE_LINK && len(pin) != 32:
			return aclDeny(AclReasonNoGrant)
		}
	}
	if grant != nil {
		grant.Audience, grant.AppMode, grant.LinkSpkiSha256 = audience, ruleMode, bytes.Clone(pin)
		unbounded := false
		self.findResourceRule(&resolved, nowMs, protocol.AclAction_ACL_ACTION_PUBLISH, func(rule *aclRule) bool {
			if classOf(rule) != class {
				return false
			}
			grant.GrantIds = append(grant.GrantIds, bytes.Clone(rule.row.GetRuleId()))
			if rule.expiresMs == 0 {
				unbounded = true
			} else if grant.ExpiresMs < rule.expiresMs {
				grant.ExpiresMs = rule.expiresMs
			}
			return false
		})
		if unbounded {
			grant.ExpiresMs = 0
		}
	}
	return aclAllowRule(first)
}
