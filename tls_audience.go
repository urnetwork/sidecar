//go:build !sidecar_http && !ios_extension

// §13.7's audience check (R-TLS-5, D-TLS-5, D-TLS-13, FI-11, I-4, owner decision 42): only the front enforces a
// publish grant's audience, and a modified sidecar skips it (§21.4), so the front makes no claim to any server and
// takes its grant from this device's own evaluation of its config (TlsFrontPolicy), never from the ticket or a
// server's answer. The check gives a pass bound to one connection, and only a pass opens the target
// (TlsFrontConn.openTarget), so no application byte reaches the local service before it, whatever the ALPN:
//
//	public          passes, explicitly
//	members         §7.8's edge login: a sealed __Host-ur-session naming a member this device's config holds now,
//	                checked on every request, so a removal ends the session at the next one; without one, a
//	                navigation goes to edge login and anything else is refused (S5)
//	link            http: a __Host-ur-link cookie holding a TlsLinkToken that verifies (tls_link.go); raw: the
//	                handshake's client certificate hashing to the grant's pin over TLS 1.3
//	members-device  members' edge login and then a consented device's edge-login statement (tls_members_device.go):
//	                a session that names that device, which counts while the device stays consented for its member
//	                and the member a member, checked on every request; without one, a navigation goes to edge login
//
// The issuer's ID token is checked against this config's members too (§2.8 EX8), never trusted alone.
//
// NewTlsFrontConfigPolicy is the production policy, over the verified ConfigState: a grant is the set of this
// sidecar's publish rules that take the host and the endpoint's tls/ name for listen, or where none does, those that
// take the host and bind no socket at all, never one binding another port's name; rules that disagree on audience,
// mode or pin give none, the closed direction. ACL-M5-01's AclState.PublishGrant is meant to answer the same; until
// it lands this reads the rules itself.
//
// Each check sits between barriers, tls.front_audience.before and .after, keyed by the connection's id. Safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The tls/ name §13.9's system publish serves, and the receiver's listen grant that stands in for its grants.
const (
	tlsSystemPublishName   = "tls/443/mta-sts"
	tlsSystemPublishListen = "smtp/25/mx"
)

// One endpoint's publish grant as this device's evaluation holds it (§8.4): the audience, mode and pin the front
// enforces. A copy, which the caller may keep.
type TlsPublishGrant struct {
	// The rule_ids of the rules that grant it, one but where several agree. A link token names one.
	GrantIds [][]byte
	// members, members-device, link or public; unspecified reads as members and is never answered.
	Audience protocol.AclAudience
	// http or raw; unspecified reads as http and is never answered.
	AppMode protocol.AclAppMode
	// A raw link's pin, 32 bytes, else nil.
	LinkSpkiSha256 []byte
	// When the last of the rules ends; zero for none.
	Expires time.Time
	// The config version the grant was read at, ConfigState.Pin's; 0 where the policy does not say.
	PolicyVersion uint64
}

// Whether grantId is one of the grant's rules.
func (self *TlsPublishGrant) holds(grantId []byte) bool {
	for _, held := range self.GrantIds {
		if bytes.Equal(held, grantId) {
			return true
		}
	}
	return false
}

// What the front reads of this device's own evaluation of its config (owner decisions 3, 6 and 42; §8.10). Each
// answer is the newest verified state's, at now. Safe for concurrent use.
type TlsFrontPolicy interface {
	// This sidecar's grant to publish host under the tls/ name, nil for none.
	PublishGrant(name string, host string, now time.Time) *TlsPublishGrant
	// signerId's grant of rule grantId to publish host under name, nil when that sidecar holds none by that rule:
	// whether a link token's signer is a sidecar the grant names.
	PublishGrantOf(signerId Id, grantId []byte, name string, host string, now time.Time) *TlsPublishGrant
	// Whether memberId is a member of this network now.
	MemberActive(memberId Id, now time.Time) bool
	// An admitted, unrevoked sidecar's identity public key, nil for any other.
	IdentityKey(sidecarId Id) []byte
	// Whether sidecarId is a device of memberId consented now (§8.5's consented(d, M)), and neither read_only, whose
	// statements every verifier refuses (§7.9), nor suspended: what may vouch for a members-device login.
	DeviceConsented(sidecarId Id, memberId Id, now time.Time) bool
}

// The policy over this device's verified config: state answers the newest ConfigState its config client holds, nil
// before the first, when every question refuses.
func NewTlsFrontConfigPolicy(sidecarId Id, state func() *ConfigState) TlsFrontPolicy {
	return &tlsFrontConfigPolicy{sidecarId: sidecarId, state: state}
}

// See NewTlsFrontConfigPolicy.
type tlsFrontConfigPolicy struct {
	sidecarId Id
	state     func() *ConfigState
}

// The newest state's ACL evaluation, nil when there is none.
func (self *tlsFrontConfigPolicy) acl() *AclState {
	state := self.state()
	if state == nil {
		return nil
	}
	acl, err := state.Acl()
	if err != nil {
		return nil
	}
	return acl
}

// See TlsFrontPolicy. The grant carries the version of the state it was read from.
func (self *tlsFrontConfigPolicy) PublishGrant(name string, host string, now time.Time) *TlsPublishGrant {
	state := self.state()
	if state == nil {
		return nil
	}
	acl, err := state.Acl()
	if err != nil {
		return nil
	}
	grant := tlsPublishGrantOf(acl, AclSidecarSubject(self.sidecarId), name, host, nil, now)
	if grant != nil {
		grant.PolicyVersion = state.Pin().GetVersion()
	}
	return grant
}

// See TlsFrontPolicy.
func (self *tlsFrontConfigPolicy) PublishGrantOf(signerId Id, grantId []byte, name string, host string, now time.Time) *TlsPublishGrant {
	if len(grantId) == 0 {
		return nil
	}
	return tlsPublishGrantOf(self.acl(), AclSidecarSubject(signerId), name, host, grantId, now)
}

// See TlsFrontPolicy.
func (self *tlsFrontConfigPolicy) MemberActive(memberId Id, now time.Time) bool {
	state := self.state()
	return state != nil && state.Member(memberId) != nil
}

// See TlsFrontPolicy.
func (self *tlsFrontConfigPolicy) DeviceConsented(sidecarId Id, memberId Id, now time.Time) bool {
	state := self.state()
	if state == nil {
		return false
	}
	acl, err := state.Acl()
	if err != nil {
		return false
	}
	row := state.SidecarRow(sidecarId)
	if row == nil || row.GetRevokedAt() != 0 || row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0 ||
		state.Suspended(sidecarId) {
		return false
	}
	return acl.ConsentedFor(sidecarId, memberId)
}

// See TlsFrontPolicy.
func (self *tlsFrontConfigPolicy) IdentityKey(sidecarId Id) []byte {
	state := self.state()
	if state == nil {
		return nil
	}
	// a revoked row signs nothing; with no row only the genesis owner has a key (ConfigState.IdentityKey)
	if row := state.SidecarRow(sidecarId); row != nil && row.GetRevokedAt() != 0 {
		return nil
	}
	return bytes.Clone(state.IdentityKey(sidecarId))
}

// The grant subject holds to publish host under name at now, by rule grantId alone when it is not nil: see the file
// header. The system publish stands on the receiver's smtp/25/mx listen grant, public and http (§13.9).
func tlsPublishGrantOf(state *AclState, subject AclSubject, name string, host string, grantId []byte, now time.Time) *TlsPublishGrant {
	if state == nil || host == "" {
		return nil
	}
	if name == tlsSystemPublishName {
		decision := state.MayListen(subject, AclSocketName{PublicName: tlsSystemPublishListen}, now)
		if !decision.Allowed || decision.Rule == nil || (grantId != nil && !bytes.Equal(decision.Rule.GetRuleId(), grantId)) {
			return nil
		}
		grant := &TlsPublishGrant{
			GrantIds: [][]byte{bytes.Clone(decision.Rule.GetRuleId())},
			Audience: protocol.AclAudience_ACL_AUDIENCE_PUBLIC,
			AppMode:  protocol.AclAppMode_ACL_APP_MODE_HTTP,
		}
		if expires := decision.Rule.GetExpires(); expires != 0 {
			grant.Expires = time.UnixMilli(expires)
		}
		return grant
	}
	nowMs := now.UnixMilli()
	resolved := state.resolve(&subject, nowMs)
	if resolved.deny != 0 {
		return nil
	}
	// rules that bind this name, and rules that bind no socket at all; a rule binding another socket is neither
	hostOnlyRules := []*aclRule{}
	boundRules := []*aclRule{}
	state.findResourceRule(&resolved, nowMs, protocol.AclAction_ACL_ACTION_PUBLISH, func(rule *aclRule) bool {
		if grantId != nil && !bytes.Equal(rule.row.GetRuleId(), grantId) {
			return false
		}
		coversHost := false
		coversName := false
		bindsSocket := false
		for _, pattern := range rule.publicNames {
			if strings.Contains(pattern, "/") {
				bindsSocket = true
				coversName = coversName || aclPublicSocketCovers(pattern, name)
			} else {
				coversHost = coversHost || aclDnsHostCovers(pattern, host)
			}
		}
		switch {
		case !coversHost:
		case coversName && rule.allows(protocol.AclAction_ACL_ACTION_LISTEN):
			boundRules = append(boundRules, rule)
		case !bindsSocket:
			hostOnlyRules = append(hostOnlyRules, rule)
		}
		// every rule is read, so the set is whole
		return false
	})
	rules := boundRules
	if len(rules) == 0 {
		rules = hostOnlyRules
	}
	if len(rules) == 0 {
		return nil
	}
	grant := &TlsPublishGrant{
		Audience:       tlsGrantAudience(rules[0].row.GetAudience()),
		AppMode:        tlsGrantAppMode(rules[0].row.GetAppMode()),
		LinkSpkiSha256: bytes.Clone(rules[0].row.GetLinkSpkiSha256()),
	}
	unbounded := false
	for _, rule := range rules {
		if tlsGrantAudience(rule.row.GetAudience()) != grant.Audience || tlsGrantAppMode(rule.row.GetAppMode()) != grant.AppMode ||
			!bytes.Equal(rule.row.GetLinkSpkiSha256(), grant.LinkSpkiSha256) {
			// rules that disagree leave the front no audience to enforce, so none passes
			return nil
		}
		grant.GrantIds = append(grant.GrantIds, bytes.Clone(rule.row.GetRuleId()))
		if rule.expiresMs == 0 {
			unbounded = true
		} else if expires := time.UnixMilli(rule.expiresMs); expires.After(grant.Expires) {
			grant.Expires = expires
		}
	}
	if unbounded {
		grant.Expires = time.Time{}
	}
	return grant
}

// An audience with unspecified read as members (§8.4's default).
func tlsGrantAudience(audience protocol.AclAudience) protocol.AclAudience {
	if audience == protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED {
		return protocol.AclAudience_ACL_AUDIENCE_MEMBERS
	}
	return audience
}

// An app mode with unspecified read as http (§8.4's default).
func tlsGrantAppMode(appMode protocol.AclAppMode) protocol.AclAppMode {
	if appMode == protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED {
		return protocol.AclAppMode_ACL_APP_MODE_HTTP
	}
	return appMode
}

// What one audience check gives one connection, and on http one request: the only key to its target.
type tlsAudiencePass struct {
	conn     *TlsFrontConn
	audience protocol.AclAudience
	// the grant the check passed under, which a reach receipt names (tls_reach_receipt.go)
	grant *TlsPublishGrant
	// members and members-device: who the session names
	memberId Id
}

// Carries a pass on a request's context, to the target's transport.
type tlsAudiencePassKey struct{}

// The pass ctx carries, nil for none.
func tlsAudiencePassOf(ctx context.Context) *tlsAudiencePass {
	pass, _ := ctx.Value(tlsAudiencePassKey{}).(*tlsAudiencePass)
	return pass
}

// How one HTTP request's check came out.
type tlsAudienceOutcome int

const (
	// The request reaches the service with the pass.
	tlsAudiencePassed tlsAudienceOutcome = iota + 1
	// members, no counted session, on a navigation: edge login.
	tlsAudienceLogin
	// members, no counted session, not a navigation: 401.
	tlsAudienceUnauthorized
	// Anything else: 403.
	tlsAudienceForbidden
)

// One HTTP request's verdict.
type tlsAudienceVerdict struct {
	outcome tlsAudienceOutcome
	// set when passed
	pass *tlsAudiencePass
	// the grant the check read, nil when there was none
	grant *TlsPublishGrant
}

// One front's check.
type tlsAudienceCheck struct {
	front *TlsFront
}

// The endpoint's grant at now, for the mode the registration signed, nil for none or another mode.
func (self *tlsAudienceCheck) grant(appMode protocol.AclAppMode, now time.Time) *TlsPublishGrant {
	target := self.front.target
	grant := self.front.policy.PublishGrant(target.Name, target.host(), now)
	if grant == nil || grant.AppMode != appMode {
		return nil
	}
	return grant
}

// raw: public passes; link needs the handshake's client certificate to hash to the grant's pin, over TLS 1.3.
func (self *tlsAudienceCheck) checkRaw(conn *TlsFrontConn) *tlsAudiencePass {
	testHookBarrier("tls.front_audience.before", conn.barrierKey)
	defer testHookBarrier("tls.front_audience.after", conn.barrierKey)
	grant := self.grant(protocol.AclAppMode_ACL_APP_MODE_RAW, self.front.clock.Now())
	if grant == nil {
		return nil
	}
	switch grant.Audience {
	case protocol.AclAudience_ACL_AUDIENCE_PUBLIC:
	case protocol.AclAudience_ACL_AUDIENCE_LINK:
		if tlsLinkPinCheck(conn.ConnectionState(), grant.LinkSpkiSha256) != nil {
			return nil
		}
	default:
		return nil
	}
	return &tlsAudiencePass{conn: conn, audience: grant.Audience, grant: grant}
}

// http: one request's check, on view's counted cookies (§13.7's other-origins row).
func (self *tlsAudienceCheck) checkHttp(r *http.Request, conn *TlsFrontConn, view *tlsHttpSessionView) *tlsAudienceVerdict {
	testHookBarrier("tls.front_audience.before", conn.barrierKey)
	defer testHookBarrier("tls.front_audience.after", conn.barrierKey)
	now := self.front.clock.Now()
	grant := self.grant(protocol.AclAppMode_ACL_APP_MODE_HTTP, now)
	if grant == nil {
		return &tlsAudienceVerdict{outcome: tlsAudienceForbidden}
	}
	switch grant.Audience {
	case protocol.AclAudience_ACL_AUDIENCE_PUBLIC:
		return &tlsAudienceVerdict{outcome: tlsAudiencePassed, grant: grant, pass: &tlsAudiencePass{conn: conn, audience: grant.Audience, grant: grant}}
	case protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE:
		session := self.front.sessions.openSession(view.session, tlsEdgeLoginOrigin(conn), now)
		counts := session != nil && self.front.policy.MemberActive(session.memberId, now)
		if counts && grant.Audience == protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE {
			// a members session names no device, and a device that lost its standing vouches for nothing now
			counts = session.deviceSidecarId != (Id{}) && self.front.policy.DeviceConsented(session.deviceSidecarId, session.memberId, now)
		}
		if counts {
			return &tlsAudienceVerdict{outcome: tlsAudiencePassed, grant: grant, pass: &tlsAudiencePass{
				conn:     conn,
				audience: grant.Audience,
				grant:    grant,
				memberId: session.memberId,
			}}
		}
		if view.navigation {
			return &tlsAudienceVerdict{outcome: tlsAudienceLogin, grant: grant}
		}
		return &tlsAudienceVerdict{outcome: tlsAudienceUnauthorized, grant: grant}
	case protocol.AclAudience_ACL_AUDIENCE_LINK:
		if _, err := self.verifyLink(view.link, conn, grant, now); err == nil {
			return &tlsAudienceVerdict{outcome: tlsAudiencePassed, grant: grant, pass: &tlsAudiencePass{conn: conn, audience: grant.Audience, grant: grant}}
		}
		return &tlsAudienceVerdict{outcome: tlsAudienceForbidden, grant: grant}
	}
	// nothing else is an audience
	return &tlsAudienceVerdict{outcome: tlsAudienceForbidden, grant: grant}
}
