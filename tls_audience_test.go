//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The production policy's grant binds the endpoint's tls/ name: one host published on two ports under different
// audiences gives each endpoint its own, so 8443's public grant never opens 443's members endpoint.
func TestTlsPublishGrantOfBindsTheListenName(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	device := fixture.device(owner)
	atom := fixture.sidecarAtom(device)
	members := fixture.rule([]Id{atom}, []*protocol.AclTarget{{PublicName: "app"}, {PublicName: "tls/443/app"}},
		protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN)
	public := fixture.rule([]Id{atom}, []*protocol.AclTarget{{PublicName: "app"}, {PublicName: "tls/8443/app"}},
		protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN)
	public.Audience = protocol.AclAudience_ACL_AUDIENCE_PUBLIC
	public.Expires = aclTestNow.Add(time.Hour).UnixMilli()
	state := fixture.state(t)
	subject := AclSidecarSubject(device)

	grant := tlsPublishGrantOf(state, subject, "tls/443/app", "app", nil, aclTestNow)
	if grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_MEMBERS || grant.AppMode != protocol.AclAppMode_ACL_APP_MODE_HTTP ||
		len(grant.GrantIds) != 1 || !bytes.Equal(grant.GrantIds[0], members.RuleId) || !grant.Expires.IsZero() {
		t.Fatalf("443: %+v", grant)
	}
	grant = tlsPublishGrantOf(state, subject, "tls/8443/app", "app", nil, aclTestNow)
	if grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC || !bytes.Equal(grant.GrantIds[0], public.RuleId) ||
		!grant.Expires.Equal(time.UnixMilli(public.Expires)) {
		t.Fatalf("8443: %+v", grant)
	}
	// a rule binding another port's name never stands in, so 8443 past its own rule has none
	if grant := tlsPublishGrantOf(state, subject, "tls/8443/app", "app", nil, aclTestNow.Add(time.Hour)); grant != nil {
		t.Errorf("8443 past its rule's expiry: %+v", grant)
	}
	if grant := tlsPublishGrantOf(state, subject, "tls/8443/app", "app", public.RuleId, aclTestNow); grant == nil || !bytes.Equal(grant.GrantIds[0], public.RuleId) {
		t.Errorf("by rule id: %+v", grant)
	}
	if grant := tlsPublishGrantOf(state, subject, "tls/443/app", "app", public.RuleId, aclTestNow); grant != nil {
		t.Errorf("another port's rule by its id: %+v", grant)
	}
	if grant := tlsPublishGrantOf(state, subject, "tls/443/other", "other", nil, aclTestNow); grant != nil {
		t.Errorf("an unpublished host: %+v", grant)
	}
	if grant := tlsPublishGrantOf(state, AclSidecarSubject(NewId()), "tls/443/app", "app", nil, aclTestNow); grant != nil {
		t.Errorf("an unadmitted sidecar: %+v", grant)
	}
	if grant := tlsPublishGrantOf(nil, subject, "tls/443/app", "app", nil, aclTestNow); grant != nil {
		t.Errorf("no state: %+v", grant)
	}
}

// Host-only publish rules that disagree on audience, mode or pin leave the front nothing to enforce, so none
// passes; ones that agree make one grant of every rule.
func TestTlsPublishGrantOfRefusesDisagreeingRules(t *testing.T) {
	for _, agree := range []bool{true, false} {
		fixture := newAclTestFixture()
		owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
		device := fixture.device(owner)
		atom := fixture.sidecarAtom(device)
		first := fixture.rule([]Id{atom}, []*protocol.AclTarget{{PublicName: "app"}}, protocol.AclAction_ACL_ACTION_PUBLISH)
		second := fixture.rule([]Id{atom}, []*protocol.AclTarget{{PublicName: "*"}}, protocol.AclAction_ACL_ACTION_PUBLISH)
		first.Audience = protocol.AclAudience_ACL_AUDIENCE_LINK
		second.Audience = protocol.AclAudience_ACL_AUDIENCE_LINK
		if !agree {
			second.Audience = protocol.AclAudience_ACL_AUDIENCE_PUBLIC
		}
		grant := tlsPublishGrantOf(fixture.state(t), AclSidecarSubject(device), "tls/443/app", "app", nil, aclTestNow)
		if agree && (grant == nil || len(grant.GrantIds) != 2 || !grant.holds(first.RuleId) || !grant.holds(second.RuleId)) {
			t.Errorf("agreeing rules: %+v", grant)
		}
		if !agree && grant != nil {
			t.Errorf("disagreeing rules: %+v", grant)
		}
	}
}

// §13.9's system publish stands on the receiver's smtp/25/mx listen grant, public and http, and on nothing else.
func TestTlsPublishGrantOfTheSystemPublish(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	receiver := fixture.device(owner)
	other := fixture.device(owner)
	listen := fixture.rule([]Id{fixture.sidecarAtom(receiver)}, []*protocol.AclTarget{{PublicName: "smtp/25/mx"}}, protocol.AclAction_ACL_ACTION_LISTEN)
	state := fixture.state(t)
	grant := tlsPublishGrantOf(state, AclSidecarSubject(receiver), tlsSystemPublishName, "mta-sts", nil, aclTestNow)
	if grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC || grant.AppMode != protocol.AclAppMode_ACL_APP_MODE_HTTP ||
		!grant.holds(listen.RuleId) {
		t.Fatalf("the receiver: %+v", grant)
	}
	if grant := tlsPublishGrantOf(state, AclSidecarSubject(other), tlsSystemPublishName, "mta-sts", nil, aclTestNow); grant != nil {
		t.Errorf("a sidecar with no listen grant: %+v", grant)
	}
}

// With no verified state every question the policy answers refuses.
func TestTlsFrontConfigPolicyRefusesWithoutState(t *testing.T) {
	policy := NewTlsFrontConfigPolicy(NewId(), func() *ConfigState { return nil })
	now := aclTestNow
	if policy.PublishGrant("tls/443/app", "app", now) != nil || policy.PublishGrantOf(NewId(), NewId().Bytes(), "tls/443/app", "app", now) != nil ||
		policy.MemberActive(NewId(), now) || policy.IdentityKey(NewId()) != nil {
		t.Error("a policy with no state answered")
	}
	if policy.PublishGrantOf(NewId(), nil, "tls/443/app", "app", now) != nil {
		t.Error("a grant of no rule id")
	}
}

// §7.8: the member check repeats on every request against this device's config, so a removal ends a session at the
// next request: a navigation goes back to edge login, anything else is refused, and neither reaches the service.
func TestTlsAudienceRemovedMemberSessionEnds(t *testing.T) {
	memberId := NewId()
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		fixture.policy.members[memberId] = true
	})
	session := fixture.sealSession(t, memberId)
	client := fixture.httpClient(tlsAlpnHttp11)
	request := func() *http.Request {
		request := tlsFrontTestNavigation(t, http.MethodGet, "/private")
		request.AddCookie(&http.Cookie{Name: tlsSessionCookieName, Value: session})
		return request
	}
	if response, body := tlsFrontTestDo(t, client, request()); response.StatusCode != http.StatusOK || body != "backend" {
		t.Fatalf("a member's session: %d", response.StatusCode)
	}
	fixture.backend.nextRequest(t)
	fixture.policy.stateLock.Lock()
	delete(fixture.policy.members, memberId)
	fixture.policy.stateLock.Unlock()
	response, _ := tlsFrontTestDo(t, client, request())
	if response.StatusCode != http.StatusFound || !strings.HasPrefix(response.Header.Get("Location"), tlsFrontTestIssuer+"/oauth/authorize?") {
		t.Errorf("a removed member's navigation: %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	api, err := http.NewRequest(http.MethodGet, "https://"+tlsFrontTestServerName+"/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	api.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteSameOrigin)
	api.AddCookie(&http.Cookie{Name: tlsSessionCookieName, Value: session})
	if response, _ := tlsFrontTestDo(t, client, api); response.StatusCode != http.StatusUnauthorized {
		t.Errorf("a removed member's fetch: %d", response.StatusCode)
	}
	if dials, _ := fixture.backend.counts(); dials != 1 {
		t.Errorf("%d dials, one before the removal", dials)
	}
}

// A session past its 12 h, or sealed for another host, is no session.
func TestTlsAudienceRefusesAStaleOrForeignSession(t *testing.T) {
	memberId := NewId()
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		fixture.policy.members[memberId] = true
	})
	session := fixture.sealSession(t, memberId)
	foreign, err := fixture.front.sessions.sealSession(tlsFrontTestOtherName, &tlsSession{
		memberId: memberId, issueTime: fixture.clock.Now(), expireTime: fixture.clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := fixture.httpClient(tlsAlpnHttp11)
	fetch := func(value string) int {
		request, err := http.NewRequest(http.MethodGet, "https://"+tlsFrontTestServerName+"/api", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteSameOrigin)
		request.AddCookie(&http.Cookie{Name: tlsSessionCookieName, Value: value})
		response, _ := tlsFrontTestDo(t, client, request)
		return response.StatusCode
	}
	if status := fetch(foreign); status != http.StatusUnauthorized {
		t.Errorf("another host's session: %d", status)
	}
	fixture.clock.advance(fixture.settings.SessionLifetime)
	if status := fetch(session); status != http.StatusUnauthorized {
		t.Errorf("a session past its life: %d", status)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// members-device waits on M6's device statement, so nothing passes it yet, signed in or not.
func TestTlsAudienceMembersDeviceRefused(t *testing.T) {
	memberId := NewId()
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		fixture.policy.members[memberId] = true
	})
	request := tlsFrontTestNavigation(t, http.MethodGet, "/")
	request.AddCookie(&http.Cookie{Name: tlsSessionCookieName, Value: fixture.sealSession(t, memberId)})
	if response, _ := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), request); response.StatusCode != http.StatusForbidden {
		t.Errorf("%d", response.StatusCode)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}
