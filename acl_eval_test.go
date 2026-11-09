// §8.6's checks on hand-made rows and a fake view: each autogroup, hard denies, expiry at exactly t,
// autogroup:self, sockets expanding to listeners, ports, routes, publishes, sends and the subjects that are
// no sidecars. Pure, on every leg.

package sidecar

import (
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network with one subject of each class, for the autogroup cases.
type aclTestSubjects struct {
	fixture         *aclTestFixture
	ownerMember     Id
	adminMember     Id
	auditorMember   Id
	plainMember     Id
	ownerDevice     Id
	adminDevice     Id
	auditorDevice   Id
	memberDevice    Id
	ephemeral       Id
	tagId           Id
	tagged          Id
	taggedEphemeral Id
	appClient       Id
	legacyClient    Id
	target          Id
}

func newAclTestSubjects() *aclTestSubjects {
	fixture := newAclTestFixture()
	self := &aclTestSubjects{fixture: fixture}
	self.ownerMember = fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.adminMember = fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	self.auditorMember = fixture.member(bridge.MemberRole_MEMBER_ROLE_AUDITOR)
	self.plainMember = fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.ownerDevice = fixture.device(self.ownerMember)
	self.adminDevice = fixture.device(self.adminMember)
	self.auditorDevice = fixture.device(self.auditorMember)
	self.memberDevice = fixture.device(self.plainMember)
	self.ephemeral = fixture.device(self.plainMember)
	fixture.admission(self.ephemeral).Ephemeral = true
	self.tagId = fixture.tag(self.adminMember)
	self.tagged = fixture.agent(self.plainMember, self.tagId)
	self.taggedEphemeral = fixture.agent(self.plainMember, self.tagId)
	fixture.admission(self.taggedEphemeral).Ephemeral = true
	self.appClient = NewId()
	self.legacyClient = NewId()
	self.target = fixture.device(self.ownerMember)
	return self
}

func (self *aclTestSubjects) subject(id Id) AclSubject {
	switch id {
	case self.appClient:
		return AclClientSubject(id, self.plainMember, nil, "")
	case self.legacyClient:
		return AclClientSubject(id, Id{}, nil, "")
	}
	return AclSidecarSubject(id)
}

// Each autogroup in a src holds exactly the subjects §8.4 and D-ACL-20 put in it.
func TestAclEachAutogroupHoldsItsSubjects(t *testing.T) {
	cases := []struct {
		autogroup protocol.AclAutogroup
		members   []func(subjects *aclTestSubjects) Id
	}{
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.ownerDevice },
			func(s *aclTestSubjects) Id { return s.adminDevice },
			func(s *aclTestSubjects) Id { return s.auditorDevice },
			func(s *aclTestSubjects) Id { return s.memberDevice },
			func(s *aclTestSubjects) Id { return s.ephemeral },
		}},
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_OWNER, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.ownerDevice },
		}},
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.ownerDevice },
			func(s *aclTestSubjects) Id { return s.adminDevice },
		}},
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.auditorDevice },
		}},
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.ownerDevice },
			func(s *aclTestSubjects) Id { return s.adminDevice },
			func(s *aclTestSubjects) Id { return s.auditorDevice },
			func(s *aclTestSubjects) Id { return s.memberDevice },
			func(s *aclTestSubjects) Id { return s.ephemeral },
			func(s *aclTestSubjects) Id { return s.tagged },
			func(s *aclTestSubjects) Id { return s.taggedEphemeral },
		}},
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.tagged },
			func(s *aclTestSubjects) Id { return s.taggedEphemeral },
		}},
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.appClient },
			func(s *aclTestSubjects) Id { return s.legacyClient },
		}},
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.ephemeral },
		}},
		{autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK, members: []func(*aclTestSubjects) Id{
			func(s *aclTestSubjects) Id { return s.ownerDevice },
			func(s *aclTestSubjects) Id { return s.adminDevice },
			func(s *aclTestSubjects) Id { return s.auditorDevice },
			func(s *aclTestSubjects) Id { return s.memberDevice },
			func(s *aclTestSubjects) Id { return s.ephemeral },
			func(s *aclTestSubjects) Id { return s.tagged },
			func(s *aclTestSubjects) Id { return s.taggedEphemeral },
			func(s *aclTestSubjects) Id { return s.appClient },
			func(s *aclTestSubjects) Id { return s.legacyClient },
		}},
	}
	for _, c := range cases {
		subjects := newAclTestSubjects()
		subjects.fixture.rule(autogroupAtoms(c.autogroup), []*protocol.AclTarget{aclSidecarTarget(subjects.target)}, protocol.AclAction_ACL_ACTION_DIAL)
		state := subjects.fixture.state(t)
		want := map[Id]bool{}
		for _, member := range c.members {
			want[member(subjects)] = true
		}
		all := []Id{subjects.ownerDevice, subjects.adminDevice, subjects.auditorDevice, subjects.memberDevice, subjects.ephemeral,
			subjects.tagged, subjects.taggedEphemeral, subjects.appClient, subjects.legacyClient}
		for _, id := range all {
			decision := state.Reach(subjects.subject(id), AclSidecarSubject(subjects.target), aclTestNow)
			if decision.Allowed != want[id] {
				t.Errorf("%s: subject %v allowed %t, want %t (%s)", protocol.AclAutogroup_name[int32(c.autogroup)], id, decision.Allowed, want[id], decision.Reason)
			}
		}
	}
}

// User and group atoms hold an untagged subject's member and never a tagged one, whose tags it holds
// instead; a sidecar atom holds its sidecar.
func TestAclUserGroupTagAndSidecarAtoms(t *testing.T) {
	subjects := newAclTestSubjects()
	fixture := subjects.fixture
	group := fixture.group(subjects.plainMember)
	sidecarAtom := fixture.sidecarAtom(subjects.auditorDevice)
	targetOf := map[Id]Id{}
	for _, atom := range []Id{group, subjects.tagId, sidecarAtom} {
		destination := fixture.device(subjects.ownerMember)
		targetOf[atom] = destination
		fixture.rule([]Id{atom}, []*protocol.AclTarget{aclSidecarTarget(destination)}, protocol.AclAction_ACL_ACTION_DIAL)
	}
	state := fixture.state(t)
	cases := []struct {
		atom    Id
		subject Id
		allowed bool
	}{
		{atom: group, subject: subjects.memberDevice, allowed: true},
		{atom: group, subject: subjects.ephemeral, allowed: true},
		{atom: group, subject: subjects.appClient, allowed: true},
		{atom: group, subject: subjects.tagged, allowed: false},
		{atom: group, subject: subjects.ownerDevice, allowed: false},
		{atom: subjects.tagId, subject: subjects.tagged, allowed: true},
		{atom: subjects.tagId, subject: subjects.taggedEphemeral, allowed: true},
		{atom: subjects.tagId, subject: subjects.memberDevice, allowed: false},
		{atom: sidecarAtom, subject: subjects.auditorDevice, allowed: true},
		{atom: sidecarAtom, subject: subjects.adminDevice, allowed: false},
	}
	for i, c := range cases {
		decision := state.Reach(subjects.subject(c.subject), AclSidecarSubject(targetOf[c.atom]), aclTestNow)
		if decision.Allowed != c.allowed {
			t.Errorf("case %d: allowed %t (%s)", i, decision.Allowed, decision.Reason)
		}
	}
}

// A tagged admission's tag holds even before a base lists the sidecar under the tag's atom, since the
// admission is what is signed.
func TestAclTagHoldsFromTheAdmission(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	destination := fixture.device(owner)
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclSidecarTarget(destination)}, protocol.AclAction_ACL_ACTION_DIAL)
	agent := NewId()
	fixture.view.sidecars[agent] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: agent.Bytes(), AdmittedAt: 9}, TagIds: []Id{tagId}}
	state := fixture.state(t)
	if decision := state.Reach(AclSidecarSubject(agent), AclSidecarSubject(destination), aclTestNow); !decision.Allowed {
		t.Errorf("refused: %s", decision.Reason)
	}
}

// Every hard deny the state shows refuses a source, and refuses a destination too.
func TestAclHardDeniesRefuse(t *testing.T) {
	cases := []struct {
		name   string
		reason AclReason
		edit   func(fixture *aclTestFixture, sidecarId Id, memberId Id)
	}{
		{name: "revoked", reason: AclReasonRevoked, edit: func(fixture *aclTestFixture, sidecarId Id, memberId Id) {
			fixture.admission(sidecarId).Row.RevokedAt = fixture.next()
		}},
		{name: "parked", reason: AclReasonParked, edit: func(fixture *aclTestFixture, sidecarId Id, memberId Id) {
			fixture.view.parked[sidecarId] = true
		}},
		{name: "suspended", reason: AclReasonSuspended, edit: func(fixture *aclTestFixture, sidecarId Id, memberId Id) {
			fixture.rows.Suspensions = append(fixture.rows.Suspensions, &protocol.AclSuspension{Subject: sidecarId.Bytes()})
		}},
		{name: "past not_after", reason: AclReasonExpired, edit: func(fixture *aclTestFixture, sidecarId Id, memberId Id) {
			fixture.admission(sidecarId).Row.NotAfter = aclTestNow.UnixMilli()
		}},
		{name: "member gone", reason: AclReasonUnadmitted, edit: func(fixture *aclTestFixture, sidecarId Id, memberId Id) {
			delete(fixture.view.members, memberId)
		}},
		{name: "never admitted", reason: AclReasonUnadmitted, edit: func(fixture *aclTestFixture, sidecarId Id, memberId Id) {
			delete(fixture.view.sidecars, sidecarId)
		}},
	}
	for _, c := range cases {
		for _, deniedIsSource := range []bool{true, false} {
			fixture := newAclTestFixture()
			owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
			deniedMember := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
			denied := fixture.device(deniedMember)
			other := fixture.device(owner)
			fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER),
				[]*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)}, protocol.AclAction_ACL_ACTION_DIAL)
			c.edit(fixture, denied, deniedMember)
			state := fixture.state(t)
			source, destination := denied, other
			if !deniedIsSource {
				source, destination = other, denied
			}
			decision := state.Reach(AclSidecarSubject(source), AclSidecarSubject(destination), aclTestNow)
			if decision.Allowed || decision.Reason != c.reason {
				t.Errorf("%s, denied is source %t: %+v, want %s", c.name, deniedIsSource, decision, c.reason)
			}
		}
	}
}

// A caller's deny, an abuse halt or quota, refuses as the state's own do, for a source or a destination.
func TestAclCallerDenyRefuses(t *testing.T) {
	subjects := newAclTestSubjects()
	subjects.fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK),
		[]*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK)}, protocol.AclAction_ACL_ACTION_DIAL)
	state := subjects.fixture.state(t)
	source := AclSidecarSubject(subjects.memberDevice)
	destination := AclSidecarSubject(subjects.target)
	if decision := state.Reach(source, destination, aclTestNow); !decision.Allowed {
		t.Fatalf("baseline refused: %s", decision.Reason)
	}
	source.Deny = AclReasonAbuseHalt
	if decision := state.Reach(source, destination, aclTestNow); decision.Allowed || decision.Reason != AclReasonAbuseHalt {
		t.Errorf("source halt: %+v", decision)
	}
	source.Deny = 0
	destination.Deny = AclReasonQuota
	if decision := state.Reach(source, destination, aclTestNow); decision.Allowed || decision.Reason != AclReasonQuota {
		t.Errorf("destination quota: %+v", decision)
	}
	client := AclClientSubject(subjects.legacyClient, Id{}, nil, "")
	client.Deny = AclReasonUnapproved
	if decision := state.Reach(client, AclSidecarSubject(subjects.target), aclTestNow); decision.Reason != AclReasonUnapproved {
		t.Errorf("unapproved client: %+v", decision)
	}
}

// A suspended client is refused by the rows' suspensions, and its member's leaving refuses it too.
func TestAclClientHardDenies(t *testing.T) {
	subjects := newAclTestSubjects()
	subjects.fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED),
		[]*protocol.AclTarget{aclSidecarTarget(subjects.target)}, protocol.AclAction_ACL_ACTION_DIAL)
	subjects.fixture.rows.Suspensions = append(subjects.fixture.rows.Suspensions, &protocol.AclSuspension{Subject: subjects.legacyClient.Bytes()})
	state := subjects.fixture.state(t)
	if decision := state.Reach(subjects.subject(subjects.legacyClient), AclSidecarSubject(subjects.target), aclTestNow); decision.Reason != AclReasonSuspended {
		t.Errorf("suspended client: %+v", decision)
	}
	gone := AclClientSubject(NewId(), NewId(), nil, "")
	if decision := state.Reach(gone, AclSidecarSubject(subjects.target), aclTestNow); decision.Reason != AclReasonUnadmitted {
		t.Errorf("member gone: %+v", decision)
	}
	if decision := state.Reach(subjects.subject(subjects.appClient), AclSidecarSubject(subjects.target), aclTestNow); !decision.Allowed {
		t.Errorf("app client refused: %s", decision.Reason)
	}
}

// A rule is in force before its expiry and not at it, a grant and a sidecar's not_after alike (§8.6).
func TestAclExpiryTakesEffectAtExactlyItsTime(t *testing.T) {
	subjects := newAclTestSubjects()
	expires := aclTestNow.Add(time.Hour)
	rule := subjects.fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER),
		[]*protocol.AclTarget{aclSidecarTarget(subjects.target)}, protocol.AclAction_ACL_ACTION_DIAL)
	rule.Expires = expires.UnixMilli()
	subjects.fixture.admission(subjects.ephemeral).Row.NotAfter = expires.UnixMilli()
	state := subjects.fixture.state(t)
	source := AclSidecarSubject(subjects.memberDevice)
	destination := AclSidecarSubject(subjects.target)
	if decision := state.Reach(source, destination, expires.Add(-time.Millisecond)); !decision.Allowed || decision.Rule != rule {
		t.Errorf("before expiry: %+v", decision)
	}
	if decision := state.Reach(source, destination, expires); decision.Allowed {
		t.Errorf("at expiry: %+v", decision)
	}
	if decision := state.Reach(AclSidecarSubject(subjects.ephemeral), destination, expires.Add(-time.Millisecond)); !decision.Allowed {
		t.Errorf("ephemeral before its not_after: %+v", decision)
	}
	if decision := state.Reach(AclSidecarSubject(subjects.ephemeral), destination, expires); decision.Reason != AclReasonExpired {
		t.Errorf("ephemeral at its not_after: %+v", decision)
	}
}

// autogroup:self reaches the subjects sharing the source's owner or sponsor, and nothing once a tagged
// source's sponsor is gone.
func TestAclSelfTargetReachesTheSameOwner(t *testing.T) {
	fixture := newAclTestFixture()
	alice := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	bob := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(alice)
	laptop := fixture.device(alice)
	phone := fixture.device(alice)
	bobDevice := fixture.device(bob)
	aliceAgent := fixture.agent(alice, tagId)
	orphanAgent := fixture.agent(alice, tagId)
	delete(fixture.view.sponsors, orphanAgent)
	aliceApp := NewId()
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER, protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED, protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED),
		[]*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, protocol.AclAction_ACL_ACTION_DIAL)
	state := fixture.state(t)
	cases := []struct {
		source, destination AclSubject
		allowed             bool
	}{
		{source: AclSidecarSubject(laptop), destination: AclSidecarSubject(phone), allowed: true},
		{source: AclSidecarSubject(laptop), destination: AclSidecarSubject(bobDevice), allowed: false},
		{source: AclSidecarSubject(aliceAgent), destination: AclSidecarSubject(laptop), allowed: true},
		{source: AclSidecarSubject(laptop), destination: AclSidecarSubject(aliceAgent), allowed: true},
		{source: AclSidecarSubject(orphanAgent), destination: AclSidecarSubject(laptop), allowed: false},
		{source: AclSidecarSubject(laptop), destination: AclSidecarSubject(orphanAgent), allowed: false},
		{source: AclClientSubject(aliceApp, alice, nil, ""), destination: AclSidecarSubject(phone), allowed: true},
		{source: AclClientSubject(NewId(), Id{}, nil, ""), destination: AclSidecarSubject(phone), allowed: false},
		{source: AclSidecarSubject(laptop), destination: AclClientSubject(aliceApp, alice, nil, ""), allowed: true},
	}
	for i, c := range cases {
		if decision := state.Reach(c.source, c.destination, aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("case %d: allowed %t (%s)", i, decision.Allowed, decision.Reason)
		}
	}
}

// A dial grant on a socket reaches the subjects that listen on it, while their listen grant is in force,
// and no one else (§8.10).
func TestAclSocketDialReachesItsListeners(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	dbTag := fixture.tag(owner)
	dialer := fixture.device(owner)
	listener := fixture.agent(owner, dbTag)
	bystander := fixture.device(owner)
	db := aclTestTokenPath(7)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER),
		[]*protocol.AclTarget{aclSocketRowTarget(false, db)}, protocol.AclAction_ACL_ACTION_DIAL)
	listen := fixture.rule([]Id{dbTag}, []*protocol.AclTarget{aclSocketRowTarget(false, db)}, protocol.AclAction_ACL_ACTION_LISTEN)
	listen.Expires = aclTestNow.Add(time.Minute).UnixMilli()
	state := fixture.state(t)
	if decision := state.Reach(AclSidecarSubject(dialer), AclSidecarSubject(listener), aclTestNow); !decision.Allowed {
		t.Errorf("listener refused: %s", decision.Reason)
	}
	if decision := state.Reach(AclSidecarSubject(dialer), AclSidecarSubject(bystander), aclTestNow); decision.Allowed {
		t.Errorf("non-listener reached: %+v", decision)
	}
	if decision := state.Reach(AclSidecarSubject(dialer), AclSidecarSubject(listener), aclTestNow.Add(time.Minute)); decision.Allowed {
		t.Errorf("reached after the listen grant expired: %+v", decision)
	}
	if decision := state.MayDialSocket(AclSidecarSubject(dialer), db, aclTestNow); !decision.Allowed {
		t.Errorf("socket dial refused: %s", decision.Reason)
	}
	if decision := state.MayDialSocket(AclSidecarSubject(dialer), aclTestTokenPath(8), aclTestNow); decision.Allowed {
		t.Errorf("another socket dialed: %+v", decision)
	}
}

// A prefix dial grant reaches a listener of a name below it, and a bare * socket every application one.
func TestAclSocketPrefixesReachListeners(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	prefixDialer := fixture.device(owner)
	allDialer := fixture.agent(owner, tagId)
	listener := fixture.device(owner)
	listenerAtom := fixture.sidecarAtom(listener)
	prefixDialerAtom := fixture.sidecarAtom(prefixDialer)
	fixture.rule([]Id{prefixDialerAtom}, []*protocol.AclTarget{aclSocketRowTarget(true, aclTestTokenPath(1))}, protocol.AclAction_ACL_ACTION_DIAL)
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclSocketRowTarget(true)}, protocol.AclAction_ACL_ACTION_DIAL)
	fixture.rule([]Id{listenerAtom}, []*protocol.AclTarget{aclSocketRowTarget(false, aclTestTokenPath(1, 2))}, protocol.AclAction_ACL_ACTION_LISTEN)
	state := fixture.state(t)
	for _, dialer := range []Id{prefixDialer, allDialer} {
		if decision := state.Reach(AclSidecarSubject(dialer), AclSidecarSubject(listener), aclTestNow); !decision.Allowed {
			t.Errorf("dialer %v refused: %s", dialer, decision.Reason)
		}
	}
}

// A route grant naming subjects reaches them as its via subjects (§8.10).
func TestAclRouteGrantReachesItsViaSubjects(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	exitTag := fixture.tag(owner)
	source := fixture.device(owner)
	exit := fixture.agent(owner, exitTag)
	other := fixture.agent(owner, fixture.tag(owner))
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER),
		[]*protocol.AclTarget{aclCidrTarget("10.0.0.0/8"), aclAtomTarget(exitTag)}, protocol.AclAction_ACL_ACTION_ROUTE)
	state := fixture.state(t)
	if decision := state.Reach(AclSidecarSubject(source), AclSidecarSubject(exit), aclTestNow); !decision.Allowed {
		t.Errorf("via subject refused: %s", decision.Reason)
	}
	if decision := state.Reach(AclSidecarSubject(source), AclSidecarSubject(other), aclTestNow); decision.Allowed {
		t.Errorf("other subject reached: %+v", decision)
	}
	address := netip.MustParseAddr("10.1.2.3")
	if decision := state.MayRoute(AclSidecarSubject(source), address, 6, 443, AclSidecarSubject(exit), aclTestNow); !decision.Allowed {
		t.Errorf("route via the exit refused: %s", decision.Reason)
	}
	if decision := state.MayRoute(AclSidecarSubject(source), address, 6, 443, AclSidecarSubject(other), aclTestNow); decision.Allowed {
		t.Errorf("route via another: %+v", decision)
	}
	if decision := state.MayRoute(AclSidecarSubject(source), netip.MustParseAddr("192.0.2.1"), 6, 443, AclSidecarSubject(exit), aclTestNow); decision.Allowed {
		t.Errorf("route outside the range: %+v", decision)
	}
}

// 0.0.0.0/0 and ::/0 leave out loopback and link-local (§8.4), a rule naming them opens them, and
// autogroup:internet takes only public addresses.
func TestAclRouteRangesAndTheInternet(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	source := fixture.device(owner)
	via := fixture.device(owner)
	loopbackUser := fixture.device(owner)
	internetUser := fixture.device(owner)
	fixture.rule([]Id{fixture.sidecarAtom(source)}, []*protocol.AclTarget{aclCidrTarget("0.0.0.0/0"), aclCidrTarget("::/0")}, protocol.AclAction_ACL_ACTION_ROUTE)
	fixture.rule([]Id{fixture.sidecarAtom(loopbackUser)}, []*protocol.AclTarget{aclCidrTarget("127.0.0.0/8")}, protocol.AclAction_ACL_ACTION_ROUTE)
	fixture.rule([]Id{fixture.sidecarAtom(internetUser)}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET)}, protocol.AclAction_ACL_ACTION_ROUTE)
	state := fixture.state(t)
	cases := []struct {
		source  Id
		address string
		allowed bool
	}{
		{source: source, address: "198.51.100.9", allowed: true},
		{source: source, address: "10.0.0.1", allowed: true},
		{source: source, address: "2001:db8::1", allowed: true},
		{source: source, address: "127.0.0.1", allowed: false},
		{source: source, address: "169.254.1.1", allowed: false},
		{source: source, address: "::1", allowed: false},
		{source: source, address: "fe80::1", allowed: false},
		{source: loopbackUser, address: "127.0.0.1", allowed: true},
		{source: internetUser, address: "198.51.100.9", allowed: true},
		{source: internetUser, address: "10.0.0.1", allowed: false},
		{source: internetUser, address: "127.0.0.1", allowed: false},
	}
	for i, c := range cases {
		decision := state.MayRoute(AclSidecarSubject(c.source), netip.MustParseAddr(c.address), 6, 443, AclSidecarSubject(via), aclTestNow)
		if decision.Allowed != c.allowed {
			t.Errorf("case %d (%s): allowed %t (%s)", i, c.address, decision.Allowed, decision.Reason)
		}
	}
}

// A dial grant's ports take a protocol and port, none taking every one.
func TestAclDialPortsMatch(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	source := fixture.device(owner)
	api := fixture.agent(owner, tagId)
	anyPort := fixture.device(owner)
	rule := fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclAtomTarget(tagId)}, protocol.AclAction_ACL_ACTION_DIAL)
	rule.Ports = []*protocol.AclPortRange{{Protocol: aclIpProtocolTcp, First: 443, Last: 443}, {Protocol: 0, First: 8000, Last: 8100}}
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclSidecarTarget(anyPort)}, protocol.AclAction_ACL_ACTION_DIAL)
	state := fixture.state(t)
	cases := []struct {
		destination Id
		ipProtocol  uint32
		port        uint32
		allowed     bool
	}{
		{destination: api, ipProtocol: aclIpProtocolTcp, port: 443, allowed: true},
		{destination: api, ipProtocol: aclIpProtocolUdp, port: 443, allowed: false},
		{destination: api, ipProtocol: aclIpProtocolTcp, port: 80, allowed: false},
		{destination: api, ipProtocol: aclIpProtocolUdp, port: 8050, allowed: true},
		{destination: api, ipProtocol: aclIpProtocolTcp, port: 8101, allowed: false},
		{destination: anyPort, ipProtocol: aclIpProtocolUdp, port: 9, allowed: true},
	}
	for i, c := range cases {
		decision := state.MayDial(AclSidecarSubject(source), AclSidecarSubject(c.destination), c.ipProtocol, c.port, aclTestNow)
		if decision.Allowed != c.allowed {
			t.Errorf("case %d: allowed %t (%s)", i, decision.Allowed, decision.Reason)
		}
	}
	// reach reads no ports: the contract gate is who talks to whom
	if decision := state.Reach(AclSidecarSubject(source), AclSidecarSubject(api), aclTestNow); !decision.Allowed {
		t.Errorf("reach refused: %s", decision.Reason)
	}
}

// listen on application sockets by token path, and on tls/ and smtp/ names by public_name with globs,
// a last * taking every name below its prefix.
func TestAclListenOnSockets(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	agent := fixture.agent(owner, tagId)
	device := fixture.device(owner)
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclSocketRowTarget(false, aclTestTokenPath(4)), {PublicName: "tls/443/*-preview"}},
		protocol.AclAction_ACL_ACTION_LISTEN)
	fixture.rule([]Id{fixture.sidecarAtom(device)}, []*protocol.AclTarget{{PublicName: "tls/*"}, {PublicName: "smtp/25/mx"}},
		protocol.AclAction_ACL_ACTION_LISTEN)
	state := fixture.state(t)
	cases := []struct {
		subject Id
		socket  AclSocketName
		allowed bool
	}{
		{subject: agent, socket: AclSocketName{NameToken: aclTestTokenPath(4)}, allowed: true},
		{subject: agent, socket: AclSocketName{NameToken: aclTestTokenPath(5)}, allowed: false},
		{subject: agent, socket: AclSocketName{PublicName: "tls/443/app-preview"}, allowed: true},
		{subject: agent, socket: AclSocketName{PublicName: "tls/443/app"}, allowed: false},
		{subject: agent, socket: AclSocketName{PublicName: "tls/443/app-preview/x"}, allowed: false},
		{subject: device, socket: AclSocketName{PublicName: "tls/443/blog"}, allowed: true},
		{subject: device, socket: AclSocketName{PublicName: "tls/8443/blog"}, allowed: true},
		{subject: device, socket: AclSocketName{PublicName: "tls"}, allowed: false},
		{subject: device, socket: AclSocketName{PublicName: "smtp/25/mx"}, allowed: true},
		{subject: device, socket: AclSocketName{PublicName: "smtp/587/mx"}, allowed: false},
	}
	for i, c := range cases {
		if decision := state.MayListen(AclSidecarSubject(c.subject), c.socket, aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("case %d: allowed %t (%s)", i, decision.Allowed, decision.Reason)
		}
	}
}

// A publish grant takes dns hosts label by label, and its decision carries the grant's audience, mode and
// pin.
func TestAclPublishCarriesItsGrant(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	agent := fixture.agent(owner, tagId)
	rule := fixture.rule([]Id{tagId}, []*protocol.AclTarget{{PublicName: "*-preview"}, {PublicName: "app.acme"}}, protocol.AclAction_ACL_ACTION_PUBLISH)
	rule.Audience = protocol.AclAudience_ACL_AUDIENCE_LINK
	rule.AppMode = protocol.AclAppMode_ACL_APP_MODE_RAW
	rule.LinkSpkiSha256 = make([]byte, 32)
	state := fixture.state(t)
	decision := state.MayPublish(AclSidecarSubject(agent), "app-preview", aclTestNow)
	if !decision.Allowed || decision.Rule.GetAudience() != protocol.AclAudience_ACL_AUDIENCE_LINK || decision.Rule.GetAppMode() != protocol.AclAppMode_ACL_APP_MODE_RAW {
		t.Errorf("publish: %+v", decision)
	}
	for _, host := range []string{"app", "x.app-preview", "app.acme.other"} {
		if decision := state.MayPublish(AclSidecarSubject(agent), host, aclTestNow); decision.Allowed {
			t.Errorf("%s published", host)
		}
	}
	if decision := state.MayPublish(AclSidecarSubject(agent), "app.acme", aclTestNow); !decision.Allowed {
		t.Errorf("scope host refused: %s", decision.Reason)
	}
}

// send needs a send grant with mail_send.
func TestAclSendNeedsMailSend(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	sender := fixture.device(owner)
	other := fixture.device(owner)
	fixture.rule([]Id{fixture.sidecarAtom(sender)}, []*protocol.AclTarget{{MailSend: true}}, protocol.AclAction_ACL_ACTION_SEND)
	fixture.rule([]Id{fixture.sidecarAtom(other)}, []*protocol.AclTarget{aclSidecarTarget(sender)}, protocol.AclAction_ACL_ACTION_SEND)
	state := fixture.state(t)
	if decision := state.MaySend(AclSidecarSubject(sender), aclTestNow); !decision.Allowed {
		t.Errorf("sender refused: %s", decision.Reason)
	}
	if decision := state.MaySend(AclSidecarSubject(other), aclTestNow); decision.Allowed {
		t.Errorf("send without mail_send: %+v", decision)
	}
}

// An activated grant ends at the base whose rows drop its requests rule (FS-14).
func TestAclActivatedGrantEndsWithItsRequestsRule(t *testing.T) {
	for _, requestStays := range []bool{true, false} {
		fixture := newAclTestFixture()
		owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
		source := fixture.device(owner)
		destination := fixture.device(owner)
		requestRuleId := NewId().Bytes()
		if requestStays {
			fixture.rows.Requests = []*protocol.AclRequestRule{{RuleId: requestRuleId}}
		}
		grant := fixture.rule([]Id{fixture.sidecarAtom(source)}, []*protocol.AclTarget{aclSidecarTarget(destination)}, protocol.AclAction_ACL_ACTION_DIAL)
		grant.SourceRuleId = requestRuleId
		state := fixture.state(t)
		if decision := state.Reach(AclSidecarSubject(source), AclSidecarSubject(destination), aclTestNow); decision.Allowed != requestStays {
			t.Errorf("requests rule kept %t: allowed %t", requestStays, decision.Allowed)
		}
	}
}

// client:<id>, role: and principal: atoms hold the clients they name, a legacy client takes only its
// client atom, autogroup:untagged and autogroup:network, and a client target names one
// (plan-ACL-nonsidecar-subjects).
func TestAclClientRoleAndPrincipalAtoms(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	target := fixture.device(owner)
	legacy := NewId()
	embedded := NewId()
	clientAtom := fixture.atom(&protocol.AclAtom{ClientIds: [][]byte{legacy.Bytes()}})
	roleAtom := fixture.atom(&protocol.AclAtom{Role: "kiosk"})
	principalAtom := fixture.atom(&protocol.AclAtom{Principal: "user-17"})
	for _, atom := range []Id{clientAtom, roleAtom, principalAtom} {
		fixture.rule([]Id{atom}, []*protocol.AclTarget{aclSidecarTarget(target)}, protocol.AclAction_ACL_ACTION_DIAL)
	}
	fixture.rule([]Id{fixture.sidecarAtom(target)}, []*protocol.AclTarget{{ClientId: legacy.Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
	state := fixture.state(t)
	cases := []struct {
		subject AclSubject
		allowed bool
	}{
		{subject: AclClientSubject(legacy, Id{}, nil, ""), allowed: true},
		{subject: AclClientSubject(embedded, Id{}, []string{"guest", "kiosk"}, ""), allowed: true},
		{subject: AclClientSubject(embedded, Id{}, nil, "user-17"), allowed: true},
		{subject: AclClientSubject(embedded, Id{}, []string{"guest"}, "user-18"), allowed: false},
	}
	for i, c := range cases {
		if decision := state.Reach(c.subject, AclSidecarSubject(target), aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("case %d: allowed %t (%s)", i, decision.Allowed, decision.Reason)
		}
	}
	if decision := state.Reach(AclSidecarSubject(target), AclClientSubject(legacy, Id{}, nil, ""), aclTestNow); !decision.Allowed {
		t.Errorf("client target refused: %s", decision.Reason)
	}
	if decision := state.Reach(AclSidecarSubject(target), AclClientSubject(embedded, Id{}, nil, ""), aclTestNow); decision.Allowed {
		t.Errorf("unnamed client reached: %+v", decision)
	}
}

// A subject of another network matches only atoms listing its network, and an anonymous visitor only
// autogroup:public.
func TestAclRemoteAndPublicSubjects(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	target := fixture.device(owner)
	partner := NewId()
	networkAtom := fixture.atom(&protocol.AclAtom{NetworkIds: [][]byte{partner.Bytes()}})
	fixture.rule([]Id{networkAtom}, []*protocol.AclTarget{aclSidecarTarget(target)}, protocol.AclAction_ACL_ACTION_DIAL)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_PUBLIC), []*protocol.AclTarget{{PublicName: "tls/443/blog"}},
		protocol.AclAction_ACL_ACTION_DIAL)
	state := fixture.state(t)
	if decision := state.Reach(AclRemoteSubject(partner), AclSidecarSubject(target), aclTestNow); !decision.Allowed {
		t.Errorf("partner refused: %s", decision.Reason)
	}
	if decision := state.Reach(AclRemoteSubject(NewId()), AclSidecarSubject(target), aclTestNow); decision.Allowed {
		t.Errorf("other network reached: %+v", decision)
	}
	if decision := state.Reach(AclPublicSubject(), AclSidecarSubject(target), aclTestNow); decision.Allowed {
		t.Errorf("public reached a subject: %+v", decision)
	}
}

// No rule, no allow: the deny base (D-ACL-2), and the decision says so.
func TestAclDenyIsTheBase(t *testing.T) {
	subjects := newAclTestSubjects()
	state := subjects.fixture.state(t)
	decision := state.Reach(AclSidecarSubject(subjects.memberDevice), AclSidecarSubject(subjects.target), aclTestNow)
	if decision.Allowed || decision.Reason != AclReasonNoGrant || decision.Reason.String() != "no_grant" {
		t.Errorf("%+v", decision)
	}
}
