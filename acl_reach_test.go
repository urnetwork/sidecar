// The reach enumerators against the checks they extend: on generated policies and states each enumerator is empty
// exactly where its check refuses and holds exactly the rules that allow alone, in rule id order; an expired or revoked
// grant is absent; the implicit document's rows with no document; EgressMode against the contract gate's
// egressRestricted; and StandingCovers on a nested prefix, a missing via subject, an exit and a port outside the list.
// Pure, on every leg.

package sidecar

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An id drawn from a seeded source, never of the autogroup form.
func aclReachTestId(source *rand.Rand) Id {
	id := Id{}
	for i := range id {
		id[i] = byte(source.Uint32())
	}
	id[0] |= 0x80
	return id
}

// A generated network: members, devices, agents, an app client, a legacy client and another network, with random rules
// over them, every id drawn from one seed.
type aclReachTestWorld struct {
	fixture  *aclTestFixture
	subjects []AclSubject
}

func newAclReachTestWorld(seed uint64) *aclReachTestWorld {
	source := rand.New(rand.NewPCG(seed, 17))
	fixture := newAclTestFixture()
	world := &aclReachTestWorld{fixture: fixture}
	pick := func(n int) int { return source.IntN(n) }

	roles := []bridge.MemberRole{bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN, bridge.MemberRole_MEMBER_ROLE_MEMBER}
	memberIds := []Id{}
	for _, role := range roles {
		memberId := aclReachTestId(source)
		fixture.view.members[memberId] = &bridge.MemberRow{MemberId: memberId.Bytes(), Role: role}
		memberIds = append(memberIds, memberId)
	}
	atoms := autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER, protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED,
		protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED, protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK,
		protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR, protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN)
	newAtom := func(row *protocol.AclAtom) Id {
		atom := aclReachTestId(source)
		row.Atom = atom.Bytes()
		fixture.rows.Atoms = append(fixture.rows.Atoms, row)
		atoms = append(atoms, atom)
		return atom
	}
	newAtom(&protocol.AclAtom{MemberIds: [][]byte{memberIds[0].Bytes(), memberIds[2].Bytes()}})
	tags := []Id{newAtom(&protocol.AclAtom{}), newAtom(&protocol.AclAtom{})}

	sidecarIds := []Id{}
	admit := func(facts *AclSidecar) Id {
		sidecarId := aclReachTestId(source)
		facts.Row.SidecarId = sidecarId.Bytes()
		facts.Row.AdmittedAt = fixture.next()
		fixture.view.sidecars[sidecarId] = facts
		sidecarIds = append(sidecarIds, sidecarId)
		world.subjects = append(world.subjects, AclSidecarSubject(sidecarId))
		return sidecarId
	}
	for _, memberId := range memberIds {
		for range 1 + pick(2) {
			admit(&AclSidecar{Row: &bridge.SidecarRow{}, MemberId: memberId, Ephemeral: pick(5) == 0})
		}
	}
	for i := range 2 {
		tagId := tags[i]
		agent := admit(&AclSidecar{Row: &bridge.SidecarRow{Sponsor: memberIds[i].Bytes()}, TagIds: []Id{tagId}})
		fixture.view.sponsors[agent] = memberIds[i]
		for _, atomRow := range fixture.rows.Atoms {
			if Id(atomRow.Atom) == tagId {
				atomRow.SidecarIds = append(atomRow.SidecarIds, agent.Bytes())
			}
		}
	}
	// the hard denies: a revoked device, a parked one and a suspended one, when the draw names them
	if pick(2) == 0 {
		fixture.view.sidecars[sidecarIds[pick(len(sidecarIds))]].Row.RevokedAt = fixture.next()
	}
	if pick(2) == 0 {
		fixture.view.parked[sidecarIds[pick(len(sidecarIds))]] = true
	}
	if pick(2) == 0 {
		fixture.rows.Suspensions = append(fixture.rows.Suspensions, &protocol.AclSuspension{Subject: sidecarIds[pick(len(sidecarIds))].Bytes()})
	}
	newAtom(&protocol.AclAtom{SidecarIds: [][]byte{sidecarIds[pick(len(sidecarIds))].Bytes()}})

	clientId, legacyId, networkId := aclReachTestId(source), aclReachTestId(source), aclReachTestId(source)
	newAtom(&protocol.AclAtom{ClientIds: [][]byte{legacyId.Bytes()}})
	newAtom(&protocol.AclAtom{NetworkIds: [][]byte{networkId.Bytes()}})
	world.subjects = append(world.subjects,
		AclClientSubject(clientId, memberIds[2], nil, ""), AclClientSubject(legacyId, Id{}, nil, ""), AclRemoteSubject(networkId))

	requestIds := [][]byte{}
	for range 1 + pick(2) {
		request := &protocol.AclRequestRule{RuleId: aclReachTestId(source).Bytes()}
		fixture.rows.Requests = append(fixture.rows.Requests, request)
		requestIds = append(requestIds, request.RuleId)
	}
	actions := []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_ROUTE,
		protocol.AclAction_ACL_ACTION_LISTEN, protocol.AclAction_ACL_ACTION_READ}
	for range 8 + pick(24) {
		rule := &protocol.AclRule{RuleId: aclReachTestId(source).Bytes(), PortsLimited: pick(3) == 0}
		for range 1 + pick(2) {
			rule.SrcAtoms = append(rule.SrcAtoms, atoms[pick(len(atoms))].Bytes())
		}
		for range pick(4) {
			switch pick(6) {
			case 0, 1:
				rule.Targets = append(rule.Targets, aclAtomTarget(atoms[pick(len(atoms))]))
			case 2:
				rule.Targets = append(rule.Targets, aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF))
			case 3:
				rule.Targets = append(rule.Targets, aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET))
			case 4:
				rule.Targets = append(rule.Targets, aclSidecarTarget(sidecarIds[pick(len(sidecarIds))]))
			case 5:
				rule.Targets = append(rule.Targets, &protocol.AclTarget{ClientId: legacyId.Bytes()})
			}
		}
		for _, action := range actions {
			if pick(2) == 0 {
				rule.Actions = append(rule.Actions, uint32(action))
			}
		}
		switch pick(4) {
		case 0:
			rule.Expires = aclTestNow.UnixMilli() - int64(1+pick(1000))
		case 1:
			rule.Expires = aclTestNow.UnixMilli() + int64(1+pick(1000))
		}
		if pick(5) == 0 {
			// an activated grant, its requests rule held or gone (FS-14)
			rule.RuleId = append(rule.RuleId, aclReachTestId(source).Bytes()...)
			rule.SourceRuleId = requestIds[pick(len(requestIds))]
			if pick(3) == 0 {
				rule.SourceRuleId = aclReachTestId(source).Bytes()
			}
		}
		fixture.rows.Rules = append(fixture.rows.Rules, rule)
	}
	return world
}

// The rows with only the rule at index kept, so a check on them answers whether that rule alone allows.
func aclReachTestOneRule(rows *protocol.AclRows, index int) *protocol.AclRows {
	one := proto.Clone(rows).(*protocol.AclRows)
	one.Rules = []*protocol.AclRule{one.Rules[index]}
	return one
}

// The rule ids an enumerator answered.
func aclReachTestIds(reach []AclReachRule) [][]byte {
	ids := [][]byte{}
	for _, rule := range reach {
		ids = append(ids, rule.RuleId)
	}
	return ids
}

// For every pair of subjects of every generated network, each enumerator is empty exactly where its check refuses,
// names the rule the check found, and holds exactly the rules each of which allows on its own: every rule in force, in
// rule id order, an activated grant's grant id beside it.
func TestAclReachAgreesWithTheChecks(t *testing.T) {
	private, public := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("198.51.100.7")
	for seed := uint64(1); seed <= 40; seed += 1 {
		world := newAclReachTestWorld(seed)
		state := world.fixture.state(t)
		singles := []*AclState{}
		for i := range world.fixture.rows.Rules {
			single, err := NewAclState(aclReachTestOneRule(world.fixture.rows, i), world.fixture.view)
			if err != nil {
				t.Fatal(err)
			}
			singles = append(singles, single)
		}
		type enumerator struct {
			name  string
			rules func(state *AclState, a AclSubject, b AclSubject) []AclReachRule
			check func(state *AclState, a AclSubject, b AclSubject) AclDecision
		}
		enumerators := []enumerator{
			{
				name: "DialRules",
				rules: func(state *AclState, a AclSubject, b AclSubject) []AclReachRule {
					return state.DialRules(a, b, aclTestNow)
				},
				check: func(state *AclState, a AclSubject, b AclSubject) AclDecision { return state.MayDial(a, b, aclTestNow) },
			},
			{
				name: "RouteRules",
				rules: func(state *AclState, a AclSubject, b AclSubject) []AclReachRule {
					return state.RouteRules(a, b, aclTestNow)
				},
				check: func(state *AclState, a AclSubject, b AclSubject) AclDecision {
					return state.MayRoute(a, private, b, aclTestNow)
				},
			},
			{
				name: "ExitRules",
				rules: func(state *AclState, a AclSubject, b AclSubject) []AclReachRule {
					return state.ExitRules(a, b, aclTestNow)
				},
				check: func(state *AclState, a AclSubject, b AclSubject) AclDecision {
					return state.MayRoute(a, public, b, aclTestNow)
				},
			},
		}
		allowedCount := 0
		for _, a := range world.subjects {
			for _, b := range world.subjects {
				for _, e := range enumerators {
					reach := e.rules(state, a, b)
					decision := e.check(state, a, b)
					if (len(reach) != 0) != decision.Allowed {
						t.Fatalf("seed %d %s: %d rules where the check answers %t (%s)", seed, e.name, len(reach), decision.Allowed, decision.Reason)
					}
					ids := aclReachTestIds(reach)
					if decision.Allowed {
						allowedCount += 1
						if !slices.ContainsFunc(ids, func(id []byte) bool { return bytes.Equal(id, decision.Rule.GetRuleId()) }) {
							t.Fatalf("seed %d %s: the check's rule is not among the enumerator's", seed, e.name)
						}
					}
					if !slices.IsSortedFunc(ids, bytes.Compare) {
						t.Fatalf("seed %d %s: out of rule id order", seed, e.name)
					}
					want := [][]byte{}
					for i, single := range singles {
						if e.check(single, a, b).Allowed {
							want = append(want, world.fixture.rows.Rules[i].GetRuleId())
						}
					}
					slices.SortFunc(want, bytes.Compare)
					if !slices.EqualFunc(ids, want, bytes.Equal) {
						t.Fatalf("seed %d %s: %d rules, where %d allow alone", seed, e.name, len(ids), len(want))
					}
					for _, rule := range reach {
						row := state.rules[slices.IndexFunc(state.rules, func(r aclRule) bool { return bytes.Equal(r.row.GetRuleId(), rule.RuleId) })]
						if !row.activeAt(aclTestNow.UnixMilli()) || rule.ExpiresMs != row.expiresMs || rule.PortsLimited != row.portsLimited {
							t.Fatalf("seed %d %s: a rule answered not as its row holds it", seed, e.name)
						}
						if (len(rule.GrantId) != 0) != (len(row.row.GetSourceRuleId()) != 0) || (rule.GrantId != nil && !bytes.Equal(rule.GrantId, rule.RuleId)) {
							t.Fatalf("seed %d %s: grant id %x for a rule whose source is %x", seed, e.name, rule.GrantId, row.row.GetSourceRuleId())
						}
					}
				}
			}
		}
		if allowedCount == 0 {
			t.Errorf("seed %d: no pair allowed anything, so the seed proves nothing", seed)
		}
	}
}

// Rows out of rule id order still answer in it.
func TestAclReachAnswersInRuleIdOrder(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop, phone := fixture.device(owner), fixture.device(owner)
	member := autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	for _, first := range []byte{0xc0, 0x40, 0x80} {
		rule := fixture.rule(member, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
			protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_ROUTE)
		rule.RuleId[0] = first
	}
	state := fixture.state(t)
	for name, reach := range map[string][]AclReachRule{
		"dial":  state.DialRules(AclSidecarSubject(laptop), AclSidecarSubject(phone), aclTestNow),
		"route": state.RouteRules(AclSidecarSubject(laptop), AclSidecarSubject(phone), aclTestNow),
		"exit":  state.ExitRules(AclSidecarSubject(laptop), AclSidecarSubject(phone), aclTestNow),
	} {
		firsts := []byte{}
		for _, rule := range reach {
			firsts = append(firsts, rule.RuleId[0])
		}
		if !bytes.Equal(firsts, []byte{0x40, 0x80, 0xc0}) {
			t.Errorf("%s: %x", name, firsts)
		}
	}
}

// An activated grant answers with its grant id while it stands, and is absent past its expiry and after its
// GrantRevoke; a rule past its expiry is absent from exactly its time; a hard-denied end answers nothing.
func TestAclReachLeavesOutWhatHasEnded(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	expiring := fixture.rule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET)},
		protocol.AclAction_ACL_ACTION_ROUTE)
	expiring.Expires = aclTestNow.UnixMilli() + 1000
	state := fixture.state(t)
	laptop, phone := AclSidecarSubject(cast.laptop), AclSidecarSubject(cast.phone)
	if rules := state.DialRules(laptop, phone, aclTestNow); len(rules) != 0 {
		t.Fatalf("dial rules before the grant: %d", len(rules))
	}

	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	activate := newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone) + ":tcp:22"}, []string{"dial"}, 0).
		approve(t, cast.member, device, aclTestDecisionNotAfter).approve(t, cast.owner, device, aclTestDecisionNotAfter).activate()
	statement := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop)
	verdict, err := state.CheckStatement(statement, &aclTestSpendCheck{})
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	fixture.rows = rows
	state = fixture.state(t)
	rules := state.DialRules(laptop, phone, aclTestNow)
	if len(rules) != 1 || !bytes.Equal(rules[0].GrantId, activate.GetGrantId()) || !bytes.Equal(rules[0].RuleId, activate.GetGrantId()) ||
		!rules[0].PortsLimited || rules[0].ExpiresMs != aclTestNow.UnixMilli()+aclRequestDefaultExpiryMs {
		t.Fatalf("the activated grant: %+v", rules)
	}
	if rules := state.DialRules(laptop, phone, aclTestNow.Add(2*time.Hour)); len(rules) != 0 {
		t.Errorf("the grant past its expiry: %d rules", len(rules))
	}
	if rules := state.DialRules(phone, laptop, aclTestNow); len(rules) != 0 {
		t.Errorf("the grant answers its reverse: %d rules", len(rules))
	}

	exits := state.ExitRules(laptop, phone, aclTestNow)
	if len(exits) != 1 || !bytes.Equal(exits[0].RuleId, expiring.RuleId) || !exits[0].Internet || exits[0].GrantId != nil {
		t.Fatalf("the internet rule: %+v", exits)
	}
	if rules := state.ExitRules(laptop, phone, time.UnixMilli(expiring.Expires)); len(rules) != 0 {
		t.Errorf("a rule at exactly its expiry: %d rules", len(rules))
	}
	if rules := state.RouteRules(laptop, phone, aclTestNow); len(rules) != 0 {
		t.Errorf("an internet rule routes to a private address: %d rules", len(rules))
	}

	revoke := fixture.statement(bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{GrantId: activate.GetGrantId()}, cast.laptop)
	state, _ = fixture.apply(t, state, revoke)
	if rules := state.DialRules(laptop, phone, aclTestNow); len(rules) != 0 {
		t.Errorf("the revoked grant: %d rules", len(rules))
	}

	if rules := state.ExitRules(laptop, AclSidecarSubject(cast.revoked), aclTestNow); len(rules) != 0 {
		t.Errorf("a revoked via: %d rules", len(rules))
	}
	if rules := state.ExitRules(AclSidecarSubject(cast.revoked), phone, aclTestNow); len(rules) != 0 {
		t.Errorf("a revoked source: %d rules", len(rules))
	}
	fixture.rows.Suspensions = append(fixture.rows.Suspensions, &protocol.AclSuspension{Subject: cast.laptop.Bytes()})
	if rules := fixture.state(t).ExitRules(laptop, phone, aclTestNow); len(rules) != 0 {
		t.Errorf("a suspended source: %d rules", len(rules))
	}
}

// With no document the implicit document's rows answer: untagged sidecars dial and route anything and exit through
// any sidecar by its first rule, tagged ones dial their sponsor's subjects on tcp:443 alone, and route nothing.
func TestAclReachImplicitDocument(t *testing.T) {
	world := newAclCompileWorld("reach implicit")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := AclSidecarSubject(world.device("laptop", owner))
	phone := AclSidecarSubject(world.device("phone", owner))
	agent := AclSidecarSubject(world.agent("agent", owner, "worker"))
	other := AclSidecarSubject(world.agent("other agent", owner, "worker"))
	state := world.state(t)
	if state.HasDocument() {
		t.Fatal("the world holds a document")
	}
	first := aclImplicitRuleId(0).Bytes()
	for name, reach := range map[string][]AclReachRule{
		"dial":  state.DialRules(laptop, phone, aclTestNow),
		"route": state.RouteRules(laptop, agent, aclTestNow),
		"exit":  state.ExitRules(laptop, phone, aclTestNow),
	} {
		if len(reach) != 1 || !bytes.Equal(reach[0].RuleId, first) || reach[0].PortsLimited || reach[0].GrantId != nil {
			t.Errorf("%s: %+v", name, reach)
		}
	}
	dial := state.DialRules(agent, other, aclTestNow)
	if len(dial) != 1 || !bytes.Equal(dial[0].RuleId, aclImplicitRuleId(3).Bytes()) || !dial[0].PortsLimited {
		t.Errorf("the agent's dial: %+v", dial)
	}
	if reach := state.RouteRules(agent, laptop, aclTestNow); len(reach) != 0 {
		t.Errorf("the agent routes: %+v", reach)
	}
	if reach := state.ExitRules(agent, laptop, aclTestNow); len(reach) != 0 {
		t.Errorf("the agent exits: %+v", reach)
	}
	local, err := CompileAclLocal(world.input())
	if err != nil {
		t.Fatal(err)
	}
	if rule := local.Rule(dial[0].RuleId); rule == nil || !slices.Equal(rule.Ports, []AclPortRange{{Protocol: aclIpProtocolTcp, First: 443, Last: 443}}) {
		t.Errorf("the agent's dial's ports: %+v", rule)
	}
}

// EgressMode, which the contract gate's egressRestricted reads as any mode other than auto: a row naming the subject's
// id wins, else the first row in subject order naming an atom it holds, else auto; malformed bytes anywhere read as none.
func TestAclEgressMode(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := fixture.device(owner)
	free := fixture.device(owner)
	tagA, tagB := fixture.tag(owner), fixture.tag(owner)
	if bytes.Compare(tagB.Bytes(), tagA.Bytes()) < 0 {
		tagA, tagB = tagB, tagA
	}
	both := fixture.agent(owner, tagA, tagB)
	onlyB := fixture.agent(owner, tagB)
	named := fixture.agent(owner, tagA)
	clientId := NewId()
	exits, none := bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE
	data := []byte(nil)
	var err error
	for _, row := range []struct {
		subject Id
		mode    bridge.BridgeEgressMode
	}{
		{subject: laptop, mode: exits}, {subject: tagA, mode: exits}, {subject: tagB, mode: none},
		{subject: named, mode: none}, {subject: clientId, mode: none},
	} {
		if data, err = bridgeRowsWithEgress(data, row.subject, row.mode); err != nil {
			t.Fatal(err)
		}
	}
	fixture.rows.Bridge = data
	state := fixture.state(t)
	cases := []struct {
		subject AclSubject
		mode    bridge.BridgeEgressMode
	}{
		{subject: AclSidecarSubject(laptop), mode: exits},
		{subject: AclSidecarSubject(free), mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO},
		{subject: AclSidecarSubject(both), mode: exits},
		{subject: AclSidecarSubject(onlyB), mode: none},
		{subject: AclSidecarSubject(named), mode: none},
		{subject: AclClientSubject(clientId, owner, nil, ""), mode: none},
		{subject: AclClientSubject(NewId(), owner, nil, ""), mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO},
	}
	for i, c := range cases {
		if mode := state.EgressMode(c.subject); mode != c.mode {
			t.Errorf("case %d: %s, want %s", i, mode, c.mode)
		}
	}
	for i, malformed := range [][]byte{append(bytes.Clone(data), 0x0a, 0x02, 0x08), append(bytes.Clone(data), 0x12, 0x00), {0x0a, 0x03, 0x10, 0x01, 0x00}} {
		fixture.rows.Bridge = malformed
		state := fixture.state(t)
		if mode := state.EgressMode(AclSidecarSubject(free)); mode != none {
			t.Errorf("malformed %d: %s", i, mode)
		}
		if mode := state.EgressMode(AclSidecarSubject(laptop)); mode != none {
			t.Errorf("malformed %d, a subject a row names: %s", i, mode)
		}
	}
}

// A document for StandingCovers: a route via the router, a route with no via, an exit via the router, a database's
// ports, the router's every port and an expired grant.
const aclStandingTestPolicy = `{
  "grants": [
    { "src": ["autogroup:member"], "dst": ["ip:10.0.0.0/8"], "allow": ["route"], "via": ["tag:router"] },
    { "src": ["autogroup:member"], "dst": ["ip:192.168.0.0/16"], "allow": ["route"] },
    { "src": ["autogroup:member"], "dst": ["autogroup:internet"], "allow": ["route"], "via": ["tag:router"] },
    { "src": ["autogroup:member"], "dst": ["tag:db"], "allow": ["dial"], "ip": ["tcp:5432", "tcp:6000-6010", "udp:6008-6020"] },
    { "src": ["autogroup:member"], "dst": ["tag:router"], "allow": ["dial"] },
    { "src": ["autogroup:member"], "dst": ["tag:cache"], "allow": ["dial"], "expires": "2020-01-01T00:00:00Z" },
  ],
}`

// One standing route filing as the ledger holds it.
func aclStandingTestRoute(owner Id, routeRuleIds []Id, kind bridge.BridgeRouteKind, prefixes ...string) *BridgeLedgerRule {
	route := &bridge.BridgeRouteBody{Kind: kind}
	for _, text := range prefixes {
		prefix := netip.MustParsePrefix(text)
		address := prefix.Addr().As4()
		route.Prefixes = append(route.Prefixes, &bridge.BridgeIpv4Prefix{
			Address: uint32(address[0])<<24 | uint32(address[1])<<16 | uint32(address[2])<<8 | uint32(address[3]), Length: uint32(prefix.Bits()),
		})
	}
	rule := &BridgeLedgerRule{SignedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, Owner: owner, Route: route, Standing: true}
	for _, ruleId := range routeRuleIds {
		rule.RouteRuleIds = append(rule.RouteRuleIds, ruleId.Bytes())
	}
	return rule
}

// One standing map filing as the ledger holds it.
func aclStandingTestMap(host Id, protocolNumber uint32, ports ...[2]uint32) *BridgeLedgerRule {
	body := &bridge.BridgeMapBody{Protocol: protocolNumber, Target: []byte{192, 0, 2, 20}}
	for _, port := range ports {
		body.Ports = append(body.Ports, &bridge.BridgePortRange{First: port[0], Last: port[1]})
	}
	return &BridgeLedgerRule{SignedType: bridge.SignedType_SIGNED_BRIDGE_MAP, Owner: host, Map: body, Standing: true}
}

// Under a document: a route's prefixes must lie in a grant's that its route_rule_ids name, nested included, with its
// advertiser among the grant's via subjects, a grant with no via holding any; an exit needs a grant reaching public
// destinations; a map needs a dial grant naming its host whose ports cover it; an expired grant, a revoked owner and a
// policy the device does not hold cover nothing.
func TestAclStandingCoversUnderADocument(t *testing.T) {
	world := newAclCompileWorld("standing")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := world.device("laptop", owner)
	router := world.agent("router", owner, "router")
	db := world.agent("db", owner, "db")
	cache := world.agent("cache", owner, "cache")
	revokedRouter := world.agent("revoked router", owner, "router")
	world.sidecars[len(world.sidecars)-1].RevokedAt = 1
	world.setPolicy(t, aclStandingTestPolicy)
	state := world.state(t)
	local, err := CompileAclLocal(world.input())
	if err != nil {
		t.Fatal(err)
	}
	viaRoute, noViaRoute, exitRoute := world.documentRuleId(t, "grant", 0), world.documentRuleId(t, "grant", 1), world.documentRuleId(t, "grant", 2)
	routerDial := world.documentRuleId(t, "grant", 4)
	subnet, exit := bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET, bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT
	tcp, udp, icmp := uint32(aclIpProtocolTcp), uint32(aclIpProtocolUdp), uint32(aclIpProtocolIcmp)
	cases := []struct {
		name    string
		rule    *BridgeLedgerRule
		covered bool
	}{
		{name: "a nested prefix", rule: aclStandingTestRoute(router, []Id{viaRoute}, subnet, "10.1.0.0/16"), covered: true},
		{name: "the grant's own prefix", rule: aclStandingTestRoute(router, []Id{viaRoute}, subnet, "10.0.0.0/8"), covered: true},
		{name: "a prefix outside", rule: aclStandingTestRoute(router, []Id{viaRoute}, subnet, "203.0.113.0/24")},
		{name: "one prefix of two outside", rule: aclStandingTestRoute(router, []Id{viaRoute}, subnet, "10.1.0.0/16", "172.16.0.0/12")},
		{name: "a wider prefix", rule: aclStandingTestRoute(router, []Id{viaRoute}, subnet, "10.0.0.0/7")},
		{name: "no rule named", rule: aclStandingTestRoute(router, nil, subnet, "10.1.0.0/16")},
		{name: "a rule named that does not route", rule: aclStandingTestRoute(router, []Id{routerDial}, subnet, "10.1.0.0/16")},
		{name: "a missing via subject", rule: aclStandingTestRoute(db, []Id{viaRoute}, subnet, "10.1.0.0/16")},
		{name: "a second rule names the via", rule: aclStandingTestRoute(router, []Id{noViaRoute, viaRoute}, subnet, "10.2.0.0/16"), covered: true},
		{name: "no via holds any advertiser", rule: aclStandingTestRoute(db, []Id{noViaRoute}, subnet, "192.168.4.0/24"), covered: true},
		{name: "a revoked advertiser", rule: aclStandingTestRoute(revokedRouter, []Id{viaRoute}, subnet, "10.1.0.0/16")},
		{name: "an exit via the router", rule: aclStandingTestRoute(router, []Id{exitRoute}, exit), covered: true},
		{name: "an exit from no via", rule: aclStandingTestRoute(db, []Id{exitRoute}, exit)},
		{name: "an exit under a subnet rule", rule: aclStandingTestRoute(router, []Id{viaRoute}, exit)},
		{name: "a map on a listed port", rule: aclStandingTestMap(db, tcp, [2]uint32{5432, 5432}), covered: true},
		{name: "a map on a port outside the list", rule: aclStandingTestMap(db, tcp, [2]uint32{5433, 5433})},
		{name: "a map inside a listed range", rule: aclStandingTestMap(db, tcp, [2]uint32{6000, 6005}), covered: true},
		{name: "a map past a listed range", rule: aclStandingTestMap(db, tcp, [2]uint32{6005, 6011})},
		{name: "a map on every port of a limited rule", rule: aclStandingTestMap(db, tcp)},
		{name: "a map on another protocol's port", rule: aclStandingTestMap(db, udp, [2]uint32{5432, 5432})},
		{name: "a map across a protocol's ranges", rule: aclStandingTestMap(db, udp, [2]uint32{6008, 6020}), covered: true},
		{name: "an icmp map of a limited rule", rule: aclStandingTestMap(db, icmp)},
		{name: "a map of a host every port reaches", rule: aclStandingTestMap(router, tcp), covered: true},
		{name: "an icmp map of a host every port reaches", rule: aclStandingTestMap(router, icmp), covered: true},
		{name: "a map of a host no grant names", rule: aclStandingTestMap(laptop, tcp, [2]uint32{22, 22})},
		{name: "a map under an expired grant", rule: aclStandingTestMap(cache, tcp, [2]uint32{80, 80})},
		{name: "a void filing", rule: &BridgeLedgerRule{SignedType: bridge.SignedType_SIGNED_BRIDGE_MAP, Owner: router}},
	}
	for _, c := range cases {
		if covered := local.StandingCovers(state, c.rule, aclTestNow); covered != c.covered {
			t.Errorf("%s: covered %t", c.name, covered)
		}
	}
	var none *AclLocalPolicy
	if none.StandingCovers(state, aclStandingTestRoute(router, []Id{viaRoute}, subnet, "10.1.0.0/16"), aclTestNow) {
		t.Error("no policy held, and a route is covered")
	}
	if none.StandingCovers(state, aclStandingTestMap(db, tcp, [2]uint32{5432, 5432}), aclTestNow) {
		t.Error("no policy held, and a port-limited map is covered")
	}
	if !none.StandingCovers(state, aclStandingTestMap(router, tcp, [2]uint32{22, 22}), aclTestNow) {
		t.Error("no policy held, and a map under a rule limiting no port is not covered")
	}
	if local.StandingCovers(nil, aclStandingTestMap(router, tcp), aclTestNow) || local.StandingCovers(state, nil, aclTestNow) {
		t.Error("no state or no rule is covered")
	}
}

// With no document an untagged owner's filings are covered whatever they name (owner decision 120), and a tagged
// owner's only by the implicit document's rules: a map under its first rule's every port, a route only naming that rule;
// a nil policy judges as the implicit document's.
func TestAclStandingCoversWithNoDocument(t *testing.T) {
	world := newAclCompileWorld("standing implicit")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := world.device("laptop", owner)
	agent := world.agent("agent", owner, "worker")
	state := world.state(t)
	compiled, err := CompileAclLocal(world.input())
	if err != nil {
		t.Fatal(err)
	}
	subnet := bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET
	first := aclImplicitRuleId(0)
	cases := []struct {
		name    string
		rule    *BridgeLedgerRule
		covered bool
	}{
		{name: "an untagged owner's route naming nothing", rule: aclStandingTestRoute(laptop, nil, subnet, "10.0.0.0/8"), covered: true},
		{name: "an untagged owner's map", rule: aclStandingTestMap(laptop, aclIpProtocolTcp, [2]uint32{22, 22}), covered: true},
		{name: "a tagged owner's route naming nothing", rule: aclStandingTestRoute(agent, nil, subnet, "10.0.0.0/8")},
		{name: "a tagged owner's route naming the first rule", rule: aclStandingTestRoute(agent, []Id{first}, subnet, "10.0.0.0/8"), covered: true},
		{name: "a tagged owner's loopback route", rule: aclStandingTestRoute(agent, []Id{first}, subnet, "127.0.0.0/8")},
		{name: "a tagged owner's map", rule: aclStandingTestMap(agent, aclIpProtocolTcp, [2]uint32{5432, 5432}), covered: true},
	}
	var none *AclLocalPolicy
	for _, c := range cases {
		for name, local := range map[string]*AclLocalPolicy{"compiled": compiled, "nil": none} {
			if covered := local.StandingCovers(state, c.rule, aclTestNow); covered != c.covered {
				t.Errorf("%s, %s policy: covered %t", c.name, name, covered)
			}
		}
	}
}

// The implicit document's local policy, which a nil policy reads with no document, compiles from the binary alone and
// is the one a no-document network's input gives.
func TestAclImplicitLocalPolicyCompiles(t *testing.T) {
	implicit := aclImplicitLocalPolicy()
	if implicit == nil || implicit.HasDocument {
		t.Fatalf("the implicit local policy: %+v", implicit)
	}
	world := newAclCompileWorld("implicit local")
	world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	compiled, err := CompileAclLocal(world.input())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(implicit.Rules, compiled.Rules, func(a AclLocalRule, b AclLocalRule) bool {
		return a.RuleId == b.RuleId && slices.Equal(a.Ports, b.Ports) && slices.Equal(a.Cidrs, b.Cidrs)
	}) {
		t.Errorf("the implicit rules differ from a network's:\n%+v\n%+v", implicit.Rules, compiled.Rules)
	}
}
