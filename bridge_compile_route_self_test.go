//go:build !ios_extension

// A route rule that names no ip: destination and no autogroup:internet on the data path (§8.4's readings, §17.7's
// advertising; owner decision 575, QD-1019), at the bridge compile, the filer and the engine: Team's grant 1 gives a
// member's laptop an entry for each prefix its own desktop's approved route serves and the desktop a route row for the
// laptop, another member's device's prefix is not reached, an exit is not opened, a rule of tag:db through tag:router
// reaches only a device carrying both tags, an activated grant with no local detail stays closed, a remapped route is
// reached by its exposed prefix, the engine answers a preview from the routes the compile answers, and the filer names
// grant 1 for its own device's route.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a policy source compiles to over a state's members and sidecars, as a head carrying it would give them.
type testBridgePolicy struct {
	t      testing.TB
	source []byte
	rows   *protocol.AclRows
	local  *AclLocalPolicy
}

// The id the policy's rules table gives a rule by its canonical form.
func testBridgePolicyRuleId(canonicalSha256 [sha256.Size]byte) Id {
	return testConfigId("bridge policy rule " + hex.EncodeToString(canonicalSha256[:]))
}

// Compiles source for the network at state, with a tags row for each of tagIds, by name with no tag: prefix.
func testBridgeCompilePolicy(t testing.TB, state *ConfigState, networkId Id, source string, tagIds map[string]Id) *testBridgePolicy {
	t.Helper()
	policy, err := ParseAclPolicy([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := AclPolicyRuleKeys(policy)
	if err != nil {
		t.Fatal(err)
	}
	input := &AclCompileInput{
		NetworkId:  networkId,
		Policy:     []byte(source),
		Tags:       &protocol.ConfigAtomTable{},
		Groups:     &protocol.ConfigAtomTable{},
		Rules:      &protocol.ConfigRuleTable{},
		Labels:     &protocol.ConfigLabelTable{},
		Resolve:    &protocol.ConfigResolution{},
		HeadTimeMs: state.TimeMs(),
		Statements: &protocol.AclRows{},
		// the empty ledger, not a head's to read
		BridgeRoutes: []*BridgeLedgerRule{},
	}
	for _, key := range keys {
		input.Rules.Rules = append(input.Rules.Rules, &protocol.ConfigRuleId{
			CanonicalSha256: bytes.Clone(key.CanonicalSha256[:]), RuleId: testBridgePolicyRuleId(key.CanonicalSha256).Bytes(),
		})
	}
	names := []string{}
	for name := range tagIds {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		input.Tags.Atoms = append(input.Tags.Atoms, &protocol.ConfigAtomName{Name: name, AtomId: tagIds[name].Bytes()})
	}
	for _, memberId := range state.MemberIds() {
		input.Members = append(input.Members, state.Member(memberId))
	}
	for _, sidecarId := range state.SidecarIds() {
		input.Sidecars = append(input.Sidecars, state.SidecarRow(sidecarId))
	}
	rows, err := CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	local, err := CompileAclLocal(input)
	if err != nil {
		t.Fatal(err)
	}
	return &testBridgePolicy{t: t, source: []byte(source), rows: rows, local: local}
}

// The rule id of the policy's index-th grant.
func (self *testBridgePolicy) grantId(index int) Id {
	self.t.Helper()
	policy, err := ParseAclPolicy(self.source)
	if err != nil {
		self.t.Fatal(err)
	}
	keys, err := AclPolicyRuleKeys(policy)
	if err != nil {
		self.t.Fatal(err)
	}
	for _, key := range keys {
		if key.Kind == "grant" && key.Index == index {
			return testBridgePolicyRuleId(key.CanonicalSha256)
		}
	}
	self.t.Fatalf("no grant %d", index)
	return Id{}
}

// The compile net with approvals that spend: the bridge approvers' requests rule folded into a base, the owner owning
// each of tagIds there, and a binding for the host, so another device's compile links and binds it.
func newTestBridgeRouteSelfNet(t testing.TB, tagIds ...Id) *testBridgeCompileNet {
	net := newTestBridgeCompileNet(t)
	net.log.settings.AclSpendCheck = testBridgePolicySpendCheck{}
	net.foldLedger(net.n, func(rows *protocol.AclRows) {
		testBridgeWithApprovers(rows)
		for _, tagId := range tagIds {
			rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: tagId.Bytes(), TagOwnerMemberIds: [][]byte{net.ownerMemberId.Bytes()}})
		}
	})
	net.bind(net.host, 1)
	return net
}

// Files a route of device under a real single-use approval of approver's, failing the test unless the ledger holds it
// active: a subnet route of prefix, or with a nil prefix an exit.
func (self *testBridgeCompileNet) approvedRouteInForce(device testConfigDevice, approver Id, label string, prefix *bridge.BridgeIpv4Prefix) []byte {
	self.t.Helper()
	notAfterMs := self.timeMs + testBridgeDayMs
	var ruleId []byte
	var route *bridge.BridgeRoute
	if prefix != nil {
		ruleId, route = self.approvedRoute(device, approver, label, prefix, notAfterMs)
	} else {
		approval, exitId := testBridgeExposeApproval(self.t, label, device.sidecarId, []string{"0.0.0.0/0"}, device.sidecarId, approver, notAfterMs)
		ruleId = exitId
		route = self.bridgeRoute(device, ruleId, &bridge.BridgeRouteBody{Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT, Weight: 1, Approval: approval})
	}
	self.mustPost(device, bridge.SignedType_SIGNED_BRIDGE_ROUTE, route)
	if rule := self.ledgerOf(self.log).Rule(ruleId); rule == nil || !rule.Active() || rule.Standing || rule.ApprovalId == (Id{}) {
		self.t.Fatalf("the approved route %s: %+v", label, rule)
	}
	return ruleId
}

// The reader's view under a policy: its rows over the view's state and its local detail.
func (self *testBridgeCompileNet) policyView(policy *testBridgePolicy) *testBridgeCompileView {
	self.t.Helper()
	view := self.view()
	acl, err := NewAclState(policy.rows, view.state)
	if err != nil {
		self.t.Fatal(err)
	}
	view.acl, view.aclLocal = acl, policy.local
	return view
}

// The local facts of a device other than the fixture's host, at the fixture's bindings.
func (self *testBridgeCompileNet) localOf(device testConfigDevice) *BridgeCompileLocal {
	local := self.local()
	local.SidecarId = device.sidecarId
	return local
}

// Whether a subject's rows are want, in order.
func testBridgeReachRowsAre(rows []*bridge.BridgeRuleReach, want ...*bridge.BridgeRuleReach) bool {
	return slices.EqualFunc(rows, want, func(a *bridge.BridgeRuleReach, b *bridge.BridgeRuleReach) bool { return proto.Equal(a, b) })
}

// Owner decision 575 on the compile's test net, under Team's starting document: the laptop and its owner's desktop,
// which serves 192.168.7.0/24 under a real single-use approval. Grant 1 names autogroup:self as destination and via and
// no prefix, so the laptop's table gains 192.168.7.0/24 with the desktop as its link, and the desktop gives the laptop a
// route row for that prefix whole beside its dial row. Another member's device serving 192.168.8.0/24 under its own
// approval is not reached: the laptop's table holds no entry for it, and that device binds the laptop as no subject.
// The desktop's approved exit is not opened: the laptop's table holds no entry and no exit for it, and the desktop
// gives the laptop no exit row and no row of 0.0.0.0/0.
func TestCompileGrant1RoutesAMemberThroughItsOwnDevicesRoutes(t *testing.T) {
	net := newTestBridgeRouteSelfNet(t)
	homePrefix, awayPrefix := testBridgePrefix(192, 168, 7, 0, 24), testBridgePrefix(192, 168, 8, 0, 24)
	homeId := net.approvedRouteInForce(net.peer, net.member, "home", homePrefix)
	net.approvedRouteInForce(net.other, net.other.memberId, "away", awayPrefix)
	net.approvedRouteInForce(net.peer, net.member, "home exit", nil)
	policy := testBridgeCompilePolicy(t, net.log.State(), net.networkId, string(AclTeamStartDocument()), map[string]Id{"recurd": testConfigId("tag recurd")})
	grant1 := policy.grantId(0)
	if local := policy.local.Rule(grant1.Bytes()); local == nil || len(local.Cidrs) != 0 {
		t.Fatalf("grant 1's local detail: %+v", local)
	}

	// the laptop, S
	compiled, rules := testBridgeCompile(t, net.policyView(policy), net.local())
	if !compiled.State.GetHasDocument() {
		t.Fatal("has_document under Team's starting document")
	}
	entry := testBridgeCompileEntry(rules, homePrefix)
	if entry == nil || entry.GetKind() != bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK || len(entry.GetLinks()) != 1 ||
		Id(entry.GetLinks()[0].GetTargetSidecarId()) != net.peer.sidecarId || !bytes.Equal(entry.GetLinks()[0].GetRuleId(), homeId) {
		t.Fatalf("the laptop's entry for its desktop's prefix: %v", entry)
	}
	if testBridgeCompileEntry(rules, awayPrefix) != nil {
		t.Error("the laptop's table holds another member's device's prefix")
	}
	if testBridgeCompileEntry(rules, &bridge.BridgeIpv4Prefix{}) != nil || len(rules.GetEgress().GetExits()) != 0 {
		t.Errorf("the laptop's table opens an exit: %v", rules.GetEgress())
	}
	// its own desktop's /32 by grant 1's dial, and no other member's
	if testBridgeCompileEntry(rules, testBridgePrefix(100, 80, 3, 9, 32)) == nil || testBridgeCompileEntry(rules, testBridgePrefix(100, 80, 4, 10, 32)) != nil {
		t.Error("the laptop's /32 entries under grant 1")
	}

	// the desktop, the advertiser
	_, desktopRules := testBridgeCompile(t, net.policyView(policy), net.localOf(net.peer))
	subject := testBridgeCompileSubject(desktopRules, net.host.sidecarId)
	if subject == nil {
		t.Fatal("the desktop binds its member's laptop as no subject")
	}
	if !testBridgeReachRowsAre(subject.GetRoute(), &bridge.BridgeRuleReach{Prefix: homePrefix}) {
		t.Errorf("the laptop's route rows at the desktop: %v", subject.GetRoute())
	}
	if !testBridgeReachRowsAre(subject.GetDial(), &bridge.BridgeRuleReach{}) || len(subject.GetExit()) != 0 {
		t.Errorf("the laptop's dial rows %v and exit rows %v at the desktop", subject.GetDial(), subject.GetExit())
	}
	if other := testBridgeCompileSubject(desktopRules, net.other.sidecarId); other != nil {
		t.Errorf("the desktop binds another member's device: %v", other)
	}
	served := []string{}
	for _, row := range desktopRules.GetServed() {
		served = append(served, fmt.Sprintf("%d/%d/%d", row.GetKind(), row.GetPrefix().GetAddress(), row.GetPrefix().GetLength()))
	}
	if len(served) != 2 {
		t.Errorf("the desktop serves %v", served)
	}

	// the other member's device: the laptop reaches nothing of it
	_, otherRules := testBridgeCompile(t, net.policyView(policy), net.localOf(net.other))
	if subject := testBridgeCompileSubject(otherRules, net.host.sidecarId); subject != nil {
		t.Errorf("another member's device binds the laptop: %v", subject)
	}
}

// The same reading for a document's own rule: { dst: [tag:db], via: [tag:router], allow: [route] } reaches a prefix only
// of a device that carries both tags, through that device. A device tagged router alone is a via the rule holds and no
// destination of it, and one tagged db alone is a destination and no via, so the routes each serves, in force under
// their own approvals, give the laptop no entry, and neither gives the laptop a route row. The engine's preview agrees
// from the routes the compile answers, and a route filed with no approval that names the rule is covered for the device
// of both tags alone.
func TestCompileAPrefixlessRouteRuleReachesOnlyADestinationAmongItsVias(t *testing.T) {
	db, router := testConfigId("tag db"), testConfigId("tag router")
	net := newTestBridgeRouteSelfNet(t, db, router)
	agents := []struct {
		label  string
		tagIds []Id
		prefix *bridge.BridgeIpv4Prefix
		device testConfigDevice
	}{
		{label: "both", tagIds: []Id{db, router}, prefix: testBridgePrefix(10, 20, 1, 0, 24)},
		{label: "router alone", tagIds: []Id{router}, prefix: testBridgePrefix(10, 20, 2, 0, 24)},
		{label: "db alone", tagIds: []Id{db}, prefix: testBridgePrefix(10, 20, 3, 0, 24)},
	}
	for i := range agents {
		agent := &agents[i]
		delegation := net.delegate(net.owner, "route self "+agent.label, agent.tagIds, 1, net.timeMs+testBridgeDayMs)
		agent.device = net.device("route self agent "+agent.label, Id{})
		if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent.device, false, delegation.notAfter)); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
		net.bind(agent.device, 1)
		net.approvedRouteInForce(agent.device, net.ownerMemberId, agent.label, agent.prefix)
	}
	policy := testBridgeCompilePolicy(t, net.log.State(), net.networkId, `{
  "tagOwners": { "tag:db": ["autogroup:admin"], "tag:router": ["autogroup:admin"] },
  "grants": [ { "src": ["autogroup:member"], "dst": ["tag:db"], "via": ["tag:router"], "allow": ["route"] } ],
}`, map[string]Id{"db": db, "router": router})

	local := net.local()
	local.AnswerServedRoutes = true
	compiled, rules := testBridgeCompile(t, net.policyView(policy), local)
	engine := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	if err := engine.Install(net.policyView(policy).acl, policy.local); err != nil {
		t.Fatal(err)
	}
	engine.InstallRoutes(compiled.ServedRoutes)
	now := time.UnixMilli(net.log.State().TimeMs())
	for i, agent := range agents {
		if len(compiled.ServedRoutes.Prefixes(agent.device.sidecarId)) != 1 {
			t.Fatalf("the routes in force of %s: %v", agent.label, compiled.ServedRoutes.Prefixes(agent.device.sidecarId))
		}
		inside := netip.AddrFrom4([4]byte{10, 20, byte(i + 1), 9})
		decision := engine.AllowRoute(AclSidecarSubject(net.host.sidecarId), inside, aclIpProtocolTcp, 22, AclSidecarSubject(agent.device.sidecarId), now)
		if decision.Allowed != (agent.label == "both") {
			t.Errorf("the engine's preview through %s: %+v", agent.label, decision)
		}
	}
	for _, agent := range agents {
		entry := testBridgeCompileEntry(rules, agent.prefix)
		if reached := entry != nil; reached != (agent.label == "both") {
			t.Errorf("the laptop's entry for the prefix of %s: %v", agent.label, entry)
		}
		if entry != nil && (len(entry.GetLinks()) != 1 || Id(entry.GetLinks()[0].GetTargetSidecarId()) != agent.device.sidecarId) {
			t.Errorf("the entry's links: %v", entry.GetLinks())
		}
		_, agentRules := testBridgeCompile(t, net.policyView(policy), net.localOf(agent.device))
		subject := testBridgeCompileSubject(agentRules, net.host.sidecarId)
		switch agent.label {
		case "both":
			if subject == nil || !testBridgeReachRowsAre(subject.GetRoute(), &bridge.BridgeRuleReach{Prefix: agent.prefix}) || len(subject.GetDial())+len(subject.GetExit()) != 0 {
				t.Errorf("the laptop at the device of both tags: %v", subject)
			}
		case "router alone":
			// a via of the rule, so the laptop is a subject there, with no row: its destinations do not name it
			if subject == nil || len(subject.GetRoute())+len(subject.GetDial())+len(subject.GetExit()) != 0 {
				t.Errorf("the laptop at the device tagged router alone: %v", subject)
			}
		default:
			if subject != nil {
				t.Errorf("the laptop at the device tagged db alone: %v", subject)
			}
		}
	}
	// filed with no approval: in force, and the laptop's, for the device of both tags alone
	standingPrefixes := []*bridge.BridgeIpv4Prefix{}
	for i, agent := range agents {
		standingPrefixes = append(standingPrefixes, testBridgePrefix(10, 30, byte(i+1), 0, 24))
		standingId := net.standingRoute(agent.device, "standing "+agent.label, standingPrefixes[i], policy.grantId(0).Bytes())
		standing := net.ledgerOf(net.log).Rule(standingId)
		if standing == nil || !standing.Standing {
			t.Fatalf("the route %s filed with no approval: %+v", agent.label, standing)
		}
		if covered := policy.local.StandingCovers(net.policyView(policy).acl, standing, now); covered != (agent.label == "both") {
			t.Errorf("the rule covers the unapproved route of %s: %t", agent.label, covered)
		}
	}
	_, rules = testBridgeCompile(t, net.policyView(policy), net.local())
	for i, agent := range agents {
		if reached := testBridgeCompileEntry(rules, standingPrefixes[i]) != nil; reached != (agent.label == "both") {
			t.Errorf("the laptop's entry for the unapproved route of %s: %t", agent.label, reached)
		}
	}
}

// QD-003 beside owner decision 575: an activated grant has no local detail, so whether it names a prefix is not the
// device's to say, and it stays closed. A route grant activated for the laptop through its own desktop, which grant 1's
// shape would reach, gives the laptop no entry for the desktop's prefix and the desktop no route row for the laptop,
// while the same row as a rule of the head with its local detail gives both.
func TestCompileAnActivatedRouteGrantWithNoLocalDetailStaysClosed(t *testing.T) {
	net := newTestBridgeRouteSelfNet(t)
	homePrefix := testBridgePrefix(192, 168, 7, 0, 24)
	net.approvedRouteInForce(net.peer, net.member, "home", homePrefix)
	requestId, headRuleId := testConfigId("route self requests rule"), testConfigId("route self head rule")
	grantId := sha256.Sum256([]byte("route self activated grant"))
	selfAtom := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()
	memberAtom := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()
	view := func(activated bool) *testBridgeCompileView {
		view := net.view()
		rule := &protocol.AclRule{
			RuleId:   headRuleId.Bytes(),
			SrcAtoms: [][]byte{memberAtom},
			Targets:  []*protocol.AclTarget{{Atom: selfAtom}},
			Via:      []*protocol.AclTarget{{Atom: selfAtom}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
		}
		rows := &protocol.AclRows{HasDocument: true, Rules: []*protocol.AclRule{rule}}
		local := &AclLocalPolicy{HasDocument: true}
		if activated {
			rule.RuleId, rule.SourceRuleId = grantId[:], requestId.Bytes()
			rows.Requests = []*protocol.AclRequestRule{{
				RuleId:        requestId.Bytes(),
				SrcAtoms:      [][]byte{memberAtom},
				Targets:       []*protocol.AclTarget{{Atom: selfAtom}},
				Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
				ApproverAtoms: [][]byte{selfAtom},
			}}
		} else {
			local.Rules = []AclLocalRule{{RuleId: headRuleId}}
		}
		acl, err := NewAclState(rows, view.state)
		if err != nil {
			t.Fatal(err)
		}
		view.acl, view.aclLocal = acl, local
		return view
	}
	for _, activated := range []bool{false, true} {
		// the grant stands at the policy either way: the closed direction is the compile's
		acl := view(activated).acl
		if reach := acl.RouteRules(AclSidecarSubject(net.host.sidecarId), AclSidecarSubject(net.peer.sidecarId), time.UnixMilli(net.log.State().TimeMs())); len(reach) != 1 || !reach[0].ViaDestination {
			t.Fatalf("activated %t: the laptop's route rules through its desktop: %+v", activated, reach)
		}
		_, rules := testBridgeCompile(t, view(activated), net.local())
		if reached := testBridgeCompileEntry(rules, homePrefix) != nil; reached == activated {
			t.Errorf("activated %t: the laptop's entry for its desktop's prefix: %t", activated, reached)
		}
		_, desktopRules := testBridgeCompile(t, view(activated), net.localOf(net.peer))
		subject := testBridgeCompileSubject(desktopRules, net.host.sidecarId)
		if subject == nil {
			t.Fatalf("activated %t: the desktop binds the laptop as no subject", activated)
		}
		if rowed := 0 < len(subject.GetRoute()); rowed == activated {
			t.Errorf("activated %t: the laptop's route rows at the desktop: %v", activated, subject.GetRoute())
		}
	}
}

// A remapped route under grant 1: the laptop's table holds its exposed prefix read into the block, never its LAN
// prefix, which is what a sender addresses, and the desktop gives the laptop a row for the prefix and for its exposed
// prefix, each whole.
func TestCompileGrant1ReachesARemappedRouteByItsExposedPrefix(t *testing.T) {
	net := newTestBridgeRouteSelfNet(t)
	lanPrefix, exposedPrefix := testBridgePrefix(192, 168, 7, 0, 24), testBridgePrefix(100, 80, 200, 0, 24)
	approval, ruleId := testBridgeExposeApproval(t, "remap", net.peer.sidecarId, []string{"192.168.7.0/24"}, net.peer.sidecarId, net.member, net.timeMs+testBridgeDayMs)
	body := testBridgeApprovedSubnet(lanPrefix, approval)
	body.ExposedPrefix = exposedPrefix
	net.mustPost(net.peer, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(net.peer, ruleId, body))
	if rule := net.ledgerOf(net.log).Rule(ruleId); rule == nil || !rule.Active() || rule.ApprovalId == (Id{}) {
		t.Fatalf("the remapped route: %+v", rule)
	}
	policy := testBridgeCompilePolicy(t, net.log.State(), net.networkId, string(AclTeamStartDocument()), map[string]Id{"recurd": testConfigId("tag recurd")})

	_, rules := testBridgeCompile(t, net.policyView(policy), net.local())
	if entry := testBridgeCompileEntry(rules, exposedPrefix); entry == nil || len(entry.GetLinks()) != 1 || Id(entry.GetLinks()[0].GetTargetSidecarId()) != net.peer.sidecarId {
		t.Fatalf("the laptop's entry for the exposed prefix: %v", entry)
	}
	if testBridgeCompileEntry(rules, lanPrefix) != nil {
		t.Error("the laptop's table holds a remapped route's LAN prefix")
	}
	_, desktopRules := testBridgeCompile(t, net.policyView(policy), net.localOf(net.peer))
	subject := testBridgeCompileSubject(desktopRules, net.host.sidecarId)
	if subject == nil || !testBridgeReachRowsAre(subject.GetRoute(), &bridge.BridgeRuleReach{Prefix: exposedPrefix}, &bridge.BridgeRuleReach{Prefix: lanPrefix}) {
		t.Errorf("the laptop's route rows at the desktop: %v", subject.GetRoute())
	}
}

// ur bridge's previews by the same reading: the compile answers every advertiser's subnet routes in force where its
// host asks, and an engine holding them allows the laptop a prefix its own desktop serves through that desktop, and
// refuses a public address, an address its desktop does not serve, and every address through another member's device.
// Before the routes are installed, and once they are cleared, a rule with no prefix routes to nothing. A compile that
// was not asked answers none.
func TestAllowRouteAnswersByTheRoutesTheCompileHoldsInForce(t *testing.T) {
	net := newTestBridgeRouteSelfNet(t)
	net.approvedRouteInForce(net.peer, net.member, "home", testBridgePrefix(192, 168, 7, 0, 24))
	net.approvedRouteInForce(net.other, net.other.memberId, "away", testBridgePrefix(192, 168, 8, 0, 24))
	net.approvedRouteInForce(net.peer, net.member, "home exit", nil)
	policy := testBridgeCompilePolicy(t, net.log.State(), net.networkId, string(AclTeamStartDocument()), map[string]Id{"recurd": testConfigId("tag recurd")})
	grant1 := policy.grantId(0)
	view := net.policyView(policy)
	if compiled, _ := testBridgeCompile(t, view, net.local()); compiled.ServedRoutes != nil {
		t.Fatalf("a compile that was not asked answers routes: %+v", compiled.ServedRoutes)
	}
	local := net.local()
	local.AnswerServedRoutes = true
	compiled, _ := testBridgeCompile(t, view, local)
	served := compiled.ServedRoutes
	if !slices.Equal(served.Prefixes(net.peer.sidecarId), []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}) ||
		!slices.Equal(served.Prefixes(net.other.sidecarId), []netip.Prefix{netip.MustParsePrefix("192.168.8.0/24")}) ||
		len(served.Prefixes(net.host.sidecarId)) != 0 {
		t.Fatalf("the routes in force: %+v", served)
	}

	engine := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	if err := engine.Install(view.acl, policy.local); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(view.state.TimeMs())
	laptop, desktop, other := AclSidecarSubject(net.host.sidecarId), AclSidecarSubject(net.peer.sidecarId), AclSidecarSubject(net.other.sidecarId)
	home, away, public := netip.MustParseAddr("192.168.7.20"), netip.MustParseAddr("192.168.8.20"), netip.MustParseAddr("203.0.113.9")
	allows := func(address netip.Addr, via AclSubject) bool {
		t.Helper()
		decision := engine.AllowRoute(laptop, address, aclIpProtocolTcp, 22, via, now)
		if decision.Allowed && !bytes.Equal(decision.Rule.GetRuleId(), grant1.Bytes()) {
			t.Fatalf("allowed by another rule: %+v", decision)
		}
		return decision.Allowed
	}
	if allows(home, desktop) {
		t.Error("with no routes installed the engine routes to a prefix")
	}
	engine.InstallRoutes(served)
	if !allows(home, desktop) {
		t.Error("the engine refuses a prefix the laptop's own desktop serves")
	}
	for _, refused := range []struct {
		label   string
		address netip.Addr
		via     AclSubject
	}{
		{label: "a public address through its own desktop, which is an exit", address: public, via: desktop},
		{label: "an address its desktop does not serve", address: away, via: desktop},
		{label: "another member's device's prefix through that device", address: away, via: other},
		{label: "its desktop's prefix through another member's device", address: home, via: other},
		{label: "no address", address: netip.Addr{}, via: desktop},
	} {
		if allows(refused.address, refused.via) {
			t.Errorf("the engine routes to %s", refused.label)
		}
	}
	engine.InstallRoutes(nil)
	if allows(home, desktop) {
		t.Error("with the routes cleared the engine routes to a prefix")
	}
}

// The filer names grant 1 for its own device's route, as every reader then covers a standing one: under Team's starting
// document a subnet route this host exposes names grant 1 in its route_rule_ids, and an exit names none; with no
// compiled policy where the document stands it names none, since whether a rule names a prefix is the policy's to say.
func TestBridgeRouteNamesGrant1ForItsOwnDevicesRoute(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	policy := testBridgeCompilePolicy(t, world.net.log.State(), world.net.networkId, string(AclTeamStartDocument()), map[string]Id{"recurd": testConfigId("tag recurd")})
	grant1 := policy.grantId(0)
	world.net.withAclRows(func(rows *protocol.AclRows) {
		rows.HasDocument = true
		rows.Rules = append(rows.Rules, policy.rows.GetRules()...)
		slices.SortFunc(rows.Rules, func(a *protocol.AclRule, b *protocol.AclRule) int { return bytes.Compare(a.GetRuleId(), b.GetRuleId()) })
	})
	world.heads.reader = newTestConfigHeadReader(world.net)
	world.filer.args.AclLocal = func() *AclLocalPolicy { return policy.local }
	view, err := world.filer.view(ctx)
	if err != nil {
		t.Fatal(err)
	}
	subnet := &bridge.BridgeRouteBody{Prefixes: []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 168, 7, 0, 24)}, Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET, Weight: 1}
	if ruleIds := world.filer.routeRuleIds(view, subnet); len(ruleIds) != 1 || !bytes.Equal(ruleIds[0], grant1.Bytes()) {
		t.Fatalf("the route rules a subnet route names: %x, grant 1 %x", ruleIds, grant1.Bytes())
	}
	exit := &bridge.BridgeRouteBody{Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT, Weight: 1}
	if ruleIds := world.filer.routeRuleIds(view, exit); len(ruleIds) != 0 {
		t.Errorf("the route rules an exit names: %x", ruleIds)
	}
	filing, err := world.filer.Expose(ctx, world.mcp(), &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if rule := world.ledger().Rule(filing.RuleId); rule == nil || len(rule.RouteRuleIds) != 1 || !bytes.Equal(rule.RouteRuleIds[0], grant1.Bytes()) {
		t.Fatalf("the filed route's rules: %+v", rule)
	}
	world.filer.args.AclLocal = nil
	if ruleIds := world.filer.routeRuleIds(view, subnet); len(ruleIds) != 0 {
		t.Errorf("with no compiled policy under a document the filer named rules: %x", ruleIds)
	}
}
