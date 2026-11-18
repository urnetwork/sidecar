//go:build !sidecar_http && !ios_extension

// Team's documents (ACL-M6-01), pure (T1): the starting document compiles to its golden and passes its own tests under
// Team's limits; its grant 1 routes a member through the member's own devices alone, to the prefixes their routes in
// force serve, and dials them as before (owner decisions 344 and 575); two approvers validate on Team alone and are
// enforced at GrantActivate; scope hosts validate only for a scope the network holds and *.<scope> covers that scope
// alone, a member scope's hosts its member's consented devices alone; SCIM's group:<name>@<domain> validates with no
// groups entry; and FS-85's worker case at the rule level, a harness decision refused and the destination owner's
// device decision passing.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §20.4's Team column, as GET /sidecar/limits would give it.
func aclTestTeamLimits() *AclLimits {
	return &AclLimits{Rules: 5000, Groups: 500, Requests: 500, ApproversTwo: true, NetworkShares: 500, StandingPublishes: true}
}

// A team: dana with an invited first device and a second an admin admitted, amir with a device, an Owner, and tag
// recurd's row.
type aclTeamWorld struct {
	world       *aclCompileWorld
	owner       Id
	ownerDevice Id
	dana        Id
	danaFirst   Id
	danaSecond  Id
	amir        Id
	amirDevice  Id
}

func newAclTeamWorld(t testing.TB, policy string) *aclTeamWorld {
	world := newAclCompileWorld("team")
	self := &aclTeamWorld{world: world}
	self.owner = world.member("owner@team.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.ownerDevice = world.device("owner device", self.owner)
	self.dana = world.member("dana@team.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.danaFirst = world.device("dana first", self.dana)
	self.danaSecond = world.device("dana second", self.dana)
	self.amir = world.member("amir@team.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.amirDevice = world.device("amir device", self.amir)
	for _, row := range world.sidecars {
		if Id(row.SidecarId) == self.danaFirst {
			// dana's invited first device, admitted by the Owner's device outside every cascade
			row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)
			row.AdmissionSigners = [][]byte{self.ownerDevice.Bytes()}
		}
	}
	world.tag("recurd")
	world.setPolicy(t, policy)
	return self
}

// The starting document compiles to its golden, with has_document, grant 1's via autogroup:self apart from its target
// (owner decision 344), validates on Team and passes its own tests, autogroup:self#route among them.
func TestAclTeamStartCompilesToItsGoldenAndPassesItsTests(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocument()))
	rows := team.world.compile(t)
	if !rows.GetHasDocument() || len(rows.GetRules()) != 2 || len(rows.GetRequests()) != 1 {
		t.Fatalf("has_document %v, %d rules, %d requests", rows.GetHasDocument(), len(rows.GetRules()), len(rows.GetRequests()))
	}
	grant1 := team.world.documentRuleId(t, "grant", 0).Bytes()
	index := slices.IndexFunc(rows.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), grant1) })
	if index < 0 {
		t.Fatal("no row of grant 1")
	}
	selfAtom := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()
	if row := rows.GetRules()[index]; len(row.GetVia()) != 1 || !bytes.Equal(row.GetVia()[0].GetAtom(), selfAtom) ||
		len(row.GetTargets()) != 1 || !bytes.Equal(row.GetTargets()[0].GetAtom(), selfAtom) ||
		!slices.Equal(row.GetActions(), []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL), uint32(protocol.AclAction_ACL_ACTION_ROUTE)}) {
		t.Errorf("grant 1's row: %v", row)
	}
	golden, err := testAclVectorFiles.ReadFile("testdata/acl/vectors/team_start_rows.hex")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(aclEncodeRows(t, rows)); got != strings.TrimSpace(string(golden)) {
		t.Fatalf("the starting document compiles to other rows:\n%s", got)
	}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("validation on Team: %v", err)
	}
	report, err := AclPolicyTestRun(&AclPolicyTestInput{Compile: team.world.input(), View: team.world.view(), Now: aclTestNow})
	if err != nil || !report.Passed() || report.TestCount != 2 || report.CheckCount != 6 {
		t.Fatalf("its tests: %+v, %v", report, err)
	}
	request := rows.GetRequests()[0]
	dstOwner := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER).Bytes()
	if !slices.ContainsFunc(request.GetApproverAtoms(), func(atom []byte) bool { return string(atom) == string(dstOwner) }) || request.GetApprovers() != 1 ||
		!slices.Equal(request.GetEvidence(), []uint32{uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE), uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)}) {
		t.Errorf("the directory rule %+v", request)
	}
}

// Grant 1's route (owner decision 344): dana's laptop routes through her own home device, which serves 192.168.7.0/24
// under an approved route, by grant 1 alone, at MayRoute, at the contract gate, in RouteRules and ExitRules, which agree
// with it and name the home device a destination of grant 1 for her laptop; through amir's device, whose approved route
// serves 192.168.8.0/24, nothing routes at any of them, nor does amir route through dana's. Rows carry no prefix, and
// grant 1 names none, so it reaches the prefixes a via its destinations name serves (owner decision 575): dana's engine
// routes her laptop to her home device's prefix once it holds the routes in force, and to no public address, no
// address the home device does not serve and nothing through amir's device, and to nothing before it holds them. By the
// same reading grant 1 covers a subnet route a member's device files with no approval that names it, which that
// member's own devices alone then reach, and covers neither one that does not name it nor an exit.
func TestAclTeamStartRoutesThroughAMembersOwnDevicesAlone(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocument()))
	grant1 := team.world.documentRuleId(t, "grant", 0)
	laptop, home, amir := team.danaFirst, team.danaSecond, team.amirDevice
	danaServed := team.world.ledgerRoute("dana's home", home, true)
	danaServed.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 168, 7, 0, 24)}
	amirServed := team.world.ledgerRoute("amir's home", amir, true)
	amirServed.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 168, 8, 0, 24)}
	if routes := aclTestRouteRows(t, team.world.compile(t)); len(routes) != 2 {
		t.Fatalf("the approved routes in force at the fold: %v", routes)
	}
	danaAddress, amirAddress := netip.MustParseAddr("192.168.7.20"), netip.MustParseAddr("192.168.8.20")

	state := team.world.state(t)
	gate, end := aclRouteRowsTestGate(t, state)
	// whether source routes to address through via, every read agreeing, and by grant 1 alone where it does
	routes := func(source Id, address netip.Addr, via Id) bool {
		t.Helper()
		sourceSubject, viaSubject := AclSidecarSubject(source), AclSidecarSubject(via)
		decision := state.MayRoute(sourceSubject, address, viaSubject, aclTestNow)
		routeRules := state.RouteRules(sourceSubject, viaSubject, aclTestNow)
		exitRules := state.ExitRules(sourceSubject, viaSubject, aclTestNow)
		if (0 < len(routeRules)) != decision.Allowed || (0 < len(exitRules)) != decision.Allowed {
			t.Fatalf("through %v the reads disagree: MayRoute %+v, %d route rules, %d exit rules", via, decision, len(routeRules), len(exitRules))
		}
		if decision.Allowed && (!bytes.Equal(decision.Rule.GetRuleId(), grant1.Bytes()) || len(routeRules) != 1 ||
			!bytes.Equal(routeRules[0].RuleId, grant1.Bytes()) || routeRules[0].Internet || routeRules[0].PortsLimited ||
			!routeRules[0].ViaDestination) {
			t.Fatalf("through %v: %+v, %+v", via, decision, routeRules)
		}
		if decision.Allowed && !aclRouteRowsTestReaches(gate, end(source), end(via)) {
			t.Fatalf("the gate refused the route through %v", via)
		}
		return decision.Allowed
	}
	if !routes(laptop, danaAddress, home) {
		t.Error("dana's laptop routes nothing through her home device")
	}
	if routes(laptop, amirAddress, amir) || aclRouteRowsTestReaches(gate, end(laptop), end(amir)) {
		t.Error("dana's laptop reaches through amir's device")
	}
	if routes(amir, danaAddress, home) || aclRouteRowsTestReaches(gate, end(amir), end(home)) {
		t.Error("amir reaches through dana's home device")
	}

	engine := aclRouteRowsTestEngine(t, laptop, team.world)
	engineRoutes := func(address netip.Addr, via Id) bool {
		t.Helper()
		decision := engine.AllowRoute(AclSidecarSubject(laptop), address, aclIpProtocolTcp, 22, AclSidecarSubject(via), aclTestNow)
		if decision.Allowed && !bytes.Equal(decision.Rule.GetRuleId(), grant1.Bytes()) {
			t.Fatalf("dana's engine routed by another rule: %+v", decision)
		}
		return decision.Allowed
	}
	if engineRoutes(danaAddress, home) {
		t.Error("dana's engine routed to a prefix before it held the routes in force")
	}
	engine.InstallRoutes(NewAclServedRoutes([]AclServedRoute{
		{Advertiser: home, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}},
		{Advertiser: amir, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.8.0/24")}},
	}))
	if !engineRoutes(danaAddress, home) {
		t.Error("dana's engine refused her home device's prefix")
	}
	if engineRoutes(netip.MustParseAddr("203.0.113.9"), home) {
		t.Error("dana's engine routed to a public address through her home device")
	}
	if engineRoutes(amirAddress, home) {
		t.Error("dana's engine routed through her home device to a prefix it does not serve")
	}
	if engineRoutes(amirAddress, amir) || engineRoutes(danaAddress, amir) {
		t.Error("dana's engine routed through amir's device")
	}

	local, err := CompileAclLocal(team.world.input())
	if err != nil {
		t.Fatal(err)
	}
	unapproved := func(label string, advertiser Id, ruleIds ...Id) *BridgeLedgerRule {
		standing := team.world.ledgerRoute(label, advertiser, false, ruleIds...)
		standing.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 168, 9, 0, 24)}
		return standing
	}
	for _, advertiser := range []Id{home, amir} {
		if !local.StandingCovers(state, unapproved("named", advertiser, grant1), aclTestNow) {
			t.Errorf("grant 1 does not cover the route %v files with no approval that names it", advertiser)
		}
		if local.StandingCovers(state, unapproved("unnamed", advertiser), aclTestNow) {
			t.Errorf("grant 1 covers a route of %v that does not name it", advertiser)
		}
		exit := unapproved("exit", advertiser, grant1)
		exit.Route = &bridge.BridgeRouteBody{Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT, Weight: 1}
		if local.StandingCovers(state, exit, aclTestNow) {
			t.Errorf("grant 1 covers an exit of %v", advertiser)
		}
	}
	// no compiled policy under the document: whether a rule names a prefix is the policy's to say, so none is covered
	if (*AclLocalPolicy)(nil).StandingCovers(state, unapproved("no policy", home, grant1), aclTestNow) {
		t.Error("a nil policy under a document covers a route")
	}
}

// Dial between a member's own devices is grant 1's as it was: dana's laptop dials her home device by grant 1, which
// limits no port, so the home device's engine takes the laptop at any port; amir's device dials neither, and is taken
// by neither.
func TestAclTeamStartDialsAMembersOwnDevicesAsBefore(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocument()))
	grant1 := team.world.documentRuleId(t, "grant", 0)
	laptop, home, amir := team.danaFirst, team.danaSecond, team.amirDevice
	state := team.world.state(t)
	for _, pair := range [][2]Id{{laptop, home}, {home, laptop}} {
		decision := state.MayDial(AclSidecarSubject(pair[0]), AclSidecarSubject(pair[1]), aclTestNow)
		dialRules := state.DialRules(AclSidecarSubject(pair[0]), AclSidecarSubject(pair[1]), aclTestNow)
		if !decision.Allowed || !bytes.Equal(decision.Rule.GetRuleId(), grant1.Bytes()) || len(dialRules) != 1 || !bytes.Equal(dialRules[0].RuleId, grant1.Bytes()) {
			t.Errorf("%v dials %v: %+v, %+v", pair[0], pair[1], decision, dialRules)
		}
	}
	for _, pair := range [][2]Id{{laptop, amir}, {amir, laptop}, {amir, home}} {
		if decision := state.MayDial(AclSidecarSubject(pair[0]), AclSidecarSubject(pair[1]), aclTestNow); decision.Allowed {
			t.Errorf("%v dials %v: %+v", pair[0], pair[1], decision)
		}
	}
	engine := aclRouteRowsTestEngine(t, home, team.world)
	for _, port := range []uint32{22, 443, 50000} {
		inbound := &AclInbound{Source: AclSidecarSubject(laptop), IpProtocol: aclIpProtocolTcp, Port: port}
		if decision := engine.AllowInbound(inbound, aclTestNow); !decision.Allowed {
			t.Errorf("the home device refused dana's laptop at %d: %s", port, decision.Reason)
		}
		inbound.Source = AclSidecarSubject(amir)
		if decision := engine.AllowInbound(inbound, aclTestNow); decision.Allowed {
			t.Errorf("the home device took amir's device at %d", port)
		}
	}
}

// The starting document with the directory rule given two approvers, the destination's owner and an admin.
const aclTestTeamTwoApprovers = `{
  "tagOwners": { "tag:recurd": ["autogroup:member"] },
  "grants": [ { "src": ["autogroup:member", "autogroup:untagged"], "dst": ["autogroup:self"], "via": ["autogroup:self"],
                "allow": ["dial", "route"] } ],
  "requests": [
    { "src": ["autogroup:member", "autogroup:tagged"],
      "dst": ["autogroup:member", "autogroup:tagged", "sock:*"], "allow": ["dial"],
      "approver": ["autogroup:dst-owner", "autogroup:admin"], "approvers": 2,
      "evidence": ["device", "presence"], "maxExpiry": "30d" },
  ],
}`

// The decisions a GrantActivate of requester's dial to destination under the document's first requests rule carries.
func (self *aclTeamWorld) grantActivate(t *testing.T, requester Id, destination Id, approvals map[Id]protocol.ApprovalChannel) *AclStatement {
	t.Helper()
	grant := newAclTestGrant(t, self.world.documentRuleId(t, "request", 0).Bytes(), requester, []string{aclTestDst(destination)}, []string{"dial"}, 0)
	for _, approver := range slices.SortedFunc(maps.Keys(approvals), Id.Cmp) {
		grant.approve(t, approver, approvals[approver], aclTestDecisionNotAfter)
	}
	return &AclStatement{
		Type: bridge.SignedType_SIGNED_GRANT_ACTIVATE, Body: grant.activate(),
		Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: requester}}, N: 100, TimeMs: aclTestNow.UnixMilli(),
	}
}

// Two approvers validate only on Team, and on Team one approver's decision activates nothing while two do.
func TestAclTeamTwoApproversOnTeamAlone(t *testing.T) {
	team := newAclTeamWorld(t, aclTestTeamTwoApprovers)
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("on Team: %v", err)
	}
	pro := aclTestTeamLimits()
	pro.ApproversTwo = false
	validation := &AclValidationError{}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: pro}); !errors.As(err, &validation) ||
		len(validation.Refusals) != 1 || !strings.Contains(validation.Refusals[0].String(), "approvers") {
		t.Fatalf("below Team: %v", err)
	}
	state := team.world.state(t)
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	spend := &aclTestSpendCheck{refused: map[Id]bool{}}
	if _, err := state.CheckStatement(team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.amir: device}), spend); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("one of two approvers: %v", err)
	}
	if _, err := state.CheckStatement(team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.amir: device, team.owner: device}), spend); err != nil {
		t.Errorf("the owner of the destination and an admin: %v", err)
	}
}

// FS-85's worker case at the rule level: under the starting document's directory rule, the destination owner's harness
// decision activates nothing and its device decision does, meeting §8.6's admin clause (owner decision 180).
func TestAclTeamDirectoryRuleRefusesAHarnessDecision(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocument()))
	state := team.world.state(t)
	spend := &aclTestSpendCheck{refused: map[Id]bool{}}
	harness := team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.amir: protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS})
	if _, err := state.CheckStatement(harness, spend); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("a harness decision: %v", err)
	}
	device := team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.amir: protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE})
	if _, err := state.CheckStatement(device, spend); err != nil {
		t.Errorf("the owner's device decision: %v", err)
	}
	other := team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.dana: protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE})
	if _, err := state.CheckStatement(other, spend); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("the requester's own decision: %v", err)
	}
}

// A document publishing in the eng scope and dana's member scope.
const aclTestTeamScopes = `{
  "grants": [
    { "src": ["autogroup:member"], "dst": ["dns:*.eng", "dns:*.dana"], "allow": ["publish"] },
    { "src": ["autogroup:member"], "dst": ["sock:tls/443/*.eng", "sock:smtp/25/mx.eng", "sock:tls/443/*.dana"], "allow": ["listen"] },
  ],
}`

// Scope hosts: validation takes a scope the network's Team scopes hold and no other, nor any with no scopes known;
// *.<scope> covers its own scope's hosts and no other's; and a member scope's host takes its member's consented devices
// alone.
func TestAclTeamScopeHosts(t *testing.T) {
	team := newAclTeamWorld(t, aclTestTeamScopes)
	scopes := map[string]AclScope{"eng": {Label: "eng"}, "dana": {Label: "dana", MemberId: team.dana}}
	resolve := func(label string) (AclScope, bool) {
		scope, found := scopes[label]
		return scope, found
	}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits(), ResolveScope: resolve}); err != nil {
		t.Fatalf("known scopes: %v", err)
	}
	validation := &AclValidationError{}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits()}); !errors.As(err, &validation) || len(validation.Refusals) != 5 {
		t.Errorf("no scopes known: %v", err)
	}
	unknown := newAclTeamWorld(t, `{ "grants": [ { "src": ["autogroup:member"], "dst": ["dns:app.ops", "dns:app.*"], "allow": ["publish"] } ] }`)
	if err := ValidateAclPolicy(&AclValidateInput{Compile: unknown.world.input(), Limits: aclTestTeamLimits(), ResolveScope: resolve}); !errors.As(err, &validation) || len(validation.Refusals) != 2 {
		t.Errorf("an unknown scope and a glob scope: %v", err)
	}

	state := team.world.state(t)
	member := AclSidecarSubject(team.amirDevice)
	for _, c := range []struct {
		host string
		want bool
	}{
		{host: "app.eng", want: true}, {host: "app.ops", want: false}, {host: "eng", want: false}, {host: "app", want: false},
	} {
		if got := state.MayPublish(member, c.host, aclTestNow).Allowed; got != c.want {
			t.Errorf("publish %s: %v", c.host, got)
		}
	}
	for _, c := range []struct {
		name string
		want bool
	}{
		{name: "tls/443/app.eng", want: true}, {name: "tls/443/app.ops", want: false}, {name: "smtp/25/mx.eng", want: true}, {name: "smtp/25/mx.ops", want: false},
	} {
		if got := state.MayListen(member, AclSocketName{PublicName: c.name}, aclTestNow).Allowed; got != c.want {
			t.Errorf("listen %s: %v", c.name, got)
		}
	}
	danaScope := scopes["dana"]
	if decision := state.MayPublishInScope(AclSidecarSubject(team.danaFirst), "app.dana", danaScope, aclTestNow); !decision.Allowed {
		t.Errorf("dana's consented device in her scope: %+v", decision)
	}
	for name, subject := range map[string]Id{"dana's unconsented device": team.danaSecond, "amir's device": team.amirDevice} {
		if decision := state.MayPublishInScope(AclSidecarSubject(subject), "app.dana", danaScope, aclTestNow); decision.Allowed || decision.Reason != AclReasonUnconsented {
			t.Errorf("%s in dana's scope: %+v", name, decision)
		}
	}
	if decision := state.MayListenInScope(AclSidecarSubject(team.amirDevice), AclSocketName{PublicName: "tls/443/app.dana"}, danaScope, aclTestNow); decision.Allowed {
		t.Errorf("amir listening in dana's scope: %+v", decision)
	}
	if decision := state.MayPublishInScope(member, "app.eng", scopes["eng"], aclTestNow); !decision.Allowed {
		t.Errorf("a tag scope's host: %+v", decision)
	}
}

// SCIM's group:<name>@<domain> validates with no groups entry, as SCIM keeps its members (§7.6), and compiles to its
// atom.
func TestAclTeamScimGroup(t *testing.T) {
	team := newAclTeamWorld(t, `{ "grants": [ { "src": ["group:eng@corp.example"], "dst": ["autogroup:self"], "allow": ["dial"] } ] }`)
	atomId := team.world.group("eng@corp.example")
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("a SCIM group: %v", err)
	}
	rows := team.world.compile(t)
	if !slices.ContainsFunc(rows.GetAtoms(), func(atom *protocol.AclAtom) bool {
		return Id(atom.GetAtom()) == atomId && len(atom.GetMemberIds()) == 0
	}) {
		t.Errorf("no atom for the SCIM group")
	}
}
