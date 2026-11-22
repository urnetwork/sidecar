//go:build !ios_extension

// Activated route grants at the bridge compile (bridge_compile_grants.go; owner decisions 220 and 679, QD-003,
// QD-1164): a route grant activated through the log, its prefixes and ports sealed in its action's detail, gives its
// requester's table an entry of each route in force its prefixes meet, linked to the advertiser, and gives the
// advertiser a route row of the requester's for exactly the parts of what it serves those prefixes cover, at exactly
// the detail's ports, under the grant's id and expiry; a detail naming no port reaches every port; one naming
// 0.0.0.0/0 opens an exit row; a reader that starts at a base after the grant landed compiles the same state; past its
// expiry and after its GrantRevoke the entries and rows are gone; and a detail sealed to a generation this device does
// not hold, one that does not open under the key it holds, one whose target_port names no protocol, and a port-limited
// grant whose action the state does not hold give none, each with its wait or alarm. Synthetic values only.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The compile net where route grants activate: its rows hold a document with no rule of its own, so only an activated
// grant opens a route, and the bridge approvers' requests rule, which takes a member's route grant to its own member's
// devices with that member approving, under the policy spend check; the desktop serves 192.168.7.0/24 and
// 192.168.9.0/24 under real single-use approvals; and the laptop has a binding, so the desktop's compile binds it.
type testBridgeGrantNet struct {
	*testBridgeCompileNet
	t        *testing.T
	inRoute  []byte
	outRoute []byte
}

// The two prefixes the desktop serves: the one the tests' grants name parts of, and one they do not.
func testBridgeGrantPrefixes() (*bridge.BridgeIpv4Prefix, *bridge.BridgeIpv4Prefix) {
	return testBridgePrefix(192, 168, 7, 0, 24), testBridgePrefix(192, 168, 9, 0, 24)
}

func newTestBridgeGrantNet(t *testing.T) *testBridgeGrantNet {
	compileNet := newTestBridgeCompileNet(t)
	compileNet.log.settings.AclSpendCheck = testBridgePolicySpendCheck{}
	compileNet.foldLedger(compileNet.n, func(rows *protocol.AclRows) {
		rows.HasDocument = true
		testBridgeWithApprovers(rows)
	})
	compileNet.bind(compileNet.host, 1)
	net := &testBridgeGrantNet{testBridgeCompileNet: compileNet, t: t}
	inPrefix, outPrefix := testBridgeGrantPrefixes()
	net.inRoute = net.approvedRouteInForce(net.peer, net.member, "grant in", inPrefix)
	net.outRoute = net.approvedRouteInForce(net.peer, net.member, "grant out", outPrefix)
	return net
}

// A version-4 route grant of the laptop's through the desktop under the bridge approvers' requests rule, the desktop by
// id alone in its clear grant_dst and detail sealed as a daemon seals one (testWithSealedDetail, generation 3's key in
// the net's network), ending at expiresMs; seal, when set, seals the detail itself.
func (self *testBridgeGrantNet) routeGrantAction(detail *protocol.CanonicalActionDetail, expiresMs int64,
	seal func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail)) []byte {
	action := &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: canonicalActionVersionSealedGrant,
		RuleId: testBridgeRequestRuleId, Subject: self.host.sidecarId.Bytes(),
		GrantDst: []string{aclTestDst(self.peer.sidecarId)}, GrantAllow: []string{"route"}, ExpiresMillis: expiresMs,
	}
	if seal == nil {
		testWithSealedDetail(action, detail)
	} else {
		seal(action, detail)
	}
	return testConfigMarshal(self.t, action)
}

// Activates the grant whose action is actionBytes through the log, approved by the laptop's member on a device under
// an approval label fixes, so its grant id is the same each run; answers the grant id.
func (self *testBridgeGrantNet) activate(label string, actionBytes []byte) []byte {
	self.t.Helper()
	approvalId := testConfigId("route grant approval " + label)
	grant := &aclTestGrant{
		actionBytes: actionBytes,
		approvalId:  approvalId,
		requestSha:  sha256.Sum256(append([]byte("route grant request "), approvalId[:]...)),
		subject:     self.host.sidecarId,
	}
	grant.approve(self.t, self.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, self.timeMs+testBridgeDayMs)
	activate := grant.activate()
	activate.Header = self.header()
	self.mustPost(self.host, bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate)
	return activate.GetGrantId()
}

// The view of a reader's tip, holding generation 3's key, which the grants' details are sealed under, where withKey.
func (self *testBridgeGrantNet) grantViewOf(log *ConfigLog, withKey bool) *testBridgeCompileView {
	view := self.viewOf(log)
	if withKey {
		view.keys = append(slices.Clone(view.keys), testConfigSealKey(testActionDetailGeneration))
	}
	return view
}

// The laptop's entry of a prefix and the laptop's route and exit rows at the desktop, compiled at the reader's tip.
func (self *testBridgeGrantNet) compileGrant(log *ConfigLog, withKey bool, prefix *bridge.BridgeIpv4Prefix) (*BridgeCompiled, *bridge.BridgeRuleEntry, *BridgeCompiled, *bridge.BridgeRuleSubject) {
	self.t.Helper()
	compiled, rules := testBridgeCompile(self.t, self.grantViewOf(log, withKey), self.local())
	desktopCompiled, desktopRules := testBridgeCompile(self.t, self.grantViewOf(log, withKey), self.localOf(self.peer))
	return compiled, testBridgeCompileEntry(rules, prefix), desktopCompiled, testBridgeCompileSubject(desktopRules, self.host.sidecarId)
}

// Whether an entry is the desktop's route's, linked to the desktop alone.
func (self *testBridgeGrantNet) linkedToDesktop(entry *bridge.BridgeRuleEntry, routeId []byte) bool {
	return entry != nil && entry.GetKind() == bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK && len(entry.GetLinks()) == 1 &&
		Id(entry.GetLinks()[0].GetTargetSidecarId()) == self.peer.sidecarId && bytes.Equal(entry.GetLinks()[0].GetRuleId(), routeId)
}

// One route row under a grant.
func testBridgeGrantRow(grantId []byte, prefix *bridge.BridgeIpv4Prefix, ipProtocol uint32, port uint32, expiresMs int64) *bridge.BridgeRuleReach {
	row := &bridge.BridgeRuleReach{GrantId: grantId, Prefix: prefix, Protocol: ipProtocol, Expires: expiresMs}
	if port != 0 {
		row.Ports = []*bridge.BridgePortRange{{First: port, Last: port}}
	}
	return row
}

// The rows in 12.2.4's order.
func testBridgeGrantRowsSorted(rows ...*bridge.BridgeRuleReach) []*bridge.BridgeRuleReach {
	slices.SortStableFunc(rows, bridgeCompileReachCompare)
	return rows
}

// A grant naming 192.168.7.0/25 by cidr and 192.168.7.128/26 by ip: destination, at the desktop's tcp 22 and udp 53,
// gives the laptop an entry of 192.168.7.0/24 linked to the desktop and none of 192.168.9.0/24, which its prefixes do
// not meet, and gives the desktop exactly four route rows of the laptop's, each of its parts at each of its ports
// under its id and expiry, with no dial or exit row. A second grant naming 192.168.9.0/24 and no port gives that
// route's entry and one row of every protocol. The grant was opened once a compile, and nothing alarmed or waited.
func TestCompileAnActivatedRouteGrantGivesItsEntriesAndRowsByItsDetail(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	inPrefix, outPrefix := testBridgeGrantPrefixes()
	expiresMs := net.timeMs + 60*60*1000
	desktopDst := aclTestDst(net.peer.sidecarId)
	grantId := net.activate("ported", net.routeGrantAction(&protocol.CanonicalActionDetail{
		Cidrs:    []string{"192.168.7.0/25"},
		GrantDst: []string{"ip:192.168.7.128/26", desktopDst + ":tcp:22", desktopDst + ":udp:53"},
	}, expiresMs, nil))

	compiled, entry, desktopCompiled, subject := net.compileGrant(net.log, true, inPrefix)
	if !net.linkedToDesktop(entry, net.inRoute) {
		t.Fatalf("the laptop's entry of the desktop's route: %v", entry)
	}
	_, rules := testBridgeCompile(t, net.grantViewOf(net.log, true), net.local())
	if testBridgeCompileEntry(rules, outPrefix) != nil {
		t.Error("the laptop's table holds a route the grant's prefixes do not meet")
	}
	if subject == nil {
		t.Fatal("the desktop binds the laptop as no subject")
	}
	low, high := testBridgePrefix(192, 168, 7, 0, 25), testBridgePrefix(192, 168, 7, 128, 26)
	want := testBridgeGrantRowsSorted(
		testBridgeGrantRow(grantId, low, aclIpProtocolTcp, 22, expiresMs), testBridgeGrantRow(grantId, low, aclIpProtocolUdp, 53, expiresMs),
		testBridgeGrantRow(grantId, high, aclIpProtocolTcp, 22, expiresMs), testBridgeGrantRow(grantId, high, aclIpProtocolUdp, 53, expiresMs),
	)
	if !testBridgeReachRowsAre(subject.GetRoute(), want...) {
		t.Errorf("the laptop's route rows at the desktop: %v", subject.GetRoute())
	}
	if len(subject.GetDial())+len(subject.GetExit()) != 0 {
		t.Errorf("a route grant gave dial rows %v and exit rows %v", subject.GetDial(), subject.GetExit())
	}
	for _, each := range []*BridgeCompiled{compiled, desktopCompiled} {
		if len(each.Alarms) != 0 || len(each.Waits) != 0 {
			t.Errorf("an opened grant alarmed %v and waited for %v", each.Alarms, each.Waits)
		}
	}

	// a second grant, naming the other route whole and no port, reaches it at every port
	everyId := net.activate("every port", net.routeGrantAction(&protocol.CanonicalActionDetail{
		GrantDst: []string{"ip:192.168.9.0/24"},
	}, expiresMs, nil))
	_, outEntry, _, subject := net.compileGrant(net.log, true, outPrefix)
	if !net.linkedToDesktop(outEntry, net.outRoute) {
		t.Fatalf("the laptop's entry of the route the second grant names: %v", outEntry)
	}
	want = testBridgeGrantRowsSorted(append(want, testBridgeGrantRow(everyId, outPrefix, 0, 0, expiresMs))...)
	if subject == nil || !testBridgeReachRowsAre(subject.GetRoute(), want...) {
		t.Errorf("the laptop's route rows with both grants: %v", subject.GetRoute())
	}
}

// A grant whose detail names 0.0.0.0/0 reaches public destinations through the desktop, which serves an approved exit:
// the desktop gives the laptop an exit row under it, and a route row of each prefix it serves whole, as a document rule
// of 0.0.0.0/0 gives; a grant of a private prefix alone gives no exit row.
func TestCompileAnActivatedRouteGrantOfEveryAddressOpensAnExitRow(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	inPrefix, outPrefix := testBridgeGrantPrefixes()
	net.approvedRouteInForce(net.peer, net.member, "grant exit", nil)
	expiresMs := net.timeMs + 60*60*1000
	privateId := net.activate("private", net.routeGrantAction(&protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/24"}}, expiresMs, nil))
	_, _, _, subject := net.compileGrant(net.log, true, inPrefix)
	if subject == nil || len(subject.GetExit()) != 0 {
		t.Fatalf("a grant of a private prefix at the desktop: %v", subject)
	}
	everyId := net.activate("every address", net.routeGrantAction(&protocol.CanonicalActionDetail{Cidrs: []string{"0.0.0.0/0"}}, expiresMs, nil))
	_, _, _, subject = net.compileGrant(net.log, true, inPrefix)
	if subject == nil || !testBridgeReachRowsAre(subject.GetExit(), testBridgeGrantRow(everyId, nil, 0, 0, expiresMs)) {
		t.Fatalf("the laptop's exit rows under a grant of every address: %v", subject)
	}
	want := testBridgeGrantRowsSorted(
		testBridgeGrantRow(privateId, inPrefix, 0, 0, expiresMs),
		testBridgeGrantRow(everyId, inPrefix, 0, 0, expiresMs), testBridgeGrantRow(everyId, outPrefix, 0, 0, expiresMs),
	)
	if !testBridgeReachRowsAre(subject.GetRoute(), want...) {
		t.Errorf("the laptop's route rows under both grants: %v", subject.GetRoute())
	}
}

// A reader that starts at a base folded past the activation holds no action of its own and recovers it from the base's
// head (ConfigState.grantActionsAtHead), so it compiles the same state as the reader present since the bootstrap, for
// the laptop and for the desktop alike.
func TestCompileAnActivatedRouteGrantAtAReaderStartedAtABase(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	inPrefix, _ := testBridgeGrantPrefixes()
	net.activate("restored", net.routeGrantAction(&protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/25"}}, net.timeMs+60*60*1000, nil))
	tip := net.n
	if reached := net.foldLedger(tip, nil); reached != tip {
		t.Fatalf("the base folded through %d, want %d", reached, tip)
	}
	restored := net.restoredReader()
	if 0 < len(restored.State().grantActions) {
		t.Fatal("the restored reader holds the grant's action of its own: the head's recovery is not what this tests")
	}
	for _, local := range []*BridgeCompileLocal{net.local(), net.localOf(net.peer)} {
		present, _ := testBridgeCompile(t, net.grantViewOf(net.log, true), local)
		cold, rules := testBridgeCompile(t, net.grantViewOf(restored, true), local)
		if cold.Digest != present.Digest {
			t.Errorf("compiling for %s, the reader started at the base compiled another state", local.SidecarId)
		}
		if local.SidecarId == net.host.sidecarId && !net.linkedToDesktop(testBridgeCompileEntry(rules, inPrefix), net.inRoute) {
			t.Error("the reader started at the base gives the laptop no entry of the grant's route")
		}
	}
}

// Past its expiry and after its GrantRevoke a grant's entry and rows are gone at the next compile: a grant ending at
// expiresMs stands at a state one millisecond before it and is gone at a state at it, where the laptop is no subject
// at the desktop at all, and a grant its subject revokes is gone at the state after the revoke, the state no longer
// holding its action.
func TestCompileDropsAnActivatedRouteGrantAtItsExpiryAndRevoke(t *testing.T) {
	inPrefix, _ := testBridgeGrantPrefixes()
	stands := func(net *testBridgeGrantNet) bool {
		t.Helper()
		_, entry, _, subject := net.compileGrant(net.log, true, inPrefix)
		entered, rowed := entry != nil, subject != nil && 0 < len(subject.GetRoute())
		if entered != rowed {
			t.Fatalf("the laptop's entry %t beside its route rows %t", entered, rowed)
		}
		if entered && !net.linkedToDesktop(entry, net.inRoute) {
			t.Fatalf("the laptop's entry: %v", entry)
		}
		return entered
	}

	expiring := newTestBridgeGrantNet(t)
	expiresMs := expiring.timeMs + 60*60*1000
	expiring.activate("expiring", expiring.routeGrantAction(&protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/25"}}, expiresMs, nil))
	if !stands(expiring) {
		t.Fatal("the grant does not stand before its expiry")
	}
	// each tick lands a second past the net's time
	expiring.timeMs = expiresMs - 1 - 1000
	expiring.tick(&bridge.ApiTick{})
	if expiring.log.State().TimeMs() != expiresMs-1 || !stands(expiring) {
		t.Fatalf("at %d, a millisecond before its expiry, the grant does not stand", expiring.log.State().TimeMs())
	}
	expiring.timeMs = expiresMs - 1000
	expiring.tick(&bridge.ApiTick{})
	if stands(expiring) {
		t.Errorf("at %d, its expiry, the grant stands", expiring.log.State().TimeMs())
	}
	if _, _, _, subject := expiring.compileGrant(expiring.log, true, inPrefix); subject != nil {
		t.Errorf("past its only grant's expiry the laptop is a subject at the desktop: %v", subject)
	}

	revoked := newTestBridgeGrantNet(t)
	grantId := revoked.activate("revoked", revoked.routeGrantAction(&protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/25"}}, revoked.timeMs+60*60*1000, nil))
	if !stands(revoked) {
		t.Fatal("the grant does not stand before its revoke")
	}
	revoked.mustPost(revoked.host, bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{Header: revoked.header(), GrantId: grantId})
	if stands(revoked) {
		t.Error("the grant stands after its GrantRevoke")
	}
	if _, held := revoked.log.State().grantActions[string(grantId)]; held {
		t.Error("the state keeps the revoked grant's action")
	}
}

// A grant whose detail does not open here gives no entry and no row, the closed direction, and says why: sealed to a
// generation this device does not hold, it waits for that generation and alarms nothing, and the same compile with the
// key gives both; sealed under another network's context, so it does not open under the key held, and naming a
// target_port with no protocol, it alarms state_unverified naming the grant and no prefix or port.
func TestCompileGivesNothingForAnActivatedRouteGrantWhoseDetailDoesNotOpen(t *testing.T) {
	inPrefix, _ := testBridgeGrantPrefixes()
	// a generation not held
	net := newTestBridgeGrantNet(t)
	net.activate("unkeyed", net.routeGrantAction(&protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/25"}}, net.timeMs+60*60*1000, nil))
	compiled, entry, desktopCompiled, subject := net.compileGrant(net.log, false, inPrefix)
	if entry != nil || (subject != nil && 0 < len(subject.GetRoute())) {
		t.Errorf("with its generation's key not held the grant gave an entry %v and rows %v", entry, subject)
	}
	wait := BridgeCompileWait{Kind: BridgeCompileWaitGeneration, Generation: testActionDetailGeneration}
	for _, each := range []*BridgeCompiled{compiled, desktopCompiled} {
		if !slices.Contains(each.Waits, wait) || testBridgeCompileAlarmed(each, SidecarBridgeAlarmStateUnverified) {
			t.Errorf("a generation not held waits for %v and alarms %v", each.Waits, each.Alarms)
		}
	}
	if _, entry, _, subject := net.compileGrant(net.log, true, inPrefix); entry == nil || subject == nil || len(subject.GetRoute()) == 0 {
		t.Errorf("with the key the grant gives an entry %v and rows %v", entry, subject)
	}

	for _, c := range []struct {
		name   string
		detail *protocol.CanonicalActionDetail
		seal   func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail)
		why    string
	}{
		{
			name: "sealed in another network", detail: &protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/25"}}, why: "does not open here",
			seal: func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) {
				clearBytes, err := canonicalActionClearBytes(action)
				if err != nil {
					t.Fatal(err)
				}
				sealContext, err := CanonicalActionDetailSealContext(testConfigId("another network"), clearBytes)
				if err != nil {
					t.Fatal(err)
				}
				if action.SealedDetail, err = SealConfigBody(testConfigSealKey(testActionDetailGeneration), sealContext, detail, testActionDetailRandom()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{name: "a port with no protocol", detail: &protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/25"}, TargetPort: 22}, why: "names a port with no protocol"},
	} {
		net := newTestBridgeGrantNet(t)
		grantId := net.activate(c.name, net.routeGrantAction(c.detail, net.timeMs+60*60*1000, c.seal))
		compiled, entry, desktopCompiled, subject := net.compileGrant(net.log, true, inPrefix)
		if entry != nil || (subject != nil && 0 < len(subject.GetRoute())) {
			t.Errorf("%s: the grant gave an entry %v and rows %v", c.name, entry, subject)
		}
		for _, each := range []*BridgeCompiled{compiled, desktopCompiled} {
			index := slices.IndexFunc(each.Alarms, func(alarm BridgeAlarm) bool { return alarm.Reason == SidecarBridgeAlarmStateUnverified })
			if index < 0 {
				t.Errorf("%s: no state_unverified alarm: %v", c.name, each.Alarms)
				continue
			}
			alarm := each.Alarms[index]
			if alarm.SidecarId != net.host.sidecarId || !strings.Contains(alarm.Detail, "grant "+hex.EncodeToString(grantId)) || !strings.Contains(alarm.Detail, c.why) ||
				strings.Contains(alarm.Detail, "192.168") {
				t.Errorf("%s: the alarm %+v", c.name, alarm)
			}
			if slices.ContainsFunc(each.Alarms[index+1:], func(alarm BridgeAlarm) bool { return alarm.Reason == SidecarBridgeAlarmStateUnverified }) {
				t.Errorf("%s: the grant alarmed more than once a compile: %v", c.name, each.Alarms)
			}
		}
	}
}

// The desktop's compiled states under a route grant of the laptop's crosses into the external test, as
// ForwardProviderFixture does, so the root keeps its device-independent build: the state while the grant stands and
// after its GrantRevoke, at a clock standing at each state's time, the flows the grant's detail admits and those it
// does not.
type RouteGrantHostFixture struct {
	Granted, Revoked           *bridge.BridgeState
	GrantedClock, RevokedClock Clock
	NetworkId, SubjectId       Id
	HostId                     Id
	Admitted, Refused          []RouteGrantFlow
}

// One flow of the laptop's to a destination behind the desktop.
type RouteGrantFlow struct {
	// The IP protocol number.
	Protocol uint32
	To       netip.AddrPort
}

// Compiles RouteGrantHostFixture's states: a grant naming 192.168.7.0/25 at the desktop's tcp 22, under which the
// desktop serves 192.168.7.0/24 and 192.168.9.0/24.
func CompileActivatedRouteGrantHost(t *testing.T) RouteGrantHostFixture {
	net := newTestBridgeGrantNet(t)
	grantId := net.activate("host", net.routeGrantAction(&protocol.CanonicalActionDetail{
		Cidrs: []string{"192.168.7.0/25"}, GrantDst: []string{aclTestDst(net.peer.sidecarId) + ":tcp:22"},
	}, net.timeMs+60*60*1000, nil))
	flow := func(ipProtocol uint32, to string) RouteGrantFlow {
		return RouteGrantFlow{Protocol: ipProtocol, To: netip.MustParseAddrPort(to)}
	}
	fixture := RouteGrantHostFixture{
		NetworkId: net.networkId, SubjectId: net.host.sidecarId, HostId: net.peer.sidecarId,
		Admitted: []RouteGrantFlow{flow(aclIpProtocolTcp, "192.168.7.10:22"), flow(aclIpProtocolTcp, "192.168.7.127:22")},
		Refused: []RouteGrantFlow{
			// another port, another protocol, the served route's part the grant does not name, and another route
			flow(aclIpProtocolTcp, "192.168.7.10:23"), flow(aclIpProtocolUdp, "192.168.7.10:22"),
			flow(aclIpProtocolTcp, "192.168.7.130:22"), flow(aclIpProtocolTcp, "192.168.9.10:22"),
		},
	}
	compiled, _ := testBridgeCompile(t, net.grantViewOf(net.log, true), net.localOf(net.peer))
	fixture.Granted, fixture.GrantedClock = compiled.State, &identityTestClock{current: time.UnixMilli(net.log.State().TimeMs())}
	net.mustPost(net.host, bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{Header: net.header(), GrantId: grantId})
	compiled, _ = testBridgeCompile(t, net.grantViewOf(net.log, true), net.localOf(net.peer))
	fixture.Revoked, fixture.RevokedClock = compiled.State, &identityTestClock{current: time.UnixMilli(net.log.State().TimeMs())}
	return fixture
}

// A port-limited activated grant whose action the state does not hold, as rows a base carries name it and no head's
// folds hold it, gives no entry and no row and alarms state_unverified; the same row limiting no ports, an action
// that seals no detail, stays closed alarming nothing (QD-003).
func TestCompileGivesNothingForAnActivatedRouteGrantWhoseActionIsNotHeld(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	inPrefix, _ := testBridgeGrantPrefixes()
	grantId := sha256.Sum256([]byte("route grant whose action is not held"))
	for _, portsLimited := range []bool{true, false} {
		view := net.grantViewOf(net.log, true)
		rows := proto.Clone(view.state.aclRows).(*protocol.AclRows)
		hostAtom := AclDerivedAtom(AclDerivedAtomSidecar, net.host.sidecarId.Bytes())
		rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: hostAtom.Bytes(), SidecarIds: [][]byte{net.host.sidecarId.Bytes()}})
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:       grantId[:],
			SrcAtoms:     [][]byte{hostAtom.Bytes()},
			Targets:      []*protocol.AclTarget{{SidecarId: net.peer.sidecarId.Bytes()}},
			Via:          []*protocol.AclTarget{{SidecarId: net.peer.sidecarId.Bytes()}},
			Actions:      []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
			PortsLimited: portsLimited,
			Expires:      net.timeMs + 60*60*1000,
			SourceRuleId: testBridgeRequestRuleId,
		})
		acl, err := NewAclState(rows, view.state)
		if err != nil {
			t.Fatal(err)
		}
		if reach := acl.RouteRules(AclSidecarSubject(net.host.sidecarId), AclSidecarSubject(net.peer.sidecarId), time.UnixMilli(net.log.State().TimeMs())); len(reach) != 1 {
			t.Fatalf("ports limited %t: the grant does not stand at the policy: %+v", portsLimited, reach)
		}
		view.acl = acl
		compiled, rules := testBridgeCompile(t, view, net.local())
		if testBridgeCompileEntry(rules, inPrefix) != nil {
			t.Errorf("ports limited %t: the laptop's table holds the grant's route", portsLimited)
		}
		desktopView := net.grantViewOf(net.log, true)
		desktopView.acl = acl
		_, desktopRules := testBridgeCompile(t, desktopView, net.localOf(net.peer))
		if subject := testBridgeCompileSubject(desktopRules, net.host.sidecarId); subject == nil || len(subject.GetRoute()) != 0 {
			t.Errorf("ports limited %t: the laptop at the desktop: %v", portsLimited, subject)
		}
		if alarmed := testBridgeCompileAlarmed(compiled, SidecarBridgeAlarmStateUnverified); alarmed != portsLimited {
			t.Errorf("ports limited %t: alarmed %t: %v", portsLimited, alarmed, compiled.Alarms)
		}
	}
}
