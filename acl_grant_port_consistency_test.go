//go:build !ios_extension

// The readers of a port-limited activated dial grant read its ports alike, through acl_grant_route.go's dial reader
// (aclGrantDialPortsOf; owner decisions 220 and 804; QD-740, QD-1428): the bridge compile's host dial rows open its
// sealed detail once a compile with its route reading and wait or alarm for a detail that does not open here as the
// route rows do. Each test that accepts fails before this change, but for the guards that say they held before.
// Synthetic values only.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The compile's grant net with the bridge approvers' requests rule taking a member's dial to its own devices beside
// its route, so a dial grant of the laptop's to the desktop activates through the log.
func newTestPortConsistencyNet(t *testing.T) *testBridgeGrantNet {
	net := newTestBridgeGrantNet(t)
	net.foldLedger(net.n, func(rows *protocol.AclRows) {
		for _, request := range rows.GetRequests() {
			if bytes.Equal(request.GetRuleId(), testBridgeRequestRuleId) {
				request.Actions = append(request.Actions, uint32(protocol.AclAction_ACL_ACTION_DIAL))
			}
		}
	})
	return net
}

// A version-4 grant of the laptop's to the desktop asking allow, the desktop by id alone in its clear grant_dst, its
// detail sealed as a daemon seals one (testWithSealedDetail) or by seal where set, ending an hour from the net's time.
func testPortConsistencyGrantAction(net *testBridgeGrantNet, allow []string, detail *protocol.CanonicalActionDetail,
	seal func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail)) []byte {
	action := &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: canonicalActionVersionSealedGrant,
		RuleId: testBridgeRequestRuleId, Subject: net.host.sidecarId.Bytes(),
		GrantDst: []string{aclTestDst(net.peer.sidecarId)}, GrantAllow: allow, ExpiresMillis: net.timeMs + 60*60*1000,
	}
	if seal == nil {
		testWithSealedDetail(action, detail)
	} else {
		seal(action, detail)
	}
	return testConfigMarshal(net.t, action)
}

// A seal of detail for action under another network's context, so it does not open under the key the net's devices
// hold in the net's own network.
func testPortConsistencySealElsewhere(t *testing.T) func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) {
	return func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) {
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
	}
}

// The desktop's compile at the reader's tip, holding generation 3's key where withKey, and the laptop's subject there,
// nil for none.
func testPortConsistencyDesktop(t *testing.T, net *testBridgeGrantNet, withKey bool) (*BridgeCompiled, *bridge.BridgeRuleSubject) {
	t.Helper()
	compiled, rules := testBridgeCompile(t, net.grantViewOf(net.log, withKey), net.localOf(net.peer))
	return compiled, testBridgeCompileSubject(rules, net.host.sidecarId)
}

// The state_unverified alarms a compile raised.
func testPortConsistencyUnverified(compiled *BridgeCompiled) []BridgeAlarm {
	alarms := []BridgeAlarm{}
	for _, alarm := range compiled.Alarms {
		if alarm.Reason == SidecarBridgeAlarmStateUnverified {
			alarms = append(alarms, alarm)
		}
	}
	return alarms
}

// A dial grant sealed to a generation this device does not hold gives the laptop no dial row at the desktop and waits
// for that generation, alarming nothing, as a route grant's detail does; with the key the same compile gives the rows
// its detail names, tcp 22 and udp 53, under its id and expiry, and waits for nothing. Before this change the compile
// gave no row and named no wait, so the component never fetched the key the rows waited on.
func TestCompileWaitsForAnActivatedDialGrantsKeyGeneration(t *testing.T) {
	net := newTestPortConsistencyNet(t)
	desktopDst := aclTestDst(net.peer.sidecarId)
	expiresMs := net.timeMs + 60*60*1000
	grantId := net.activate("dial key", testPortConsistencyGrantAction(net, []string{"dial"}, &protocol.CanonicalActionDetail{
		GrantDst: []string{desktopDst + ":tcp:22", desktopDst + ":udp:53"},
	}, nil))

	compiled, subject := testPortConsistencyDesktop(t, net, false)
	if subject != nil && 0 < len(subject.GetDial()) {
		t.Errorf("with its generation's key not held the grant gave dial rows %v", subject.GetDial())
	}
	wait := BridgeCompileWait{Kind: BridgeCompileWaitGeneration, Generation: testActionDetailGeneration}
	if !slices.Contains(compiled.Waits, wait) {
		t.Errorf("a dial grant's generation not held names no wait: %v", compiled.Waits)
	}
	if alarms := testPortConsistencyUnverified(compiled); len(alarms) != 0 {
		t.Errorf("a generation not held alarmed %v", alarms)
	}

	compiled, subject = testPortConsistencyDesktop(t, net, true)
	want := testBridgeGrantRowsSorted(
		testBridgeGrantRow(grantId, nil, aclIpProtocolTcp, 22, expiresMs), testBridgeGrantRow(grantId, nil, aclIpProtocolUdp, 53, expiresMs),
	)
	if subject == nil || !testBridgeReachRowsAre(subject.GetDial(), want...) {
		t.Fatalf("with the key, the laptop's dial rows at the desktop: %v", subject)
	}
	if len(compiled.Waits) != 0 || len(testPortConsistencyUnverified(compiled)) != 0 {
		t.Errorf("an opened dial grant waited for %v and alarmed %v", compiled.Waits, compiled.Alarms)
	}
}

// A dial grant whose detail does not open under the key held, sealed in another network, gives no dial row and alarms
// state_unverified once, naming the grant and why and no port, as a route grant's does; so does a port-limited dial
// grant whose action the state does not hold, while the same rule limiting no ports, an action sealing no detail, stands
// at every port and alarms nothing. Before this change neither alarmed.
func TestCompileAlarmsForAnActivatedDialGrantWhoseDetailDoesNotOpen(t *testing.T) {
	net := newTestPortConsistencyNet(t)
	desktopDst := aclTestDst(net.peer.sidecarId)
	grantId := net.activate("dial elsewhere", testPortConsistencyGrantAction(net, []string{"dial"}, &protocol.CanonicalActionDetail{
		GrantDst: []string{desktopDst + ":tcp:2222"},
	}, testPortConsistencySealElsewhere(t)))
	compiled, subject := testPortConsistencyDesktop(t, net, true)
	if subject != nil && 0 < len(subject.GetDial()) {
		t.Errorf("a detail that does not open gave dial rows %v", subject.GetDial())
	}
	alarms := testPortConsistencyUnverified(compiled)
	if len(alarms) != 1 {
		t.Fatalf("state_unverified alarms %v, want one", compiled.Alarms)
	}
	if alarm := alarms[0]; alarm.SidecarId != net.host.sidecarId || !strings.Contains(alarm.Detail, "grant "+hex.EncodeToString(grantId)) ||
		!strings.Contains(alarm.Detail, aclGrantRouteUnreadNotOpened.String()) || strings.Contains(alarm.Detail, "2222") {
		t.Errorf("the alarm %+v", alarm)
	}

	// a port-limited dial grant whose action the state does not hold, as rows a base carries name it
	for _, portsLimited := range []bool{true, false} {
		held := newTestPortConsistencyNet(t)
		missingId := sha256.Sum256([]byte("dial grant whose action is not held"))
		view := held.grantViewOf(held.log, true)
		rows := testPortConsistencyRowsWith(t, view.state.aclRows, &protocol.AclRule{
			RuleId:       missingId[:],
			SrcAtoms:     [][]byte{AclDerivedAtom(AclDerivedAtomSidecar, held.host.sidecarId.Bytes()).Bytes()},
			Targets:      []*protocol.AclTarget{{SidecarId: held.peer.sidecarId.Bytes()}},
			Actions:      []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
			PortsLimited: portsLimited,
			Expires:      held.timeMs + 60*60*1000,
			SourceRuleId: testBridgeRequestRuleId,
		}, held.host.sidecarId)
		acl, err := NewAclState(rows, view.state)
		if err != nil {
			t.Fatal(err)
		}
		view.acl = acl
		compiled, rules := testBridgeCompile(t, view, held.localOf(held.peer))
		subject := testBridgeCompileSubject(rules, held.host.sidecarId)
		alarmed := len(testPortConsistencyUnverified(compiled)) != 0
		switch {
		case portsLimited && (!alarmed || (subject != nil && 0 < len(subject.GetDial()))):
			t.Errorf("an action not held: alarmed %t, the laptop %v", alarmed, subject)
		case !portsLimited && (alarmed || subject == nil || !testBridgeReachRowsAre(subject.GetDial(),
			&bridge.BridgeRuleReach{GrantId: missingId[:], Expires: held.timeMs + 60*60*1000})):
			t.Errorf("a rule limiting no ports: alarmed %t, the laptop %v", alarmed, subject)
		}
	}
}

// The rows with rule added, its source sidecar's derived atom beside it.
func testPortConsistencyRowsWith(t *testing.T, base *protocol.AclRows, rule *protocol.AclRule, source Id) *protocol.AclRows {
	t.Helper()
	rows := proto.Clone(base).(*protocol.AclRows)
	sourceAtom := AclDerivedAtom(AclDerivedAtomSidecar, source.Bytes())
	rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: sourceAtom.Bytes(), SidecarIds: [][]byte{source.Bytes()}})
	rows.Rules = append(rows.Rules, rule)
	return rows
}

// A grant allowing dial and route whose detail does not open opens it once a compile, for its dial rows and its route
// rows both, and so alarms once, where the dial rows' own alarm would otherwise give it a second; with its detail open
// it gives the desktop's dial rows at its port and route rows of its prefix, at the same port, a route grant's ports
// being every port its sidecar destinations name. A guard of the shared opening: before this change the dial rows
// alarmed nothing, so this held then too.
func TestCompileOpensAGrantAllowingDialAndRouteOnce(t *testing.T) {
	desktopDetail := func(net *testBridgeGrantNet) *protocol.CanonicalActionDetail {
		return &protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/25"}, GrantDst: []string{aclTestDst(net.peer.sidecarId) + ":tcp:22"}}
	}
	both := []string{"dial", "route"}

	net := newTestPortConsistencyNet(t)
	net.activate("both elsewhere", testPortConsistencyGrantAction(net, both, desktopDetail(net), testPortConsistencySealElsewhere(t)))
	compiled, subject := testPortConsistencyDesktop(t, net, true)
	if alarms := testPortConsistencyUnverified(compiled); len(alarms) != 1 {
		t.Errorf("a grant allowing both alarmed %d times a compile: %v", len(alarms), alarms)
	}
	if subject != nil && 0 < len(subject.GetDial())+len(subject.GetRoute()) {
		t.Errorf("a detail that does not open gave dial rows %v and route rows %v", subject.GetDial(), subject.GetRoute())
	}

	opened := newTestPortConsistencyNet(t)
	expiresMs := opened.timeMs + 60*60*1000
	grantId := opened.activate("both", testPortConsistencyGrantAction(opened, both, desktopDetail(opened), nil))
	compiled, subject = testPortConsistencyDesktop(t, opened, true)
	if subject == nil || !testBridgeReachRowsAre(subject.GetDial(), testBridgeGrantRow(grantId, nil, aclIpProtocolTcp, 22, expiresMs)) {
		t.Fatalf("the laptop's dial rows at the desktop: %v", subject)
	}
	if !testBridgeReachRowsAre(subject.GetRoute(), testBridgeGrantRow(grantId, testBridgePrefix(192, 168, 7, 0, 25), aclIpProtocolTcp, 22, expiresMs)) {
		t.Errorf("the laptop's route rows at the desktop: %v", subject.GetRoute())
	}
	if len(compiled.Waits) != 0 || len(testPortConsistencyUnverified(compiled)) != 0 {
		t.Errorf("an opened grant waited for %v and alarmed %v", compiled.Waits, compiled.Alarms)
	}
}
