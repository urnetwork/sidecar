// The bridge compiler on the test network (bridge_compile.go, bridge_compile_rows.go; DESIGN-DETAILS 12.6's compiler
// row): §8.5's no-document rows, a route in force only while a standing grant covers it, autogroup:untagged's rows, a map
// onto the daemon or the overlay void here, a name the zone publishes omitted, a withdrawn route draining, the waits
// named, the block kept on a refusal, a ledger file that fails its hash or bodies past their budget refusing the compile,
// each ledger file read once, equal bytes across runs, GOMAXPROCS and a daemon's and a restored reader's views, and the
// golden states testdata/bridge/compile/ holds, which bridge_compile_parse_test.go hands the device role's parser.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The compile fixture: a ledger net whose host S is a member's laptop, beside that member's desktop, another member's
// laptop and the owner's device, all untagged; a block of 100.80.0.0/16 in every head the view reads; an address for
// each but the owner's device; and a binding for every peer.
type testBridgeCompileNet struct {
	*testBridgeLedgerNet
	member Id
	host   testConfigDevice
	peer   testConfigDevice
	other  testConfigDevice
	// the signed BridgeBlock every head the view reads carries, nil for none
	blockFile []byte
	// the names file every head the view reads carries, nil for none
	namesFile []byte
	bindings  *BridgeBindingCache
}

// The fixture's block.
func testBridgeCompileBlock() *bridge.BridgeBlock {
	return &bridge.BridgeBlock{Ipv4Prefix: testBridgePrefix(100, 80, 0, 0, 16)}
}

// A client id of a device's, its generation-th.
func testBridgeCompileClientId(device testConfigDevice, generation int64) Id {
	digest := sha256.Sum256(append([]byte(fmt.Sprintf("bridge compile client %d ", generation)), device.sidecarId.Bytes()...))
	return Id(digest[:len(Id{})])
}

func newTestBridgeCompileNet(t testing.TB) *testBridgeCompileNet {
	ledgerNet := newTestBridgeLedgerNet(t)
	member, laptop, desktop := testBridgeCast(ledgerNet.testConfigNet)
	_, other := ledgerNet.consentedMember("other")
	self := &testBridgeCompileNet{
		testBridgeLedgerNet: ledgerNet,
		member:              member,
		host:                laptop,
		peer:                desktop,
		other:               other,
		bindings:            NewBridgeBindingCache(7*24*time.Hour, 16),
	}
	self.blockFile = self.sign(self.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testBridgeCompileBlock())
	claims := []struct {
		device testConfigDevice
		ipv4   uint32
	}{
		{device: laptop, ipv4: testBridgeIpv4(100, 80, 3, 7)},
		{device: desktop, ipv4: testBridgeIpv4(100, 80, 3, 9)},
		{device: other, ipv4: testBridgeIpv4(100, 80, 4, 10)},
	}
	for _, claim := range claims {
		self.mustPost(claim.device, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, self.bridgeAddress(claim.device, claim.ipv4))
	}
	for _, device := range []testConfigDevice{desktop, other, self.owner} {
		self.bind(device, 1)
	}
	return self
}

// Records a device's generation-th client as its current binding.
func (self *testBridgeCompileNet) bind(device testConfigDevice, generation int64) {
	clientId := testBridgeCompileClientId(device, generation)
	self.bindings.Record(&BridgeBinding{
		SidecarId: device.sidecarId, ClientId: clientId, ClientPublicKey: clientId.Bytes(), IdentityPublicKey: device.publicKey(),
		Generation: generation, Signed: clientId.Bytes(),
	}, time.UnixMilli(testConfigStartMs))
}

// A view over a reader's tip, counting the ledger files the compile opens. Acl and AclLocal stand in for a head's
// policy where a test sets them.
type testBridgeCompileView struct {
	state    *ConfigState
	acl      *AclState
	aclLocal *AclLocalPolicy
	head     *ConfigHead
	rows     BridgeLedgerRows
	keys     []*EvsRepoKey
	// LedgerFile's calls by path
	opened map[string]int
}

func (self *testBridgeCompileView) State() *ConfigState       { return self.state }
func (self *testBridgeCompileView) Acl() *AclState            { return self.acl }
func (self *testBridgeCompileView) AclLocal() *AclLocalPolicy { return self.aclLocal }
func (self *testBridgeCompileView) Head() *ConfigHead         { return self.head }

func (self *testBridgeCompileView) LedgerFile(path string) (BridgeLedgerFileReader, error) {
	self.opened[path] += 1
	if self.rows == nil {
		return nil, nil
	}
	return self.rows.LedgerFile(path)
}

func (self *testBridgeCompileView) RepoKeyAt(generation uint64) *EvsRepoKey {
	return testConfigSealKeyAt(self.keys...)(generation)
}

// The view of a reader's tip: its state and acl, and the head its newest base names with the fixture's block and names.
func (self *testBridgeCompileNet) viewOf(log *ConfigLog) *testBridgeCompileView {
	self.t.Helper()
	state := log.State()
	acl, err := state.Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	head := self.heads[state.Base().GetConfigVersion()]
	if head == nil {
		self.t.Fatalf("no head at version %d", state.Base().GetConfigVersion())
	}
	if self.blockFile != nil {
		if head, err = head.WithFile(ConfigHeadBridgeBlockPath, self.blockFile); err != nil {
			self.t.Fatal(err)
		}
	}
	if self.namesFile != nil {
		if head, err = head.WithFile(ConfigHeadNamesPath, self.namesFile); err != nil {
			self.t.Fatal(err)
		}
	}
	rows, err := NewBridgeLedgerHeadRows(head, self.settings)
	if err != nil {
		self.t.Fatal(err)
	}
	return &testBridgeCompileView{state: state, acl: acl, head: head, rows: rows, keys: self.keys, opened: map[string]int{}}
}

// The view of the reader under test.
func (self *testBridgeCompileNet) view() *testBridgeCompileView {
	return self.viewOf(self.log)
}

// The host's local facts at the fixture's bindings.
func (self *testBridgeCompileNet) local() *BridgeCompileLocal {
	return &BridgeCompileLocal{
		SidecarId:       self.host.sidecarId,
		DaemonListeners: []string{"127.0.0.1:17000", "[::1]:17001"},
		Bindings:        self.bindings.Snapshot(),
		NameZones:       []string{"Net.Ur.Example.", "net.ur.example"},
	}
}

// Compiles, failing the test on an error or a digest that is not the state's, and answers the output and its rules.
func testBridgeCompile(t testing.TB, view BridgeConfigView, local *BridgeCompileLocal) (*BridgeCompiled, *bridge.BridgeRules) {
	t.Helper()
	compiled, err := CompileBridgeState(view, local, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := BridgeStateDigest(compiled.State)
	if err != nil || digest != compiled.Digest {
		t.Fatalf("the digest is not the state's: %v", err)
	}
	rules := &bridge.BridgeRules{}
	if err := proto.Unmarshal(compiled.State.GetRules(), rules); err != nil {
		t.Fatal(err)
	}
	return compiled, rules
}

// The entry at a prefix, nil for none.
func testBridgeCompileEntry(rules *bridge.BridgeRules, prefix *bridge.BridgeIpv4Prefix) *bridge.BridgeRuleEntry {
	for _, entry := range rules.GetEntries() {
		if proto.Equal(entry.GetPrefix(), prefix) {
			return entry
		}
	}
	return nil
}

// The subject of a sidecar, nil for none.
func testBridgeCompileSubject(rules *bridge.BridgeRules, sidecarId Id) *bridge.BridgeRuleSubject {
	for _, subject := range rules.GetSubjects() {
		if Id(subject.GetSidecarId()) == sidecarId {
			return subject
		}
	}
	return nil
}

// Whether the compile raised an alarm for a reason.
func testBridgeCompileAlarmed(compiled *BridgeCompiled, reason SidecarBridgeAlarm) bool {
	return slices.ContainsFunc(compiled.Alarms, func(alarm BridgeAlarm) bool { return alarm.Reason == reason })
}

// A standing subnet route of a device, named by label, for the route rules ruleIds.
func (self *testBridgeCompileNet) standingRoute(device testConfigDevice, label string, prefix *bridge.BridgeIpv4Prefix, ruleIds ...[]byte) []byte {
	self.t.Helper()
	ruleId := testBridgeRuleId(label)
	body := testBridgeSubnet(prefix, label+" site")
	route := self.bridgeRoute(device, ruleId, body)
	route.RouteRuleIds = ruleIds
	self.mustPost(device, bridge.SignedType_SIGNED_BRIDGE_ROUTE, route)
	return ruleId
}

// §8.5 with no document: every untagged sidecar reaches S with no rows, which rule 4 passes, and S reaches every one,
// so the table holds a /32 link for each addressed peer and none for the owner's unaddressed device; every subject
// carries its member and current client, and its identity; the block's own entries come first; S's address is its own.
func TestCompileWithNoDocumentLinksEveryAddressedPeer(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	compiled, rules := testBridgeCompile(t, net.view(), net.local())
	state := compiled.State
	if state.GetHasDocument() || !proto.Equal(state.GetAuth(), net.log.State().Pin()) || len(compiled.Waits) != 0 || len(compiled.Alarms) != 0 {
		t.Fatalf("has_document %t, auth %v, waits %v, alarms %v", state.GetHasDocument(), state.GetAuth(), compiled.Waits, compiled.Alarms)
	}
	if !proto.Equal(rules.GetBlock(), testBridgePrefix(100, 80, 0, 0, 16)) || !slices.Equal(rules.GetAddresses(), []uint32{testBridgeIpv4(100, 80, 3, 7)}) {
		t.Fatalf("block %v, addresses %v", rules.GetBlock(), rules.GetAddresses())
	}
	kinds := []bridge.BridgeRuleEntryKind{}
	for _, entry := range rules.GetEntries() {
		kinds = append(kinds, entry.GetKind())
	}
	link, unassigned, service := bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK, bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNASSIGNED, bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE
	if !slices.Equal(kinds, []bridge.BridgeRuleEntryKind{unassigned, service, link, link}) {
		t.Fatalf("entry kinds %v", kinds)
	}
	for _, peer := range []struct {
		device  testConfigDevice
		address *bridge.BridgeIpv4Prefix
	}{
		{device: net.peer, address: testBridgePrefix(100, 80, 3, 9, 32)},
		{device: net.other, address: testBridgePrefix(100, 80, 4, 10, 32)},
	} {
		entry := testBridgeCompileEntry(rules, peer.address)
		if entry == nil || len(entry.GetLinks()) != 1 {
			t.Fatalf("the entry of %v: %v", peer.address, entry)
		}
		got := entry.GetLinks()[0]
		if Id(got.GetTargetSidecarId()) != peer.device.sidecarId || Id(got.GetTargetClientId()) != testBridgeCompileClientId(peer.device, 1) ||
			!bytes.Equal(got.GetTargetIdentityPublicKey(), peer.device.publicKey()) || Id(got.GetTargetMemberId()) != peer.device.memberId ||
			got.GetWeight() != 1 || len(got.GetRuleId()) != 0 {
			t.Errorf("the link of %v: %v", peer.address, got)
		}
	}
	if len(rules.GetSubjects()) != 3 || len(state.GetIdentities()) != 3 {
		t.Fatalf("%d subjects and %d identities", len(rules.GetSubjects()), len(state.GetIdentities()))
	}
	for i, subject := range rules.GetSubjects() {
		if 0 < i && bytes.Compare(rules.GetSubjects()[i-1].GetSidecarId(), subject.GetSidecarId()) >= 0 {
			t.Error("subjects out of sidecar_id order")
		}
		if subject.GetTagged() || len(subject.GetDial())+len(subject.GetRoute())+len(subject.GetExit()) != 0 || len(subject.GetClientIds()) != 1 {
			t.Errorf("subject %x: %v", subject.GetSidecarId(), subject)
		}
		identity := state.GetIdentities()[i]
		if !bytes.Equal(identity.GetSidecarId(), subject.GetSidecarId()) || len(identity.GetIdentityPublicKey()) != 32 || identity.GetRevoked() {
			t.Errorf("identity %d: %v", i, identity)
		}
	}
	if subject := testBridgeCompileSubject(rules, net.owner.sidecarId); subject == nil || Id(subject.GetMemberId()) != net.ownerMemberId {
		t.Errorf("the owner's device as a subject: %v", subject)
	}
	if testBridgeCompileSubject(rules, net.host.sidecarId) != nil {
		t.Error("S is a subject of its own")
	}
	if rules.GetEgress().GetMode() != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO || rules.GetUntagged() != nil {
		t.Errorf("egress %v, untagged %v", rules.GetEgress(), rules.GetUntagged())
	}
	if !slices.Equal(state.GetDaemonListeners(), net.local().DaemonListeners) || !slices.Equal(state.GetNameZones(), []string{"net.ur.example"}) {
		t.Errorf("listeners %v, zones %v", state.GetDaemonListeners(), state.GetNameZones())
	}
	if !slices.Equal(compiled.LinkTargets, slices.SortedFunc(slices.Values([]Id{net.peer.sidecarId, net.other.sidecarId}), Id.Cmp)) {
		t.Errorf("link targets %v", compiled.LinkTargets)
	}
	if !proto.Equal(compiled.Block, testBridgeCompileBlock()) {
		t.Errorf("the block in force %v", compiled.Block)
	}
}

// 12.5's missing binding and pending body: a peer with no binding keeps its /32 entry with no link, so its range
// rejects rather than falls to the default route, and its subject has no client; a route sealed to a generation not
// held is pending, compiles nothing, and is waited for; both are named in Waits, in order.
func TestCompileNamesWhatItWaitsFor(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	net.bindings.Forget(net.other.sidecarId)
	ruleId := testBridgeRuleId("pending")
	net.mustPost(net.peer, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(net.peer, ruleId, testBridgeSubnet(testBridgePrefix(192, 0, 2, 0, 24), "lab"), 2))
	compiled, rules := testBridgeCompile(t, net.view(), net.local())
	want := []BridgeCompileWait{
		{Kind: BridgeCompileWaitBinding, SidecarId: net.other.sidecarId},
		{Kind: BridgeCompileWaitGeneration, Generation: 2},
	}
	if !slices.Equal(compiled.Waits, want) {
		t.Fatalf("waits %v, want %v", compiled.Waits, want)
	}
	if entry := testBridgeCompileEntry(rules, testBridgePrefix(100, 80, 4, 10, 32)); entry == nil || len(entry.GetLinks()) != 0 {
		t.Errorf("the unbound peer's entry: %v", entry)
	}
	if subject := testBridgeCompileSubject(rules, net.other.sidecarId); subject == nil || len(subject.GetClientIds()) != 0 {
		t.Errorf("the unbound peer's subject: %v", subject)
	}
	if testBridgeCompileEntry(rules, testBridgePrefix(192, 0, 2, 0, 24)) != nil {
		t.Error("a pending route compiled")
	}
	if slices.Contains(compiled.LinkTargets, net.other.sidecarId) {
		t.Error("an unbound peer is a link target")
	}

	// the key arrives, and the next compile opens the route
	view := net.view()
	view.keys = append(view.keys, testConfigSealKey(2))
	compiled, rules = testBridgeCompile(t, view, net.local())
	if entry := testBridgeCompileEntry(rules, testBridgePrefix(192, 0, 2, 0, 24)); entry == nil || len(entry.GetLinks()) != 1 || !bytes.Equal(entry.GetLinks()[0].GetRuleId(), ruleId) {
		t.Fatalf("the opened route's entry: %v", entry)
	}
	if slices.ContainsFunc(compiled.Waits, func(wait BridgeCompileWait) bool { return wait.Kind == BridgeCompileWaitGeneration }) {
		t.Errorf("waits %v once the key is held", compiled.Waits)
	}
}

// 12.2.4's "in force": with no document a standing route of an untagged advertiser is covered (owner decision 120); under
// a document only while a route rule its route_rule_ids name covers its prefix and holds its advertiser as via, and S
// uses it only through a rule of its own via the advertiser whose prefixes meet it. A policy edit that drops the rule
// ends the route at the next compile, and one that restores it brings it back.
func TestAStandingRuleFollowsThePolicy(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	policyRule := testConfigId("policy route rule")
	prefix := testBridgePrefix(192, 0, 2, 0, 24)
	ruleId := net.standingRoute(net.peer, "standing", prefix, policyRule.Bytes())

	_, rules := testBridgeCompile(t, net.view(), net.local())
	if entry := testBridgeCompileEntry(rules, prefix); entry == nil || len(entry.GetLinks()) != 1 || !bytes.Equal(entry.GetLinks()[0].GetRuleId(), ruleId) {
		t.Fatalf("with no document: %v", entry)
	}

	documentView := func(covered bool) *testBridgeCompileView {
		view := net.view()
		rows := &protocol.AclRows{HasDocument: true}
		local := &AclLocalPolicy{HasDocument: true}
		if covered {
			rows.Rules = append(rows.Rules, &protocol.AclRule{
				RuleId:   policyRule.Bytes(),
				SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
				Targets:  []*protocol.AclTarget{{SidecarId: net.peer.sidecarId.Bytes()}},
				Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
			})
			local.Rules = append(local.Rules, AclLocalRule{RuleId: policyRule, Cidrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
		}
		acl, err := NewAclState(rows, view.state)
		if err != nil {
			t.Fatal(err)
		}
		view.acl, view.aclLocal = acl, local
		return view
	}
	compiled, rules := testBridgeCompile(t, documentView(true), net.local())
	if !compiled.State.GetHasDocument() {
		t.Fatal("has_document under a document")
	}
	entry := testBridgeCompileEntry(rules, prefix)
	if entry == nil || len(entry.GetLinks()) != 1 || Id(entry.GetLinks()[0].GetTargetSidecarId()) != net.peer.sidecarId {
		t.Fatalf("under a covering rule: %v", entry)
	}
	if testBridgeCompileEntry(rules, testBridgePrefix(100, 80, 3, 9, 32)) != nil {
		t.Error("a /32 of a peer S may not dial under the document")
	}
	if _, rules := testBridgeCompile(t, documentView(false), net.local()); testBridgeCompileEntry(rules, prefix) != nil {
		t.Fatal("the route stands with the rule dropped")
	}
	if _, rules := testBridgeCompile(t, documentView(true), net.local()); testBridgeCompileEntry(rules, prefix) == nil {
		t.Fatal("the route does not come back with the rule")
	}
}

// QD-733: under a document the rows autogroup:untagged holds at S are BridgeRules.untagged, with no ids. An untagged
// sidecar is autogroup:member, never autogroup:untagged, which other clients hold (§8.4), so a member device's subject
// holds the member rule's rows alone; with no document there are none.
func TestUntaggedRowsAreAutogroupUntaggeds(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	view := net.view()
	dialRule, memberRule := testConfigId("untagged dial rule"), testConfigId("member dial rule")
	rows := &protocol.AclRows{HasDocument: true}
	for _, rule := range []struct {
		ruleId       Id
		autogroup    protocol.AclAutogroup
		portsLimited bool
	}{
		{ruleId: dialRule, autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED, portsLimited: true},
		{ruleId: memberRule, autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER},
	} {
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:       rule.ruleId.Bytes(),
			SrcAtoms:     [][]byte{AclAutogroupAtom(rule.autogroup).Bytes()},
			Targets:      []*protocol.AclTarget{{SidecarId: net.host.sidecarId.Bytes()}},
			Actions:      []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
			PortsLimited: rule.portsLimited,
		})
	}
	slices.SortFunc(rows.Rules, func(a *protocol.AclRule, b *protocol.AclRule) int { return bytes.Compare(a.GetRuleId(), b.GetRuleId()) })
	acl, err := NewAclState(rows, view.state)
	if err != nil {
		t.Fatal(err)
	}
	view.acl = acl
	view.aclLocal = &AclLocalPolicy{HasDocument: true, Rules: []AclLocalRule{
		{RuleId: dialRule, Ports: []AclPortRange{{Protocol: aclIpProtocolTcp, First: 22, Last: 22}, {Protocol: 0, First: 8000, Last: 8001}}},
		{RuleId: memberRule},
	}}
	slices.SortFunc(view.aclLocal.Rules, func(a AclLocalRule, b AclLocalRule) int { return a.RuleId.Cmp(b.RuleId) })
	_, rules := testBridgeCompile(t, view, net.local())
	untagged := rules.GetUntagged()
	if untagged == nil || len(untagged.GetSidecarId())+len(untagged.GetMemberId())+len(untagged.GetClientIds()) != 0 || untagged.GetTagged() {
		t.Fatalf("untagged %v", untagged)
	}
	// tcp:22, then the any-protocol range as TCP and UDP, since ICMP has no port
	want := []*bridge.BridgeRuleReach{
		{Protocol: aclIpProtocolTcp, Ports: []*bridge.BridgePortRange{{First: 22, Last: 22}}},
		{Protocol: aclIpProtocolTcp, Ports: []*bridge.BridgePortRange{{First: 8000, Last: 8001}}},
		{Protocol: aclIpProtocolUdp, Ports: []*bridge.BridgePortRange{{First: 8000, Last: 8001}}},
	}
	if len(untagged.GetDial()) != len(want) {
		t.Fatalf("untagged dial rows %v", untagged.GetDial())
	}
	for i, row := range want {
		if !proto.Equal(untagged.GetDial()[i], row) {
			t.Errorf("row %d: %v, want %v", i, untagged.GetDial()[i], row)
		}
	}
	memberRows := []*bridge.BridgeRuleReach{{Protocol: 0}}
	for _, device := range []testConfigDevice{net.peer, net.other, net.owner} {
		subject := testBridgeCompileSubject(rules, device.sidecarId)
		if subject == nil || !slices.EqualFunc(subject.GetDial(), memberRows, func(a *bridge.BridgeRuleReach, b *bridge.BridgeRuleReach) bool { return proto.Equal(a, b) }) {
			t.Errorf("subject %v: %v", device.sidecarId, subject)
		}
	}
	if _, rules := testBridgeCompile(t, net.view(), net.local()); rules.GetUntagged() != nil {
		t.Errorf("with no document: untagged %v", rules.GetUntagged())
	}
}

// §17.6's rule 0 and rule 2 at the compile, D-BRIDGE-19: S's map to a LAN service compiles, read into the block, and a
// map onto one of the daemon's listeners, by loopback or the listener's own address, or onto another host's overlay
// address is void here with map_refused, its other rows compiling.
func TestCompileVoidsAMapOntoTheDaemonOrTheOverlay(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	hostAddress := testBridgeIpv4(100, 80, 3, 7)
	mapOf := func(label string, port uint32, target []byte, targetPort uint32) []byte {
		ruleId := testBridgeRuleId(label)
		body := testBridgeMapBody(hostAddress, port, targetPort)
		body.Target = target
		net.mustPost(net.host, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMap(net.host, ruleId, 0, body))
		return ruleId
	}
	lan := mapOf("lan", 8080, []byte{192, 0, 2, 20}, 80)
	mapOf("daemon by loopback", 9000, []byte{127, 0, 0, 1}, 17000)
	mapOf("daemon by v6 loopback", 9001, netip.IPv6Loopback().AsSlice(), 17001)
	mapOf("overlay", 9002, []byte{100, 80, 3, 9}, 22)
	unrelated := mapOf("an unrelated loopback service", 9003, []byte{127, 0, 0, 1}, 5432)

	compiled, rules := testBridgeCompile(t, net.view(), net.local())
	mapIds := [][]byte{}
	for _, ruleMap := range rules.GetMaps() {
		mapIds = append(mapIds, ruleMap.GetMapId())
	}
	wantIds := [][]byte{lan, unrelated}
	slices.SortFunc(wantIds, bytes.Compare)
	if !slices.EqualFunc(mapIds, wantIds, bytes.Equal) {
		t.Fatalf("maps %x, want %x", mapIds, wantIds)
	}
	for _, ruleMap := range rules.GetMaps() {
		if !proto.Equal(ruleMap.GetMatchPrefix(), testBridgePrefix(100, 80, 3, 7, 32)) || ruleMap.GetProtocol() != aclIpProtocolTcp {
			t.Errorf("map %x: %v", ruleMap.GetMapId(), ruleMap)
		}
	}
	refused := 0
	for _, alarm := range compiled.Alarms {
		if alarm.Reason == SidecarBridgeAlarmMapRefused {
			refused += 1
		}
	}
	if refused != 3 {
		t.Errorf("%d maps refused, alarms %v", refused, compiled.Alarms)
	}
}

// §12.9: the names are each addressed sidecar among S and those it may dial, to its address in the block, and a name
// the zone publishes is left out (BRIDGE-M4-14 relies on it); a name of a sidecar with no address is not held.
func TestCompileOmitsANamePublishedInTheZone(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	net.namesFile = testConfigMarshal(t, &protocol.ConfigNameTable{Names: []*protocol.ConfigName{
		{SidecarId: net.host.sidecarId.Bytes(), Name: "laptop"},
		{SidecarId: net.peer.sidecarId.Bytes(), Name: "desktop"},
		{SidecarId: net.other.sidecarId.Bytes(), Name: "studio"},
		{SidecarId: net.owner.sidecarId.Bytes(), Name: "owner"},
	}})
	local := net.local()
	local.PublishedNames = []string{"STUDIO."}
	compiled, _ := testBridgeCompile(t, net.view(), local)
	want := map[string]uint32{"laptop": testBridgeIpv4(100, 80, 3, 7), "desktop": testBridgeIpv4(100, 80, 3, 9)}
	names := compiled.State.GetNames()
	if len(names) != len(want) {
		t.Fatalf("names %v", names)
	}
	for name, address := range want {
		if names[name] != address {
			t.Errorf("%s: %x", name, names[name])
		}
	}
}

// §17.8's disposition: a route withdrawn to drain stays compiled, its link marked draining from the withdrawal, until
// max(drain_seconds, 600 s) of the log's time, then leaves; a reset withdrawal leaves at once.
func TestAWithdrawnRouteDrainsThenLeaves(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	drained := testBridgePrefix(192, 0, 2, 0, 24)
	reset := testBridgePrefix(198, 51, 100, 0, 24)
	drainedId := net.standingRoute(net.peer, "drained", drained)
	resetId := net.standingRoute(net.peer, "reset", reset)
	withdrawal := net.mustPost(net.peer, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(drainedId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN))
	withdrawnMs := net.timeMs
	net.mustPost(net.peer, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(resetId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))

	_, rules := testBridgeCompile(t, net.view(), net.local())
	entry := testBridgeCompileEntry(rules, drained)
	if entry == nil || len(entry.GetLinks()) != 1 {
		t.Fatalf("the draining route's entry at %d: %v", withdrawal.Pin.GetVersion(), entry)
	}
	if link := entry.GetLinks()[0]; link.GetDrainingSince() != withdrawnMs || link.GetDrainUntil() != withdrawnMs {
		t.Errorf("the draining link %v, withdrawn at %d", link, withdrawnMs)
	}
	if testBridgeCompileEntry(rules, reset) != nil {
		t.Error("a reset route compiled")
	}

	// a statement 600 s after the withdrawal moves the log's time past the drain
	net.timeMs = withdrawnMs + DefaultBridgeCompileSettings().DrainMinimum.Milliseconds() - 1000
	net.mustPost(net.host, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgress(net.host.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, nil))
	if _, rules := testBridgeCompile(t, net.view(), net.local()); testBridgeCompileEntry(rules, drained) != nil {
		t.Fatalf("the route stands at %d, its drain over", net.timeMs)
	}
}

// D-BRIDGE-16: a head whose block no admin signed keeps the previous block and alarms block_refused; with none held, the
// rest compiles with no address and no entry.
func TestCompileKeepsThePreviousBlockOnARefusal(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	net.blockFile = net.sign(net.peer, bridge.SignedType_SIGNED_BRIDGE_BLOCK, &bridge.BridgeBlock{Ipv4Prefix: testBridgePrefix(10, 44, 0, 0, 16)})
	local := net.local()
	local.PreviousBlock = testBridgeCompileBlock()
	compiled, rules := testBridgeCompile(t, net.view(), local)
	if !testBridgeCompileAlarmed(compiled, SidecarBridgeAlarmBlockRefused) || !proto.Equal(compiled.Block, local.PreviousBlock) ||
		!proto.Equal(rules.GetBlock(), testBridgePrefix(100, 80, 0, 0, 16)) {
		t.Fatalf("block %v, rules' %v, alarms %v", compiled.Block, rules.GetBlock(), compiled.Alarms)
	}
	compiled, rules = testBridgeCompile(t, net.view(), net.local())
	if compiled.Block != nil || rules.GetBlock() != nil || len(rules.GetAddresses())+len(rules.GetEntries()) != 0 || len(rules.GetSubjects()) != 3 {
		t.Fatalf("with no block held: %v", rules)
	}
}

// 12.5: a ledger file that fails its hash, and unfolded bodies past UnfoldedBodyMaxByteCount, refuse the compile: no
// state, the previous block handed back, and state_unverified or ledger_over_budget.
func TestCompileRefusesALedgerThatDoesNotVerifyOrPassesItsBudget(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	net.standingRoute(net.peer, "folded", testBridgePrefix(192, 0, 2, 0, 24))
	net.foldLedger(net.n, nil)
	view := net.view()
	manifest := view.rows.Manifest()
	if manifest == nil || len(manifest.GetFiles()) == 0 {
		t.Fatal("the fold wrote no ledger file")
	}
	path := manifest.GetFiles()[0].GetPath()
	tampered := view.head.File(path)
	tampered[len(tampered)-1] ^= 1
	head, err := view.head.WithFile(path, tampered)
	if err != nil {
		t.Fatal(err)
	}
	view.head = head
	if view.rows, err = NewBridgeLedgerHeadRows(head, net.settings); err != nil {
		t.Fatal(err)
	}
	local := net.local()
	local.PreviousBlock = &bridge.BridgeBlock{Ipv4Prefix: testBridgePrefix(10, 44, 0, 0, 16)}
	compiled, err := CompileBridgeState(view, local, nil)
	if !errors.Is(err, ErrBridgeCompileRefused) || compiled.State != nil || !testBridgeCompileAlarmed(compiled, SidecarBridgeAlarmStateUnverified) ||
		!proto.Equal(compiled.Block, local.PreviousBlock) {
		t.Fatalf("a tampered file: %v, %v, block %v", err, compiled.Alarms, compiled.Block)
	}

	net.standingRoute(net.peer, "unfolded", testBridgePrefix(198, 51, 100, 0, 24))
	settings := DefaultBridgeLedgerSettings()
	settings.UnfoldedBodyMaxByteCount = 16
	compiled, err = CompileBridgeState(net.view(), net.local(), settings)
	if !errors.Is(err, ErrBridgeCompileRefused) || compiled.State != nil || !testBridgeCompileAlarmed(compiled, SidecarBridgeAlarmLedgerOverBudget) {
		t.Fatalf("past the budget: %v, %v", err, compiled.Alarms)
	}
	if _, err := CompileBridgeState(net.view(), net.local(), nil); err != nil {
		t.Fatalf("under the default budget: %v", err)
	}
}

// 12.2.4's passes: the compile reads each ledger file the manifest names once, front to back, at a base that folded the
// statements and again with statements past it, and none the manifest does not name.
func TestCompileReadsEachLedgerFileOnce(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	for i := range 3 {
		net.standingRoute(net.peer, fmt.Sprint("folded ", i), testBridgePrefix(192, 0, 2, byte(i*64), 26))
	}
	net.foldLedger(net.n, nil)
	net.standingRoute(net.other, "unfolded", testBridgePrefix(198, 51, 100, 0, 24))
	view := net.view()
	_, rules := testBridgeCompile(t, view, net.local())
	manifest := view.rows.Manifest()
	if manifest == nil || len(manifest.GetFiles()) < 2 {
		t.Fatalf("the fold's manifest %v", manifest)
	}
	for _, file := range manifest.GetFiles() {
		if view.opened[file.GetPath()] != 1 {
			t.Errorf("%s opened %d times", file.GetPath(), view.opened[file.GetPath()])
		}
	}
	if len(view.opened) != len(manifest.GetFiles()) {
		t.Errorf("opened %v, the manifest names %d files", view.opened, len(manifest.GetFiles()))
	}
	for i := range 3 {
		if testBridgeCompileEntry(rules, testBridgePrefix(192, 0, 2, byte(i*64), 26)) == nil {
			t.Errorf("the folded route %d did not compile", i)
		}
	}
	if testBridgeCompileEntry(rules, testBridgePrefix(198, 51, 100, 0, 24)) == nil {
		t.Error("the unfolded route did not compile")
	}
}

// 12.2.4's equal bytes: a reader present since the bootstrap and one restored at the newest base, a forwarding role's
// kind of view, compile one state, byte for byte.
func TestCompileIsEqualOnADaemonAndAForwarderView(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	net.standingRoute(net.peer, "folded", testBridgePrefix(192, 0, 2, 0, 24))
	net.foldLedger(net.n, nil)
	net.standingRoute(net.other, "unfolded", testBridgePrefix(198, 51, 100, 0, 24))
	present, err := CompileBridgeState(net.viewOf(net.presentReader()), net.local(), nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := CompileBridgeState(net.viewOf(net.restoredReader()), net.local(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if present.Digest != restored.Digest {
		t.Fatalf("a present and a restored reader compile %x and %x", present.Digest, restored.Digest)
	}
}

// QD-009 at the compile: a client id the bindings give two subjects is left out of both with principal_mismatch, since
// the device role refuses a state that binds a client twice and a sealed subject must resolve to one sidecar.
func TestAClientIdOfTwoSubjectsBindsNeither(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	shared := testBridgeCompileClientId(net.peer, 1)
	net.bindings.Record(&BridgeBinding{
		SidecarId: net.other.sidecarId, ClientId: shared, IdentityPublicKey: net.other.publicKey(), Generation: 2, Signed: []byte("shared"),
	}, time.UnixMilli(testConfigStartMs))
	compiled, rules := testBridgeCompile(t, net.view(), net.local())
	for _, device := range []testConfigDevice{net.peer, net.other} {
		subject := testBridgeCompileSubject(rules, device.sidecarId)
		if subject == nil || slices.ContainsFunc(subject.GetClientIds(), func(clientId []byte) bool { return Id(clientId) == shared }) {
			t.Errorf("subject %v holds the shared client: %v", device.sidecarId, subject)
		}
	}
	if !testBridgeCompileAlarmed(compiled, SidecarBridgeAlarmPrincipalMismatch) {
		t.Errorf("alarms %v", compiled.Alarms)
	}
}

// §17.4's block_conflict at the compile: a subnet route inside the network's block would take hosts' addresses, so it
// compiles no entry and alarms, while one around the block compiles and leaves the block's entries the more specific.
func TestARoutePrefixInsideTheBlockIsRefused(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	inside := testBridgePrefix(100, 80, 200, 0, 24)
	around := testBridgePrefix(100, 64, 0, 0, 10)
	net.standingRoute(net.peer, "inside", inside)
	net.standingRoute(net.other, "around", around)
	compiled, rules := testBridgeCompile(t, net.view(), net.local())
	if testBridgeCompileEntry(rules, inside) != nil || !testBridgeCompileAlarmed(compiled, SidecarBridgeAlarmBlockConflict) {
		t.Fatalf("a route inside the block: %v", compiled.Alarms)
	}
	if testBridgeCompileEntry(rules, around) == nil || testBridgeCompileEntry(rules, testBridgePrefix(100, 80, 0, 0, 16)) == nil {
		t.Fatal("a route around the block")
	}
}

// The anchor a device role is set pending with: the network, A_0 and the sidecar's id and key.
func TestCompileBridgePendingAnchorsTheNetwork(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	state := net.log.State()
	pending := CompileBridgePending(state, &SidecarIdentity{SidecarId: net.host.sidecarId, IdentityPublicKey: net.host.publicKey()})
	if Id(pending.GetNetworkId()) != net.networkId || !bytes.Equal(pending.GetGenesisSha256(), state.genesisChain[:]) ||
		Id(pending.GetSidecarId()) != net.host.sidecarId || !bytes.Equal(pending.GetIdentityPublicKey(), net.host.publicKey()) {
		t.Fatalf("pending %v", pending)
	}
	if CompileBridgePending(nil, nil) != nil {
		t.Error("a pending of nothing")
	}
}

// The golden states, embedded so they read on every leg.
//
//go:embed testdata/bridge/compile
var testBridgeCompileVectorFiles embed.FS

// One golden state: its digest and its deterministic bytes, hex.
type testBridgeCompileVector struct {
	Digest string `json:"digest"`
	State  string `json:"state"`
}

// The fixture states the golden file holds: no document, and one with routes, a map, names and a waiting peer.
func testBridgeCompileVectorStates(t testing.TB) map[string]*BridgeCompiled {
	plain := newTestBridgeCompileNet(t)
	plainCompiled, _ := testBridgeCompile(t, plain.view(), plain.local())

	rich := newTestBridgeCompileNet(t)
	rich.namesFile = testConfigMarshal(t, &protocol.ConfigNameTable{Names: []*protocol.ConfigName{
		{SidecarId: rich.host.sidecarId.Bytes(), Name: "laptop"},
		{SidecarId: rich.peer.sidecarId.Bytes(), Name: "desktop"},
	}})
	rich.standingRoute(rich.peer, "golden route", testBridgePrefix(192, 0, 2, 0, 24))
	rich.standingRoute(rich.host, "golden served", testBridgePrefix(198, 51, 100, 0, 24))
	body := testBridgeMapBody(testBridgeIpv4(100, 80, 3, 7), 8080, 80)
	rich.mustPost(rich.host, bridge.SignedType_SIGNED_BRIDGE_MAP, rich.bridgeMap(rich.host, testBridgeRuleId("golden map"), 0, body))
	rich.foldLedger(rich.n, nil)
	rich.bindings.Forget(rich.other.sidecarId)
	richCompiled, _ := testBridgeCompile(t, rich.view(), rich.local())
	return map[string]*BridgeCompiled{"no-document": plainCompiled, "routes-map-names": richCompiled}
}

// testdata/bridge/compile/states.json: the fixtures' states byte for byte, equal across runs and GOMAXPROCS, so a leg
// or a release whose compile differs in one byte fails here. SIDECAR_REGENERATE_BRIDGE_COMPILE_VECTORS=1 rewrites them,
// which only a change to the compile's rules or the test network's fixtures should need.
func TestCompileMatchesItsGoldenStates(t *testing.T) {
	encode := func(states map[string]*BridgeCompiled) map[string]testBridgeCompileVector {
		vectors := map[string]testBridgeCompileVector{}
		for name, compiled := range states {
			stateBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(compiled.State)
			if err != nil {
				t.Fatal(err)
			}
			vectors[name] = testBridgeCompileVector{Digest: hex.EncodeToString(compiled.Digest[:]), State: hex.EncodeToString(stateBytes)}
		}
		return vectors
	}
	got := encode(testBridgeCompileVectorStates(t))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	if again := encode(testBridgeCompileVectorStates(t)); !reflect.DeepEqual(again, got) {
		t.Fatal("a second run at GOMAXPROCS 1 compiled other bytes")
	}
	if os.Getenv("SIDECAR_REGENERATE_BRIDGE_COMPILE_VECTORS") != "" {
		encoded, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("testdata/bridge/compile/states.json", append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := testBridgeCompileVectorFiles.ReadFile("testdata/bridge/compile/states.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]testBridgeCompileVector{}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(got) {
		t.Fatalf("%d golden states, %d compiled", len(want), len(got))
	}
	for name, vector := range want {
		if got[name] != vector {
			t.Errorf("%s: compiled %s, golden %s", name, got[name].Digest, vector.Digest)
		}
	}
}
