// §17.8's statements on the test network (bridge_statement.go, bridge_statement_rules.go): each statement's signer
// class at id level, every refusal alone beside the filing that passes; a read_only device's statement; rule id
// vectors; a withdrawn id before and after a fold and its drop past the decision's not_after; a decision's uses; a
// base re-applying the statements for a new device; the body level's addresses, tombstones, overlaps, held ids, pending
// and void bodies; D-BRIDGE-16's block check; and I-18's canary, a prefix, port and address that appear only inside
// sealed bodies.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const testBridgeDayMs = int64(24 * 60 * 60 * 1000)

// The statement vectors, embedded so they read on every leg, the page Worker's included.
//
//go:embed testdata/bridge/statements
var testBridgeStatementFiles embed.FS

// An IPv4 address as bridge.proto's fixed32 holds one.
func testBridgeIpv4(a byte, b byte, c byte, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

// A prefix, its address already masked.
func testBridgePrefix(a byte, b byte, c byte, d byte, length uint32) *bridge.BridgeIpv4Prefix {
	return &bridge.BridgeIpv4Prefix{Address: testBridgeIpv4(a, b, c, d), Length: length}
}

// How long every reader holds a released address, by the ledger's default settings (§17.4, I-14).
var testBridgeTombstoneMs = DefaultBridgeLedgerSettings().AddressTombstoneTimeout.Milliseconds()

// A rule id from a label, as a standing grant's 32 random bytes.
func testBridgeRuleId(label string) []byte {
	digest := sha256.Sum256([]byte("bridge test rule " + label))
	return digest[:]
}

// body sealed into a statement of signedType with this header, under the config's generation, with a nonce drawn from
// the header's so a run repeats.
func (self *testConfigNet) bridgeSeal(signedType bridge.SignedType, header *bridge.StatementHeader, body proto.Message, generation uint64) []byte {
	self.t.Helper()
	nonce := sha256.Sum256(append([]byte("bridge test seal nonce "), header.GetNonce()...))
	sealed, err := SealConfigBody(testConfigSealKey(generation), NewConfigSealContext(signedType, header), body, bytes.NewReader(nonce[:24]))
	if err != nil {
		self.t.Fatal(err)
	}
	return sealed
}

// A BridgeAddress of device at ipv4, sealed to generation 1.
func (self *testConfigNet) bridgeAddress(device testConfigDevice, ipv4 uint32) *bridge.BridgeAddress {
	header := self.header()
	return &bridge.BridgeAddress{
		Header: header, SidecarId: device.sidecarId.Bytes(),
		SealedBody: self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_ADDRESS, header, &bridge.BridgeAddressBody{Ipv4: ipv4}, 1),
	}
}

// A BridgeRoute advertised by device under ruleId, its body sealed to generation.
func (self *testConfigNet) bridgeRouteAt(device testConfigDevice, ruleId []byte, body *bridge.BridgeRouteBody, generation uint64) *bridge.BridgeRoute {
	header := self.header()
	return &bridge.BridgeRoute{
		Header: header, RouteId: ruleId, Advertiser: device.sidecarId.Bytes(),
		SealedBody: self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_ROUTE, header, body, generation),
	}
}

// bridgeRouteAt generation 1.
func (self *testConfigNet) bridgeRoute(device testConfigDevice, ruleId []byte, body *bridge.BridgeRouteBody) *bridge.BridgeRoute {
	return self.bridgeRouteAt(device, ruleId, body, 1)
}

// A BridgeMap hosted by device under ruleId, sealed to generation 1.
func (self *testConfigNet) bridgeMap(device testConfigDevice, ruleId []byte, expires int64, body *bridge.BridgeMapBody) *bridge.BridgeMap {
	header := self.header()
	return &bridge.BridgeMap{
		Header: header, MapId: ruleId, Host: device.sidecarId.Bytes(), Expires: expires,
		SealedBody: self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_MAP, header, body, 1),
	}
}

// A BridgeWithdraw of ruleId.
func (self *testConfigNet) bridgeWithdraw(ruleId []byte, mode bridge.BridgeWithdrawMode) *bridge.BridgeWithdraw {
	return &bridge.BridgeWithdraw{Header: self.header(), RuleId: ruleId, Mode: mode}
}

// A BridgeEgress of subject's mode in the clear, its body, when there is one, sealed to generation 1.
func (self *testConfigNet) bridgeEgress(subject Id, mode bridge.BridgeEgressMode, body *bridge.BridgeEgressBody) *bridge.BridgeEgress {
	header := self.header()
	egress := &bridge.BridgeEgress{Header: header, Subject: subject.Bytes(), Mode: mode}
	if body != nil {
		egress.SealedBody = self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_EGRESS, header, body, 1)
	}
	return egress
}

// A BridgeAlias sealed to generation 1.
func (self *testConfigNet) bridgeAlias(body *bridge.BridgeAliasBody) *bridge.BridgeAlias {
	header := self.header()
	return &bridge.BridgeAlias{Header: header, SealedBody: self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_ALIAS, header, body, 1)}
}

// A subnet route's body of one prefix at a site.
func testBridgeSubnet(prefix *bridge.BridgeIpv4Prefix, siteId string) *bridge.BridgeRouteBody {
	return &bridge.BridgeRouteBody{
		Prefixes: []*bridge.BridgeIpv4Prefix{prefix}, SiteId: []byte(siteId), Weight: 1,
		Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET,
	}
}

// A TCP map's body from port to a LAN target's port.
func testBridgeMapBody(matchAddress uint32, port uint32, targetPort uint32) *bridge.BridgeMapBody {
	return &bridge.BridgeMapBody{
		MatchPrefix: &bridge.BridgeIpv4Prefix{Address: matchAddress, Length: 32}, Protocol: 6,
		Ports: []*bridge.BridgePortRange{{First: port, Last: port}}, Target: []byte{192, 168, 9, 20}, TargetPort: targetPort,
	}
}

// The ledger of the net's reader at its tip, opened with generation 1's key and whatever else is passed.
func (self *testConfigNet) bridgeLedger(keys ...*EvsRepoKey) *BridgeLedger {
	state := self.log.State()
	keys = append(keys, testConfigSealKey(1))
	return state.Bridge().Open(&BridgeLedgerReader{State: state, RepoKeyAt: testConfigSealKeyAt(keys...)})
}

// The ledger's entry for the statement an entry at n carried.
func testBridgeEntryAt(t *testing.T, ledger *BridgeLedger, n uint64) *BridgeLedgerEntry {
	t.Helper()
	for _, entry := range ledger.Entries() {
		if entry.Statement.N == n {
			return entry
		}
	}
	t.Fatalf("the ledger holds no statement at %d", n)
	return nil
}

// Fails unless the ledger made want of the statement at n, and a void one says why under ErrBridgeVoid.
func testBridgeDisposition(t *testing.T, ledger *BridgeLedger, n uint64, want BridgeDisposition) *BridgeLedgerEntry {
	t.Helper()
	entry := testBridgeEntryAt(t, ledger, n)
	if entry.Disposition != want {
		t.Fatalf("the statement at %d: disposition %d (%v), want %d", n, entry.Disposition, entry.Reason, want)
	}
	if (want == BridgeDispositionVoid) != errors.Is(entry.Reason, ErrBridgeVoid) {
		t.Fatalf("the statement at %d: reason %v", n, entry.Reason)
	}
	return entry
}

// A member with two admitted devices beside the fixture's owner.
func testBridgeCast(net *testConfigNet) (Id, testConfigDevice, testConfigDevice) {
	member, laptop := net.consentedMember("m")
	desktop := net.device("m desktop", member)
	net.admitDevice(laptop, desktop, 0)
	return member, laptop, desktop
}

// §17.8's signer table at id level, at every reader, the keyless gate's included: each statement from the one class
// that may sign it, and refused alone from the nearest other; ids of the wrong size, a missing body, an expired map
// and an unknown withdraw mode refused as the rule's; and a BridgeEgress whose clear mode is unspecified, outside the
// enum or at odds with its body refused, each beside the filing that passes.
func TestBridgeStatementsTakeTheirSignersAlone(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	_, otherLaptop := net.consentedMember("other")
	stranger := net.device("never admitted", testConfigId("m"))
	address, route, mapType := bridge.SignedType_SIGNED_BRIDGE_ADDRESS, bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_MAP
	withdraw, alias := bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, bridge.SignedType_SIGNED_BRIDGE_ALIAS

	// BridgeAddress: the sidecar itself or an admin
	net.mustRefuse(otherLaptop, address, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)), ErrConfigAuthority)
	net.mustPost(laptop, address, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)))
	net.mustPost(net.owner, address, net.bridgeAddress(desktop, testBridgeIpv4(100, 80, 3, 8)))
	net.mustRefuse(net.owner, address, net.bridgeAddress(stranger, testBridgeIpv4(100, 80, 3, 9)), ErrConfigRule)
	short := net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7))
	short.SidecarId = short.SidecarId[:8]
	net.mustRefuse(laptop, address, short, ErrConfigRule)
	unsealed := net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7))
	unsealed.SealedBody = nil
	net.mustRefuse(laptop, address, unsealed, ErrConfigRule)

	// BridgeRoute: its advertiser, and no admin in its place
	routeId, body := testBridgeRuleId("route"), testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")
	net.mustRefuse(net.owner, route, net.bridgeRoute(laptop, routeId, body), ErrConfigAuthority)
	net.mustPost(laptop, route, net.bridgeRoute(laptop, routeId, body))
	shortRoute := net.bridgeRoute(laptop, testBridgeRuleId("short")[:16], body)
	net.mustRefuse(laptop, route, shortRoute, ErrConfigRule)
	unsealedRoute := net.bridgeRoute(laptop, testBridgeRuleId("unsealed"), body)
	unsealedRoute.SealedBody = []byte("no seal")
	net.mustRefuse(laptop, route, unsealedRoute, ErrConfigRule)
	badRules := net.bridgeRoute(laptop, testBridgeRuleId("bad rules"), body)
	badRules.RouteRuleIds = [][]byte{{1, 2, 3}}
	net.mustRefuse(laptop, route, badRules, ErrConfigRule)

	// BridgeMap: its host, unexpired at its entry
	mapId, mapBody := testBridgeRuleId("map"), testBridgeMapBody(testBridgeIpv4(100, 80, 3, 8), 8443, 443)
	net.mustRefuse(laptop, mapType, net.bridgeMap(desktop, mapId, 0, mapBody), ErrConfigAuthority)
	net.mustPost(desktop, mapType, net.bridgeMap(desktop, mapId, net.timeMs+testConfigHourMs, mapBody))
	net.mustRefuse(desktop, mapType, net.bridgeMap(desktop, testBridgeRuleId("expired"), net.timeMs, mapBody), ErrConfigRule)

	// BridgeWithdraw: the rule's signer or an admin
	net.mustRefuse(otherLaptop, withdraw, net.bridgeWithdraw(routeId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET), ErrConfigAuthority)
	net.mustRefuse(laptop, withdraw, net.bridgeWithdraw(routeId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_UNSPECIFIED), ErrConfigRule)
	net.mustRefuse(laptop, withdraw, net.bridgeWithdraw(routeId[:8], bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET), ErrConfigRule)
	net.mustPost(laptop, withdraw, net.bridgeWithdraw(routeId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN))
	net.mustPost(net.owner, withdraw, net.bridgeWithdraw(mapId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))

	// BridgeAlias: all of its row is sealed, so its signer is whoever accepts
	aliasBody := &bridge.BridgeAliasBody{ShareId: testConfigId("share").Bytes(), AliasPrefix: testBridgePrefix(100, 80, 128, 0, 24), Host: testConfigId("far host").Bytes()}
	net.mustPost(laptop, alias, net.bridgeAlias(aliasBody))
	unsealedAlias := net.bridgeAlias(aliasBody)
	unsealedAlias.SealedBody = nil
	net.mustRefuse(laptop, alias, unsealedAlias, ErrConfigRule)

	// BridgeEgress: an admin, a device of the subject's own member, or a sponsor's, its mode in the clear
	egressType, none, exits := bridge.SignedType_SIGNED_BRIDGE_EGRESS, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	net.mustRefuse(otherLaptop, egressType, net.bridgeEgress(laptop.sidecarId, none, nil), ErrConfigAuthority)
	net.mustPost(desktop, egressType, net.bridgeEgress(laptop.sidecarId, none, nil))
	net.mustPost(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, exits, &bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{desktop.sidecarId.Bytes()}}))
	net.mustRefuse(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED, nil), ErrConfigRule)
	net.mustRefuse(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, bridge.BridgeEgressMode(9), nil), ErrConfigRule)
	net.mustRefuse(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, exits, nil), ErrConfigRule)
	net.mustRefuse(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, none, &bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{desktop.sidecarId.Bytes()}}), ErrConfigRule)

	// a BridgeBlock rides a head and never the log
	block := &bridge.BridgeBlock{Ipv4Prefix: testBridgePrefix(100, 80, 0, 0, 16)}
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, block, ErrConfigRule)

	if got := net.log.State().Bridge().Len(); got != 9 {
		t.Errorf("the fold holds %d statements, want the 9 that took effect", got)
	}
	net.everyReaderAgrees()
}

// §7.9's read_only refusal covers every bridge statement, and a revoked signer's is refused whatever it names.
func TestAReadOnlyOrRevokedDeviceFilesNoBridgeStatement(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop, desktop := testBridgeCast(net)
	page := net.device("m page", member)
	net.admitDevice(laptop, page, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	body := testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")
	reset := bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET

	net.mustRefuse(page, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(page, testBridgeIpv4(100, 80, 3, 7)), ErrConfigReadOnly)
	net.mustRefuse(page, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(page, testBridgeRuleId("page route"), body), ErrConfigReadOnly)
	net.mustRefuse(page, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMap(page, testBridgeRuleId("page map"), 0, testBridgeMapBody(1, 80, 80)), ErrConfigReadOnly)
	net.mustRefuse(page, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(testBridgeRuleId("page route"), reset), ErrConfigReadOnly)
	net.mustRefuse(page, bridge.SignedType_SIGNED_BRIDGE_ALIAS, net.bridgeAlias(&bridge.BridgeAliasBody{}), ErrConfigReadOnly)
	net.mustRefuse(page, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgress(page.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE, nil), ErrConfigReadOnly)
	// the positive twin: the same route from a device that is not read_only
	net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(desktop, testBridgeRuleId("page route"), body))

	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(desktop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	if verdict := net.post(desktop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(desktop, testBridgeRuleId("after revoke"), body)); verdict.Accepted() {
		t.Error("a revoked device's route took effect")
	}
	if verdict := net.post(desktop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(testBridgeRuleId("page route"), reset)); verdict.Accepted() {
		t.Error("a revoked device's withdrawal took effect")
	}
	net.everyReaderAgrees()
}

// One rule id vector: an approval and the action a use hashed, and what §16.6 and §17.8 derive from them.
type testBridgeRuleIdVector struct {
	Name            string `json:"name"`
	ApprovalId      string `json:"approval_id"`
	CanonicalAction string `json:"canonical_action"`
	ActionId        string `json:"action_id"`
	EffectKey       string `json:"effect_key"`
	RuleId          string `json:"rule_id"`
}

// testdata/bridge/statements/rule_ids.json: BridgeRuleId over §16.6's effect_key, which a reader recomputes from the
// BridgeApproval a rule carries, so a retry or a restart files one id. Each vector is also recomputed with nothing but
// SHA-256, so the constants cannot drift with the functions.
func TestBridgeRuleIdVectors(t *testing.T) {
	data, err := testBridgeStatementFiles.ReadFile("testdata/bridge/statements/rule_ids.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := []testBridgeRuleIdVector{}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 3 {
		t.Fatalf("%d vectors", len(vectors))
	}
	unhex := func(text string) []byte {
		decoded, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	seen := map[string]bool{}
	for _, vector := range vectors {
		approvalId, err := IdFromBytes(unhex(vector.ApprovalId))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		action := unhex(vector.CanonicalAction)
		actionId := ApprovalActionId(approvalId, action)
		effectKey := ApprovalEffectKey(approvalId, actionId)
		ruleId := BridgeRuleId(effectKey)
		if hex.EncodeToString(actionId[:]) != vector.ActionId || hex.EncodeToString(effectKey[:]) != vector.EffectKey || hex.EncodeToString(ruleId[:]) != vector.RuleId {
			t.Errorf("%s: action_id %x, effect_key %x, rule_id %x", vector.Name, actionId, effectKey, ruleId)
		}
		byHand := sha256.Sum256(append([]byte("urnetwork-sidecar-v1/bridge-rule"), unhex(vector.EffectKey)...))
		if hex.EncodeToString(byHand[:]) != vector.RuleId {
			t.Errorf("%s: by hand %x", vector.Name, byHand)
		}
		if seen[vector.RuleId] {
			t.Errorf("%s: a rule id another vector has", vector.Name)
		}
		seen[vector.RuleId] = true
	}
}

// A withdrawn id is refused before a fold at id level, at every reader. After a fold the keyless verifiers hold no
// withdrawal, so the log takes the filing, and a full reader's ledger, opened over the head's ledger rows, voids it. A
// rule under a standing grant is dropped once its last filing's header could no longer be replayed, and its id is then
// free.
func TestAWithdrawnBridgeRuleIdIsRefusedBeforeAndAfterAFold(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, _ := testBridgeCast(net.testConfigNet)
	_, otherLaptop := net.consentedMember("other")
	route, withdraw := bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW
	reset := bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET
	ruleId, body := testBridgeRuleId("route"), testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")

	net.mustPost(laptop, route, net.bridgeRoute(laptop, ruleId, body))
	// another signer's own route under another id is untouched by what follows
	otherId := testBridgeRuleId("other route")
	net.mustPost(otherLaptop, route, net.bridgeRoute(otherLaptop, otherId, testBridgeSubnet(testBridgePrefix(10, 9, 0, 0, 16), "far")))
	net.mustPost(laptop, withdraw, net.bridgeWithdraw(ruleId, reset))
	net.mustRefuse(laptop, route, net.bridgeRoute(laptop, ruleId, body), ErrConfigRule)
	// a withdrawal ahead of its rule's filing binds what its own signer files, and nobody else's
	aheadId := testBridgeRuleId("ahead")
	net.mustPost(laptop, withdraw, net.bridgeWithdraw(aheadId, reset))
	net.mustRefuse(laptop, route, net.bridgeRoute(laptop, aheadId, body), ErrConfigRule)
	net.mustPost(otherLaptop, route, net.bridgeRoute(otherLaptop, aheadId, testBridgeSubnet(testBridgePrefix(10, 8, 0, 0, 16), "far")))
	net.everyReaderAgrees()
	if rule := net.log.State().Bridge().Rule(ruleId); rule == nil || rule.Withdrawn == nil || len(rule.Filings) != 1 {
		t.Fatalf("the fold's rule: %+v", rule)
	}
	if rule := net.log.State().Bridge().Rule(otherId); rule == nil || rule.Withdrawn != nil {
		t.Fatalf("the other signer's rule: %+v", rule)
	}

	net.foldLedger(net.n, nil)
	if net.log.State().Bridge().Len() != 0 {
		t.Fatal("a base's rows carry no bridge statement, so the fold starts empty")
	}
	refiled := net.mustPost(laptop, route, net.bridgeRoute(laptop, ruleId, body))
	net.everyReaderAgrees()
	ledger := net.ledgerOf(net.log)
	testBridgeDisposition(t, ledger, refiled.Pin.GetVersion(), BridgeDispositionVoid)
	if rule := ledger.Rule(ruleId); rule == nil || rule.Withdrawn == nil || rule.Active() || rule.First != nil {
		t.Fatalf("the ledger's rule after the fold, taken from the rows: %+v", rule)
	}
	if rule := ledger.Rule(otherId); rule == nil || !rule.Active() || !rule.Standing {
		t.Fatalf("the other signer's rule in the ledger: %+v", rule)
	}

	// 8 days on, the withdrawn filing's header has expired everywhere: the fold drops the id, and a filing of it is new
	net.foldLedger(net.n, nil)
	net.timeMs += 8 * testBridgeDayMs
	again := net.mustPost(laptop, route, net.bridgeRoute(laptop, ruleId, body))
	ledger = net.ledgerOf(net.log)
	testBridgeDisposition(t, ledger, again.Pin.GetVersion(), BridgeDispositionActive)
	if rule := ledger.Rule(ruleId); rule == nil || !rule.Active() || rule.FirstAt != again.Pin.GetVersion() {
		t.Fatalf("the rule after its withdrawn id was dropped: %+v", rule)
	}
}

// What a test approval says of itself: the test's approvals carry these as their canonical_action, and the test's
// check reads them back, so the ledger's counting runs without §16.6's real decisions.
type testBridgeApproval struct {
	Approval   string `json:"approval"`
	RuleId     []byte `json:"rule_id"`
	Uses       uint32 `json:"uses"`
	NotAfterMs int64  `json:"not_after_ms"`
}

func (self testBridgeApproval) wire(t *testing.T) *bridge.BridgeApproval {
	encoded, err := json.Marshal(self)
	if err != nil {
		t.Fatal(err)
	}
	return &bridge.BridgeApproval{CanonicalAction: encoded}
}

// A judge with generation 1's key and whatever else is passed, whose approvals verify as the test's say.
func testBridgeTestJudge(keys ...*EvsRepoKey) *BridgeBodyJudge {
	return &BridgeBodyJudge{RepoKeyAt: testConfigSealKeyAt(append(keys, testConfigSealKey(1))...), checkApproval: testBridgeApprovalCheck}
}

// A judge with generation 1's key and whatever else is passed, verifying approvals as the state does.
func testBridgeJudge(keys ...*EvsRepoKey) *BridgeBodyJudge {
	return &BridgeBodyJudge{RepoKeyAt: testConfigSealKeyAt(append(keys, testConfigSealKey(1))...)}
}

// Reads a test approval back as verified facts.
func testBridgeApprovalCheck(before *ConfigState, statement *BridgeLogStatement, body proto.Message, approval *bridge.BridgeApproval) (*BridgeApprovalFacts, error) {
	said := testBridgeApproval{}
	if err := json.Unmarshal(approval.GetCanonicalAction(), &said); err != nil {
		return nil, err
	}
	if said.NotAfterMs+aclDecisionSkewMs < statement.TimeMs {
		return nil, errors.New("the test decision expired")
	}
	return &BridgeApprovalFacts{ApprovalId: testConfigId(said.Approval), RuleId: said.RuleId, Uses: said.Uses, NotAfterMs: said.NotAfterMs}, nil
}

// A decision's rules stop at its uses: of three ids filed under a two-use decision the third is void, a retry of a
// held id adds none, and a rule whose id its approval does not fix is void. A withdrawn id stays in the fold with its
// approval until the decision's not_after, and is dropped only past it.
func TestADecisionsBridgeRulesStopAtItsUses(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, _ := testBridgeCast(net)
	net.log.settings.BridgeBodyJudge = testBridgeTestJudge()
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	notAfter := net.timeMs + 2*testBridgeDayMs
	approved := func(label string, a byte) (*bridge.BridgeRouteBody, []byte) {
		ruleId := testBridgeRuleId(label)
		body := testBridgeSubnet(testBridgePrefix(10, a, 0, 0, 16), "site")
		body.Approval = testBridgeApproval{Approval: "two uses", RuleId: ruleId, Uses: 2, NotAfterMs: notAfter}.wire(t)
		return body, ruleId
	}
	firstBody, firstId := approved("first", 1)
	secondBody, secondId := approved("second", 2)
	thirdBody, thirdId := approved("third", 3)
	first := net.mustPost(laptop, route, net.bridgeRoute(laptop, firstId, firstBody))
	retry := net.mustPost(laptop, route, net.bridgeRoute(laptop, firstId, firstBody))
	second := net.mustPost(laptop, route, net.bridgeRoute(laptop, secondId, secondBody))
	third := net.mustPost(laptop, route, net.bridgeRoute(laptop, thirdId, thirdBody))
	// an id its approval does not fix
	strayBody, _ := approved("stray", 4)
	stray := net.mustPost(laptop, route, net.bridgeRoute(laptop, testBridgeRuleId("not the approval's"), strayBody))

	open := net.bridgeLedger
	ledger := open()
	testBridgeDisposition(t, ledger, first.Pin.GetVersion(), BridgeDispositionActive)
	testBridgeDisposition(t, ledger, retry.Pin.GetVersion(), BridgeDispositionHeld)
	testBridgeDisposition(t, ledger, second.Pin.GetVersion(), BridgeDispositionActive)
	testBridgeDisposition(t, ledger, third.Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, stray.Pin.GetVersion(), BridgeDispositionVoid)
	if rule := ledger.Rule(firstId); rule == nil || rule.Standing || rule.ApprovalId != testConfigId("two uses") || rule.ApprovalNotAfterMs != notAfter {
		t.Fatalf("the first rule: %+v", rule)
	}
	if rule := ledger.Rule(thirdId); rule == nil || !rule.Void || rule.Active() {
		t.Fatalf("the third rule holds its id and nothing else: %+v", rule)
	}

	// a reader whose log installed no judge holds no verdict, so every approved rule waits: unjudged opens nothing
	unjudged := net.newReader().State()
	unjudgedLedger := unjudged.Bridge().Open(&BridgeLedgerReader{State: unjudged, RepoKeyAt: testConfigSealKeyAt(testConfigSealKey(1))})
	testBridgeDisposition(t, unjudgedLedger, first.Pin.GetVersion(), BridgeDispositionPending)
	if rule := unjudgedLedger.Rule(firstId); rule == nil || rule.Active() || !rule.Pending {
		t.Fatalf("an unjudged rule: %+v", rule)
	}

	// withdrawn, the id stays with its approval until the decision's not_after and its skew, then leaves the fold
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(firstId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
	ledger = open()
	kept := false
	for _, rule := range ledger.Rules(route) {
		kept = kept || (bytes.Equal(rule.RuleId, firstId) && rule.Withdrawn != nil && rule.ApprovalId == testConfigId("two uses"))
	}
	if !kept {
		t.Fatal("a withdrawn id left the fold before its decision's not_after")
	}
	state := net.log.State()
	for _, c := range []struct {
		timeMs int64
		kept   bool
	}{{timeMs: notAfter + aclDecisionSkewMs, kept: true}, {timeMs: notAfter + aclDecisionSkewMs + 1, kept: false}} {
		late := state.Bridge().Open(&BridgeLedgerReader{State: state, RepoKeyAt: testConfigSealKeyAt(testConfigSealKey(1)), TimeMs: c.timeMs})
		found := false
		for _, rule := range late.Rules(route) {
			found = found || bytes.Equal(rule.RuleId, firstId)
		}
		if found != c.kept {
			t.Errorf("at %d the withdrawn id is kept %v, want %v", c.timeMs, found, c.kept)
		}
	}
}

// Lets every decision spend, so CheckBridgeApproval's own checks are the ones that decide.
type testBridgeSpendCheck struct{}

func (self testBridgeSpendCheck) Spendable(state *AclState, decision *StoredApprovalDecision, action *StoredCanonicalAction, spender Id, pin *bridge.AuthPin, now time.Time) error {
	if state == nil || pin == nil {
		return errors.New("no state to spend under")
	}
	return nil
}

// A bridge_expose approval for target over cidrs, with one device decision by approver for requester.
func testBridgeExposeApproval(t testing.TB, label string, target Id, cidrs []string, requester Id, approver Id, notAfterMs int64) (*bridge.BridgeApproval, []byte) {
	action := testConfigMarshal(t, &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EXPOSE), Version: 1, TargetSidecarId: target.Bytes(), Cidrs: cidrs,
	})
	approvalId := testConfigId("expose approval " + label)
	payload, requestSha := sha256.Sum256(action), sha256.Sum256([]byte("expose request"))
	decision := &protocol.ApprovalDecision{
		ApprovalId: approvalId.Bytes(), RequestSha256: requestSha[:], PayloadSha256: payload[:],
		Decision: uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE), Uses: 1, NotAfterMillis: notAfterMs,
		ApproverMemberId: approver.Bytes(), Channel: uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE), RequesterSidecarId: requester.Bytes(),
		AuthPin: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)}, Version: 1,
	}
	signed := &bridge.Signed{Body: testConfigMarshal(t, decision), Signature: make([]byte, 64), Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION)}
	ruleId := BridgeRuleId(ApprovalEffectKey(approvalId, ApprovalActionId(approvalId, action)))
	return &bridge.BridgeApproval{CanonicalAction: action, Decisions: []*bridge.Signed{signed}}, ruleId[:]
}

// CheckBridgeApproval on real decisions, judged where each entry lands: a route under the id its approval fixes and
// inside its cidrs is in force; one under another id, outside the cidrs, signed by a sidecar the decision does not
// name, under an action for another target, or filed past the decision's not_after is void; and so is every one filed
// while no spend check is installed.
func TestABridgeApprovalVerifiesAsAGrantActivateDoes(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop, desktop := testBridgeCast(net)
	net.log.settings.BridgeBodyJudge = testBridgeJudge()
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	notAfter := net.timeMs + testBridgeDayMs

	// no spend check is installed yet, so the judge refuses every decision where its entry lands: an unbuilt check
	// fails closed
	unbuiltApproval, unbuiltId := testBridgeExposeApproval(t, "unbuilt", laptop.sidecarId, []string{"192.168.0.0/16"}, laptop.sidecarId, member, notAfter)
	unbuiltBody := testBridgeSubnet(testBridgePrefix(192, 168, 6, 0, 24), "site")
	unbuiltBody.Approval = unbuiltApproval
	unbuilt := net.mustPost(laptop, route, net.bridgeRoute(laptop, unbuiltId, unbuiltBody))
	if entry := testBridgeDisposition(t, net.bridgeLedger(), unbuilt.Pin.GetVersion(), BridgeDispositionVoid); !errors.Is(entry.Reason, ErrAclSpendCheckUnbuilt) {
		t.Fatalf("the unbuilt spend check: %v", entry.Reason)
	}
	net.log.settings.AclSpendCheck = testBridgeSpendCheck{}
	approval, ruleId := testBridgeExposeApproval(t, "first", laptop.sidecarId, []string{"192.168.0.0/16"}, laptop.sidecarId, member, notAfter)
	withApproval := func(prefix *bridge.BridgeIpv4Prefix) *bridge.BridgeRouteBody {
		body := testBridgeSubnet(prefix, "site")
		body.Approval = approval
		return body
	}
	outside := net.mustPost(laptop, route, net.bridgeRoute(laptop, ruleId, withApproval(testBridgePrefix(10, 1, 0, 0, 16))))
	otherId := net.mustPost(laptop, route, net.bridgeRoute(laptop, testBridgeRuleId("not the approval's"), withApproval(testBridgePrefix(192, 168, 7, 0, 24))))
	// a decision is spendable only by its requester
	desktopApproval, desktopRuleId := testBridgeExposeApproval(t, "desktop", desktop.sidecarId, []string{"192.168.0.0/16"}, laptop.sidecarId, member, notAfter)
	desktopBody := testBridgeSubnet(testBridgePrefix(192, 168, 8, 0, 24), "site")
	desktopBody.Approval = desktopApproval
	otherRequester := net.mustPost(desktop, route, net.bridgeRoute(desktop, desktopRuleId, desktopBody))
	// nor does an action that names another target cover the signer's own route
	targetApproval, targetRuleId := testBridgeExposeApproval(t, "target", desktop.sidecarId, []string{"192.168.0.0/16"}, laptop.sidecarId, member, notAfter)
	targetBody := testBridgeSubnet(testBridgePrefix(192, 168, 9, 0, 24), "site")
	targetBody.Approval = targetApproval
	otherTarget := net.mustPost(laptop, route, net.bridgeRoute(laptop, targetRuleId, targetBody))

	// the first filing of the fixed id is void above, so its id is held by a void filing: a second approval shows the
	// passing case under its own id
	goodApproval, goodId := testBridgeExposeApproval(t, "good", laptop.sidecarId, []string{"192.168.0.0/16", "10.20.0.0/16"}, laptop.sidecarId, member, notAfter)
	goodBody := testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")
	goodBody.Approval = goodApproval
	good := net.mustPost(laptop, route, net.bridgeRoute(laptop, goodId, goodBody))

	ledger := net.bridgeLedger()
	testBridgeDisposition(t, ledger, outside.Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, otherId.Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, otherRequester.Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, otherTarget.Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, good.Pin.GetVersion(), BridgeDispositionActive)
	if rule := ledger.Rule(goodId); rule == nil || !rule.Active() || rule.Standing || rule.ApprovalNotAfterMs != notAfter {
		t.Fatalf("the approved rule: %+v", rule)
	}

	// past the decision's not_after and its skew, the same approval files nothing new
	lateApproval, lateId := testBridgeExposeApproval(t, "late", laptop.sidecarId, []string{"172.16.0.0/12"}, laptop.sidecarId, member, notAfter)
	lateBody := testBridgeSubnet(testBridgePrefix(172, 16, 5, 0, 24), "site")
	lateBody.Approval = lateApproval
	net.timeMs = notAfter + aclDecisionSkewMs
	late := net.mustPost(laptop, route, net.bridgeRoute(laptop, lateId, lateBody))
	testBridgeDisposition(t, net.bridgeLedger(), late.Pin.GetVersion(), BridgeDispositionVoid)
}

// One device decision by approver for requester under label's approval_id: it approves the action stored as decided,
// with uses.
func testBridgeDecision(t testing.TB, label string, decided []byte, uses uint32, requester Id, approver Id, notAfterMs int64) *bridge.Signed {
	approvalId := testConfigId("expose approval " + label)
	payload, requestSha := sha256.Sum256(decided), sha256.Sum256([]byte("expose request"))
	decision := &protocol.ApprovalDecision{
		ApprovalId: approvalId.Bytes(), RequestSha256: requestSha[:], PayloadSha256: payload[:],
		Decision: uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE), Uses: uses, NotAfterMillis: notAfterMs,
		ApproverMemberId: approver.Bytes(), Channel: uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE), RequesterSidecarId: requester.Bytes(),
		AuthPin: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)}, Version: 1,
	}
	return &bridge.Signed{Body: testConfigMarshal(t, decision), Signature: make([]byte, 64), Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION)}
}

// A bridge_expose use of target over cidrs, as stored.
func testBridgeExposeUse(t testing.TB, target Id, cidrs ...string) []byte {
	return testConfigMarshal(t, &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EXPOSE), Version: 1, TargetSidecarId: target.Bytes(), Cidrs: cidrs,
	})
}

// The template of a multi-use bridge_expose for target, as stored: scope set, every use's cidrs its own.
func testBridgeExposeTemplate(t testing.TB, target Id) []byte {
	return testConfigMarshal(t, &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_EXPOSE), Version: 1, Scope: true, TargetSidecarId: target.Bytes(),
	})
}

// The rule id §17.8 derives from a use under label's approval.
func testBridgeUseRuleId(label string, use []byte) []byte {
	approvalId := testConfigId("expose approval " + label)
	ruleId := BridgeRuleId(ApprovalEffectKey(approvalId, ApprovalActionId(approvalId, use)))
	return ruleId[:]
}

// A subnet route over one prefix carrying approval.
func testBridgeApprovedSubnet(prefix *bridge.BridgeIpv4Prefix, approval *bridge.BridgeApproval) *bridge.BridgeRouteBody {
	body := testBridgeSubnet(prefix, "site")
	body.Approval = approval
	return body
}

// A multi-use decision (owner decision 218): with template_action set, a decision of 3 uses over the template files
// three rules, each under the id its own use fixes, and a fourth is void; a retry of a held use adds none. Without a
// template the same decision fixes one rule id, whatever its uses say.
func TestAMultiUseBridgeDecisionFilesUpToItsUses(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop, _ := testBridgeCast(net)
	net.log.settings.AclSpendCheck = testBridgeSpendCheck{}
	net.log.settings.BridgeBodyJudge = testBridgeJudge()
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	notAfter := net.timeMs + testBridgeDayMs
	template := testBridgeExposeTemplate(t, laptop.sidecarId)
	decision := testBridgeDecision(t, "three uses", template, 3, laptop.sidecarId, member, notAfter)
	verdicts := []ConfigVerdict{}
	ruleIds := [][]byte{}
	for _, a := range []byte{1, 2, 3, 4} {
		use := testBridgeExposeUse(t, laptop.sidecarId, "192.168."+string(rune('0'+a))+".0/24")
		approval := &bridge.BridgeApproval{CanonicalAction: use, TemplateAction: template, Decisions: []*bridge.Signed{decision}}
		ruleId := testBridgeUseRuleId("three uses", use)
		ruleIds = append(ruleIds, ruleId)
		verdicts = append(verdicts, net.mustPost(laptop, route, net.bridgeRoute(laptop, ruleId, testBridgeApprovedSubnet(testBridgePrefix(192, 168, a, 0, 24), approval))))
	}
	// a retry of the first use files its held id again
	firstUse := testBridgeExposeUse(t, laptop.sidecarId, "192.168.1.0/24")
	retryApproval := &bridge.BridgeApproval{CanonicalAction: firstUse, TemplateAction: template, Decisions: []*bridge.Signed{decision}}
	retry := net.mustPost(laptop, route, net.bridgeRoute(laptop, ruleIds[0], testBridgeApprovedSubnet(testBridgePrefix(192, 168, 1, 0, 24), retryApproval)))

	ledger := net.bridgeLedger()
	for i, verdict := range verdicts[:3] {
		testBridgeDisposition(t, ledger, verdict.Pin.GetVersion(), BridgeDispositionActive)
		if rule := ledger.Rule(ruleIds[i]); rule == nil || !rule.Active() || rule.ApprovalId != testConfigId("expose approval three uses") {
			t.Fatalf("use %d: %+v", i, rule)
		}
	}
	testBridgeDisposition(t, ledger, verdicts[3].Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, retry.Pin.GetVersion(), BridgeDispositionHeld)

	// the same decision over a use, with no template: one action, so one rule id
	single := testBridgeExposeUse(t, laptop.sidecarId, "10.9.0.0/16")
	singleDecision := testBridgeDecision(t, "no template", single, 3, laptop.sidecarId, member, notAfter)
	singleApproval := &bridge.BridgeApproval{CanonicalAction: single, Decisions: []*bridge.Signed{singleDecision}}
	singleId := testBridgeUseRuleId("no template", single)
	first := net.mustPost(laptop, route, net.bridgeRoute(laptop, singleId, testBridgeApprovedSubnet(testBridgePrefix(10, 9, 1, 0, 24), singleApproval)))
	other := net.mustPost(laptop, route, net.bridgeRoute(laptop, testBridgeRuleId("a second id"), testBridgeApprovedSubnet(testBridgePrefix(10, 9, 2, 0, 24), singleApproval)))
	ledger = net.bridgeLedger()
	testBridgeDisposition(t, ledger, first.Pin.GetVersion(), BridgeDispositionActive)
	testBridgeDisposition(t, ledger, other.Pin.GetVersion(), BridgeDispositionVoid)
}

// A template binds its uses, each refusal beside the approval that holds: a use that does not match its template (a
// field the template fills that the use does not equal), a template that is no scope action, one that does not parse
// as a stored action, a template the decisions do not hash, and a template under a single-use decision are each void.
func TestABridgeApprovalHoldsAUseToItsTemplate(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop, desktop := testBridgeCast(net)
	net.log.settings.AclSpendCheck = testBridgeSpendCheck{}
	net.log.settings.BridgeBodyJudge = testBridgeJudge()
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	notAfter := net.timeMs + testBridgeDayMs
	template := testBridgeExposeTemplate(t, laptop.sidecarId)
	file := func(label string, a byte, templateAction []byte, decided []byte, uses uint32) ConfigVerdict {
		t.Helper()
		use := testBridgeExposeUse(t, laptop.sidecarId, "172.16."+string(rune('0'+a))+".0/24")
		approval := &bridge.BridgeApproval{
			CanonicalAction: use, TemplateAction: templateAction,
			Decisions: []*bridge.Signed{testBridgeDecision(t, label, decided, uses, laptop.sidecarId, member, notAfter)},
		}
		return net.mustPost(laptop, route, net.bridgeRoute(laptop, testBridgeUseRuleId(label, use), testBridgeApprovedSubnet(testBridgePrefix(172, 16, a, 0, 24), approval)))
	}
	good := file("good", 1, template, template, 2)
	otherTarget := testBridgeExposeTemplate(t, desktop.sidecarId)
	mismatch := file("mismatch", 2, otherTarget, otherTarget, 2)
	unscoped := testBridgeExposeUse(t, laptop.sidecarId)
	noScope := file("no scope", 3, unscoped, unscoped, 2)
	unparsed := []byte{0xff, 0xff, 0xff}
	notParsed := file("not parsed", 4, unparsed, unparsed, 2)
	notHashed := file("not hashed", 5, template, testBridgeExposeUse(t, laptop.sidecarId, "172.16.5.0/24"), 2)
	singleUse := file("single use", 6, template, template, 1)

	ledger := net.bridgeLedger()
	testBridgeDisposition(t, ledger, good.Pin.GetVersion(), BridgeDispositionActive)
	for name, verdict := range map[string]ConfigVerdict{
		"a use outside its template": mismatch, "a template with no scope": noScope, "a template that does not parse": notParsed,
		"a template the decisions do not hash": notHashed, "a template under a single-use decision": singleUse,
	} {
		if entry := testBridgeEntryAt(t, ledger, verdict.Pin.GetVersion()); entry.Disposition != BridgeDispositionVoid || !errors.Is(entry.Reason, ErrBridgeVoid) {
			t.Errorf("%s: disposition %d, %v", name, entry.Disposition, entry.Reason)
		}
	}
}

// FS-14's shape for §17.8: a base's rows carry no bridge statement, so the base's tail re-applies the ones past its
// folded_through, and a new device, a restored reader and a keyless gate hold the BridgeLog the long-running reader
// has, withdrawal and admin signer included.
func TestABaseReappliesBridgeStatementsForANewDevice(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	routeId, body := testBridgeRuleId("route"), testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)))
	foldedThrough := net.n
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, routeId, body))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(desktop, testBridgeIpv4(100, 80, 3, 8)))
	net.mustRefuse(desktop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(routeId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET), ErrConfigAuthority)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(routeId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN))
	before := net.log.State().Bridge()
	if before.Len() != 4 {
		t.Fatalf("%d statements before the base", before.Len())
	}

	net.fold(net.owner, foldedThrough, 2)
	want := net.log.State().Bridge()
	if want.Len() != 3 || !reflect.DeepEqual(want.Statements(), before.Statements()[1:]) {
		t.Fatalf("the long-running reader holds %d statements past the fold", want.Len())
	}
	if !want.Statements()[1].SignerAdmin || want.Statements()[0].SignerAdmin {
		t.Error("the admin's address and the advertiser's route keep their signers' classes over the base")
	}
	for i, reader := range net.everyReader() {
		got := reader.State().Bridge()
		if !reflect.DeepEqual(got.Statements(), want.Statements()) {
			t.Errorf("reader %d holds %d statements, the long-running reader %d", i, got.Len(), want.Len())
		}
		if rule := got.Rule(routeId); rule == nil || rule.Withdrawn == nil {
			t.Errorf("reader %d: the route's withdrawal did not re-apply", i)
		}
	}
	// and each judges the next filing alike: the withdrawn id is refused
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, routeId, body), ErrConfigRule)
	net.everyReaderAgrees()
}

// The first BridgeAddress in log order wins; a second for an addressed host, a taken address, the block's services,
// x.y.z.0, x.y.z.255 and the upper /17 while the lower has room are void, each beside a claim that holds.
func TestTheFirstBridgeAddressInLogOrderWins(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop, desktop := testBridgeCast(net)
	_, otherLaptop := net.consentedMember("other")
	phone, tablet := net.device("m phone", member), net.device("m tablet", member)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(laptop, tablet, 0)
	address := bridge.SignedType_SIGNED_BRIDGE_ADDRESS
	claim := func(device testConfigDevice, ipv4 uint32) uint64 {
		return net.mustPost(device, address, net.bridgeAddress(device, ipv4)).Pin.GetVersion()
	}
	first := claim(laptop, testBridgeIpv4(100, 80, 3, 7))
	taken := claim(otherLaptop, testBridgeIpv4(100, 80, 3, 7))
	second := claim(laptop, testBridgeIpv4(100, 80, 3, 9))
	otherwise := claim(otherLaptop, testBridgeIpv4(100, 80, 3, 9))
	services := claim(desktop, testBridgeIpv4(100, 80, 0, 9))
	zero := claim(desktop, testBridgeIpv4(100, 80, 4, 0))
	broadcast := claim(desktop, testBridgeIpv4(100, 80, 4, 255))
	upper := claim(desktop, testBridgeIpv4(100, 80, 255, 254))
	last := claim(desktop, testBridgeIpv4(100, 80, 127, 254))

	ledger := net.bridgeLedger()
	for n, want := range map[uint64]BridgeDisposition{
		first: BridgeDispositionActive, taken: BridgeDispositionVoid, second: BridgeDispositionVoid, otherwise: BridgeDispositionActive,
		services: BridgeDispositionVoid, zero: BridgeDispositionVoid, broadcast: BridgeDispositionVoid, upper: BridgeDispositionVoid,
		last: BridgeDispositionActive,
	} {
		testBridgeDisposition(t, ledger, n, want)
	}
	addresses := ledger.Addresses()
	if len(addresses) != 3 || ledger.LowerTakenCount() != 3 {
		t.Fatalf("%d addresses, %d of the lower /17 taken", len(addresses), ledger.LowerTakenCount())
	}
	if held := ledger.Address(laptop.sidecarId); held == nil || held.HostBits != 3<<8|7 || held.Statement.N != first {
		t.Errorf("the laptop's address: %+v", held)
	}
	if held := ledger.Address(otherLaptop.sidecarId); held == nil || held.HostBits != 3<<8|9 {
		t.Errorf("the other laptop's address: %+v", held)
	}
	if ledger.Address(phone.sidecarId) != nil || !ledger.HostBitsTaken(3<<8|7) || ledger.HostBitsTaken(3<<8|8) {
		t.Error("what the ledger says is taken")
	}
}

// I-14: a released address is a tombstone for 30 days by the log's time. A day short of that a claim of it is void and
// the ledger still holds it taken; past it the next claim holds.
func TestAReleasedBridgeAddressIsATombstoneForThirtyDays(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop, desktop := testBridgeCast(net)
	phone, tablet := net.device("m phone", member), net.device("m tablet", member)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(laptop, tablet, 0)
	address := bridge.SignedType_SIGNED_BRIDGE_ADDRESS
	ipv4 := testBridgeIpv4(100, 80, 3, 7)
	net.mustPost(desktop, address, net.bridgeAddress(desktop, ipv4))
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(desktop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	releasedMs := net.timeMs

	ledger := net.bridgeLedger()
	tombstones := ledger.Tombstones()
	if len(ledger.Addresses()) != 0 || len(tombstones) != 1 || tombstones[0].HostBits != 3<<8|7 || !tombstones[0].ReleasedMsKnown || tombstones[0].ReleasedMs != releasedMs {
		t.Fatalf("after the revocation: %d addresses, tombstones %+v", len(ledger.Addresses()), tombstones)
	}

	net.timeMs = releasedMs + testBridgeTombstoneMs - testBridgeDayMs
	early := net.mustPost(phone, address, net.bridgeAddress(phone, ipv4))
	ledger = net.bridgeLedger()
	testBridgeDisposition(t, ledger, early.Pin.GetVersion(), BridgeDispositionVoid)
	if tombstones := ledger.Tombstones(); len(tombstones) != 1 || !tombstones[0].Holds(ledger.TimeMs()) || !ledger.HostBitsTaken(3<<8|7) {
		t.Errorf("a tombstone a day short of 30: %+v", tombstones)
	}

	// the entry's own time is 1 s past the tip's, so this one lands exactly 30 days after the release
	net.timeMs = releasedMs + testBridgeTombstoneMs - 1000
	exact := net.mustPost(tablet, address, net.bridgeAddress(tablet, ipv4))
	ledger = net.bridgeLedger()
	testBridgeDisposition(t, ledger, exact.Pin.GetVersion(), BridgeDispositionActive)
	if held := ledger.Address(tablet.sidecarId); held == nil || held.HostBits != 3<<8|7 || len(ledger.Tombstones()) != 0 {
		t.Errorf("after 30 days: %+v, tombstones %v", held, ledger.Tombstones())
	}
	// the phone's void claim left it unaddressed, so it may still claim another
	free := net.mustPost(phone, address, net.bridgeAddress(phone, testBridgeIpv4(100, 80, 3, 8)))
	testBridgeDisposition(t, net.bridgeLedger(), free.Pin.GetVersion(), BridgeDispositionActive)
}

// A body sealed to a generation the reader lacks is pending: its id is held and nothing is active, a bodiless
// withdrawal of it applies at once, and it opens when the key arrives. A seal that does not open is void and an alarm,
// and its id stays held.
func TestABridgeBodyWaitsForItsGenerationAndABrokenSealAlarms(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	pendingId, brokenId := testBridgeRuleId("pending"), testBridgeRuleId("broken")
	body := testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")
	waits := net.mustPost(laptop, route, net.bridgeRouteAt(laptop, pendingId, body, 2))
	refiling := net.mustPost(laptop, route, net.bridgeRouteAt(laptop, pendingId, body, 2))
	broken := net.bridgeRoute(desktop, brokenId, body)
	broken.SealedBody[len(broken.SealedBody)-1] ^= 1
	alarm := net.mustPost(desktop, route, broken)
	held := net.mustPost(desktop, route, net.bridgeRoute(desktop, brokenId, testBridgeSubnet(testBridgePrefix(10, 4, 0, 0, 16), "site")))

	ledger := net.bridgeLedger()
	if entry := testBridgeDisposition(t, ledger, waits.Pin.GetVersion(), BridgeDispositionPending); entry.Generation != 2 {
		t.Errorf("the pending entry waits for generation %d", entry.Generation)
	}
	testBridgeDisposition(t, ledger, refiling.Pin.GetVersion(), BridgeDispositionPending)
	if rule := ledger.Rule(pendingId); rule == nil || !rule.Pending || rule.Active() || rule.Route != nil {
		t.Fatalf("the pending rule: %+v", rule)
	}
	if pending := ledger.Pending(); len(pending) != 2 {
		t.Errorf("%d pending entries", len(pending))
	}
	testBridgeDisposition(t, ledger, alarm.Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, held.Pin.GetVersion(), BridgeDispositionVoid)
	if alarms := ledger.Alarms(); len(alarms) != 1 || alarms[0].Statement.N != alarm.Pin.GetVersion() {
		t.Errorf("the alarms: %v", alarms)
	}

	withKey := net.bridgeLedger(testConfigSealKey(2))
	testBridgeDisposition(t, withKey, waits.Pin.GetVersion(), BridgeDispositionActive)
	testBridgeDisposition(t, withKey, refiling.Pin.GetVersion(), BridgeDispositionHeld)
	if rule := withKey.Rule(pendingId); rule == nil || !rule.Active() || !proto.Equal(rule.Route, body) {
		t.Fatalf("the rule once its generation arrived: %+v", rule)
	}

	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(pendingId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
	if rule := net.bridgeLedger().Rule(pendingId); rule == nil || rule.Withdrawn == nil || !rule.Pending {
		t.Errorf("a bodiless withdrawal of a pending rule: %+v", rule)
	}
	// a reader with no key at all still holds every id
	keyless := net.log.State().Bridge().Open(nil)
	if rule := keyless.Rule(brokenId); rule == nil || !rule.Pending {
		t.Errorf("a keyless reader's rule: %+v", rule)
	}
}

// D-BRIDGE-8 at body level: an identical prefix is an HA replica at one named site or a remap; nesting passes;
// another site's identical prefix, or one naming no site, is void, each beside the advertisement that holds.
func TestIdenticalBridgePrefixesAreReplicasOrRemaps(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop, desktop := testBridgeCast(net)
	phone, tablet := net.device("m phone", member), net.device("m tablet", member)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(laptop, tablet, 0)
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	lan := testBridgePrefix(192, 168, 1, 0, 24)
	file := func(device testConfigDevice, label string, body *bridge.BridgeRouteBody) uint64 {
		return net.mustPost(device, route, net.bridgeRoute(device, testBridgeRuleId(label), body)).Pin.GetVersion()
	}
	first := file(laptop, "first", testBridgeSubnet(lan, "office"))
	replica := file(desktop, "replica", testBridgeSubnet(lan, "office"))
	otherSite := file(phone, "other site", testBridgeSubnet(lan, "home"))
	noSite := file(phone, "no site", testBridgeSubnet(lan, ""))
	remapBody := testBridgeSubnet(lan, "home")
	remapBody.ExposedPrefix = testBridgePrefix(100, 80, 200, 0, 24)
	remap := file(phone, "remap", remapBody)
	nested := file(tablet, "nested", testBridgeSubnet(testBridgePrefix(192, 168, 0, 0, 16), "campus"))
	// an exposed prefix another site's route holds, and one that maps a prefix of another length
	clashBody := testBridgeSubnet(testBridgePrefix(10, 1, 1, 0, 24), "lab")
	clashBody.ExposedPrefix = testBridgePrefix(100, 80, 200, 0, 24)
	clash := file(tablet, "clash", clashBody)
	widthBody := testBridgeSubnet(testBridgePrefix(10, 2, 0, 0, 16), "lab")
	widthBody.ExposedPrefix = testBridgePrefix(100, 80, 201, 0, 24)
	width := file(tablet, "width", widthBody)
	lowerBody := testBridgeSubnet(testBridgePrefix(10, 3, 1, 0, 24), "lab")
	lowerBody.ExposedPrefix = testBridgePrefix(100, 80, 5, 0, 24)
	lower := file(tablet, "lower", lowerBody)
	exit := file(tablet, "exit", &bridge.BridgeRouteBody{Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT, Weight: 1})

	ledger := net.bridgeLedger()
	for n, want := range map[uint64]BridgeDisposition{
		first: BridgeDispositionActive, replica: BridgeDispositionActive, otherSite: BridgeDispositionVoid, noSite: BridgeDispositionVoid,
		remap: BridgeDispositionActive, nested: BridgeDispositionActive, clash: BridgeDispositionVoid, width: BridgeDispositionVoid,
		lower: BridgeDispositionVoid, exit: BridgeDispositionActive,
	} {
		testBridgeDisposition(t, ledger, n, want)
	}
	if ranges := ledger.UpperRanges(); len(ranges) != 1 || ranges[0] != [2]uint32{200 << 8, 200<<8 | 255} {
		t.Errorf("the upper /17's ranges: %v", ranges)
	}
	active := 0
	for _, rule := range ledger.Rules(route) {
		if rule.Active() {
			active += 1
		}
	}
	if active != 5 {
		t.Errorf("%d routes in force, want 5", active)
	}
}

// A filing of a held id changes only weight, site_id and drain_seconds and activates nothing; one that changes a
// prefix is void and leaves the rule as it was. A map's refiling changes drain_seconds alone.
func TestAFilingOfAHeldBridgeIdChangesOnlyItsWeightSiteAndDrain(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	route, mapType := bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_MAP
	routeId, mapId := testBridgeRuleId("route"), testBridgeRuleId("map")
	body := testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")
	first := net.mustPost(laptop, route, net.bridgeRoute(laptop, routeId, body))
	changed := proto.Clone(body).(*bridge.BridgeRouteBody)
	changed.Weight, changed.SiteId, changed.DrainSeconds = 5, []byte("moved"), 60
	held := net.mustPost(laptop, route, net.bridgeRoute(laptop, routeId, changed))
	widened := proto.Clone(changed).(*bridge.BridgeRouteBody)
	widened.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 168, 0, 0, 16)}
	wider := net.mustPost(laptop, route, net.bridgeRoute(laptop, routeId, widened))
	// the id level refuses a held id from another signer or as another kind
	net.mustRefuse(desktop, route, net.bridgeRoute(desktop, routeId, body), ErrConfigAuthority)
	net.mustRefuse(laptop, mapType, net.bridgeMap(laptop, routeId, 0, testBridgeMapBody(1, 80, 80)), ErrConfigRule)

	mapBody := testBridgeMapBody(testBridgeIpv4(100, 80, 3, 8), 8443, 443)
	expires := net.timeMs + testConfigHourMs
	net.mustPost(desktop, mapType, net.bridgeMap(desktop, mapId, expires, mapBody))
	drained := proto.Clone(mapBody).(*bridge.BridgeMapBody)
	drained.DrainSeconds = 120
	mapHeld := net.mustPost(desktop, mapType, net.bridgeMap(desktop, mapId, expires, drained))
	retargeted := proto.Clone(drained).(*bridge.BridgeMapBody)
	retargeted.TargetPort = 22
	mapChanged := net.mustPost(desktop, mapType, net.bridgeMap(desktop, mapId, expires, retargeted))
	laterExpiry := net.mustPost(desktop, mapType, net.bridgeMap(desktop, mapId, expires+testConfigHourMs, drained))

	ledger := net.bridgeLedger()
	testBridgeDisposition(t, ledger, first.Pin.GetVersion(), BridgeDispositionActive)
	testBridgeDisposition(t, ledger, held.Pin.GetVersion(), BridgeDispositionHeld)
	testBridgeDisposition(t, ledger, wider.Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, mapHeld.Pin.GetVersion(), BridgeDispositionHeld)
	testBridgeDisposition(t, ledger, mapChanged.Pin.GetVersion(), BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, laterExpiry.Pin.GetVersion(), BridgeDispositionVoid)
	if rule := ledger.Rule(routeId); rule == nil || !proto.Equal(rule.Route, changed) || rule.First.N != first.Pin.GetVersion() || rule.Newest.N != held.Pin.GetVersion() {
		t.Errorf("the held route: %+v", rule)
	}
	if rule := ledger.Rule(mapId); rule == nil || !proto.Equal(rule.Map, drained) || rule.Expires != expires {
		t.Errorf("the held map: %+v", rule)
	}
	if rules := ledger.Rules(mapType); len(rules) != 1 {
		t.Errorf("%d maps", len(rules))
	}
}

// A map's body: ICMP with ports, ports out of order, a target that is no address and a second range under a
// target_port are void, beside one of each protocol that holds.
func TestABridgeMapsBodyIsHeldToItsShape(t *testing.T) {
	good := testBridgeMapBody(testBridgeIpv4(100, 80, 3, 8), 8443, 443)
	if err := bridgeCheckMapBody(good, nil); err != nil {
		t.Fatal(err)
	}
	icmp := &bridge.BridgeMapBody{MatchPrefix: good.GetMatchPrefix(), Protocol: 1, Target: good.GetTarget()}
	if err := bridgeCheckMapBody(icmp, nil); err != nil {
		t.Fatal(err)
	}
	change := func(edit func(body *bridge.BridgeMapBody)) *bridge.BridgeMapBody {
		body := proto.Clone(good).(*bridge.BridgeMapBody)
		edit(body)
		return body
	}
	for name, body := range map[string]*bridge.BridgeMapBody{
		"icmp with ports":    change(func(body *bridge.BridgeMapBody) { body.Protocol = 1 }),
		"another protocol":   change(func(body *bridge.BridgeMapBody) { body.Protocol = 47 }),
		"ports out of order": change(func(body *bridge.BridgeMapBody) { body.Ports = []*bridge.BridgePortRange{{First: 90, Last: 80}} }),
		"a port past 65535":  change(func(body *bridge.BridgeMapBody) { body.Ports = []*bridge.BridgePortRange{{First: 80, Last: 70000}} }),
		"overlapping ranges": change(func(body *bridge.BridgeMapBody) {
			body.Ports = []*bridge.BridgePortRange{{First: 80, Last: 90}, {First: 90, Last: 95}}
		}),
		"two ranges one port": change(func(body *bridge.BridgeMapBody) {
			body.Ports = []*bridge.BridgePortRange{{First: 80, Last: 80}, {First: 90, Last: 90}}
		}),
		"a short target":     change(func(body *bridge.BridgeMapBody) { body.Target = []byte{10, 0, 0} }),
		"a wide match":       change(func(body *bridge.BridgeMapBody) { body.MatchPrefix = testBridgePrefix(100, 0, 0, 0, 8) }),
		"bits past the mask": change(func(body *bridge.BridgeMapBody) { body.MatchPrefix = testBridgePrefix(100, 80, 3, 8, 24) }),
		"a long drain":       change(func(body *bridge.BridgeMapBody) { body.DrainSeconds = 3601 }),
		"no match prefix":    change(func(body *bridge.BridgeMapBody) { body.MatchPrefix = nil }),
	} {
		if err := bridgeCheckMapBody(body, nil); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// D-BRIDGE-16 and §22.5's §17 row: a block is a /16 in 100.64.0.0/10 or RFC 1918, a /15 and every range outside
// refused; a head carrying a refused block, one no admin signed, or none where the reader held one leaves the reader
// its previous block and an alarm, and the head's own block is taken when it passes.
func TestAHeadsBridgeBlockOutsideTheRangesIsRefusedAndTheReaderKeepsItsBlock(t *testing.T) {
	block := func(prefix *bridge.BridgeIpv4Prefix) *bridge.BridgeBlock {
		return &bridge.BridgeBlock{Ipv4Prefix: prefix}
	}
	for _, prefix := range []*bridge.BridgeIpv4Prefix{
		testBridgePrefix(100, 64, 0, 0, 16), testBridgePrefix(100, 127, 0, 0, 16), testBridgePrefix(10, 0, 0, 0, 16), testBridgePrefix(10, 255, 0, 0, 16),
		testBridgePrefix(172, 16, 0, 0, 16), testBridgePrefix(172, 31, 0, 0, 16), testBridgePrefix(192, 168, 0, 0, 16),
	} {
		if err := CheckBridgeBlock(block(prefix)); err != nil {
			t.Errorf("%v: %v", prefix, err)
		}
	}
	for _, prefix := range []*bridge.BridgeIpv4Prefix{
		testBridgePrefix(100, 63, 0, 0, 16), testBridgePrefix(100, 128, 0, 0, 16), testBridgePrefix(172, 15, 0, 0, 16), testBridgePrefix(172, 32, 0, 0, 16),
		testBridgePrefix(192, 169, 0, 0, 16), testBridgePrefix(169, 254, 0, 0, 16), testBridgePrefix(8, 8, 0, 0, 16), testBridgePrefix(11, 0, 0, 0, 16),
		testBridgePrefix(100, 64, 0, 0, 15), testBridgePrefix(100, 64, 0, 0, 17), testBridgePrefix(10, 0, 0, 0, 8), testBridgePrefix(100, 80, 1, 0, 16), nil,
	} {
		if err := CheckBridgeBlock(block(prefix)); !errors.Is(err, ErrBridgeBlockRefused) {
			t.Errorf("%v: %v", prefix, err)
		}
	}
	draining := &bridge.BridgeBlock{Ipv4Prefix: testBridgePrefix(100, 80, 0, 0, 16), PreviousPrefix: testBridgePrefix(100, 81, 0, 0, 16), DrainUntil: 1}
	if err := CheckBridgeBlock(draining); err != nil {
		t.Error(err)
	}
	for name, refused := range map[string]*bridge.BridgeBlock{
		"a previous block outside the ranges": {Ipv4Prefix: draining.Ipv4Prefix, PreviousPrefix: testBridgePrefix(8, 8, 0, 0, 16), DrainUntil: 1},
		"a previous block with no drain":      {Ipv4Prefix: draining.Ipv4Prefix, PreviousPrefix: draining.PreviousPrefix},
		"a drain with no previous block":      {Ipv4Prefix: draining.Ipv4Prefix, DrainUntil: 1},
		"the block as its own previous":       {Ipv4Prefix: draining.Ipv4Prefix, PreviousPrefix: draining.Ipv4Prefix, DrainUntil: 1},
		"no block":                            nil,
	} {
		if err := CheckBridgeBlock(refused); !errors.Is(err, ErrBridgeBlockRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}

	net := newTestConfigNet(t)
	_, laptop, _ := testBridgeCast(net)
	state := net.log.State()
	headWith := func(signer testConfigDevice, held *bridge.BridgeBlock) *ConfigHead {
		head, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, net.sign(signer, bridge.SignedType_SIGNED_BRIDGE_BLOCK, held))
		if err != nil {
			t.Fatal(err)
		}
		return head
	}
	previous := block(testBridgePrefix(100, 80, 0, 0, 16))
	next := block(testBridgePrefix(10, 44, 0, 0, 16))

	if got, err := ReadBridgeBlock(testConfigHead(t, net), state, nil); got != nil || err != nil {
		t.Errorf("a head with no block, read by a reader that held none: %v, %v", got, err)
	}
	if got, err := ReadBridgeBlock(headWith(net.owner, next), state, previous); err != nil || !proto.Equal(got, next) {
		t.Errorf("an admin's valid block: %v, %v", got, err)
	}
	for name, head := range map[string]*ConfigHead{
		"outside the ranges": headWith(net.owner, block(testBridgePrefix(8, 8, 0, 0, 16))),
		"a /15":              headWith(net.owner, block(testBridgePrefix(100, 64, 0, 0, 15))),
		"signed by no admin": headWith(laptop, next),
		"dropped":            testConfigHead(t, net),
	} {
		got, err := ReadBridgeBlock(head, state, previous)
		if !errors.Is(err, ErrBridgeBlockRefused) || got != previous {
			t.Errorf("%s: the reader holds %v with %v, want its previous block and the alarm", name, got, err)
		}
	}
}

// I-18 and D-BRIDGE-6: a canary prefix, port and address appear only inside sealed bodies. Nothing a server holds of
// the statements, their entries as sequenced, the id-level fold or the rows a base would carry, shows the canary in
// any encoding the wire uses, while a reader with the key reads each of them back.
func TestABridgeCanaryAppearsOnlyInsideSealedBodies(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	canaryAddress := testBridgeIpv4(100, 93, 77, 201)
	canaryPrefix := testBridgePrefix(203, 0, 113, 0, 24)
	canaryPort, canaryTarget := uint32(51234), []byte{198, 51, 100, 77}
	routeId, mapId := testBridgeRuleId("canary route"), testBridgeRuleId("canary map")
	firstEntry := len(net.entries)
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(laptop, canaryAddress))
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, routeId, testBridgeSubnet(canaryPrefix, "canary site")))
	mapBody := &bridge.BridgeMapBody{
		MatchPrefix: &bridge.BridgeIpv4Prefix{Address: canaryAddress, Length: 32}, Protocol: 6,
		Ports: []*bridge.BridgePortRange{{First: canaryPort, Last: canaryPort}}, Target: canaryTarget, TargetPort: canaryPort,
	}
	net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMap(desktop, mapId, 0, mapBody))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_ALIAS, net.bridgeAlias(&bridge.BridgeAliasBody{
		ShareId: testConfigId("canary share").Bytes(), AliasPrefix: testBridgePrefix(100, 93, 201, 0, 24), Host: testConfigId("canary host").Bytes(),
	}))
	canaryExit := testConfigId("canary exit")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgress(laptop.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS,
		&bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{canaryExit.Bytes()}}))

	needles := map[string][]byte{
		"the canary site": []byte("canary site"), "the map's target": canaryTarget, "the alias's host": testConfigId("canary host").Bytes(),
		"the exit": canaryExit.Bytes(),
	}
	for name, value := range map[string]uint32{"the address": canaryAddress, "the prefix": canaryPrefix.GetAddress(), "the alias prefix": testBridgeIpv4(100, 93, 201, 0)} {
		needles[name+", big-endian"] = binary.BigEndian.AppendUint32(nil, value)
		needles[name+", as fixed32"] = binary.LittleEndian.AppendUint32(nil, value)
	}
	// a port is a varint wherever the wire carries one
	needles["the port"] = binary.AppendUvarint(nil, uint64(canaryPort))

	state := net.log.State()
	visible := map[string][]byte{"the rows a base carries": testConfigRowsBytes(t, state)}
	for i, entryBytes := range net.entries[firstEntry:] {
		visible["entry "+string(rune('a'+i))] = entryBytes
	}
	fold := []byte{}
	for _, statement := range state.Bridge().Statements() {
		fold = append(fold, statement.StatementId[:]...)
		fold = append(fold, statement.Seal.NetworkId...)
		fold = append(fold, statement.Seal.Nonce...)
		fold = append(fold, statement.RuleId...)
		fold = append(fold, statement.Subject.Bytes()...)
		fold = append(fold, statement.Signer.Bytes()...)
		for _, routeRuleId := range statement.RouteRuleIds {
			fold = append(fold, routeRuleId...)
		}
		fold = binary.BigEndian.AppendUint64(fold, uint64(statement.Expires))
	}
	visible["the id-level fold"] = fold
	for place, data := range visible {
		for name, needle := range needles {
			if bytes.Contains(data, needle) {
				t.Errorf("%s shows %s", place, name)
			}
		}
	}

	ledger := net.bridgeLedger()
	if held := ledger.Address(laptop.sidecarId); held == nil || held.HostBits != canaryAddress&0xffff {
		t.Errorf("the reader's address: %+v", held)
	}
	if rule := ledger.Rule(routeId); rule == nil || !proto.Equal(rule.Route.GetPrefixes()[0], canaryPrefix) {
		t.Errorf("the reader's route: %+v", rule)
	}
	if rule := ledger.Rule(mapId); rule == nil || rule.Map.GetTargetPort() != canaryPort || !bytes.Equal(rule.Map.GetTarget(), canaryTarget) {
		t.Errorf("the reader's map: %+v", rule)
	}
	if aliases := ledger.Aliases(); len(aliases) != 1 || aliases[0].Body.GetAliasPrefix().GetAddress() != testBridgeIpv4(100, 93, 201, 0) {
		t.Errorf("the reader's aliases: %v", aliases)
	}
	if egress := ledger.Egress(); len(egress) != 1 || len(egress[0].ExitSidecarIds) != 1 || egress[0].ExitSidecarIds[0] != canaryExit {
		t.Errorf("the reader's egress: %+v", egress)
	}
}

// Aliases and exposed prefixes hold the upper /17 apart: an alias over another, one in the lower /17 or wider than
// /17, and a second for one target of a share are void; and so is one a device filed that was no admin's where it
// landed (DESIGN-DETAILS 12.2.3), beside the admin's that holds.
func TestBridgeAliasesHoldTheUpperHalfApart(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, _ := testBridgeCast(net)
	aliasBy := func(signer testConfigDevice, target uint32, prefix *bridge.BridgeIpv4Prefix) uint64 {
		body := &bridge.BridgeAliasBody{ShareId: testConfigId("share").Bytes(), TargetIndex: target, AliasPrefix: prefix, Host: testConfigId("far host").Bytes()}
		return net.mustPost(signer, bridge.SignedType_SIGNED_BRIDGE_ALIAS, net.bridgeAlias(body)).Pin.GetVersion()
	}
	alias := func(target uint32, prefix *bridge.BridgeIpv4Prefix) uint64 {
		return aliasBy(net.owner, target, prefix)
	}
	byMember := aliasBy(laptop, 5, testBridgePrefix(100, 80, 131, 0, 24))
	first := alias(0, testBridgePrefix(100, 80, 128, 0, 24))
	over := alias(1, testBridgePrefix(100, 80, 128, 0, 23))
	again := alias(0, testBridgePrefix(100, 80, 130, 0, 24))
	lower := alias(2, testBridgePrefix(100, 80, 64, 0, 24))
	wide := alias(3, testBridgePrefix(100, 80, 0, 0, 16))
	second := alias(4, testBridgePrefix(100, 80, 129, 0, 24))
	ledger := net.bridgeLedger()
	for n, want := range map[uint64]BridgeDisposition{
		byMember: BridgeDispositionVoid, first: BridgeDispositionActive, over: BridgeDispositionVoid, again: BridgeDispositionVoid,
		lower: BridgeDispositionVoid, wide: BridgeDispositionVoid, second: BridgeDispositionActive,
	} {
		testBridgeDisposition(t, ledger, n, want)
	}
	if ranges := ledger.UpperRanges(); len(ranges) != 2 || ranges[0] != [2]uint32{128 << 8, 128<<8 | 255} || ranges[1] != [2]uint32{129 << 8, 129<<8 | 255} {
		t.Errorf("the upper /17's ranges: %v", ranges)
	}
}

// A BridgeEgress's clear mode folds into BridgeRows at every reader, the keyless gate's included, and a reader with the
// key reads exits' exits from the body: none and exits write the subject's row and auto removes it; a body naming both
// exits and a tag leaves the subject in exits with no exit; and a statement whose mode is unspecified is refused at a
// full reader and at the gate alike, the rows unchanged.
func TestABridgeEgressFoldsItsModeAndExits(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	egressType := bridge.SignedType_SIGNED_BRIDGE_EGRESS
	exits, none, auto := bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO
	modes := func() (bridge.BridgeEgressMode, bridge.BridgeEgressMode) {
		t.Helper()
		rows, err := net.log.State().BridgeRows()
		if err != nil {
			t.Fatal(err)
		}
		return BridgeRowsEgressMode(rows, laptop.sidecarId), BridgeRowsEgressMode(rows, desktop.sidecarId)
	}

	net.mustPost(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, exits, &bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{desktop.sidecarId.Bytes()}}))
	if laptopMode, desktopMode := modes(); laptopMode != exits || desktopMode != auto {
		t.Fatalf("after exits: %s and %s", laptopMode, desktopMode)
	}
	egress := net.bridgeLedger().Egress()
	if len(egress) != 1 || egress[0].Mode != exits || len(egress[0].ExitSidecarIds) != 1 || egress[0].ExitSidecarIds[0] != desktop.sidecarId {
		t.Fatalf("exits: %+v", egress)
	}

	// no mode shows: the gate refuses it before it sequences, and every reader at its position
	unspecified := net.sign(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED, nil))
	if verdict := net.apiAtTip().Check(unspecified, net.timeMs+1000); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Fatalf("the gate on a mode unspecified: %v", verdict.Refusal)
	}
	if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, unspecified)); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Fatalf("a reader on a mode unspecified: %v", verdict.Refusal)
	}
	if laptopMode, _ := modes(); laptopMode != exits {
		t.Fatalf("a refused statement moved the rows: %s", laptopMode)
	}

	both := net.mustPost(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, exits, &bridge.BridgeEgressBody{
		ExitSidecarIds: [][]byte{desktop.sidecarId.Bytes()}, ExitTagId: testConfigId("tag").Bytes(),
	}))
	ledger := net.bridgeLedger()
	testBridgeDisposition(t, ledger, both.Pin.GetVersion(), BridgeDispositionVoid)
	if egress := ledger.Egress(); len(egress) != 1 || egress[0].Mode != exits || len(egress[0].ExitSidecarIds) != 0 {
		t.Fatalf("a void exits body leaves the mode and no exit: %+v", egress)
	}

	net.mustPost(desktop, egressType, net.bridgeEgress(desktop.sidecarId, none, nil))
	if laptopMode, desktopMode := modes(); laptopMode != exits || desktopMode != none {
		t.Fatalf("after none: %s and %s", laptopMode, desktopMode)
	}
	net.mustPost(laptop, egressType, net.bridgeEgress(laptop.sidecarId, auto, nil))
	if laptopMode, desktopMode := modes(); laptopMode != auto || desktopMode != none {
		t.Fatalf("after auto: %s and %s", laptopMode, desktopMode)
	}
	net.everyReaderAgrees()
}

// BridgeRows across a fold: a base folding through BridgeEgress entries carries their modes in its rows, and the tail
// past its folded_through re-applies over them, so a new device, a restored reader and the keyless gate hold the
// long-running reader's rows, and an entry past the base applies at each alike.
func TestBridgeRowsAreEqualAcrossAFoldOfBridgeEgress(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	egressType := bridge.SignedType_SIGNED_BRIDGE_EGRESS
	exits, none := bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE
	net.mustPost(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, none, nil))
	net.mustPost(net.owner, egressType, net.bridgeEgress(desktop.sidecarId, exits, &bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{laptop.sidecarId.Bytes()}}))
	foldedThrough := net.n
	net.mustPost(desktop, egressType, net.bridgeEgress(desktop.sidecarId, none, nil))
	before := net.log.State().aclRows.GetBridge()

	net.fold(net.owner, foldedThrough, 2)
	folded := net.statesAt[foldedThrough].aclRows.GetBridge()
	if after := net.log.State().aclRows.GetBridge(); !bytes.Equal(after, before) || bytes.Equal(folded, before) {
		t.Fatalf("the rows across the fold: %x before, %x after, %x at the fold", before, after, folded)
	}
	for i, reader := range net.everyReader() {
		if got := reader.State().aclRows.GetBridge(); !bytes.Equal(got, before) {
			t.Errorf("reader %d holds %x, the long-running reader %x", i, got, before)
		}
	}
	net.mustPost(net.owner, egressType, net.bridgeEgress(laptop.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, nil))
	rows, err := net.log.State().BridgeRows()
	if err != nil || len(rows.GetEgress()) != 1 || BridgeRowsEgressMode(rows, desktop.sidecarId) != none {
		t.Fatalf("past the fold: %v, %v", rows, err)
	}
	net.everyReaderAgrees()
}

// §22.6 at the log: a BridgeRoute and a BridgeMap can encode alike, so a body that parses says nothing of what it is.
// A route its advertiser signed, presented as a map by rewriting Signed.type, is refused by the signature, at every
// reader; presented as what it is, it takes effect.
func TestABridgeRoutePresentedAsABridgeMapIsRefused(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, _ := testBridgeCast(net)
	route := net.bridgeRoute(laptop, testBridgeRuleId("route"), testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site"))
	asMap := &bridge.BridgeMap{}
	if err := proto.Unmarshal(testConfigMarshal(t, route), asMap); err != nil || !bytes.Equal(asMap.GetMapId(), route.GetRouteId()) || !bytes.Equal(asMap.GetHost(), route.GetAdvertiser()) {
		t.Fatalf("the route does not read as a map, so this proves nothing: %v", err)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(net.sign(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, route), signed); err != nil {
		t.Fatal(err)
	}
	signed.Type = uint32(bridge.SignedType_SIGNED_BRIDGE_MAP)
	verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, testConfigMarshal(t, signed)))
	if verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
		t.Fatalf("a route presented as a map: %v", verdict.Refusal)
	}
	if net.log.State().Bridge().Len() != 0 {
		t.Fatal("the refused statement joined the fold")
	}
	signed.Type = uint32(bridge.SignedType_SIGNED_BRIDGE_ROUTE)
	if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, testConfigMarshal(t, signed))); !verdict.Accepted() {
		t.Fatalf("the route as itself: %v", verdict.Refusal)
	}
	net.everyReaderAgrees()
}
