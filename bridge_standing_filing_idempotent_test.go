//go:build !ios_extension

// A standing filing is idempotent per effect (bridge_file.go's comment): under a standing grant a rule's id is 32 random
// bytes (§17.8), so a filing whose post applied but whose answer was lost, asked again before the filer's view showed
// it, filed a second rule of the same effect under a new id. The first test shows what such a duplicate does: a second
// map of the same body stands beside the first, as does a route at the same non-empty site_id (D-BRIDGE-8's HA
// replica), and withdrawing the first leaves the second serving. The rest hold the filer to one rule: a lost answer
// asked again with the view behind the log posts the same bytes again, a route's and a map's alike, after a restart and
// after the daemon's own retry too; a marker that kept no bytes files again under its id, a filing of a held id; a
// statement left pending with no marker gives its id; withdrawing the one rule leaves nothing serving, and asking
// after that files a new rule; two different exposures take two ids; and a remap asked again, or a map asked again
// after a block change, answers its rule with nothing posted. Each is a top-level test on bridge_file_test.go's world,
// its gate passing every exposure on a standing grant.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The net's state as a follower behind the log holds it: the state it last caught up to. A WaitFor for an entry the net
// holds catches it up, as a claim's wait does, and catchUp follows the net's tip.
type testStandingLagConfig struct {
	stateLock sync.Mutex
	net       *testConfigNet
	state     *ConfigState
}

// A follower caught up to the net's tip now.
func newTestStandingLagConfig(net *testConfigNet) *testStandingLagConfig {
	return &testStandingLagConfig{net: net, state: net.log.State()}
}

// The state it last caught up to.
func (self *testStandingLagConfig) State() *ConfigState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state
}

// Catches up to the net's tip once the net holds n.
func (self *testStandingLagConfig) WaitFor(ctx context.Context, n uint64) (*ConfigState, error) {
	if self.net.n < n {
		return nil, fmt.Errorf("the net is at %d, below %d", self.net.n, n)
	}
	self.catchUp()
	return self.State(), nil
}

// Follows the net to its tip.
func (self *testStandingLagConfig) catchUp() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = self.net.log.State()
}

// A filer over the world as newFiler builds one, reading the config through config and drawing from a seed of its own,
// so a filer opened again after a restart draws no id an earlier one drew.
func (self *testBridgeFileWorld) standingFiler(config BridgeFilerConfig, seed byte) *BridgeFiler {
	self.t.Helper()
	filer, err := NewBridgeFiler(&BridgeFilerArgs{
		Sidecar:    self.sidecar,
		Config:     config,
		Heads:      self.heads,
		Grants:     NewAclGrantFiler(self.sidecar, self.engine),
		HeadWriter: func() BridgeHeadWriter { return self.heads },
		Records:    func() (RecordWriter, error) { return self.records, nil },
		Store:      self.store,
		Random:     mathrand.NewChaCha8([32]byte{seed}),
		Clock:      self.clock,
		Log:        NewNoopLogger(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return filer
}

// The world with its gate passing every exposure on a standing grant, and its filer reading the net through a follower
// that stays behind until it is caught up.
func newTestStandingWorld(t *testing.T, admin bool) (*testBridgeFileWorld, *testStandingLagConfig) {
	t.Helper()
	world := newTestBridgeFileWorld(t, admin)
	world.gate.standing = true
	lag := newTestStandingLagConfig(world.net)
	world.filer = world.standingFiler(lag, 0x31)
	return world, lag
}

// The host's rules of signedType the net's ledger holds at its tip.
func (self *testBridgeFileWorld) hostRules(signedType bridge.SignedType) []*BridgeLedgerRule {
	rules := []*BridgeLedgerRule{}
	for _, rule := range self.ledger().Rules(signedType) {
		if rule.Owner == self.hostId {
			rules = append(rules, rule)
		}
	}
	return rules
}

// The host's statements of signedType the log took, in log order.
func (self *testBridgeFileWorld) hostFilings(signedType bridge.SignedType) []*BridgeLogStatement {
	filings := []*BridgeLogStatement{}
	for _, statement := range self.net.log.State().Bridge().Statements() {
		if statement.SignedType == signedType && statement.Signer == self.hostId {
			filings = append(filings, statement)
		}
	}
	return filings
}

// The host's rules as its compile at the net's tip gives them, under no document.
func (self *testBridgeFileWorld) compiledRules() *bridge.BridgeRules {
	self.t.Helper()
	state := self.net.log.State()
	base := state.Base()
	head, err := self.heads.ReadConfigHead(context.Background(), base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		self.t.Fatal(err)
	}
	view, err := NewBridgeConfigView(state, head, nil, testConfigSealKeyAt(testConfigSealKey(1)), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	_, rules := testBridgeCompile(self.t, view, &BridgeCompileLocal{SidecarId: self.hostId})
	return rules
}

// The map ids and the served route ids of compiled rules, in their order.
func testStandingServing(rules *bridge.BridgeRules) ([][]byte, [][]byte) {
	mapIds, routeIds := [][]byte{}, [][]byte{}
	for _, ruleMap := range rules.GetMaps() {
		mapIds = append(mapIds, ruleMap.GetMapId())
	}
	for _, served := range rules.GetServed() {
		routeIds = append(routeIds, served.GetRouteId())
	}
	return mapIds, routeIds
}

// Each post's Signed bytes, in order.
func (self *testBridgeFileApi) postedBytes() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.posts)
}

// The standing markers the filer's store keeps.
func (self *testBridgeFileWorld) standingMarkers() map[string]*bridgeStandingMarker {
	self.t.Helper()
	markers := map[string]*bridgeStandingMarker{}
	for _, name := range self.store.names(bridgeFileStandingPrefix) {
		marker := &bridgeStandingMarker{}
		if found, err := self.filer.loadRecord(name, marker); err != nil || !found {
			self.t.Fatalf("the marker %s: %t %v", name, found, err)
		}
		markers[name] = marker
	}
	return markers
}

// The one standing marker the filer's store keeps, and its name.
func (self *testBridgeFileWorld) standingMarker() (string, *bridgeStandingMarker) {
	self.t.Helper()
	markers := self.standingMarkers()
	if len(markers) != 1 {
		self.t.Fatalf("%d standing markers", len(markers))
	}
	for name, marker := range markers {
		return name, marker
	}
	return "", nil
}

// A TCP map of one port of the host's address to a LAN target's 443.
func testStandingMapRequest(port uint32) *BridgeMapRequest {
	return &BridgeMapRequest{FirstPort: port, TargetPort: 443, Target: netip.MustParseAddr("192.0.2.20")}
}

// A subnet route of one prefix.
func testStandingRouteRequest(prefix string) *BridgeRouteRequest {
	return &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix(prefix)}}
}

// What a duplicate standing rule does, the hazard the filer's marker closes: a second BridgeMap of the same body under
// another id is active beside the first and compiled beside it, and withdrawing the first leaves the second serving; a
// second route of the same prefix at the same non-empty site_id is an HA replica, active and served beside the first,
// and outlives the first's withdrawal too; one at no site_id is void under D-BRIDGE-8 and serves nothing. Each
// duplicate is signed as a filer drawing a fresh id for the same effect would sign it.
func TestDuplicateStandingRulesServeBesideTheFirst(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	world.gate.standing = true
	ctx := context.Background()

	mapped, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443))
	if err != nil {
		t.Fatal(err)
	}
	first := world.ledger().Rule(mapped.RuleId)
	duplicateMap := testBridgeRuleId("a duplicate map")
	if _, err := world.filer.fileSealed(ctx, world.mcp(), bridge.SignedType_SIGNED_BRIDGE_MAP,
		&bridge.BridgeMap{MapId: duplicateMap, Host: world.hostId.Bytes(), Expires: first.Expires}, proto.Clone(first.Map)); err != nil {
		t.Fatal(err)
	}
	second := world.ledger().Rule(duplicateMap)
	if !first.Active() || second == nil || !second.Active() || !second.Standing || !proto.Equal(first.Map, second.Map) {
		t.Fatalf("the duplicate map: %+v beside %+v", second, first)
	}
	if mapIds, _ := testStandingServing(world.compiledRules()); len(mapIds) != 2 {
		t.Fatalf("%d maps compiled for one effect filed twice", len(mapIds))
	}
	if _, err := world.filer.Close(ctx, world.mcp(), mapped.RuleId, true); err != nil {
		t.Fatal(err)
	}
	if mapIds, _ := testStandingServing(world.compiledRules()); len(mapIds) != 1 || !bytes.Equal(mapIds[0], duplicateMap) {
		t.Fatalf("after the first map's withdrawal the host serves maps %x", mapIds)
	}

	sited, err := world.filer.Expose(ctx, world.mcp(), &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.60.0.0/24")}, SiteId: []byte("site")})
	if err != nil {
		t.Fatal(err)
	}
	siteRule := world.ledger().Rule(sited.RuleId)
	replica := testBridgeRuleId("a duplicate route at its site")
	if _, err := world.filer.fileSealed(ctx, world.mcp(), bridge.SignedType_SIGNED_BRIDGE_ROUTE,
		&bridge.BridgeRoute{RouteId: replica, Advertiser: world.hostId.Bytes(), RouteRuleIds: siteRule.RouteRuleIds}, proto.Clone(siteRule.Route)); err != nil {
		t.Fatal(err)
	}
	if rule := world.ledger().Rule(replica); rule == nil || !rule.Active() {
		t.Fatalf("the duplicate route at its site: %+v", rule)
	}
	if _, routeIds := testStandingServing(world.compiledRules()); len(routeIds) != 2 {
		t.Fatalf("%d routes served for one effect filed twice", len(routeIds))
	}
	if _, err := world.filer.Close(ctx, world.mcp(), sited.RuleId, true); err != nil {
		t.Fatal(err)
	}
	if _, routeIds := testStandingServing(world.compiledRules()); len(routeIds) != 1 || !bytes.Equal(routeIds[0], replica) {
		t.Fatalf("after the first route's withdrawal the host serves routes %x", routeIds)
	}

	unsited, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("10.61.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	unsitedRule := world.ledger().Rule(unsited.RuleId)
	voided := testBridgeRuleId("a duplicate route at no site")
	if _, err := world.filer.fileSealed(ctx, world.mcp(), bridge.SignedType_SIGNED_BRIDGE_ROUTE,
		&bridge.BridgeRoute{RouteId: voided, Advertiser: world.hostId.Bytes(), RouteRuleIds: unsitedRule.RouteRuleIds}, proto.Clone(unsitedRule.Route)); err != nil {
		t.Fatal(err)
	}
	if rule := world.ledger().Rule(voided); rule == nil || !rule.Void {
		t.Fatalf("the duplicate route at no site: %+v", rule)
	}
}

// A map whose post applied and whose answer was lost, asked again while the filer's view is still behind it, files one
// rule: the first ask files the host's address and then the map, and answers uncertain; the second posts the map's same
// bytes again, which api answers with the entry it holds, and answers that rule's id with no address filed; the log
// took one map of the host, and once the view catches up the ledger holds that one rule, in force, with one route
// entry for it.
func TestStandingMapWhoseAnswerWasLostIsFiledOnce(t *testing.T) {
	world, lag := newTestStandingWorld(t, false)
	ctx := context.Background()
	world.api.answers = []string{"ok", "lost"}
	if _, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443)); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a map whose answer was lost: %v", err)
	}
	landed := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_MAP)
	if len(landed) != 1 || lag.State().Bridge().Len() != 1 {
		t.Fatalf("%d maps landed, the view holds %d bridge statements", len(landed), lag.State().Bridge().Len())
	}

	filing, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(filing.RuleId, landed[0].RuleId) || filing.AddressFiled || filing.ApprovalId != (Id{}) {
		t.Fatalf("the map asked again: %+v, the landed map %x", filing, landed[0].RuleId)
	}
	posted := world.api.postedBytes()
	if len(posted) != 3 || !bytes.Equal(posted[1], posted[2]) {
		t.Fatalf("%d posts, the map asked again posting its same bytes %t", len(posted), len(posted) == 3 && bytes.Equal(posted[1], posted[2]))
	}
	if filings := world.hostFilings(bridge.SignedType_SIGNED_BRIDGE_MAP); len(filings) != 1 {
		t.Fatalf("the log took %d maps of the host", len(filings))
	}

	lag.catchUp()
	if rules := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_MAP); len(rules) != 1 || !rules[0].Active() || !rules[0].Standing {
		t.Fatalf("the host's maps: %+v", rules)
	}
	if routes := world.records.routes(t); len(routes) != 1 {
		t.Errorf("%d route entries for one map", len(routes))
	}
	again, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443))
	if err != nil || !bytes.Equal(again.RuleId, filing.RuleId) || world.api.postCount() != 3 {
		t.Fatalf("the map asked once the view shows it: %+v %v, %d posts", again, err, world.api.postCount())
	}
}

// The same for a route, the view behind the log, through a restart: the lost answer's statement stays pending until the
// daemon's own retry posts it, which api answers with its entry; a filer opened again, drawing from another seed,
// answers the route asked again with the id that landed by posting the bytes its marker keeps, and the log took one
// route of the host.
func TestStandingRouteWhoseAnswerWasLostIsFiledOnceAcrossARestart(t *testing.T) {
	world, lag := newTestStandingWorld(t, false)
	ctx := context.Background()
	world.api.answers = []string{"lost"}
	if _, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("192.168.7.0/24")); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a route whose answer was lost: %v", err)
	}
	if err := world.sidecar.PostPendingStatements(ctx); err != nil {
		t.Fatal(err)
	}
	if pendings, err := world.sidecar.pendingStatements(); err != nil || len(pendings) != 0 {
		t.Fatalf("%d statements still pending: %v", len(pendings), err)
	}
	landed := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_ROUTE)
	if len(landed) != 1 {
		t.Fatalf("%d routes landed", len(landed))
	}

	world.filer = world.standingFiler(lag, 0x32)
	filing, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("192.168.7.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(filing.RuleId, landed[0].RuleId) {
		t.Fatalf("the route asked again after a restart: %x, the landed route %x", filing.RuleId, landed[0].RuleId)
	}
	posted := world.api.postedBytes()
	if len(posted) != 3 || !bytes.Equal(posted[0], posted[1]) || !bytes.Equal(posted[0], posted[2]) {
		t.Fatalf("%d posts, not each the route's same bytes", len(posted))
	}
	if filings := world.hostFilings(bridge.SignedType_SIGNED_BRIDGE_ROUTE); len(filings) != 1 {
		t.Fatalf("the log took %d routes of the host", len(filings))
	}
	if routes := world.records.routes(t); len(routes) != 1 {
		t.Errorf("%d route entries for one route", len(routes))
	}
}

// A marker that kept no bytes, as a kill between the post's answer and the marker's write leaves it, with nothing
// pending: the route asked again files again under the marker's id, a filing of the held id, which the ledger holds
// as held beside the first; one route of the host is in force.
func TestStandingFilingWithNoBytesKeptFilesAgainUnderItsId(t *testing.T) {
	world, lag := newTestStandingWorld(t, false)
	ctx := context.Background()
	world.api.answers = []string{"lost"}
	if _, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("192.168.8.0/24")); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a route whose answer was lost: %v", err)
	}
	if err := world.sidecar.PostPendingStatements(ctx); err != nil {
		t.Fatal(err)
	}
	name, marker := world.standingMarker()
	if len(marker.Signed) == 0 {
		t.Fatal("the marker kept no bytes")
	}
	marker.Signed = nil
	if err := world.filer.saveRecord(name, marker); err != nil {
		t.Fatal(err)
	}

	filing, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("192.168.8.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(filing.RuleId, marker.RuleId) {
		t.Fatalf("the route asked again: %x, the marker's id %x", filing.RuleId, marker.RuleId)
	}
	filings := world.filingsOf(filing.RuleId)
	if len(filings) != 2 || len(world.hostFilings(bridge.SignedType_SIGNED_BRIDGE_ROUTE)) != 2 {
		t.Fatalf("%d filings of the id", len(filings))
	}
	ledger := world.ledger()
	testBridgeDisposition(t, ledger, filings[0].N, BridgeDispositionActive)
	testBridgeDisposition(t, ledger, filings[1].N, BridgeDispositionHeld)
	lag.catchUp()
	if rules := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_ROUTE); len(rules) != 1 || !rules[0].Active() {
		t.Fatalf("the host's routes: %+v", rules)
	}
	if _, kept := world.standingMarker(); !bytes.Equal(kept.RuleId, filing.RuleId) || len(kept.Signed) == 0 {
		t.Errorf("the marker after the second filing: %+v", kept)
	}
}

// A statement of the effect left pending with no marker, as an earlier build or a lost marker leaves it: the route
// asked again finds it among the sidecar's pending statements by its effect, opening its body, posts its bytes again
// and answers its id, keeping a marker for it; the log took one route of the host.
func TestStandingFilingTakesTheIdOfAPendingStatementOfItsEffect(t *testing.T) {
	world, _ := newTestStandingWorld(t, false)
	ctx := context.Background()
	world.api.answers = []string{"lost"}
	if _, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("192.168.9.0/24")); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a route whose answer was lost: %v", err)
	}
	name, _ := world.standingMarker()
	if err := world.filer.removeRecord(name); err != nil {
		t.Fatal(err)
	}
	if pendings, err := world.sidecar.pendingStatements(); err != nil || len(pendings) != 1 {
		t.Fatalf("%d statements pending: %v", len(pendings), err)
	}
	landed := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_ROUTE)

	filing, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("192.168.9.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if len(landed) != 1 || !bytes.Equal(filing.RuleId, landed[0].RuleId) {
		t.Fatalf("the route asked again: %x, landed %d", filing.RuleId, len(landed))
	}
	if filings := world.hostFilings(bridge.SignedType_SIGNED_BRIDGE_ROUTE); len(filings) != 1 {
		t.Fatalf("the log took %d routes of the host", len(filings))
	}
	if pendings, err := world.sidecar.pendingStatements(); err != nil || len(pendings) != 0 {
		t.Fatalf("%d statements still pending: %v", len(pendings), err)
	}
	if _, kept := world.standingMarker(); !bytes.Equal(kept.RuleId, filing.RuleId) {
		t.Errorf("the marker kept for the pending statement: %+v", kept)
	}
}

// Withdrawing the one rule a lost answer and an ask again filed leaves nothing serving: before, the compile serves the
// map; after a reset withdrawal the ledger holds it withdrawn and the compile serves no map. The marker is then spent:
// the map asked again files a new rule under a new id, the one map in force, and withdrawing it leaves nothing
// serving again.
func TestWithdrawingTheOneStandingRuleLeavesNothingServing(t *testing.T) {
	world, lag := newTestStandingWorld(t, false)
	ctx := context.Background()
	world.api.answers = []string{"ok", "lost"}
	if _, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443)); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a map whose answer was lost: %v", err)
	}
	filing, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443))
	if err != nil {
		t.Fatal(err)
	}
	lag.catchUp()
	if mapIds, _ := testStandingServing(world.compiledRules()); len(mapIds) != 1 || !bytes.Equal(mapIds[0], filing.RuleId) {
		t.Fatalf("the host serves maps %x", mapIds)
	}
	if _, err := world.filer.Close(ctx, world.mcp(), filing.RuleId, true); err != nil {
		t.Fatal(err)
	}
	lag.catchUp()
	if rule := world.ledger().Rule(filing.RuleId); rule == nil || rule.Withdrawn == nil || rule.Active() {
		t.Fatalf("the withdrawn map: %+v", rule)
	}
	if mapIds, _ := testStandingServing(world.compiledRules()); len(mapIds) != 0 {
		t.Fatalf("after its withdrawal the host serves maps %x", mapIds)
	}

	renewed, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(renewed.RuleId, filing.RuleId) {
		t.Fatal("the map asked after its withdrawal took the withdrawn id")
	}
	if mapIds, _ := testStandingServing(world.compiledRules()); len(mapIds) != 1 || !bytes.Equal(mapIds[0], renewed.RuleId) {
		t.Fatalf("the host serves maps %x", mapIds)
	}
	if _, kept := world.standingMarker(); !bytes.Equal(kept.RuleId, renewed.RuleId) {
		t.Errorf("the marker after the new filing: %+v", kept)
	}
	lag.catchUp()
	if _, err := world.filer.Close(ctx, world.mcp(), renewed.RuleId, true); err != nil {
		t.Fatal(err)
	}
	if mapIds, _ := testStandingServing(world.compiledRules()); len(mapIds) != 0 {
		t.Fatalf("after the second withdrawal the host serves maps %x", mapIds)
	}
}

// Two different exposures take two ids, the view behind the log and a lost answer between them: a route whose answer
// was lost and another route, a map whose answer was lost and a map of another port, each a rule of its own; the first
// of each asked again answers its own id. Once the view catches up the host holds four rules in force under four ids.
func TestTwoDifferentStandingExposuresTakeTwoIds(t *testing.T) {
	world, lag := newTestStandingWorld(t, false)
	ctx := context.Background()
	world.api.answers = []string{"lost"}
	if _, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("10.40.1.0/24")); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a route whose answer was lost: %v", err)
	}
	other, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("10.40.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := world.filer.Expose(ctx, world.mcp(), testStandingRouteRequest("10.40.1.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	world.api.answers = []string{"ok", "lost"}
	if _, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443)); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a map whose answer was lost: %v", err)
	}
	otherMap, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8444))
	if err != nil {
		t.Fatal(err)
	}
	firstMap, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443))
	if err != nil {
		t.Fatal(err)
	}

	ids := [][]byte{first.RuleId, other.RuleId, firstMap.RuleId, otherMap.RuleId}
	for i := range ids {
		for j := range i {
			if bytes.Equal(ids[i], ids[j]) {
				t.Fatalf("exposures %d and %d share an id", j, i)
			}
		}
	}
	if len(world.standingMarkers()) != 4 {
		t.Errorf("%d markers for four effects", len(world.standingMarkers()))
	}
	lag.catchUp()
	routes, maps := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_ROUTE), world.hostRules(bridge.SignedType_SIGNED_BRIDGE_MAP)
	if len(routes) != 2 || len(maps) != 2 {
		t.Fatalf("%d routes and %d maps of the host", len(routes), len(maps))
	}
	for _, rule := range append(routes, maps...) {
		if !rule.Active() || !slices.ContainsFunc(ids, func(id []byte) bool { return bytes.Equal(id, rule.RuleId) }) {
			t.Errorf("the rule %x: %+v", rule.RuleId, rule)
		}
	}
}

// A remap asked again answers its rule though each ask draws the first free block of the upper /17, which the first
// remap now holds: the second ask's exposed prefix differs from the rule's, and the effect still names that rule, so
// nothing is posted and one remap of the prefix is in force.
func TestStandingRemapAskedAgainAnswersItsRule(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	world.gate.standing = true
	ctx := context.Background()
	request := &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.70.0.0/24")}, Remap: true}
	filed, err := world.filer.Expose(ctx, world.mcp(), request)
	if err != nil {
		t.Fatal(err)
	}
	if rule := world.ledger().Rule(filed.RuleId); rule == nil || !rule.Active() || rule.Route.GetExposedPrefix() == nil {
		t.Fatalf("the remap: %+v", rule)
	}
	again, err := world.filer.Expose(ctx, world.mcp(), request)
	if err != nil || !bytes.Equal(again.RuleId, filed.RuleId) || world.api.postCount() != 1 {
		t.Fatalf("the remap asked again: %+v %v, %d posts", again, err, world.api.postCount())
	}
	if routes := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_ROUTE); len(routes) != 1 {
		t.Fatalf("%d remaps of the prefix", len(routes))
	}
}

// A map asked again after a block change answers its rule: the compile reads a map's match prefix into the block in
// force by its host bits, so the map filed under the old block serves at the host's new address, and the ask names
// the same effect there; nothing more is posted and one map of the host is in force, served at the new block.
func TestStandingMapAskedAgainAfterABlockChangeAnswersItsRule(t *testing.T) {
	world := newTestBridgeFileWorld(t, true)
	world.gate.standing = true
	ctx := context.Background()
	filed, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443))
	if err != nil {
		t.Fatal(err)
	}
	posts := world.api.postCount()
	if _, err := world.filer.SetBlock(ctx, world.confirmed(), &BridgeBlockRequest{Prefix: netip.MustParsePrefix("10.20.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	again, err := world.filer.ExposeMap(ctx, world.mcp(), testStandingMapRequest(8443))
	if err != nil || !bytes.Equal(again.RuleId, filed.RuleId) || world.api.postCount() != posts {
		t.Fatalf("the map asked again after the block change: %+v %v, %d posts after %d", again, err, world.api.postCount(), posts)
	}
	if address := again.Address.As4(); address[0] != 10 || address[1] != 20 {
		t.Errorf("the map answers at %s", again.Address)
	}
	rules := world.compiledRules()
	if mapIds, _ := testStandingServing(rules); len(mapIds) != 1 || !bytes.Equal(mapIds[0], filed.RuleId) {
		t.Fatalf("the host serves maps %x", mapIds)
	}
	if match := rules.GetMaps()[0].GetMatchPrefix(); match.GetAddress()>>16 != testBridgeIpv4(10, 20, 0, 0)>>16 {
		t.Errorf("the map matches %v", match)
	}
}
