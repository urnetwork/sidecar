// The void at the fold (bridge_ledger.go, bridge_ledger_fold.go; DESIGN-DETAILS 12.2.3 as amended for QD-761, QD-773
// and QD-774, 12.6's void row and the twins of details/BridgeVoid.tla's configurations): a writer whose plan read gkm
// whole freezes void a body sealed above every generation gkm names once it is UnformedVoidWait old in the log's time,
// and waits otherwise; it never voids for a generation gkm names or on a read that does not count; a checker voids
// nothing; every reader that holds a generation signed past GenerationFormGrace after a body's entry refuses the body,
// so one claimed after the void turns no verdict; two writers' waits freeze one void; and a filer that keeps filing
// holds the fold under the previous base, for the wait after its last filing and no longer. The writer's restart and
// clock are TestTheVoidIsMeasuredInLogTime's, on the writer itself (bridge_ledger_void_writer_test.go).

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A key of the config repo's generation whose GenRotate was signed at signedMs, with testConfigSealKey's RK_g, so a
// body sealed under testConfigSealKey(generation) opens under it: a filer's own key for a generation it claims later
// included.
func testBridgeKeySignedAt(generation uint64, signedMs int64) *EvsRepoKey {
	key := testConfigSealKey(generation)
	key.timeMs = signedMs
	return key
}

// A writer's judge over the net's keys and heads, its plan's read of gkm answering formedThrough, with the net's
// settings but for its wait, where wait is set.
func (self *testBridgeLedgerNet) writerJudge(formedThrough uint64, wait time.Duration) *BridgeBodyJudge {
	settings := *self.settings
	if wait != 0 {
		settings.UnformedVoidWait = wait
	}
	judge := self.judge()
	judge.Settings = &settings
	judge.FormedThrough = func() uint64 { return formedThrough }
	return judge
}

// What judge folds through foldedThrough over the newest base's head at the net's tip, publishing no base.
func (self *testBridgeLedgerNet) foldBy(judge *BridgeBodyJudge, foldedThrough uint64) *BridgeLedgerFold {
	self.t.Helper()
	state := self.log.State()
	fold, err := judge.Fold(self.heads[state.Base().GetConfigVersion()], state, foldedThrough, self.log.EntryTimeMs)
	if err != nil {
		self.t.Fatal(err)
	}
	return fold
}

// The head a base at the net's tip names when its writer folded by fold: the newest base's head with the fold's ledger
// files and records.
func (self *testBridgeLedgerNet) headOf(fold *BridgeLedgerFold) *ConfigHead {
	self.t.Helper()
	previous := self.heads[self.log.State().Base().GetConfigVersion()]
	head, err := fold.Apply(previous)
	if err != nil {
		self.t.Fatal(err)
	}
	records, known := self.log.foldedRecords(previous.FoldedThrough()+1, fold.FoldedThrough)
	if !known {
		self.t.Fatalf("the records through %d are not kept", fold.FoldedThrough)
	}
	if head, err = head.WithFold(records, fold.FoldedThrough); err != nil {
		self.t.Fatal(err)
	}
	return head
}

// What a full reader standing at the net's tip, holding keys, makes of a head folded through foldedThrough:
// CheckBridgeLedgerFold's answer, its reader saying formedThrough as a caller might.
func (self *testBridgeLedgerNet) checkAsReader(head *ConfigHead, keys []*EvsRepoKey, settings *BridgeLedgerSettings, formedThrough uint64, foldedThrough uint64) (bool, error) {
	state := self.log.State()
	return CheckBridgeLedgerFold(head, self.heads[state.Base().GetConfigVersion()], &BridgeLedgerReader{
		State: state, RepoKeyAt: testConfigSealKeyAt(keys...), EntryTimeMs: self.log.EntryTimeMs, FormedThrough: formedThrough,
		Settings: settings,
	}, foldedThrough)
}

// Sequences a tick at timeMs exactly, at or after the tip's time: a tip a writer folds through. Answers its position.
func (self *testConfigNet) tickAt(timeMs int64) uint64 {
	self.t.Helper()
	if timeMs < self.timeMs {
		self.t.Fatalf("a tick at %d before the tip's %d", timeMs, self.timeMs)
	}
	self.timeMs = timeMs - 1000
	self.tick(&bridge.ApiTick{})
	return self.n
}

// A BridgeMap hosted by device under ruleId, its body sealed to generation.
func (self *testConfigNet) bridgeMapAt(device testConfigDevice, ruleId []byte, expires int64, body *bridge.BridgeMapBody, generation uint64) *bridge.BridgeMap {
	header := self.header()
	return &bridge.BridgeMap{
		Header: header, MapId: ruleId, Host: device.sidecarId.Bytes(), Expires: expires,
		SealedBody: self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_MAP, header, body, generation),
	}
}

// A BridgeEgress of subject's under exits, its body sealed to generation.
func (self *testConfigNet) bridgeEgressAt(subject Id, body *bridge.BridgeEgressBody, generation uint64) *bridge.BridgeEgress {
	header := self.header()
	return &bridge.BridgeEgress{
		Header: header, Subject: subject.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS,
		SealedBody: self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_EGRESS, header, body, generation),
	}
}

// A BridgeAlias sealed to generation.
func (self *testConfigNet) bridgeAliasAt(body *bridge.BridgeAliasBody, generation uint64) *bridge.BridgeAlias {
	header := self.header()
	return &bridge.BridgeAlias{Header: header, SealedBody: self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_ALIAS, header, body, generation)}
}

// A BridgeAddress of device at ipv4, sealed to generation.
func (self *testConfigNet) bridgeAddressAt(device testConfigDevice, ipv4 uint32, generation uint64) *bridge.BridgeAddress {
	header := self.header()
	return &bridge.BridgeAddress{
		Header: header, SidecarId: device.sidecarId.Bytes(),
		SealedBody: self.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_ADDRESS, header, &bridge.BridgeAddressBody{Ipv4: ipv4}, generation),
	}
}

// A logger that keeps every line, for a writer's config_key_ alarms. Safe for concurrent use.
type testBridgeVoidLines struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testBridgeVoidLines) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testBridgeVoidLines) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *testBridgeVoidLines) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testBridgeVoidLines) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testBridgeVoidLines) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testBridgeVoidLines) V(level int32) Verbose {
	return testBridgeVoidVerbose{lines: self}
}

// The lines holding every one of words, in order of logging.
func (self *testBridgeVoidLines) holding(words ...string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	held := []string{}
	for _, line := range self.lines {
		all := true
		for _, word := range words {
			all = all && strings.Contains(line, word)
		}
		if all {
			held = append(held, line)
		}
	}
	return held
}

// Every level enabled.
type testBridgeVoidVerbose struct {
	lines *testBridgeVoidLines
}

func (self testBridgeVoidVerbose) Enabled() bool {
	return true
}

func (self testBridgeVoidVerbose) Info(args ...any) {
	self.lines.Info(args...)
}

func (self testBridgeVoidVerbose) Infof(format string, args ...any) {
	self.lines.Infof(format, args...)
}

// Fails unless entries are exactly the statements at positions, in order, each sealed to generation and filed by its
// signer.
func testBridgeVoidedAre(t *testing.T, label string, entries []*BridgeLedgerEntry, generation uint64, positions []uint64, signers []Id) {
	t.Helper()
	if len(entries) != len(positions) {
		t.Fatalf("%s: %d entries, want %d", label, len(entries), len(positions))
	}
	for i, entry := range entries {
		if entry.Statement.N != positions[i] || entry.Generation != generation || entry.Statement.Signer != signers[i] {
			t.Errorf("%s: entry %d is %d of generation %d by %s, want %d of %d by %s", label, i, entry.Statement.N, entry.Generation, entry.Statement.Signer, positions[i], generation, signers[i])
		}
		if entry.Disposition != BridgeDispositionVoid || !errors.Is(entry.Reason, ErrBridgeVoid) || !errors.Is(entry.Reason, errBridgeGenerationUnformed) || errors.Is(entry.Reason, ErrConfigSealInvalid) {
			t.Errorf("%s: entry %d at %d: disposition %d, reason %v", label, i, entry.Statement.N, entry.Disposition, entry.Reason)
		}
	}
}

// The wait and the grace the defaults give, in ms.
func testBridgeVoidTimes() (int64, int64) {
	settings := DefaultBridgeLedgerSettings()
	return settings.UnformedVoidWait.Milliseconds(), settings.GenerationFormGrace.Milliseconds()
}

// BridgeVoidReach-Voids, of a route, a map, an egress, an alias and an address, each sealed to generation 2, which gkm
// never names: the writer, whose plan read gkm whole at generation 1, folds through a tip the wait after the newest of
// them, freezes every one void and names each in Voided with nothing stopped; the head's ledger holds the route and map
// void, the egress with no exit, and no alias and no address of theirs; the reader under test, which lacks generation
// 2, takes the base unchecked, and a reader present since the bootstrap and one restored at the base hold that ledger.
// Twin Landed: the fold as it stood, with no read, stops below the first of them for good.
func TestAnUnformedFilingIsVoidedAfterTheWait(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	net.fold = net.writerJudge(1, 0)
	wait, _ := testBridgeVoidTimes()
	routeId, mapId := testBridgeRuleId("unformed route"), testBridgeRuleId("unformed map")
	filings := []ConfigVerdict{
		net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(laptop, routeId, testBridgeSubnet(testBridgePrefix(10, 7, 0, 0, 16), "u"), 2)),
		net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMapAt(desktop, mapId, 0, testBridgeMapBody(testBridgeIpv4(100, 80, 3, 9), 8080, 80), 2)),
		net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgressAt(laptop.sidecarId, &bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{desktop.sidecarId.Bytes()}}, 2)),
		net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_ALIAS, net.bridgeAliasAt(&bridge.BridgeAliasBody{
			ShareId: testConfigId("unformed share").Bytes(), AliasPrefix: testBridgePrefix(100, 80, 200, 0, 24), Host: testConfigId("unformed host").Bytes(),
		}, 2)),
		net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddressAt(desktop, testBridgeIpv4(100, 80, 3, 7), 2)),
	}
	positions, signers := []uint64{}, []Id{laptop.sidecarId, desktop.sidecarId, net.owner.sidecarId, net.owner.sidecarId, desktop.sidecarId}
	for _, filing := range filings {
		positions = append(positions, filing.Pin.GetVersion())
	}
	tip := net.tickAt(net.timeMs + wait)

	landed := net.foldBy(net.judge(), tip)
	if landed.FoldedThrough != positions[0]-1 || landed.Stopped == nil || landed.Stopped.Statement.N != positions[0] || len(landed.Voided) != 0 {
		t.Fatalf("the fold with no read: through %d, stopped %+v, voided %d", landed.FoldedThrough, landed.Stopped, len(landed.Voided))
	}

	if reached := net.foldLedger(tip, nil); reached != tip {
		t.Fatalf("the fold reached %d, want the tip %d", reached, tip)
	}
	if net.lastFold.Stopped != nil {
		t.Fatalf("the fold stopped at %d", net.lastFold.Stopped.Statement.N)
	}
	testBridgeVoidedAre(t, "Voided", net.lastFold.Voided, 2, positions, signers)

	ledger := net.ledgerOf(net.log)
	if len(ledger.Entries()) != 0 {
		t.Fatalf("%d statements left unfolded", len(ledger.Entries()))
	}
	for _, ruleId := range [][]byte{routeId, mapId} {
		if rule := ledger.Rule(ruleId); rule == nil || !rule.Void || rule.Pending || rule.Route != nil || rule.Map != nil {
			t.Errorf("a frozen rule: %+v", rule)
		}
	}
	if egress := ledger.Egress(); len(egress) != 1 || egress[0].Subject != laptop.sidecarId || egress[0].Mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS || len(egress[0].ExitSidecarIds) != 0 {
		t.Errorf("the frozen egress: %+v", egress)
	}
	if len(ledger.Aliases()) != 0 || ledger.Address(desktop.sidecarId) != nil || len(ledger.Alarms()) != 0 {
		t.Errorf("an alias, an address or an alarm survived: %d, %v, %d", len(ledger.Aliases()), ledger.Address(desktop.sidecarId), len(ledger.Alarms()))
	}
	testBridgeLedgersEqual(t, net, net.presentReader(), net.restoredReader())
}

// Twin NoWait's guard: a tip one millisecond short of the wait after a filing sealed above every generation gkm names
// stops the fold below it, the filing not voided, with config_key_waiting naming its generation and its filer; the tip
// the wait after it freezes it void, with config_key_void naming them. The wait is read against the entry at the fold
// asked, the tip, in both of the fold's opens, so an older filing the stop leaves below the fold, a wait old at that
// tip, is voided by the short fold already and named by config_key_void.
func TestAnUnformedFilingWaits(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	net.fold = net.writerJudge(1, 0)
	wait, _ := testBridgeVoidTimes()
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	older := net.mustPost(desktop, route, net.bridgeRouteAt(desktop, testBridgeRuleId("older"), testBridgeSubnet(testBridgePrefix(10, 8, 0, 0, 16), "o"), 2))
	net.timeMs += time.Hour.Milliseconds()
	filing := net.mustPost(laptop, route, net.bridgeRouteAt(laptop, testBridgeRuleId("waits"), testBridgeSubnet(testBridgePrefix(10, 9, 0, 0, 16), "w"), 2))
	k, filedMs := filing.Pin.GetVersion(), net.timeMs

	lines := &testBridgeVoidLines{}
	writer := &ConfigWriter{args: &ConfigWriterArgs{BridgeFold: net.fold.Fold}, log: lines}
	foldAt := func(tip uint64) *BridgeLedgerFold {
		state := net.log.State()
		fold, err := writer.bridgeFold(net.heads[state.Base().GetConfigVersion()], state, tip, net.log.EntryTimeMs)
		if err != nil {
			t.Fatal(err)
		}
		return fold
	}
	short := foldAt(net.tickAt(filedMs + wait - 1))
	if short.FoldedThrough != k-1 || short.Stopped == nil || short.Stopped.Statement.N != k {
		t.Fatalf("a millisecond short: through %d, stopped %+v", short.FoldedThrough, short.Stopped)
	}
	testBridgeVoidedAre(t, "a millisecond short", short.Voided, 2, []uint64{older.Pin.GetVersion()}, []Id{desktop.sidecarId})
	if waiting := lines.holding("config_key_waiting", fmt.Sprint("generation 2"), laptop.sidecarId.String(), fmt.Sprint("at ", k)); len(waiting) != 1 {
		t.Fatalf("config_key_waiting naming the filer: %q", lines.lines)
	}
	if voided := lines.holding("config_key_void", desktop.sidecarId.String()); len(voided) != 1 {
		t.Fatalf("config_key_void naming the older filer: %q", lines.lines)
	}

	tip := net.tickAt(filedMs + wait)
	at := foldAt(tip)
	if at.FoldedThrough != tip || at.Stopped != nil {
		t.Fatalf("at the wait: through %d, stopped %+v", at.FoldedThrough, at.Stopped)
	}
	testBridgeVoidedAre(t, "at the wait", at.Voided, 2, []uint64{older.Pin.GetVersion(), k}, []Id{desktop.sidecarId, laptop.sidecarId})
	if voided := lines.holding("config_key_void", laptop.sidecarId.String(), fmt.Sprint("at ", k)); len(voided) != 1 {
		t.Fatalf("config_key_void naming the filer: %q", lines.lines)
	}
}

// A writer is never void for a key that exists and has not reached it: a body sealed to generation 2, which gkm names
// and whose key this writer lacks (a broken delivery), stops the fold at any age, a year included, while one sealed to
// generation 3 above it, filed before it, is voided by the same fold.
func TestANamedGenerationIsNeverVoided(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	writer := net.writerJudge(2, 0)
	wait, _ := testBridgeVoidTimes()
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	above := net.mustPost(desktop, route, net.bridgeRouteAt(desktop, testBridgeRuleId("above"), testBridgeSubnet(testBridgePrefix(10, 10, 0, 0, 16), "a"), 3))
	named := net.mustPost(laptop, route, net.bridgeRouteAt(laptop, testBridgeRuleId("named"), testBridgeSubnet(testBridgePrefix(10, 11, 0, 0, 16), "n"), 2))
	filedMs := net.timeMs
	for _, age := range []int64{wait, 30 * testBridgeDayMs, 365 * testBridgeDayMs} {
		fold := net.foldBy(writer, net.tickAt(filedMs+age))
		if fold.FoldedThrough != named.Pin.GetVersion()-1 || fold.Stopped == nil || fold.Stopped.Statement.N != named.Pin.GetVersion() || fold.Stopped.Generation != 2 {
			t.Fatalf("at an age of %d ms: through %d, stopped %+v", age, fold.FoldedThrough, fold.Stopped)
		}
		testBridgeVoidedAre(t, fmt.Sprint("at an age of ", age), fold.Voided, 3, []uint64{above.Pin.GetVersion()}, []Id{desktop.sidecarId})
	}
}

// FormedThrough counts only a whole read, made in the plan: a failed read, a cut listing, a fork at the generation pin,
// a named generation not held (above the keys held, or a gap below the newest, or a key holding no RK_g) and no read at
// all each answer 0, and a fold on any of them voids nothing; the whole read answers G and voids. Twin StaleRead's
// guard: Fold asks the read once each plan and keeps nothing, so a generation that formed between two plans is read
// by the second, which then judges the body it opens rather than voiding it; the twin itself, a writer that plans on
// the listing it read before and lacks the new key, voids that body, and a reader holding the generation forks.
func TestNoVoidWithoutAWholeRead(t *testing.T) {
	keys := testConfigSealKeyAt(testConfigSealKey(1), testConfigSealKey(2))
	if got := BridgeFormedThrough(&BridgeGenerationRead{Whole: true, Newest: 2}, keys); got != 2 {
		t.Fatalf("a whole read: %d", got)
	}
	for _, c := range []struct {
		label string
		read  *BridgeGenerationRead
		keys  func(generation uint64) *EvsRepoKey
	}{
		{label: "a failed read", read: &BridgeGenerationRead{Err: errors.New("gkm unreachable"), Whole: true, Newest: 2}, keys: keys},
		{label: "a cut listing", read: &BridgeGenerationRead{Whole: false, Newest: 2}, keys: keys},
		{label: "a fork at the pin", read: &BridgeGenerationRead{Whole: true, Newest: 2, Forked: true}, keys: keys},
		{label: "a named generation not held", read: &BridgeGenerationRead{Whole: true, Newest: 3}, keys: keys},
		{label: "a gap below the newest", read: &BridgeGenerationRead{Whole: true, Newest: 2}, keys: testConfigSealKeyAt(testConfigSealKey(2))},
		{label: "a key holding no RK_g", read: &BridgeGenerationRead{Whole: true, Newest: 2}, keys: testConfigSealKeyAt(testConfigSealKey(1), &EvsRepoKey{generation: 2})},
		{label: "no read", read: nil, keys: keys},
	} {
		if got := BridgeFormedThrough(c.read, c.keys); got != 0 {
			t.Errorf("%s: %d", c.label, got)
		}
	}

	net := newTestBridgeLedgerNet(t)
	_, laptop, _ := testBridgeCast(net.testConfigNet)
	wait, _ := testBridgeVoidTimes()
	filing := net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(laptop, testBridgeRuleId("no read"), testBridgeSubnet(testBridgePrefix(10, 12, 0, 0, 16), "r"), 5))
	tip := net.tickAt(net.timeMs + 10*wait)
	netKeys := testConfigSealKeyAt(net.keys...)
	reads := []*BridgeGenerationRead{
		{Err: errors.New("gkm unreachable"), Whole: true, Newest: 1}, {Whole: false, Newest: 1}, {Whole: true, Newest: 1, Forked: true},
		{Whole: true, Newest: 2}, nil,
	}
	for i, read := range reads {
		judge := net.writerJudge(0, 0)
		judge.FormedThrough = func() uint64 { return BridgeFormedThrough(read, netKeys) }
		if fold := net.foldBy(judge, tip); fold.Stopped == nil || fold.Stopped.Statement.N != filing.Pin.GetVersion() || len(fold.Voided) != 0 {
			t.Errorf("read %d: stopped %+v, voided %d", i, fold.Stopped, len(fold.Voided))
		}
	}
	whole := net.writerJudge(0, 0)
	whole.FormedThrough = func() uint64 { return BridgeFormedThrough(&BridgeGenerationRead{Whole: true, Newest: 1}, netKeys) }
	if fold := net.foldBy(whole, tip); fold.FoldedThrough != tip || len(fold.Voided) != 1 {
		t.Fatalf("the whole read: through %d, voided %d", fold.FoldedThrough, len(fold.Voided))
	}

	// a body sealed to generation 2, which forms between two plans inside the grace after the body's entry
	stale := newTestBridgeLedgerNet(t)
	_, staleLaptop, _ := testBridgeCast(stale.testConfigNet)
	ruleId := testBridgeRuleId("formed between plans")
	stale.mustPost(staleLaptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, stale.bridgeRouteAt(staleLaptop, ruleId, testBridgeSubnet(testBridgePrefix(10, 13, 0, 0, 16), "s"), 2))
	filedMs := stale.timeMs
	listed, readCount := uint64(1), 0
	writer := stale.writerJudge(0, 0)
	writer.FormedThrough = func() uint64 {
		readCount += 1
		return BridgeFormedThrough(&BridgeGenerationRead{Whole: true, Newest: listed}, testConfigSealKeyAt(stale.keys...))
	}
	if fold := stale.foldBy(writer, stale.tickAt(filedMs+wait/2)); fold.Stopped == nil || len(fold.Voided) != 0 {
		t.Fatalf("the first plan, young: stopped %+v, voided %d", fold.Stopped, len(fold.Voided))
	}
	stale.keys = append(stale.keys, testBridgeKeySignedAt(2, filedMs+1000))
	listed = 2
	tip = stale.tickAt(filedMs + 2*wait)
	fold := stale.foldBy(writer, tip)
	if fold.FoldedThrough != tip || len(fold.Voided) != 0 || readCount != 2 {
		t.Fatalf("the second plan: through %d, voided %d, %d reads", fold.FoldedThrough, len(fold.Voided), readCount)
	}
	head := stale.headOf(fold)
	if checked, err := stale.checkAsReader(head, stale.keys, stale.settings, 0, tip); !checked || err != nil {
		t.Fatalf("a reader holding generation 2 checks the plan: %v, %v", checked, err)
	}
	remembered := stale.writerJudge(1, 0)
	remembered.RepoKeyAt = testConfigSealKeyAt(testConfigSealKey(1))
	staleFold := stale.foldBy(remembered, tip)
	if staleFold.FoldedThrough != tip || len(staleFold.Voided) != 1 {
		t.Fatalf("a writer on the listing it remembered: through %d, voided %d", staleFold.FoldedThrough, len(staleFold.Voided))
	}
	if _, err := stale.checkAsReader(stale.headOf(staleFold), stale.keys, stale.settings, 0, tip); !errors.Is(err, ErrConfigHeadMismatch) {
		t.Fatalf("a reader holding generation 2 took a void on a remembered listing: %v", err)
	}
}

// Twin CheckerVoids's guard and BridgeVoidReach-Unchecked: CheckBridgeLedgerFold voids nothing as unformed. A checker
// holding generation 1 alone, its reader saying FormedThrough 1 as a caller might, takes unchecked a head that froze
// void a body sealed to generation 2, whatever the body's age, and the base lands at the reader under test with that
// void; and it takes unchecked, rather than forking on, a head whose writer held a formed generation 2 and judged the
// same kind of body in force.
func TestACheckerVoidsNothing(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, _ := testBridgeCast(net.testConfigNet)
	wait, _ := testBridgeVoidTimes()
	ruleId := testBridgeRuleId("checked")
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(laptop, ruleId, testBridgeSubnet(testBridgePrefix(10, 14, 0, 0, 16), "c"), 2))
	filedMs := net.timeMs
	writer := net.writerJudge(1, 0)
	for _, age := range []int64{wait, 365 * testBridgeDayMs} {
		tip := net.tickAt(filedMs + age)
		fold := net.foldBy(writer, tip)
		if fold.FoldedThrough != tip || len(fold.Voided) != 1 {
			t.Fatalf("the writer at an age of %d ms: through %d, voided %d", age, fold.FoldedThrough, len(fold.Voided))
		}
		checked, err := net.checkAsReader(net.headOf(fold), net.keys, net.settings, 1, tip)
		if checked || err != nil {
			t.Fatalf("the checker at an age of %d ms: checked %v, %v", age, checked, err)
		}
	}
	net.fold = writer
	if tip := net.n; net.foldLedger(tip, nil) != tip {
		t.Fatalf("the base did not reach the tip %d", tip)
	}
	if rule := net.ledgerOf(net.log).Rule(ruleId); rule == nil || !rule.Void {
		t.Fatalf("the reader under test after the base: %+v", rule)
	}

	// the writer holds generation 2, signed before the body's entry, and judges the body in force; the checker lacks it
	formed := newTestBridgeLedgerNet(t)
	_, formedLaptop, _ := testBridgeCast(formed.testConfigNet)
	formedId := testBridgeRuleId("formed")
	formed.mustPost(formedLaptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, formed.bridgeRouteAt(formedLaptop, formedId, testBridgeSubnet(testBridgePrefix(10, 15, 0, 0, 16), "f"), 2))
	keyed := formed.writerJudge(2, 0)
	keyed.RepoKeyAt = testConfigSealKeyAt(testConfigSealKey(1), testBridgeKeySignedAt(2, formed.timeMs-1000))
	tip := formed.tickAt(formed.timeMs + 2*wait)
	fold := formed.foldBy(keyed, tip)
	if fold.FoldedThrough != tip || len(fold.Voided) != 0 {
		t.Fatalf("the keyed writer: through %d, voided %d", fold.FoldedThrough, len(fold.Voided))
	}
	if checked, err := formed.checkAsReader(formed.headOf(fold), formed.keys, formed.settings, 1, tip); checked || err != nil {
		t.Fatalf("a checker lacking a formed generation: checked %v, %v", checked, err)
	}
}

// QD-773's readers' half and BridgeVoidReach-LateForm: a body whose generation is signed one millisecond past the grace
// after its entry is Refused by the judge, with no alarm, and void at each of the ledger's own opens (a route, a map,
// an egress, an alias, an address); signed at the grace it is judged and opens. After a writer froze a body void as
// unformed, generation 2 is claimed under the very key the body was sealed with: a reader standing under the previous
// base that gains it folds the head's files byte for byte; one whose grace never refuses would hold the rule in force and
// fork (Twin NoGrace); a daemon that was behind turns its verdict by RejudgeBridgeBodies and takes the base with no
// fork; and RejudgeBridgeBodies leaves the frozen row as it is.
func TestALateGenerationIsNoGeneration(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	_, grace := testBridgeVoidTimes()
	routeId, mapId := testBridgeRuleId("late route"), testBridgeRuleId("late map")
	firstMs := net.timeMs + 1000
	filings := []ConfigVerdict{
		net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(laptop, routeId, testBridgeSubnet(testBridgePrefix(10, 16, 0, 0, 16), "l"), 2)),
		net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMapAt(desktop, mapId, 0, testBridgeMapBody(testBridgeIpv4(100, 80, 3, 9), 8081, 80), 2)),
		net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgressAt(laptop.sidecarId, &bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{desktop.sidecarId.Bytes()}}, 2)),
		net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_ALIAS, net.bridgeAliasAt(&bridge.BridgeAliasBody{
			ShareId: testConfigId("late share").Bytes(), AliasPrefix: testBridgePrefix(100, 80, 201, 0, 24), Host: testConfigId("late host").Bytes(),
		}, 2)),
		net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddressAt(desktop, testBridgeIpv4(100, 80, 3, 8), 2)),
	}
	lastMs := net.timeMs
	if filings[0].Pin.GetVersion()+4 != filings[4].Pin.GetVersion() {
		t.Fatal("the filings are not adjacent")
	}
	state := net.log.State()
	rows, err := NewBridgeLedgerHeadRows(net.heads[state.Base().GetConfigVersion()], nil)
	if err != nil {
		t.Fatal(err)
	}
	// the latest filing one millisecond past the grace, the others more; the first exactly at the grace, the others within
	late, onTime := testBridgeKeySignedAt(2, lastMs+grace+1), testBridgeKeySignedAt(2, firstMs+grace)
	for _, c := range []struct {
		key  *EvsRepoKey
		late bool
	}{{key: late, late: true}, {key: onTime, late: false}} {
		keys := testConfigSealKeyAt(testConfigSealKey(1), c.key)
		judge := &BridgeBodyJudge{RepoKeyAt: keys}
		for _, statement := range state.Bridge().Statements() {
			verdict := judge.Judge(bridgeStateBefore(state, statement.N, statement.TimeMs), statement)
			if verdict == nil {
				continue
			}
			refused := verdict.Kind == BridgeBodyRefused && errors.Is(verdict.Reason, errBridgeGenerationUnformed) && !errors.Is(verdict.Reason, ErrConfigSealInvalid)
			if refused != c.late || (!c.late && verdict.Kind != BridgeBodyStanding) {
				t.Errorf("late %v: the judge on %d: %+v", c.late, statement.N, verdict)
			}
		}
		ledger, err := OpenBridgeLedger(rows, &BridgeLedgerReader{State: state, RepoKeyAt: keys})
		if err != nil {
			t.Fatal(err)
		}
		for _, filing := range filings {
			entry := testBridgeEntryAt(t, ledger, filing.Pin.GetVersion())
			void := entry.Disposition == BridgeDispositionVoid && errors.Is(entry.Reason, errBridgeGenerationUnformed)
			if void != c.late || (!c.late && entry.Disposition != BridgeDispositionActive) {
				t.Errorf("late %v: the open of %d: disposition %d, %v", c.late, filing.Pin.GetVersion(), entry.Disposition, entry.Reason)
			}
		}
		if len(ledger.Alarms()) != 0 {
			t.Errorf("late %v: %d alarms", c.late, len(ledger.Alarms()))
		}
		if !c.late && (ledger.Rule(routeId) == nil || !ledger.Rule(routeId).Active() || len(ledger.Aliases()) != 1 || ledger.Address(desktop.sidecarId) == nil) {
			t.Errorf("at the grace the bodies are not in force")
		}
	}

	// the void, then generation 2 claimed under the filing's own key after it
	void := newTestBridgeLedgerNet(t)
	_, voidLaptop, _ := testBridgeCast(void.testConfigNet)
	wait, _ := testBridgeVoidTimes()
	behindKeys := []*EvsRepoKey{testConfigSealKey(1)}
	behindSettings := void.readerSettings()
	behindSettings.BridgeBodyJudge.RepoKeyAt = func(generation uint64) *EvsRepoKey { return testConfigSealKeyAt(behindKeys...)(generation) }
	behind, err := NewConfigLog(behindSettings, void.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	voidId := testBridgeRuleId("voided then claimed")
	filing := void.mustPost(voidLaptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, void.bridgeRouteAt(voidLaptop, voidId, testBridgeSubnet(testBridgePrefix(10, 17, 0, 0, 16), "v"), 2))
	for _, entryBytes := range void.entries {
		if _, err := behind.Apply(entryBytes, void.ledgerSource()); err != nil {
			t.Fatal(err)
		}
	}
	tip := void.tickAt(void.timeMs + wait)
	void.fold = void.writerJudge(1, 0)
	previousVersion := void.log.State().Base().GetConfigVersion()
	stateBefore := void.log.State()
	if reached := void.foldLedger(tip, nil); reached != tip || len(void.lastFold.Voided) != 1 {
		t.Fatalf("the writer's void: reached %d", reached)
	}
	claimed := testBridgeKeySignedAt(2, void.timeMs+60*1000)
	head, previous := void.heads[previousVersion+1], void.heads[previousVersion]
	for _, c := range []struct {
		grace time.Duration
		fork  bool
	}{{grace: 0, fork: false}, {grace: 100 * 365 * 24 * time.Hour, fork: true}} {
		settings := *void.settings
		settings.GenerationFormGrace = c.grace
		checked, err := CheckBridgeLedgerFold(head, previous, &BridgeLedgerReader{
			State: stateBefore, RepoKeyAt: testConfigSealKeyAt(testConfigSealKey(1), claimed), EntryTimeMs: void.log.EntryTimeMs, Settings: &settings,
		}, tip)
		if c.fork != errors.Is(err, ErrConfigHeadMismatch) || (!c.fork && (!checked || err != nil)) {
			t.Errorf("a reader gaining generation 2 with a grace of %s: checked %v, %v", c.grace, checked, err)
		}
	}

	// the daemon that was behind gains generation 2 and turns its verdict, then takes the tick and the base
	behindKeys = append(behindKeys, claimed)
	if changed, err := behind.RejudgeBridgeBodies(); err != nil || changed != 1 {
		t.Fatalf("the daemon behind rejudged %d: %v", changed, err)
	}
	if verdict := testBridgeVerdictAt(behind, filing.Pin.GetVersion()); verdict == nil || verdict.Kind != BridgeBodyRefused || !errors.Is(verdict.Reason, errBridgeGenerationUnformed) {
		t.Fatalf("the daemon behind's verdict: %+v", verdict)
	}
	for _, entryBytes := range void.entries[len(void.entries)-2:] {
		if verdict, err := behind.Apply(entryBytes, void.ledgerSource()); err != nil || !verdict.Accepted() {
			t.Fatalf("the daemon behind at the base: %v, %v", verdict.Refusal, err)
		}
	}
	if fork := behind.Fork(); fork != nil {
		t.Fatalf("the daemon behind forked: %v", fork)
	}
	// the frozen row stays: nothing is left to judge again, at the daemon or at the reader under test
	void.keys = append(void.keys, claimed)
	for _, log := range []*ConfigLog{behind, void.log} {
		if changed, err := log.RejudgeBridgeBodies(); err != nil || changed != 0 {
			t.Fatalf("a second rejudge changed %d: %v", changed, err)
		}
		if rule := void.ledgerOf(log).Rule(voidId); rule == nil || !rule.Void {
			t.Fatalf("the frozen row: %+v", rule)
		}
	}
	testBridgeLedgersEqual(t, void, behind)
}

// A void id stays void for the network's life: once a fold froze a route void as unformed, a later filing of its id by
// its own signer, under a body every reader opens, is void, while the id level refuses one by another signer outright,
// as for any held id; the next fold keeps the row and every reader holds one ledger.
func TestALaterFilingOfAVoidedIdIsVoid(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	net.fold = net.writerJudge(1, 0)
	wait, _ := testBridgeVoidTimes()
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	ruleId := testBridgeRuleId("voided id")
	net.mustPost(laptop, route, net.bridgeRouteAt(laptop, ruleId, testBridgeSubnet(testBridgePrefix(10, 18, 0, 0, 16), "i"), 2))
	if reached := net.foldLedger(net.tickAt(net.timeMs+wait), nil); len(net.lastFold.Voided) != 1 || reached != net.n-1 {
		t.Fatalf("the void: reached %d", reached)
	}
	again := net.mustPost(laptop, route, net.bridgeRoute(laptop, ruleId, testBridgeSubnet(testBridgePrefix(10, 18, 0, 0, 16), "i")))
	if other := net.post(desktop, route, net.bridgeRoute(desktop, ruleId, testBridgeSubnet(testBridgePrefix(10, 19, 0, 0, 16), "j"))); other.Accepted() {
		t.Fatal("another signer's filing of the void id took effect")
	}
	ledger := net.ledgerOf(net.log)
	testBridgeDisposition(t, ledger, again.Pin.GetVersion(), BridgeDispositionVoid)
	if rule := ledger.Rule(ruleId); rule == nil || !rule.Void || rule.Route != nil {
		t.Fatalf("the id: %+v", rule)
	}
	if reached := net.foldLedger(net.n, nil); reached != net.n-1 || len(net.lastFold.Voided) != 0 {
		t.Fatalf("the next fold: reached %d, voided %d", reached, len(net.lastFold.Voided))
	}
	if rule := net.ledgerOf(net.log).Rule(ruleId); rule == nil || !rule.Void {
		t.Fatalf("the id after the next fold: %+v", rule)
	}
	testBridgeLedgersEqual(t, net, net.presentReader(), net.restoredReader())
}

// BridgeVoid-Mirror and the two writers of DESIGN-DETAILS 12.2.3: writers with waits of 24 h and 48 h, each first in
// turn. A tip 30 h after a body sealed above every generation gkm names: the 48 h writer's base, where it is first,
// holds its fold below the body; the 24 h writer's base folds past it and voids it, and the 48 h writer, standing under
// the previous base, takes it unchecked. Where both would void, 49 h on, their files are byte-equal.
func TestTwoWritersFreezeOneVoid(t *testing.T) {
	short, long := 24*time.Hour, 48*time.Hour
	for _, longFirst := range []bool{false, true} {
		net := newTestBridgeLedgerNet(t)
		_, laptop, _ := testBridgeCast(net.testConfigNet)
		shortWriter, longWriter := net.writerJudge(1, short), net.writerJudge(1, long)
		filing := net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(laptop, testBridgeRuleId("two writers"), testBridgeSubnet(testBridgePrefix(10, 20, 0, 0, 16), "t"), 2))
		k := filing.Pin.GetVersion()
		tip := net.tickAt(net.timeMs + 30*time.Hour.Milliseconds())
		if longFirst {
			net.fold = longWriter
			if reached := net.foldLedger(tip, nil); reached != k-1 || net.lastFold.Stopped == nil || net.lastFold.Stopped.Statement.N != k {
				t.Fatalf("the 48 h writer first: reached %d", reached)
			}
			tip = net.tickAt(net.timeMs + 1000)
		}
		fold := net.foldBy(shortWriter, tip)
		if fold.FoldedThrough != tip || len(fold.Voided) != 1 {
			t.Fatalf("long first %v: the 24 h writer reached %d, voided %d", longFirst, fold.FoldedThrough, len(fold.Voided))
		}
		head := net.headOf(fold)
		if checked, err := net.checkAsReader(head, net.keys, longWriter.Settings, 1, tip); checked || err != nil {
			t.Fatalf("long first %v: the 48 h writer as a checker: checked %v, %v", longFirst, checked, err)
		}
		net.fold = shortWriter
		if reached := net.foldLedger(tip, nil); reached != tip {
			t.Fatalf("long first %v: the base reached %d", longFirst, reached)
		}
	}

	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(laptop, testBridgeRuleId("both void"), testBridgeSubnet(testBridgePrefix(10, 21, 0, 0, 16), "b"), 2))
	net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(desktop, testBridgeRuleId("both keep"), testBridgeSubnet(testBridgePrefix(10, 22, 0, 0, 16), "k")))
	tip := net.tickAt(net.timeMs + 49*time.Hour.Milliseconds())
	shortFold, longFold := net.foldBy(net.writerJudge(1, short), tip), net.foldBy(net.writerJudge(1, long), tip)
	if shortFold.FoldedThrough != tip || longFold.FoldedThrough != tip || len(shortFold.Voided) != 1 || len(longFold.Voided) != 1 {
		t.Fatalf("both void: through %d and %d", shortFold.FoldedThrough, longFold.FoldedThrough)
	}
	if !maps.EqualFunc(shortFold.Files, longFold.Files, bytes.Equal) || len(shortFold.Files) == 0 {
		t.Fatal("the two writers' files differ")
	}
}

// BridgeVoidReach-Held: a body sealed above every generation gkm names that has waited out its wait is not folded while
// a younger one sits at or below the previous base, since §7.9's rule lets a fold stop only at or above that base. A base
// 12 h after the older filing holds its fold below it; a day after the older one, with the younger at 12 h, the fold
// stays where it was: Stopped names the younger filing and its signer, and Voided is empty.
func TestTheFoldHoldsUnderAYoungerFilingBelowTheBase(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	net.fold = net.writerJudge(1, 0)
	wait, _ := testBridgeVoidTimes()
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	older := net.mustPost(laptop, route, net.bridgeRouteAt(laptop, testBridgeRuleId("older held"), testBridgeSubnet(testBridgePrefix(10, 23, 0, 0, 16), "o"), 2))
	olderMs := net.timeMs
	net.timeMs = olderMs + wait/2 - 1000
	younger := net.mustPost(desktop, route, net.bridgeRouteAt(desktop, testBridgeRuleId("younger held"), testBridgeSubnet(testBridgePrefix(10, 24, 0, 0, 16), "y"), 2))
	held := older.Pin.GetVersion() - 1
	if reached := net.foldLedger(net.n, nil); reached != held {
		t.Fatalf("the base at 12 h reached %d, want %d", reached, held)
	}
	tip := net.tickAt(olderMs + wait)
	if reached := net.foldLedger(tip, nil); reached != held {
		t.Fatalf("the base a day on reached %d, want %d", reached, held)
	}
	fold := net.lastFold
	if fold.Stopped == nil || fold.Stopped.Statement.N != younger.Pin.GetVersion() || fold.Stopped.Statement.Signer != desktop.sidecarId || fold.Stopped.Generation != 2 {
		t.Fatalf("stopped: %+v", fold.Stopped)
	}
	if len(fold.Voided) != 0 {
		t.Fatalf("%d voided where the fold stayed", len(fold.Voided))
	}
	ledger := net.ledgerOf(net.log)
	if rule := ledger.Rule(testBridgeRuleId("older held")); rule == nil || !rule.Pending {
		t.Fatalf("the older filing at the reader under test: %+v", rule)
	}
}

// QD-774's bound: filings sealed above every generation gkm names, 6 h apart with a base after each, then none. No base
// folds past the first while any of them is younger than the wait; a plan whose tip is one millisecond short of the wait
// past the last holds still; the first plan whose tip is the wait past the last folds through its tip and voids them
// all, in log order.
func TestTheFoldReachesTheTipAWaitAfterTheLastFiling(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, _ := testBridgeCast(net.testConfigNet)
	net.fold = net.writerJudge(1, 0)
	wait, _ := testBridgeVoidTimes()
	startMs := net.timeMs + 1000
	positions, signers := []uint64{}, []Id{}
	for i := range 4 {
		net.timeMs = startMs + int64(i)*6*time.Hour.Milliseconds() - 1000
		filing := net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(laptop, testBridgeRuleId(fmt.Sprint("kept filing ", i)), testBridgeSubnet(testBridgePrefix(10, byte(30+i), 0, 0, 16), "k"), 2))
		positions, signers = append(positions, filing.Pin.GetVersion()), append(signers, laptop.sidecarId)
		if reached := net.foldLedger(net.n, nil); reached != positions[0]-1 {
			t.Fatalf("the base after filing %d reached %d", i, reached)
		}
	}
	lastMs := startMs + 3*6*time.Hour.Milliseconds()
	short := net.foldBy(net.fold, net.tickAt(lastMs+wait-1))
	if short.FoldedThrough != positions[0]-1 || len(short.Voided) != 0 || short.Stopped == nil || short.Stopped.Statement.N != positions[3] {
		t.Fatalf("a millisecond short: through %d, voided %d, stopped %+v", short.FoldedThrough, len(short.Voided), short.Stopped)
	}
	tip := net.tickAt(lastMs + wait)
	if reached := net.foldLedger(tip, nil); reached != tip {
		t.Fatalf("the wait past the last: reached %d, want %d", reached, tip)
	}
	testBridgeVoidedAre(t, "the wait past the last", net.lastFold.Voided, 2, positions, signers)
	testBridgeLedgersEqual(t, net, net.presentReader(), net.restoredReader())
}

// Twin WaitInsideSkew's guard: a wait below the grace plus UnformedVoidWaitMargin is raised to that floor where the
// settings are read, the caller's settings unchanged; and a writer configured with a 10 min wait holds a filing until
// 90 min, the floor under the default grace.
func TestBridgeLedgerSettingsFloorTheWait(t *testing.T) {
	defaults := bridgeLedgerSettingsOrDefault(nil)
	if defaults.UnformedVoidWait != 24*time.Hour || defaults.GenerationFormGrace != time.Hour || defaults.UnformedVoidWaitMargin != 30*time.Minute {
		t.Fatalf("the defaults: %+v", defaults)
	}
	for _, c := range []struct {
		settings BridgeLedgerSettings
		wait     time.Duration
		grace    time.Duration
	}{
		{settings: BridgeLedgerSettings{UnformedVoidWait: 10 * time.Minute}, wait: 90 * time.Minute, grace: time.Hour},
		{settings: BridgeLedgerSettings{}, wait: 90 * time.Minute, grace: time.Hour},
		{settings: BridgeLedgerSettings{UnformedVoidWait: 2 * time.Hour, GenerationFormGrace: 2 * time.Hour}, wait: 150 * time.Minute, grace: 2 * time.Hour},
		{settings: BridgeLedgerSettings{UnformedVoidWait: time.Hour, GenerationFormGrace: 2 * time.Hour, UnformedVoidWaitMargin: time.Hour}, wait: 3 * time.Hour, grace: 2 * time.Hour},
		{settings: BridgeLedgerSettings{UnformedVoidWait: 24 * time.Hour}, wait: 24 * time.Hour, grace: time.Hour},
	} {
		given := c.settings
		read := bridgeLedgerSettingsOrDefault(&given)
		if read.UnformedVoidWait != c.wait || read.GenerationFormGrace != c.grace || given != c.settings {
			t.Errorf("%+v: read a wait of %s and a grace of %s", c.settings, read.UnformedVoidWait, read.GenerationFormGrace)
		}
	}

	net := newTestBridgeLedgerNet(t)
	_, laptop, _ := testBridgeCast(net.testConfigNet)
	writer := net.writerJudge(1, 10*time.Minute)
	filing := net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRouteAt(laptop, testBridgeRuleId("floored"), testBridgeSubnet(testBridgePrefix(10, 40, 0, 0, 16), "f"), 2))
	filedMs := net.timeMs
	for _, c := range []struct {
		ageMs int64
		void  bool
	}{{ageMs: 10 * time.Minute.Milliseconds(), void: false}, {ageMs: 90*time.Minute.Milliseconds() - 1, void: false}, {ageMs: 90 * time.Minute.Milliseconds(), void: true}} {
		fold := net.foldBy(writer, net.tickAt(filedMs+c.ageMs))
		if (len(fold.Voided) == 1) != c.void || (fold.Stopped != nil && fold.Stopped.Statement.N != filing.Pin.GetVersion()) {
			t.Errorf("at %d ms: voided %d, stopped %+v", c.ageMs, len(fold.Voided), fold.Stopped)
		}
	}
}
