// The bridge ledger on the test network (bridge_ledger.go, bridge_ledger_fold.go; DESIGN-DETAILS 12.6's ledger row): a
// writer folding its verdicts into each base's config head as ConfigWriter's plan does, readers present since the
// bootstrap and readers restored at each base holding one ledger, verdicts judged where their entries land and turned
// alike by a base whose rows change the policy, a fold freezing what its readers held, a mismatching fold forking, an
// unopened filing stopping the fold and judged once its generation arrives, the files' bytes equal across runs and
// GOMAXPROCS, the rule shards widening, and the file readers' refusals.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
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

// A test network whose bases name config heads that carry the bridge ledger, its reader judging with a judge that
// reads those heads.
type testBridgeLedgerNet struct {
	*testConfigNet
	// the heads the bases named, by config version
	heads map[uint64]*ConfigHead
	// the keys every judge here holds
	keys []*EvsRepoKey
	// a test approval check for every judge here, nil for the state's
	checkApproval BridgeApprovalCheck
	// the ledger's settings for every judge here
	settings *BridgeLedgerSettings
}

// A ledger net over a fresh test network: base 1's head the genesis alone, the reader under test judging with
// generation 1's key and reading heads from the net.
func newTestBridgeLedgerNet(t testing.TB) *testBridgeLedgerNet {
	return newTestBridgeLedgerNetOver(t, newTestConfigNet(t))
}

// A ledger net over net, which stands at base 1.
func newTestBridgeLedgerNetOver(t testing.TB, net *testConfigNet) *testBridgeLedgerNet {
	head, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	self := &testBridgeLedgerNet{
		testConfigNet: net,
		heads:         map[uint64]*ConfigHead{1: head},
		keys:          []*EvsRepoKey{testConfigSealKey(1)},
		settings:      DefaultBridgeLedgerSettings(),
	}
	net.log.settings.BridgeBodyJudge = self.judge()
	return self
}

// A judge over the net's keys and heads.
func (self *testBridgeLedgerNet) judge() *BridgeBodyJudge {
	return &BridgeBodyJudge{
		RepoKeyAt: func(generation uint64) *EvsRepoKey {
			return testConfigSealKeyAt(self.keys...)(generation)
		},
		ReadHead: func(configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
			head := self.heads[configVersion]
			if head == nil || !bytes.Equal(configHeadSha256, testConfigHeadSha256(configVersion)) {
				return nil, fmt.Errorf("no head at version %d", configVersion)
			}
			return head, nil
		},
		Settings:      self.settings,
		checkApproval: self.checkApproval,
	}
}

// Settings with the net's judge, for another reader of the same log.
func (self *testBridgeLedgerNet) readerSettings() *ConfigLogSettings {
	settings := testConfigLogSettings()
	settings.AclSpendCheck = self.log.settings.AclSpendCheck
	settings.BridgeBodyJudge = self.judge()
	return settings
}

// A rows source that runs a base's bridge ledger check on the head the net saved for it, then the test source's.
type testBridgeLedgerRowsSource struct {
	*testConfigRowsSource
	heads map[uint64]*ConfigHead
}

// The ledger check on the base's head, then the test source's head check.
func (self *testBridgeLedgerRowsSource) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	if check.Previous != nil && check.BridgeFoldCheck != nil {
		head := self.heads[check.Header.GetConfigVersion()]
		if head == nil {
			return nil, fmt.Errorf("%w: no head at version %d", ErrConfigHeadUnavailable, check.Header.GetConfigVersion())
		}
		if err := check.BridgeFoldCheck(head); err != nil {
			if errors.Is(err, ErrConfigHeadUnavailable) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: bridge ledger: %w", ErrConfigHeadMismatch, err)
		}
	}
	return self.testConfigRowsSource.CheckHead(check)
}

// The source the net's bases go through.
func (self *testBridgeLedgerNet) ledgerSource() *testBridgeLedgerRowsSource {
	return &testBridgeLedgerRowsSource{testConfigRowsSource: self.source, heads: self.heads}
}

// Sequences an entry made at the tip as the test net's push does, applied through the ledger's source; the entry's
// error is the caller's.
func (self *testBridgeLedgerNet) pushThrough(entryBytes []byte) (ConfigVerdict, error) {
	self.t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		self.t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		self.t.Fatal(err)
	}
	verdict, err := self.log.Apply(entryBytes, self.ledgerSource())
	if err != nil {
		return verdict, err
	}
	self.n, self.chain, self.timeMs = entry.GetN(), chain, entry.GetTimeMs()
	self.entries = append(self.entries, entryBytes)
	self.statesAt[entry.GetN()] = self.log.State()
	self.verdicts[entry.GetN()] = verdict
	return verdict, nil
}

// The head a base at the tip folding through foldedThrough names, saved at configVersion, as ConfigWriter's plan
// builds it: the previous base's head with the ledger's fold and the fold's records. Answers the head and the fold the
// ledger reached. edit, when set, changes the ledger's files after the fold, as a writer gone wrong would.
func (self *testBridgeLedgerNet) foldHead(foldedThrough uint64, configVersion uint64, edit func(files map[string][]byte)) (*ConfigHead, uint64) {
	self.t.Helper()
	state := self.log.State()
	previous := self.heads[state.Base().GetConfigVersion()]
	if previous == nil {
		self.t.Fatalf("no head at the base's version %d", state.Base().GetConfigVersion())
	}
	head := previous
	reached := previous.FoldedThrough()
	if previous.FoldedThrough() < foldedThrough {
		fold, err := self.judge().Fold(previous, state, foldedThrough, self.log.EntryTimeMs)
		if err != nil {
			self.t.Fatal(err)
		}
		if edit != nil {
			edit(fold.Files)
		}
		if head, err = fold.Apply(previous); err != nil {
			self.t.Fatal(err)
		}
		reached = fold.FoldedThrough
		records, known := self.log.foldedRecords(previous.FoldedThrough()+1, reached)
		if !known {
			self.t.Fatalf("the records through %d are not kept", reached)
		}
		if head, err = head.WithFold(records, reached); err != nil {
			self.t.Fatal(err)
		}
	}
	self.heads[configVersion] = head
	return head, reached
}

// A base at the tip folding through foldedThrough, as far as its ledger reaches, its head saved and its rows the
// reader's state at the fold, with aclEdit, when set, editing their acl part as a head's policy change does. Fails the
// test unless it lands; answers the fold reached.
func (self *testBridgeLedgerNet) foldLedger(foldedThrough uint64, aclEdit func(rows *protocol.AclRows)) uint64 {
	self.t.Helper()
	verdict, reached, err := self.tryFoldLedger(foldedThrough, aclEdit, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	if !verdict.Accepted() {
		self.t.Fatalf("the base: %v", verdict.Refusal)
	}
	return reached
}

// foldLedger, the ledger's files edited by edit, answering what the reader under test made of it.
func (self *testBridgeLedgerNet) tryFoldLedger(foldedThrough uint64, aclEdit func(rows *protocol.AclRows), edit func(files map[string][]byte)) (ConfigVerdict, uint64, error) {
	self.t.Helper()
	configVersion := self.log.State().Base().GetConfigVersion() + 1
	_, reached := self.foldHead(foldedThrough, configVersion, edit)
	folded := self.statesAt[reached]
	if folded == nil {
		self.t.Fatalf("no state at %d", reached)
	}
	rows := folded.Rows()
	if aclEdit != nil {
		aclRows := &protocol.AclRows{}
		if folded.aclRows != nil {
			aclRows = proto.Clone(folded.aclRows).(*protocol.AclRows)
		}
		aclEdit(aclRows)
		rows.Acl = testConfigMarshal(self.t, aclRows)
	}
	verdict, err := self.pushThrough(self.makeBase(self.owner, rows, reached, configVersion, folded.threshold))
	return verdict, reached, err
}

// The ledger a log holds at its tip: the head its newest base names, opened with the net's keys.
func (self *testBridgeLedgerNet) ledgerOf(log *ConfigLog) *BridgeLedger {
	self.t.Helper()
	state := log.State()
	rows, err := NewBridgeLedgerHeadRows(self.heads[state.Base().GetConfigVersion()], self.settings)
	if err != nil {
		self.t.Fatal(err)
	}
	ledger, err := OpenBridgeLedger(rows, &BridgeLedgerReader{
		State: state, RepoKeyAt: testConfigSealKeyAt(self.keys...), EntryTimeMs: log.EntryTimeMs, Settings: self.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return ledger
}

// A reader present since the bootstrap, judging with the net's judge, that applied every entry so far.
func (self *testBridgeLedgerNet) presentReader() *ConfigLog {
	self.t.Helper()
	reader, err := NewConfigLog(self.readerSettings(), self.signedGenesis)
	if err != nil {
		self.t.Fatal(err)
	}
	for _, entryBytes := range self.entries {
		if _, err := reader.Apply(entryBytes, self.ledgerSource()); err != nil {
			self.t.Fatal(err)
		}
	}
	return reader
}

// A new device judging with the net's judge, started at the newest base among the reader under test's kept entries.
func (self *testBridgeLedgerNet) restoredReader() *ConfigLog {
	self.t.Helper()
	reader, err := RestoreConfigLog(self.readerSettings(), self.log.Retained(), self.ledgerSource())
	if err != nil {
		self.t.Fatal(err)
	}
	return reader
}

// A ledger as bytes: its rows as a fold would write them at its own time, which two readers holding one ledger give
// alike.
func testBridgeLedgerBytes(t testing.TB, ledger *BridgeLedger) []byte {
	t.Helper()
	addresses, rules, egress, aliases := ledger.foldRows()
	return slices.Concat(
		testConfigMarshal(t, &protocol.BridgeLedgerAddresses{Rows: addresses}),
		testConfigMarshal(t, &protocol.BridgeLedgerRules{Rows: rules}),
		testConfigMarshal(t, &protocol.BridgeLedgerEgressSpecs{Rows: egress}),
		testConfigMarshal(t, &protocol.BridgeLedgerAliases{Rows: aliases}),
	)
}

// The verdict of the statement an entry at n carried in a log's state, nil for none.
func testBridgeVerdictAt(log *ConfigLog, n uint64) *BridgeBodyVerdict {
	for _, statement := range log.State().Bridge().Statements() {
		if statement.N == n {
			return statement.Approval
		}
	}
	return nil
}

// A requests rule a test spend check reads as the policy that lets bridge decisions spend.
var testBridgeRequestRuleId = testConfigId("bridge approvers request rule").Bytes()

// Lets a decision spend while the state's rows hold the bridge approvers' requests rule: a policy a base's head can
// change without an entry of the log, as §16.6's real check reads the governing request rule.
type testBridgePolicySpendCheck struct{}

func (self testBridgePolicySpendCheck) Spendable(state *AclState, decision *StoredApprovalDecision, action *StoredCanonicalAction, spender Id, pin *bridge.AuthPin, now time.Time) error {
	for _, request := range state.Rows().GetRequests() {
		if bytes.Equal(request.GetRuleId(), testBridgeRequestRuleId) {
			return nil
		}
	}
	return errors.New("no request rule lets this decision spend")
}

// Adds the bridge approvers' requests rule to acl rows.
func testBridgeWithApprovers(rows *protocol.AclRows) {
	rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
		RuleId:        testBridgeRequestRuleId,
		SrcAtoms:      [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
		Targets:       []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
		ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
	})
}

// Drops the bridge approvers' requests rule from acl rows.
func testBridgeWithoutApprovers(rows *protocol.AclRows) {
	rows.Requests = slices.DeleteFunc(rows.Requests, func(request *protocol.AclRequestRule) bool {
		return bytes.Equal(request.GetRuleId(), testBridgeRequestRuleId)
	})
}

// A route of device at prefix under a real single-use approval of approver's, its rule id the one the approval fixes.
func (self *testBridgeLedgerNet) approvedRoute(device testConfigDevice, approver Id, label string, prefix *bridge.BridgeIpv4Prefix, notAfterMs int64) ([]byte, *bridge.BridgeRoute) {
	self.t.Helper()
	cidr := fmt.Sprintf("%d.%d.%d.%d/%d", prefix.GetAddress()>>24, byte(prefix.GetAddress()>>16), byte(prefix.GetAddress()>>8), byte(prefix.GetAddress()), prefix.GetLength())
	approval, ruleId := testBridgeExposeApproval(self.t, label, device.sidecarId, []string{cidr}, device.sidecarId, approver, notAfterMs)
	return ruleId, self.bridgeRoute(device, ruleId, testBridgeApprovedSubnet(prefix, approval))
}

// A ledger net with the bridge approvers' requests rule in force and the policy spend check installed, at a base that
// folds every entry so far, and three devices of one member that file.
func newTestBridgePolicyNet(t testing.TB) (*testBridgeLedgerNet, Id, []testConfigDevice) {
	net := newTestBridgeLedgerNet(t)
	member, laptop, desktop := testBridgeCast(net.testConfigNet)
	tablet := net.device("m tablet", member)
	net.admitDevice(laptop, tablet, 0)
	net.log.settings.AclSpendCheck = testBridgePolicySpendCheck{}
	net.foldLedger(net.n, testBridgeWithApprovers)
	return net, member, []testConfigDevice{laptop, desktop, tablet}
}

// Fails unless every log holds one ledger at its tip, byte for byte.
func testBridgeLedgersEqual(t *testing.T, net *testBridgeLedgerNet, logs ...*ConfigLog) {
	t.Helper()
	want := testBridgeLedgerBytes(t, net.ledgerOf(net.log))
	for i, log := range logs {
		if !proto.Equal(log.State().Pin(), net.log.State().Pin()) {
			t.Fatalf("reader %d stands at %v, the net's at %v", i, log.State().Pin(), net.log.State().Pin())
		}
		if got := testBridgeLedgerBytes(t, net.ledgerOf(log)); !bytes.Equal(got, want) {
			t.Errorf("reader %d holds another ledger: %x, the net's %x", i, got, want)
		}
	}
}

// QD-668: an approval is judged on the state its entry lands on. A route approved while the approvers' rule held is
// in force, and stays so once a base folds it and drops the rule; one filed after that base is refused, at the reader
// under test, a reader present since the bootstrap and one restored at the base alike.
func TestAnApprovalIsJudgedOnTheStateItLandsOn(t *testing.T) {
	net, member, devices := newTestBridgePolicyNet(t)
	laptop := devices[0]
	notAfter := net.timeMs + testBridgeDayMs
	beforeId, before := net.approvedRoute(laptop, member, "before", testBridgePrefix(192, 168, 1, 0, 24), notAfter)
	filed := net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, before)
	if verdict := testBridgeVerdictAt(net.log, filed.Pin.GetVersion()); verdict == nil || verdict.Kind != BridgeBodyApproved {
		t.Fatalf("the route filed under the rule: %+v", verdict)
	}
	net.foldLedger(net.n, testBridgeWithoutApprovers)
	afterId, after := net.approvedRoute(laptop, member, "after", testBridgePrefix(192, 168, 2, 0, 24), notAfter)
	late := net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, after)
	if verdict := testBridgeVerdictAt(net.log, late.Pin.GetVersion()); verdict == nil || verdict.Kind != BridgeBodyRefused {
		t.Fatalf("the route filed after the rule went: %+v", verdict)
	}
	ledger := net.ledgerOf(net.log)
	if rule := ledger.Rule(beforeId); rule == nil || !rule.Active() || rule.ApprovalId != testConfigId("expose approval before") {
		t.Fatalf("the folded route: %+v", rule)
	}
	if rule := ledger.Rule(afterId); rule == nil || !rule.Void {
		t.Fatalf("the late route: %+v", rule)
	}
	testBridgeLedgersEqual(t, net, net.presentReader(), net.restoredReader())
}

// QD-668's one turn: a base that leaves an approved filing unfolded and whose rows drop the approvers' rule judges the
// filing again on its own rows, so the verdict turns, at a reader present at the filing and at one restored at the
// base alike, and fails closed. Its ledger stands where the base kept its fold.
func TestABaseJudgesItsTailOnItsOwnRows(t *testing.T) {
	net, member, devices := newTestBridgePolicyNet(t)
	laptop := devices[0]
	ruleId, route := net.approvedRoute(laptop, member, "tail", testBridgePrefix(192, 168, 3, 0, 24), net.timeMs+testBridgeDayMs)
	filed := net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, route)
	present := net.presentReader()
	if verdict := testBridgeVerdictAt(present, filed.Pin.GetVersion()); verdict == nil || verdict.Kind != BridgeBodyApproved {
		t.Fatalf("at its own position: %+v", verdict)
	}
	if rule := net.ledgerOf(net.log).Rule(ruleId); rule == nil || !rule.Active() {
		t.Fatalf("the route before the base: %+v", rule)
	}

	// a policy-only base keeps the previous fold, the filing in its tail
	keptFold := net.log.State().Base().GetFoldedThrough()
	if reached := net.foldLedger(keptFold, testBridgeWithoutApprovers); reached != keptFold {
		t.Fatalf("the base folded through %d, not %d", reached, keptFold)
	}
	if _, err := present.Apply(net.entries[len(net.entries)-1], net.ledgerSource()); err != nil {
		t.Fatal(err)
	}
	restored := net.restoredReader()
	for i, log := range []*ConfigLog{net.log, present, restored} {
		if verdict := testBridgeVerdictAt(log, filed.Pin.GetVersion()); verdict == nil || verdict.Kind != BridgeBodyRefused {
			t.Errorf("reader %d after the base: %+v", i, verdict)
		}
	}
	if rule := net.ledgerOf(net.log).Rule(ruleId); rule == nil || !rule.Void {
		t.Fatalf("the route after the base: %+v", rule)
	}
	testBridgeLedgersEqual(t, net, present, restored)
}

// FoldFaithful and FoldedStays: a fold writes the ledger its readers held at folded_through, every kind of row in it,
// and a later fold whose base drops the approvers' rule copies the frozen verdict; a reader starting at either base
// takes the rows and holds that ledger.
func TestAFoldFreezesWhatItsReadersHeld(t *testing.T) {
	net, member, devices := newTestBridgePolicyNet(t)
	laptop, desktop := devices[0], devices[1]
	route, withdraw := bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(desktop, testBridgeIpv4(100, 80, 3, 8)))
	approvedId, approved := net.approvedRoute(laptop, member, "frozen", testBridgePrefix(192, 168, 4, 0, 24), net.timeMs+testBridgeDayMs)
	net.mustPost(laptop, route, approved)
	standingId := testBridgeRuleId("standing")
	net.mustPost(desktop, route, net.bridgeRoute(desktop, standingId, testBridgeSubnet(testBridgePrefix(10, 4, 0, 0, 16), "far")))
	net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMap(desktop, testBridgeRuleId("map"), 0, testBridgeMapBody(testBridgeIpv4(100, 80, 3, 8), 8443, 443)))
	net.mustPost(desktop, withdraw, net.bridgeWithdraw(standingId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN))
	net.mustPost(net.owner, withdraw, net.bridgeWithdraw(testBridgeRuleId("reserved"), bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgress(laptop.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS,
		&bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{desktop.sidecarId.Bytes()}}))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_ALIAS, net.bridgeAlias(&bridge.BridgeAliasBody{
		ShareId: testConfigId("share").Bytes(), AliasPrefix: testBridgePrefix(100, 80, 128, 0, 24), Host: testConfigId("far host").Bytes(),
	}))
	held := testBridgeLedgerBytes(t, net.ledgerOf(net.log))

	net.foldLedger(net.n, nil)
	head := net.heads[net.log.State().Base().GetConfigVersion()]
	for _, path := range []string{ConfigHeadBridgeLedgerManifestPath, ConfigHeadBridgeLedgerAddressesPath, ConfigHeadBridgeLedgerEgressPath, ConfigHeadBridgeLedgerAliasesPath} {
		if head.File(path) == nil {
			t.Errorf("the fold wrote no %s", path)
		}
	}
	ledger := net.ledgerOf(net.log)
	if len(ledger.Entries()) != 0 || ledger.FoldedThrough() != net.log.State().Base().GetFoldedThrough() {
		t.Fatalf("after the fold the ledger reads %d unfolded statements through %d", len(ledger.Entries()), ledger.FoldedThrough())
	}
	if folded := testBridgeLedgerBytes(t, ledger); !bytes.Equal(folded, held) {
		t.Fatalf("the fold holds another ledger than its readers held:\n%x\n%x", folded, held)
	}
	if rule := ledger.Rule(testBridgeRuleId("reserved")); rule != nil || ledger.Reserved(testBridgeRuleId("reserved")) == nil {
		t.Fatal("the reservation did not fold as a reservation")
	}

	// a base dropping the approvers' rule leaves the frozen route in force
	net.foldLedger(net.n, testBridgeWithoutApprovers)
	if rule := net.ledgerOf(net.log).Rule(approvedId); rule == nil || !rule.Active() {
		t.Fatalf("the frozen route under the new policy: %+v", rule)
	}
	testBridgeLedgersEqual(t, net, net.presentReader(), net.restoredReader())
}

// FoldFaithful's other half: a head whose ledger is not the one a reader standing under the previous base folds is a
// fork at that reader, whether a row changed, a file went or the whole ledger did, beside the head that lands.
func TestALedgerFoldMismatchForks(t *testing.T) {
	cases := []struct {
		name string
		edit func(files map[string][]byte)
	}{
		{name: "a rule row's body", edit: func(files map[string][]byte) {
			for path, data := range files {
				if bytes.HasPrefix([]byte(path), []byte(ConfigHeadBridgeLedgerRulesPrefix)) {
					rules := &protocol.BridgeLedgerRules{}
					if proto.Unmarshal(data, rules) != nil || len(rules.Rows) == 0 {
						panic("no rules to edit")
					}
					rules.Rows[0].GetRoute().Weight += 1
					files[path], _ = proto.MarshalOptions{Deterministic: true}.Marshal(rules)
				}
			}
		}},
		{name: "the addresses file", edit: func(files map[string][]byte) { delete(files, ConfigHeadBridgeLedgerAddressesPath) }},
		{name: "the whole ledger", edit: func(files map[string][]byte) { clear(files) }},
	}
	for _, c := range cases {
		net := newTestBridgeLedgerNet(t)
		_, laptop, _ := testBridgeCast(net.testConfigNet)
		net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)))
		net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, testBridgeRuleId("route"), testBridgeSubnet(testBridgePrefix(10, 1, 0, 0, 16), "site")))
		_, _, err := net.tryFoldLedger(net.n, nil, c.edit)
		if !errors.Is(err, ErrConfigFork) || !bytes.Contains([]byte(err.Error()), []byte("bridge ledger")) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	net := newTestBridgeLedgerNet(t)
	_, laptop, _ := testBridgeCast(net.testConfigNet)
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, testBridgeRuleId("route"), testBridgeSubnet(testBridgePrefix(10, 1, 0, 0, 16), "site")))
	if _, _, err := net.tryFoldLedger(net.n, nil, func(files map[string][]byte) {}); err != nil {
		t.Fatalf("the honest fold: %v", err)
	}
}

// A writer never freezes what it could not open: a route sealed to a generation the writer lacks stops the fold at the
// entry before it, the routes after it stay unfolded, and the checker, which lacks it too, takes the head's rows. Once
// the generation arrives, RejudgeBridgeBodies judges the filing in the base's tail and one above the base, and the next
// fold takes both.
func TestAnUnopenedFilingStopsTheFold(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	firstId, waitingId, afterId, laterId := testBridgeRuleId("first"), testBridgeRuleId("waiting"), testBridgeRuleId("after"), testBridgeRuleId("later")
	net.mustPost(laptop, route, net.bridgeRoute(laptop, firstId, testBridgeSubnet(testBridgePrefix(10, 1, 0, 0, 16), "a")))
	waiting := net.mustPost(desktop, route, net.bridgeRouteAt(desktop, waitingId, testBridgeSubnet(testBridgePrefix(10, 2, 0, 0, 16), "b"), 2))
	net.mustPost(laptop, route, net.bridgeRoute(laptop, afterId, testBridgeSubnet(testBridgePrefix(10, 3, 0, 0, 16), "c")))
	if verdict := testBridgeVerdictAt(net.log, waiting.Pin.GetVersion()); verdict == nil || verdict.Kind != BridgeBodyUnopened || verdict.Generation != 2 {
		t.Fatalf("the waiting filing: %+v", verdict)
	}

	if reached := net.foldLedger(net.n, nil); reached != waiting.Pin.GetVersion()-1 {
		t.Fatalf("the fold reached %d, want %d", reached, waiting.Pin.GetVersion()-1)
	}
	ledger := net.ledgerOf(net.log)
	if rule := ledger.Rule(firstId); rule == nil || !rule.Active() || rule.First != nil {
		t.Fatalf("the folded route: %+v", rule)
	}
	if rule := ledger.Rule(waitingId); rule == nil || !rule.Pending {
		t.Fatalf("the waiting route: %+v", rule)
	}
	if rule := ledger.Rule(afterId); rule == nil || !rule.Active() || rule.First == nil {
		t.Fatalf("the route after it stays unfolded: %+v", rule)
	}
	later := net.mustPost(laptop, route, net.bridgeRouteAt(laptop, laterId, testBridgeSubnet(testBridgePrefix(10, 4, 0, 0, 16), "d"), 3))

	// the generations arrive: the filing in the tail and the one above the base are judged
	net.keys = append(net.keys, testConfigSealKey(2), testConfigSealKey(3))
	changed, err := net.log.RejudgeBridgeBodies()
	if err != nil || changed != 2 {
		t.Fatalf("rejudged %d: %v", changed, err)
	}
	for _, n := range []uint64{waiting.Pin.GetVersion(), later.Pin.GetVersion()} {
		if verdict := testBridgeVerdictAt(net.log, n); verdict == nil || verdict.Kind != BridgeBodyStanding {
			t.Errorf("the filing at %d after its generation arrived: %+v", n, verdict)
		}
	}
	if changed, err := net.log.RejudgeBridgeBodies(); err != nil || changed != 0 {
		t.Fatalf("a second pass rejudged %d: %v", changed, err)
	}
	ledger = net.ledgerOf(net.log)
	for _, ruleId := range [][]byte{waitingId, laterId} {
		if rule := ledger.Rule(ruleId); rule == nil || !rule.Active() {
			t.Fatalf("a rejudged route: %+v", rule)
		}
	}
	if reached := net.foldLedger(net.n, nil); reached != net.n-1 {
		t.Fatalf("the fold after the generation arrived reached %d", reached)
	}
	ledger = net.ledgerOf(net.log)
	if len(ledger.Entries()) != 0 || ledger.Rule(waitingId) == nil || !ledger.Rule(waitingId).Active() {
		t.Fatalf("the fold took the waiting route: %+v", ledger.Rule(waitingId))
	}
	testBridgeLedgersEqual(t, net, net.presentReader(), net.restoredReader())
}

// The rule shards' width is a function of the rows at the fold: past BridgeLedgerSettings.RuleShardRowCount rules they
// widen to 16 bits, rules/<xx>/<yy>, and the rows read back as one ledger.
func TestRuleShardsWiden(t *testing.T) {
	for _, c := range []struct {
		ruleCount int
		bits      uint32
	}{{ruleCount: 3, bits: 8}, {ruleCount: 4, bits: 16}} {
		net := newTestBridgeLedgerNet(t)
		net.settings.RuleShardRowCount = 3
		net.log.settings.BridgeBodyJudge = net.judge()
		_, laptop, _ := testBridgeCast(net.testConfigNet)
		for i := range c.ruleCount {
			prefix := testBridgePrefix(10, byte(i+1), 0, 0, 16)
			net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, testBridgeRuleId(fmt.Sprint("shard ", i)), testBridgeSubnet(prefix, "site")))
		}
		held := testBridgeLedgerBytes(t, net.ledgerOf(net.log))
		net.foldLedger(net.n, nil)
		head := net.heads[net.log.State().Base().GetConfigVersion()]
		manifest := &protocol.BridgeLedgerManifest{}
		if err := proto.Unmarshal(head.File(ConfigHeadBridgeLedgerManifestPath), manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.GetRuleShardBits() != c.bits {
			t.Errorf("%d rules: shards of %d bits", c.ruleCount, manifest.GetRuleShardBits())
		}
		shardCount := 0
		for _, file := range manifest.GetFiles() {
			shard, ok := bytes.CutPrefix([]byte(file.GetPath()), []byte(ConfigHeadBridgeLedgerRulesPrefix))
			if !ok {
				continue
			}
			shardCount += 1
			if wide := bytes.Contains(shard, []byte("/")); wide != (c.bits == 16) {
				t.Errorf("%d rules: a shard %s", c.ruleCount, file.GetPath())
			}
		}
		if shardCount == 0 {
			t.Errorf("%d rules: no shard", c.ruleCount)
		}
		if folded := testBridgeLedgerBytes(t, net.ledgerOf(net.log)); !bytes.Equal(folded, held) {
			t.Errorf("%d rules: the shards read back another ledger", c.ruleCount)
		}
	}
}

// What a head's ledger files must be, each refusal beside the head that reads: ledger files with no manifest, a
// file whose bytes are not the manifest's, a file the manifest does not name, a manifest of another fold, rows out of
// order, a row in another rule's shard and a row with a field this build cannot name.
func TestBridgeLedgerHeadRowsRefuseWhatNoWriterFolds(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(desktop, testBridgeIpv4(100, 80, 3, 8)))
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, testBridgeRuleId("route"), testBridgeSubnet(testBridgePrefix(10, 1, 0, 0, 16), "site")))
	net.foldLedger(net.n, nil)
	head := net.heads[net.log.State().Base().GetConfigVersion()]
	readAll := func(head *ConfigHead) error {
		rows, err := NewBridgeLedgerHeadRows(head, nil)
		if err != nil {
			return err
		}
		ledger := newBridgeLedger(&BridgeLedgerReader{}, 0, 0, false)
		return ledger.loadRows(rows)
	}
	if err := readAll(head); err != nil {
		t.Fatalf("the honest head: %v", err)
	}
	with := func(edit func(files map[string][]byte)) *ConfigHead {
		files := head.Files()
		edit(files)
		edited, err := NewConfigHead(files)
		if err != nil {
			t.Fatal(err)
		}
		return edited
	}
	addresses := &protocol.BridgeLedgerAddresses{}
	if err := proto.Unmarshal(head.File(ConfigHeadBridgeLedgerAddressesPath), addresses); err != nil || len(addresses.Rows) != 2 {
		t.Fatalf("the addresses: %v, %v", addresses, err)
	}
	// rows re-encoded, the manifest's hash and count following, so only the rows' own refusal shows
	rewrite := func(path string, message proto.Message, rowCount int) func(files map[string][]byte) {
		return func(files map[string][]byte) {
			data := testConfigMarshal(t, message)
			files[path] = data
			manifest := &protocol.BridgeLedgerManifest{}
			if err := proto.Unmarshal(files[ConfigHeadBridgeLedgerManifestPath], manifest); err != nil {
				t.Fatal(err)
			}
			for _, file := range manifest.Files {
				if file.Path == path {
					digest := sha256.Sum256(data)
					file.Sha256, file.RowCount = digest[:], uint64(rowCount)
				}
			}
			files[ConfigHeadBridgeLedgerManifestPath] = testConfigMarshal(t, manifest)
		}
	}
	reversed := &protocol.BridgeLedgerAddresses{Rows: []*protocol.BridgeLedgerAddressRow{addresses.Rows[1], addresses.Rows[0]}}
	stray := proto.Clone(addresses).(*protocol.BridgeLedgerAddresses)
	stray.Rows[0].ProtoReflect().SetUnknown(binary.AppendUvarint([]byte{0x78}, 1))
	ruleShard := BridgeLedgerRulesPath(testBridgeRuleId("route"), 8)
	otherShard := ConfigHeadBridgeLedgerRulesPrefix + "ff"
	if ruleShard == otherShard {
		otherShard = ConfigHeadBridgeLedgerRulesPrefix + "fe"
	}
	for name, edited := range map[string]*ConfigHead{
		"no manifest": with(func(files map[string][]byte) { delete(files, ConfigHeadBridgeLedgerManifestPath) }),
		"a flipped bit": with(func(files map[string][]byte) {
			files[ConfigHeadBridgeLedgerAddressesPath][len(files[ConfigHeadBridgeLedgerAddressesPath])-1] ^= 1
		}),
		"a file it does not name": with(func(files map[string][]byte) { files[ConfigHeadBridgeLedgerEgressPath] = []byte{} }),
		"rows out of order":       with(rewrite(ConfigHeadBridgeLedgerAddressesPath, reversed, 2)),
		"a field it cannot name":  with(rewrite(ConfigHeadBridgeLedgerAddressesPath, stray, 2)),
		"a rule in another shard": with(func(files map[string][]byte) {
			data := files[ruleShard]
			delete(files, ruleShard)
			files[otherShard] = data
			manifest := &protocol.BridgeLedgerManifest{}
			if err := proto.Unmarshal(files[ConfigHeadBridgeLedgerManifestPath], manifest); err != nil {
				t.Fatal(err)
			}
			for _, file := range manifest.Files {
				if file.Path == ruleShard {
					file.Path = otherShard
				}
			}
			files[ConfigHeadBridgeLedgerManifestPath] = testConfigMarshal(t, manifest)
		}),
		"another fold": with(func(files map[string][]byte) {
			manifest := &protocol.BridgeLedgerManifest{}
			if err := proto.Unmarshal(files[ConfigHeadBridgeLedgerManifestPath], manifest); err != nil {
				t.Fatal(err)
			}
			manifest.FoldedThrough -= 1
			files[ConfigHeadBridgeLedgerManifestPath] = testConfigMarshal(t, manifest)
		}),
	} {
		if err := readAll(edited); !errors.Is(err, ErrBridgeLedgerMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A file reader decodes one row at a time and answers io.EOF only once the bytes it read hash to the manifest's.
func TestABridgeLedgerFileReaderHashesWhatItRead(t *testing.T) {
	rows := &protocol.BridgeLedgerAddresses{Rows: []*protocol.BridgeLedgerAddressRow{
		{HostBits: 0x0301, SidecarId: testConfigId("a").Bytes(), ClaimedAt: 3},
		{HostBits: 0x0302, SidecarId: testConfigId("b").Bytes(), ClaimedAt: 4},
	}}
	data := testConfigMarshal(t, rows)
	digest := sha256.Sum256(data)
	read := func(data []byte, file *protocol.BridgeLedgerFile) (int, error) {
		reader := newBridgeLedgerStreamReader(bytes.NewReader(data), file, bridgeLedgerRowOf(ConfigHeadBridgeLedgerAddressesPath), DefaultBridgeLedgerSettings())
		defer reader.Close()
		count := 0
		for {
			row, err := reader.Next()
			if errors.Is(err, io.EOF) {
				return count, nil
			}
			if err != nil {
				return count, err
			}
			if !proto.Equal(row, rows.Rows[count]) {
				return count, fmt.Errorf("row %d reads back as %v", count, row)
			}
			count += 1
		}
	}
	if count, err := read(data, &protocol.BridgeLedgerFile{Sha256: digest[:], RowCount: 2}); err != nil || count != 2 {
		t.Fatalf("the honest file: %d rows, %v", count, err)
	}
	if _, err := read(data, &protocol.BridgeLedgerFile{Sha256: make([]byte, sha256.Size), RowCount: 2}); !errors.Is(err, ErrBridgeLedgerMalformed) {
		t.Errorf("another hash: %v", err)
	}
	if _, err := read(data, &protocol.BridgeLedgerFile{Sha256: digest[:], RowCount: 3}); !errors.Is(err, ErrBridgeLedgerMalformed) {
		t.Errorf("another count: %v", err)
	}
	if _, err := read(data[:len(data)-1], &protocol.BridgeLedgerFile{Sha256: digest[:], RowCount: 2}); !errors.Is(err, ErrBridgeLedgerMalformed) {
		t.Errorf("a cut file: %v", err)
	}
}

// One generated run of filings, folds and policy changes over a policy net (TestBridgeLedgerEqualFromAnyBase,
// FuzzBridgeLedgerFold): every bridge statement kind, refused ones among them, approvals under the approvers' rule, a
// device revoked, time passing past tombstones and retention, and bases that fold through the tip. turns lets a base
// keep its fold and change the policy, which may turn a tail verdict. each runs after every base.
func testBridgeLedgerRun(t testing.TB, net *testBridgeLedgerNet, member Id, devices []testConfigDevice, random *rand.Rand, stepCount int, turns bool, each func()) {
	t.Helper()
	signers := append([]testConfigDevice{net.owner}, devices...)
	ruleIds := [][]byte{}
	approvers := true
	route, mapType := bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_MAP
	pick := func(count int) int { return random.IntN(count) }
	for step := range stepCount {
		signer := signers[pick(len(signers))]
		switch pick(13) {
		case 0, 1:
			subject := signers[pick(len(signers))]
			net.post(signer, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(subject, testBridgeIpv4(100, 80, 3, byte(1+pick(6)))))
		case 2:
			ruleId := testBridgeRuleId(fmt.Sprint("run route ", step))
			ruleIds = append(ruleIds, ruleId)
			net.post(signer, route, net.bridgeRoute(signer, ruleId, testBridgeSubnet(testBridgePrefix(192, 168, byte(pick(4)), 0, 24), []string{"a", "b"}[pick(2)])))
		case 3:
			ruleId, filing := net.approvedRoute(signer, member, fmt.Sprint("run ", step), testBridgePrefix(10, byte(pick(4)), 0, 0, 16), net.timeMs+testBridgeDayMs)
			ruleIds = append(ruleIds, ruleId)
			net.post(signer, route, filing)
		case 4:
			ruleId := testBridgeRuleId(fmt.Sprint("run map ", step))
			ruleIds = append(ruleIds, ruleId)
			net.post(signer, mapType, net.bridgeMap(signer, ruleId, 0, testBridgeMapBody(testBridgeIpv4(100, 80, 3, 9), uint32(8000+pick(4)), 443)))
		case 5:
			if 0 < len(ruleIds) {
				net.post(signer, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(ruleIds[pick(len(ruleIds))], bridge.BridgeWithdrawMode(1+pick(2))))
			} else {
				net.post(signer, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(testBridgeRuleId(fmt.Sprint("ahead ", step)), bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
			}
		case 6:
			subject := signers[pick(len(signers))]
			switch pick(3) {
			case 0:
				net.post(net.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgress(subject.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE, nil))
			case 1:
				net.post(net.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgress(subject.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS,
					&bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{signers[pick(len(signers))].sidecarId.Bytes()}}))
			default:
				net.post(net.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgress(subject.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, nil))
			}
		case 7:
			net.post(signer, bridge.SignedType_SIGNED_BRIDGE_ALIAS, net.bridgeAlias(&bridge.BridgeAliasBody{
				ShareId: testConfigId("run share").Bytes(), TargetIndex: uint32(pick(3)), AliasPrefix: testBridgePrefix(100, 80, byte(128+pick(3)), 0, 24),
				Host: testConfigId("run host").Bytes(),
			}))
		case 8:
			if 0 < len(ruleIds) {
				// a retry of a held id
				net.post(signer, route, net.bridgeRoute(signer, ruleIds[pick(len(ruleIds))], testBridgeSubnet(testBridgePrefix(192, 168, byte(pick(4)), 0, 24), "a")))
			}
		case 9:
			if 3 < len(signers) && pick(3) == 0 {
				revoked := signers[len(signers)-1]
				signers = signers[:len(signers)-1]
				net.post(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(revoked, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
			}
		case 10:
			net.timeMs += int64(1+pick(20)) * testBridgeDayMs
		case 11:
			net.foldLedger(net.n, nil)
			each()
		case 12:
			if turns {
				approvers = !approvers
				edit := testBridgeWithApprovers
				if !approvers {
					edit = testBridgeWithoutApprovers
				}
				net.foldLedger(net.log.State().Base().GetFoldedThrough(), edit)
				each()
			}
		}
	}
}

// LedgerEqual (QD-667): over generated runs of filings, folds and policy changes, the reader under test, a reader
// present since the bootstrap, which checks each base's ledger itself, and a reader restored at each base hold one
// ledger at every base and at the end.
func TestBridgeLedgerEqualFromAnyBase(t *testing.T) {
	for seed := range uint64(4) {
		net, member, devices := newTestBridgePolicyNet(t)
		random := rand.New(rand.NewPCG(seed, 0xb1d9e))
		testBridgeLedgerRun(t, net, member, devices, random, 120, true, func() {
			testBridgeLedgersEqual(t, net, net.restoredReader())
		})
		testBridgeLedgersEqual(t, net, net.presentReader(), net.restoredReader())
	}
}

// The heads of the vectors' generated run at GOMAXPROCS procs, by config version.
func testBridgeLedgerVectorRun(t *testing.T, procs int) map[uint64]*ConfigHead {
	previous := runtime.GOMAXPROCS(procs)
	defer runtime.GOMAXPROCS(previous)
	net, member, devices := newTestBridgePolicyNet(t)
	testBridgeLedgerRun(t, net, member, devices, rand.New(rand.NewPCG(7, 0xde7)), 100, true, func() {})
	net.foldLedger(net.n, nil)
	return net.heads
}

// The ledger's files are byte-equal across runs and GOMAXPROCS: one generated run, twice, writes the same head at every
// config version.
func TestBridgeLedgerFilesAreDeterministic(t *testing.T) {
	first, second := testBridgeLedgerVectorRun(t, 1), testBridgeLedgerVectorRun(t, 8)
	if len(first) != len(second) || len(first) < 3 {
		t.Fatalf("%d heads and %d", len(first), len(second))
	}
	ledgerFileCount := 0
	for version, head := range first {
		other := second[version]
		if other == nil {
			t.Fatalf("no head at version %d the second time", version)
		}
		for _, path := range head.Paths() {
			if bridgeLedgerPath(path) {
				ledgerFileCount += 1
				if !bytes.Equal(head.File(path), other.File(path)) {
					t.Errorf("version %d's %s differs between runs", version, path)
				}
			}
		}
		if !slices.Equal(head.Paths(), other.Paths()) {
			t.Errorf("version %d holds other paths", version)
		}
	}
	if ledgerFileCount == 0 {
		t.Fatal("the run folded no ledger file")
	}
}


// The vectors, embedded so they read on every leg, the page Worker's included.
//
//go:embed testdata/bridge/ledger
var testBridgeLedgerVectorFiles embed.FS

// testdata/bridge/ledger/run.json: the SHA-256 of every ledger file of the vectors' run, by config version and path, so
// a leg whose encoding or fold differed in one byte fails here. SIDECAR_REGENERATE_BRIDGE_LEDGER_VECTORS=1 rewrites
// them, which only a change to the ledger's format or rules, or to the test network's fixtures, should need.
func TestBridgeLedgerFilesMatchTheirVectors(t *testing.T) {
	got := map[string]map[string]string{}
	for version, head := range testBridgeLedgerVectorRun(t, 4) {
		for _, path := range head.Paths() {
			if bridgeLedgerPath(path) {
				if got[fmt.Sprint(version)] == nil {
					got[fmt.Sprint(version)] = map[string]string{}
				}
				digest := sha256.Sum256(head.File(path))
				got[fmt.Sprint(version)][path] = hex.EncodeToString(digest[:])
			}
		}
	}
	if os.Getenv("SIDECAR_REGENERATE_BRIDGE_LEDGER_VECTORS") != "" {
		encoded, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("testdata/bridge/ledger/run.json", append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := testBridgeLedgerVectorFiles.ReadFile("testdata/bridge/ledger/run.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) < 3 {
		t.Fatalf("%d versions in the vectors", len(want))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the run's ledger files are not the vectors':\n%v\n%v", got, want)
	}
}

// BridgeLedgerSettings.UnfoldedBodyMaxByteCount bounds the unfolded bodies an open holds: past it the open refuses
// with ErrBridgeLedgerOverBudget, beside the same open under the default.
func TestAnOpenPastItsUnfoldedBudgetIsRefused(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, _ := testBridgeCast(net.testConfigNet)
	for i := range 4 {
		net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(laptop, testBridgeRuleId(fmt.Sprint("budget ", i)), testBridgeSubnet(testBridgePrefix(10, byte(i+1), 0, 0, 16), "site")))
	}
	state := net.log.State()
	rows, err := NewBridgeLedgerHeadRows(net.heads[state.Base().GetConfigVersion()], nil)
	if err != nil {
		t.Fatal(err)
	}
	reader := &BridgeLedgerReader{State: state, RepoKeyAt: testConfigSealKeyAt(net.keys...)}
	if ledger, err := OpenBridgeLedger(rows, reader); err != nil || len(ledger.Entries()) != 4 {
		t.Fatalf("under the default: %v", err)
	}
	reader.Settings = DefaultBridgeLedgerSettings()
	reader.Settings.UnfoldedBodyMaxByteCount = 16
	if _, err := OpenBridgeLedger(rows, reader); !errors.Is(err, ErrBridgeLedgerOverBudget) {
		t.Fatalf("past the budget: %v", err)
	}
}

// A fold in two steps is the fold in one: a writer extending a head another saved without a base, through a position
// past the newest base, writes the files a writer folding the same span at once writes, tombstones, retention and
// releases included, so the checkers standing under the previous base, which fold the span at once, take it.
func TestAFoldInTwoStepsIsTheFoldInOne(t *testing.T) {
	net, member, devices := newTestBridgePolicyNet(t)
	laptop, desktop, tablet := devices[0], devices[1], devices[2]
	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)))
	net.mustPost(tablet, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(tablet, testBridgeIpv4(100, 80, 3, 9)))
	standingId := testBridgeRuleId("two steps standing")
	net.mustPost(desktop, route, net.bridgeRoute(desktop, standingId, testBridgeSubnet(testBridgePrefix(10, 5, 0, 0, 16), "far")))
	_, approved := net.approvedRoute(laptop, member, "two steps", testBridgePrefix(10, 6, 0, 0, 16), net.timeMs+testBridgeDayMs)
	net.mustPost(laptop, route, approved)
	middle := net.n
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(tablet, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(standingId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
	net.timeMs += 8 * testBridgeDayMs
	net.mustPost(net.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, net.bridgeEgress(laptop.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE, nil))
	net.mustPost(desktop, route, net.bridgeRoute(desktop, testBridgeRuleId("two steps late"), testBridgeSubnet(testBridgePrefix(10, 5, 0, 0, 16), "far")))

	state := net.log.State()
	previous := net.heads[state.Base().GetConfigVersion()]
	judge := net.judge()
	once, err := judge.Fold(previous, state, net.n, net.log.EntryTimeMs)
	if err != nil || once.FoldedThrough != net.n {
		t.Fatalf("at once: %v", err)
	}
	first, err := judge.Fold(previous, state, middle, net.log.EntryTimeMs)
	if err != nil || first.FoldedThrough != middle {
		t.Fatalf("the first step: %v", err)
	}
	pending, err := first.Apply(previous)
	if err != nil {
		t.Fatal(err)
	}
	records, _ := net.log.foldedRecords(previous.FoldedThrough()+1, middle)
	if pending, err = pending.WithFold(records, middle); err != nil {
		t.Fatal(err)
	}
	second, err := judge.Fold(pending, state, net.n, net.log.EntryTimeMs)
	if err != nil {
		t.Fatalf("the second step: %v", err)
	}
	if !reflect.DeepEqual(once.Files, second.Files) || len(once.Files) < 4 {
		t.Fatalf("two steps fold other files than one: %d and %d files", len(second.Files), len(once.Files))
	}
}

// A withdrawn id past its retention reads alike whether a fold came between or not: the fold whose time passes it drops
// its row, and a statement whose time passes it finds it gone too, so a later withdrawal by a device that never filed
// it reserves the id at a reader whose fold dropped the row and at one whose ledger still held it (regression: the
// held rule voided the withdrawal at the second; FuzzBridgeLedgerFold's 16a1b8f49d60696f).
func TestAWithdrawnIdPastItsRetentionReadsAlikeAcrossAFold(t *testing.T) {
	for _, foldBetween := range []bool{true, false} {
		net := newTestBridgeLedgerNet(t)
		_, laptop, desktop := testBridgeCast(net.testConfigNet)
		ruleId := testBridgeRuleId("retention")
		net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_MAP, net.bridgeMap(laptop, ruleId, 0, testBridgeMapBody(testBridgeIpv4(100, 80, 3, 7), 8443, 443)))
		net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(ruleId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
		net.foldLedger(net.n, nil)
		// past the standing rule's retention, its newest filing's header no longer replayable
		net.timeMs += 8 * testBridgeDayMs
		if foldBetween {
			net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)))
			net.foldLedger(net.n, nil)
			if net.ledgerOf(net.log).Rule(ruleId) != nil {
				t.Fatal("the fold past the retention kept the withdrawn id")
			}
		}
		later := net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(ruleId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
		ledger := net.ledgerOf(net.log)
		testBridgeDisposition(t, ledger, later.Pin.GetVersion(), BridgeDispositionActive)
		if reserved := ledger.Reserved(ruleId); reserved == nil || reserved.Signer != desktop.sidecarId || ledger.Rule(ruleId) != nil {
			t.Fatalf("fold between %v: the later withdrawal reserved %+v", foldBetween, reserved)
		}
		// the rows the next fold writes hold the reservation and nothing else of the id
		_, rules, _, _ := ledger.foldRows()
		held := []protocol.BridgeLedgerDisposition{}
		for _, row := range rules {
			if bytes.Equal(row.GetRuleId(), ruleId) {
				held = append(held, row.GetDisposition())
			}
		}
		if !slices.Equal(held, []protocol.BridgeLedgerDisposition{protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_RESERVED}) {
			t.Fatalf("fold between %v: the id's rows %v", foldBetween, held)
		}
	}
}

// A tombstone in the upper /17 blocks an alias or an exposed prefix only while it holds at the filing's position and
// time: one that ran out by then leaves the ledger, as the fold whose time passes it drops it, so the room reads alike
// whether a fold came between or not.
func TestAnExpiredTombstoneLeavesRoomForAnAlias(t *testing.T) {
	releasedMs := testConfigStartMs
	for _, c := range []struct {
		timeMs int64
		room   bool
	}{{timeMs: releasedMs + BridgeAddressTombstoneMs - 1, room: false}, {timeMs: releasedMs + BridgeAddressTombstoneMs, room: true}} {
		ledger := newBridgeLedger(&BridgeLedgerReader{}, math.MaxUint64, c.timeMs, false)
		ledger.holdAddress(&BridgeLedgerAddress{
			SidecarId: testConfigId("spilled"), HostBits: 0x8001, ClaimedAt: 3,
			folded: &bridgeRelease{n: 5, timeMs: releasedMs, timeMsKnown: true},
		})
		alias := &BridgeLogStatement{N: 9, TimeMs: c.timeMs}
		err := ledger.holdAlias(&bridge.BridgeAliasBody{
			ShareId: testConfigId("share").Bytes(), AliasPrefix: testBridgePrefix(100, 80, 128, 0, 24), Host: testConfigId("far host").Bytes(),
		}, alias)
		if (err == nil) != c.room || ledger.HostBitsTaken(0x8001) == c.room {
			t.Errorf("at %d: %v, the tombstone taken %v", c.timeMs, err, ledger.HostBitsTaken(0x8001))
		}
	}
}
