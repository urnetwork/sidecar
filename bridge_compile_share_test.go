//go:build !ios_extension

// The bridge compile's shares (bridge_compile_share.go; DESIGN-DETAILS 12.6's shares row): a host compiles a share
// from its grant file only while the grant is live and only from tables that hash to the file's pins, carrying the
// targets it hosts with their aliases' host bits and the share's pinned ShareKey; a row it lacks is a wait, a row at
// another hash an alarm, and a revoked grant ends the share. A sender's table holds an entry of each alias in force it
// may reach the sharing network by, linked to the alias's host under the key the alias pinned, once that host's binding
// verifies under it, read into the network's current block by host bits.

package sidecar

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A compile view of the share world's reader at its tip, over the head the world's writer saved, or the one its base
// names, with the world's block.
func (self *testBridgeShareWorld) compileView() *testBridgeCompileView {
	self.t.Helper()
	state := self.net.log.State()
	acl, err := state.Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	head, err := self.testBridgeFileWorld.heads.ReadConfigHead(context.Background(), state.Base().GetConfigVersion(), state.Base().GetConfigHeadSha256())
	if err != nil {
		self.t.Fatal(err)
	}
	rows, err := NewBridgeLedgerHeadRows(head, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return &testBridgeCompileView{state: state, acl: acl, head: head, rows: rows, keys: []*EvsRepoKey{testConfigSealKey(1)}, opened: map[string]int{}}
}

// The world's host activates a share of two targets it hosts, a /24 over TCP/443 and a /32 on every protocol, which the
// other network completed at two aliases; answers the invite and the activation's filing.
func (self *testBridgeShareWorld) activatedShare() (*BridgeShareInvite, *BridgeFiling, []byte) {
	self.t.Helper()
	self.withSharesRule()
	ctx := context.Background()
	invite, err := self.filer.Invite(ctx, self.confirmed(), &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
		{Host: self.hostId, Prefix: netip.MustParsePrefix("192.168.7.0/24"), Protocol: 6, Ports: []*bridge.BridgePortRange{{First: 443, Last: 443}}},
		{Host: self.hostId, Prefix: netip.MustParsePrefix("192.168.9.9/32")},
	}})
	if err != nil {
		self.t.Fatal(err)
	}
	sharePublicKey := self.completed(invite, 0x8100, 0x8001)
	preview, err := self.filer.PreviewShare(ctx, self.confirmed(), invite.ShareId)
	if err != nil {
		self.t.Fatal(err)
	}
	filing, err := self.filer.ActivateShare(ctx, self.confirmed(), preview, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	self.install()
	return invite, filing, sharePublicKey
}

// §17.9's X side: the host's rules carry the share from its grant file and the pinned tables, its two targets with
// their aliases' host bits and lengths and their protocols and ports, under the activation's grant and the accepting
// network; the state carries the pinned ShareKey; and a host the share does not name compiles nothing of it.
func TestAShareCompilesFromItsGrantFileAndPinnedTables(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	invite, filing, sharePublicKey := world.activatedShare()
	row := world.server.row(invite.ShareId)
	local := &BridgeCompileLocal{SidecarId: world.hostId, ShareTables: []*BridgeShareRow{row}}
	compiled, rules := testBridgeCompile(t, world.compileView(), local)
	if len(rules.GetShares()) != 1 {
		t.Fatalf("%d shares compiled: %v", len(rules.GetShares()), compiled.Alarms)
	}
	share := rules.GetShares()[0]
	if !bytes.Equal(share.GetShareId(), invite.ShareId.Bytes()) || !bytes.Equal(share.GetAcceptingNetworkId(), world.other.Bytes()) ||
		!bytes.Equal(share.GetSharePublicKey(), sharePublicKey) || !bytes.Equal(share.GetGrantId(), filing.GrantId) {
		t.Fatalf("the share: %v", share)
	}
	want := []*bridge.BridgeRuleShareTarget{
		{Index: 0, AliasHostBits: 0x8100, Length: 24, Target: testBridgePrefix(192, 168, 7, 0, 24), Protocol: 6,
			Ports: []*bridge.BridgePortRange{{First: 443, Last: 443}}},
		{Index: 1, AliasHostBits: 0x8001, Length: 32, Target: testBridgePrefix(192, 168, 9, 9, 32), Ports: []*bridge.BridgePortRange{}},
	}
	if len(share.GetTargets()) != len(want) {
		t.Fatalf("the targets: %v", share.GetTargets())
	}
	for i, target := range share.GetTargets() {
		if !proto.Equal(target, want[i]) {
			t.Errorf("target %d: %v, want %v", i, target, want[i])
		}
	}
	keys := compiled.State.GetShareKeys()
	if len(keys) != 1 || !bytes.Equal(keys[0].GetShareId(), invite.ShareId.Bytes()) || !bytes.Equal(keys[0].GetPublicKey(), sharePublicKey) {
		t.Fatalf("the state's share keys: %v", keys)
	}
	// the device role takes the rules as compiled
	testBridgeRulesParse(t, compiled.State.GetRules())
	// another device of the network hosts none of the share's targets
	other := &BridgeCompileLocal{SidecarId: world.laptop.sidecarId, ShareTables: []*BridgeShareRow{row}}
	if _, otherRules := testBridgeCompile(t, world.compileView(), other); len(otherRules.GetShares()) != 0 {
		t.Fatalf("a device the share names in no target compiled %v", otherRules.GetShares())
	}
}

// A host compiles a share only from its pinned row: with none it waits for one, and with a row whose alias table is not
// the one the grant file pins it compiles nothing and alarms share_table_mismatch.
func TestAShareCompilesOnlyFromItsPinnedRow(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	invite, _, _ := world.activatedShare()
	compiled, rules := testBridgeCompile(t, world.compileView(), &BridgeCompileLocal{SidecarId: world.hostId})
	if len(rules.GetShares()) != 0 || len(compiled.State.GetShareKeys()) != 0 {
		t.Fatal("a share with no row compiled")
	}
	if !slices.Contains(compiled.Waits, BridgeCompileWait{Kind: BridgeCompileWaitShareTable, ShareId: invite.ShareId}) {
		t.Fatalf("the waits: %v", compiled.Waits)
	}
	swapped := testBridgeShareRowCopy(world.server.row(invite.ShareId))
	swapped.AliasTable = append(bytes.Clone(swapped.AliasTable), 0)
	compiled, rules = testBridgeCompile(t, world.compileView(), &BridgeCompileLocal{SidecarId: world.hostId, ShareTables: []*BridgeShareRow{swapped}})
	if len(rules.GetShares()) != 0 || !testBridgeCompileAlarmed(compiled, SidecarBridgeAlarmShareTableMismatch) {
		t.Fatalf("a row the pins refuse: %v, %v", rules.GetShares(), compiled.Alarms)
	}
}

// The share ends with its grant: once the sharing network's GrantRevoke lands, its grant file pins nothing a host
// compiles.
func TestAShareEndsWithItsGrant(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	invite, _, _ := world.activatedShare()
	local := &BridgeCompileLocal{SidecarId: world.hostId, ShareTables: []*BridgeShareRow{world.server.row(invite.ShareId)}}
	if _, rules := testBridgeCompile(t, world.compileView(), local); len(rules.GetShares()) != 1 {
		t.Fatal("the share before its revocation")
	}
	if _, err := world.filer.RevokeShare(context.Background(), world.confirmed(), invite.ShareId); err != nil {
		t.Fatal(err)
	}
	world.install()
	if _, rules := testBridgeCompile(t, world.compileView(), local); len(rules.GetShares()) != 0 {
		t.Fatalf("a share whose grant was revoked compiled %v", rules.GetShares())
	}
}

// A share of two targets on one host of the sharing network, which the world's host accepts: its share, the far host,
// the key its table pinned for it, and the aliases' prefixes in the world's block, by target.
func (self *testBridgeShareWorld) acceptedShare() (Id, Id, []byte, []*bridge.BridgeIpv4Prefix) {
	self.t.Helper()
	far := testConfigId("share host")
	hostKey := bytes.Repeat([]byte{0x44}, 32)
	targets := &bridge.BridgeShareTargets{Targets: []*bridge.BridgeShareTarget{
		{Index: 0, HostSidecarId: far.Bytes(), HostIdentityPublicKey: hostKey, Prefix: testBridgePrefix(192, 168, 7, 0, 24)},
		{Index: 1, HostSidecarId: far.Bytes(), HostIdentityPublicKey: hostKey, Prefix: testBridgePrefix(192, 168, 9, 9, 32)},
	}}
	code, _, shareId := self.invited(targets)
	accepted, err := self.filer.AcceptInvite(context.Background(), self.confirmed(), code)
	if err != nil || accepted.Status != BridgeShareAcceptStatusActive {
		self.t.Fatalf("the accept: %+v, %v", accepted, err)
	}
	prefixes := []*bridge.BridgeIpv4Prefix{}
	for _, alias := range accepted.Aliases {
		prefixes = append(prefixes, &bridge.BridgeIpv4Prefix{Address: testBridgeIpv4(100, 80, 0, 0) | alias.GetAliasHostBits(), Length: alias.GetLength()})
	}
	return shareId, far, hostKey, prefixes
}

// A standing rule of the world's network: its members' devices may dial the sharing network, Y's half of §8.11.
func (self *testBridgeShareWorld) withSharingNetworkReach() {
	self.t.Helper()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:   testConfigId("dial the sharing network").Bytes(),
			SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{NetworkId: self.other.Bytes()}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
		})
	})
	// the rows changed the head the base names
	self.testBridgeFileWorld.heads.reader = newTestConfigHeadReader(self.net)
	self.install()
}

// A sender the policy lets reach no sharing network has no share entry, whatever aliases its network holds.
func TestAnAliasRoutesNothingWithoutReachToItsNetwork(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	world.acceptedShare()
	if _, rules := testBridgeCompile(t, world.compileView(), &BridgeCompileLocal{SidecarId: world.hostId}); testBridgeCompileShareEntry(rules) != nil {
		t.Fatal("a share entry with no rule reaching the sharing network")
	}
}

// §17.9's Y side: an alias in force is an entry of the sender's table at the alias's host bits in the current block,
// linked to the alias's host in the sharing network under the key the alias pinned, at the client its binding names; a
// host whose binding is missing or names another key is a wait and links nothing.
func TestAnAliasInForceIsAShareLinkOfTheSendersTable(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	world.withSharingNetworkReach()
	shareId, far, hostKey, aliases := world.acceptedShare()
	// with no binding of the far host, the entries wait for it and carry no link
	compiled, rules := testBridgeCompile(t, world.compileView(), &BridgeCompileLocal{SidecarId: world.hostId})
	wait := BridgeCompileWait{Kind: BridgeCompileWaitShareBinding, SidecarId: far, NetworkId: world.other}
	copy(wait.IdentityPublicKey[:], hostKey)
	if !slices.Contains(compiled.Waits, wait) {
		t.Fatalf("the waits: %v", compiled.Waits)
	}
	entry := testBridgeCompileEntry(rules, aliases[0])
	if entry == nil || len(entry.GetLinks()) != 0 {
		t.Fatalf("the /24 alias's entry before the binding: %v", entry)
	}
	// a binding under another key links nothing either
	bindings := NewBridgeBindingCache(7*24*time.Hour, 16)
	farClient := testConfigId("share host client")
	bindings.Record(&BridgeBinding{SidecarId: far, ClientId: farClient, ClientPublicKey: farClient.Bytes(), IdentityPublicKey: bytes.Repeat([]byte{0x45}, 32), Generation: 1, Signed: farClient.Bytes()}, world.clock.Now())
	if _, rules := testBridgeCompile(t, world.compileView(), &BridgeCompileLocal{SidecarId: world.hostId, Bindings: bindings.Snapshot()}); testBridgeCompileShareEntry(rules) != nil {
		t.Fatal("a share link to a host whose binding names another key")
	}
	bindings.Record(&BridgeBinding{SidecarId: far, ClientId: farClient, ClientPublicKey: farClient.Bytes(), IdentityPublicKey: hostKey, Generation: 2, Signed: append(farClient.Bytes(), 2)}, world.clock.Now())
	compiled, rules = testBridgeCompile(t, world.compileView(), &BridgeCompileLocal{SidecarId: world.hostId, Bindings: bindings.Snapshot()})
	for _, prefix := range aliases {
		entry := testBridgeCompileEntry(rules, prefix)
		if entry == nil || len(entry.GetLinks()) != 1 {
			t.Fatalf("the alias's entry at %v: %v", prefix, entry)
		}
		link := entry.GetLinks()[0]
		if !bytes.Equal(link.GetTargetSidecarId(), far.Bytes()) || !bytes.Equal(link.GetTargetClientId(), farClient.Bytes()) ||
			!bytes.Equal(link.GetTargetIdentityPublicKey(), hostKey) || !bytes.Equal(link.GetShareId(), shareId.Bytes()) ||
			!bytes.Equal(link.GetTargetNetworkId(), world.other.Bytes()) || 0 < len(link.GetTargetMemberId()) {
			t.Fatalf("the share link: %v", link)
		}
	}
	if len(compiled.ShareLinks) != 1 || compiled.ShareLinks[0] != (BridgeCompiledShareLink{ShareId: shareId, TargetSidecarId: far}) {
		t.Fatalf("the share links: %v", compiled.ShareLinks)
	}
	if slices.Contains(compiled.LinkTargets, far) {
		t.Fatal("a share link's host is a link target of this network")
	}
	testBridgeRulesParse(t, compiled.State.GetRules())
}

// The first entry of the rules whose link is a share link, nil for none.
func testBridgeCompileShareEntry(rules *bridge.BridgeRules) *bridge.BridgeRuleEntry {
	for _, entry := range rules.GetEntries() {
		for _, link := range entry.GetLinks() {
			if 0 < len(link.GetShareId()) {
				return entry
			}
		}
	}
	return nil
}

// The device role's ParseBridgeRules, which bridge_compile_share_parse_test.go installs from the external test package,
// since the root links no device/ (§4.4) while its compile and the role's parser are held to each other.
var BridgeRulesParserForTest func(rules []byte) error

// Fails unless the device role takes the rules whole.
func testBridgeRulesParse(t *testing.T, rules []byte) {
	t.Helper()
	if BridgeRulesParserForTest == nil {
		t.Fatal("no device role's parser installed")
	}
	if err := BridgeRulesParserForTest(rules); err != nil {
		t.Fatalf("the device role refuses the compiled rules: %v", err)
	}
}
