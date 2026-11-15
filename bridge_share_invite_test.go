//go:build !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/netip"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The server's share rows in memory, as POST /acl/invite, POST /acl/accept-invite and GET /network/bridge/share/<id>
// keep them: an invite stored by its code's hash, a claim that names the claiming network, a completion stored once.
type testBridgeShareServer struct {
	stateLock sync.Mutex
	// the network a call comes from
	caller Id
	rows   map[Id]*BridgeShareRow
	codes  map[[sha256.Size]byte]Id
	// each completion's bytes as posted, answered or not
	completions [][]byte
	// answers the next completion with an error after storing nothing
	completeErr error
	// run as a completion arrives, before it is stored
	onComplete func()
}

func newTestBridgeShareServer(caller Id) *testBridgeShareServer {
	return &testBridgeShareServer{caller: caller, rows: map[Id]*BridgeShareRow{}, codes: map[[sha256.Size]byte]Id{}}
}

func testBridgeShareRowCopy(row *BridgeShareRow) *BridgeShareRow {
	copied := *row
	copied.TargetTable, copied.AliasTable = bytes.Clone(row.TargetTable), bytes.Clone(row.AliasTable)
	return &copied
}

// Stores an invite of network's as its admin's device would post it.
func (self *testBridgeShareServer) invite(network Id, codeHash []byte, targetTable []byte) Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	shareId := testConfigId(fmt.Sprintf("share %d", len(self.rows)))
	self.rows[shareId] = &BridgeShareRow{ShareId: shareId, SharingNetworkId: network, TargetTable: bytes.Clone(targetTable), TargetTableVersion: 1}
	self.codes[[sha256.Size]byte(codeHash)] = shareId
	return shareId
}

func (self *testBridgeShareServer) InviteBridgeShare(ctx context.Context, args *BridgeShareInviteArgs) (*BridgeShareInviteReply, error) {
	if len(args.CodeHash) != sha256.Size || len(args.TargetTable) == 0 || args.UseCount < 1 {
		return nil, errors.New("400: an invite out of form")
	}
	return &BridgeShareInviteReply{ShareId: self.invite(self.caller, args.CodeHash, args.TargetTable), UseCount: args.UseCount}, nil
}

func (self *testBridgeShareServer) ClaimBridgeShare(ctx context.Context, codeHash []byte) (*BridgeShareRow, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	shareId, ok := self.codes[[sha256.Size]byte(codeHash)]
	if !ok {
		return nil, errors.New("404: no such invite")
	}
	row := self.rows[shareId]
	if row.AcceptingNetworkId != (Id{}) && row.AcceptingNetworkId != self.caller {
		return nil, errors.New("409: the invite is used")
	}
	row.AcceptingNetworkId = self.caller
	return testBridgeShareRowCopy(row), nil
}

func (self *testBridgeShareServer) CompleteBridgeShare(ctx context.Context, shareId Id, aliasTable []byte, version uint64, status BridgeShareAcceptStatus) (*BridgeShareRow, error) {
	if self.onComplete != nil {
		self.onComplete()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.completions = append(self.completions, bytes.Clone(aliasTable))
	if err := self.completeErr; err != nil {
		self.completeErr = nil
		return nil, err
	}
	row := self.rows[shareId]
	switch {
	case row == nil || row.AcceptingNetworkId != self.caller || len(aliasTable) == 0:
		return nil, errors.New("403: no claim of this network's")
	case row.AcceptStatus != "" && !bytes.Equal(row.AliasTable, aliasTable):
		return nil, errors.New("409: the completion is stored")
	}
	row.AliasTable, row.AliasTableVersion, row.AcceptStatus = bytes.Clone(aliasTable), version, status
	return testBridgeShareRowCopy(row), nil
}

func (self *testBridgeShareServer) GetBridgeShare(ctx context.Context, shareId Id) (*BridgeShareRow, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	row := self.rows[shareId]
	if row == nil {
		return nil, errors.New("404: no such share")
	}
	return testBridgeShareRowCopy(row), nil
}

func (self *testBridgeShareServer) row(shareId Id) *BridgeShareRow {
	row, _ := self.GetBridgeShare(context.Background(), shareId)
	return row
}

// Heads that run a hook as a head is read: after a view took its state and before it plans, where another accept's
// alias lands.
type testBridgeShareHeads struct {
	*testBridgeFileHeads
	stateLock  sync.Mutex
	beforeRead []func()
}

func (self *testBridgeShareHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	self.stateLock.Lock()
	var hook func()
	if 0 < len(self.beforeRead) {
		hook, self.beforeRead = self.beforeRead[0], self.beforeRead[1:]
	}
	self.stateLock.Unlock()
	if hook != nil {
		hook()
	}
	return self.testBridgeFileHeads.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// A filer world with the share acts: the world's network is one side, and the other side is made by hand under other.
type testBridgeShareWorld struct {
	*testBridgeFileWorld
	server *testBridgeShareServer
	keys   *testBridgeShareKeys
	heads  *testBridgeShareHeads
	filer  *BridgeFiler
	other  Id
}

func newTestBridgeShareWorld(t *testing.T, admin bool) *testBridgeShareWorld {
	t.Helper()
	world := newTestBridgeFileWorld(t, admin)
	keys := newTestBridgeShareKeys(t)
	self := &testBridgeShareWorld{
		testBridgeFileWorld: world, server: newTestBridgeShareServer(world.net.networkId), keys: keys,
		heads: &testBridgeShareHeads{testBridgeFileHeads: world.heads}, other: testConfigId("the other network"),
	}
	filer, err := NewBridgeFiler(&BridgeFilerArgs{
		Sidecar: world.sidecar, Config: testBridgeFileConfig{net: world.net}, Heads: self.heads,
		Grants:     NewAclGrantFiler(world.sidecar, world.engine),
		HeadWriter: func() BridgeHeadWriter { return world.heads },
		Records:    func() (RecordWriter, error) { return world.records, nil },
		Store:      world.store, Random: mathrand.NewChaCha8([32]byte{0x21}), Clock: world.clock, Log: NewNoopLogger(),
		Share: &BridgeShareFilerArgs{Api: self.server, Keys: keys.keyring},
	})
	if err != nil {
		t.Fatal(err)
	}
	self.filer = filer
	return self
}

// The other network's invite of targets, made by hand: its code, its seal and the share the server holds.
func (self *testBridgeShareWorld) invited(targets *bridge.BridgeShareTargets) (code []byte, seal *BridgeShareSeal, shareId Id) {
	self.t.Helper()
	code = bytes.Repeat([]byte{byte(0xc0 + len(self.server.rows))}, bridgeShareCodeByteCount)
	seal, err := NewBridgeShareSeal(code, self.other, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	sealed, err := seal.Seal(BridgeShareLabelTargets, Id{}, 1, targets, mathrand.NewChaCha8([32]byte{0x22}))
	if err != nil {
		self.t.Fatal(err)
	}
	codeHash := sha256.Sum256(code)
	return code, seal, self.server.invite(self.other, codeHash[:], sealed)
}

// Another accept's alias taking the upper block at hostBits, filed by the owner's device.
func (self *testBridgeShareWorld) competitor(hostBits uint32, length uint32) {
	self.t.Helper()
	body := testBridgeShareAliasBody(fmt.Sprintf("a competing share %x", hostBits), 0, &bridge.BridgeIpv4Prefix{Address: testBridgeIpv4(100, 80, 0, 0) | hostBits, Length: length})
	self.net.mustPost(self.net.owner, bridge.SignedType_SIGNED_BRIDGE_ALIAS, self.net.bridgeAliasAt(body, 1))
}

// The share's aliases the world's ledger holds in force, by target index.
func (self *testBridgeShareWorld) aliases(shareId Id) map[uint32]*BridgeLedgerAlias {
	return bridgeShareAliasesHeld(self.ledger(), shareId)
}

// §17.9's accept, D-BRIDGE-20: the accepting admin's device opens the target table, files one alias a target with the
// target's host and identity key at the preflight's blocks, and posts active only once its own ledger shows each in
// force: the completion carries the sealed aliases and the sealed ShareKey, and the head holds the share's first
// signer.
func TestAcceptReportsActiveOnlyWhenItsLedgerDoes(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	ctx := context.Background()
	targets := testBridgeShareTargets(32, 28)
	code, seal, shareId := world.invited(targets)
	inForceAtCompletion := -1
	world.server.onComplete = func() { inForceAtCompletion = len(world.aliases(shareId)) }
	accepted, err := world.filer.AcceptInvite(ctx, world.confirmed(), code)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Status != BridgeShareAcceptStatusActive || accepted.ShareId != shareId || accepted.SharingNetworkId != world.other || len(accepted.Aliases) != 2 {
		t.Fatalf("the accept: %+v", accepted)
	}
	if inForceAtCompletion != 2 {
		t.Fatalf("the completion was posted with %d aliases in force", inForceAtCompletion)
	}
	held := world.aliases(shareId)
	for position, target := range targets.GetTargets() {
		alias := held[target.GetIndex()]
		if alias == nil || !bytes.Equal(alias.Body.GetHost(), target.GetHostSidecarId()) ||
			!bytes.Equal(alias.Body.GetHostIdentityPublicKey(), target.GetHostIdentityPublicKey()) ||
			!bytes.Equal(alias.Body.GetSharingNetworkId(), world.other.Bytes()) || alias.Signer != world.hostId {
			t.Fatalf("target %d's alias: %+v", position, alias)
		}
		if alias.Body.GetAliasPrefix().GetAddress()&0xffff != accepted.Aliases[position].GetAliasHostBits() || alias.Body.GetAliasPrefix().GetAddress()>>16 != testBridgeIpv4(100, 80, 0, 0)>>16 {
			t.Errorf("target %d's alias is at %x", position, alias.Body.GetAliasPrefix().GetAddress())
		}
	}
	// first fit from the bottom of the upper half: the /32 past .0, the /28 aligned after it
	if accepted.Aliases[0].GetAliasHostBits() != 0x8001 || accepted.Aliases[1].GetAliasHostBits() != 0x8010 {
		t.Errorf("the plan: %v", accepted.Aliases)
	}
	// what the sharing network reads: both seals open under K for this network, and hold what the ledger does
	row := world.server.row(shareId)
	opened, err := OpenBridgeShareRow(seal, row, nil)
	if err != nil {
		t.Fatal(err)
	}
	sharePublicKey, err := world.keys.keyring.PublicKey(ctx, shareId)
	if err != nil {
		t.Fatal(err)
	}
	if opened.AcceptStatus != BridgeShareAcceptStatusActive || opened.AcceptingNetworkId != world.net.networkId ||
		!bytes.Equal(opened.SharePublicKey, sharePublicKey) || !proto.Equal(opened.Aliases, &bridge.BridgeShareAliases{Aliases: accepted.Aliases}) {
		t.Fatalf("what the sharing network opens: %+v", opened)
	}
	// the first signer is in the head, certified by the ShareKey for the config's generation
	head, _ := world.heads.savedHead()
	use, err := ReadBridgeShareSigner(head, shareId)
	if err != nil || use == nil || use.Generation != 1 {
		t.Fatalf("the share's signer: %v, %v", use, err)
	}
	if _, err := bridge.VerifyShareCert(use.CertSigned, &bridge.ShareCertCheck{
		ShareId: shareId.Bytes(), SharePublicKey: sharePublicKey, NowMs: world.clock.Now().UnixMilli(), Generation: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if names, _ := world.filer.recordNames(bridgeFileShareAcceptPrefix); len(names) != 0 {
		t.Errorf("the completion's record stayed: %v", names)
	}
	// a second accept of the completed share files nothing and answers what stands
	posts := world.api.postCount()
	again, err := world.filer.AcceptInvite(ctx, world.confirmed(), code)
	if err != nil || again.Status != BridgeShareAcceptStatusActive || !bytes.Equal(again.SharePublicKey, sharePublicKey) || world.api.postCount() != posts {
		t.Fatalf("a second accept: %+v, %v", again, err)
	}

	// the release ends each alias, which drains
	released, err := world.filer.ReleaseShare(ctx, world.confirmed(), shareId)
	if err != nil || released != 2 || len(world.aliases(shareId)) != 0 || len(world.ledger().DrainingAliases()) != 2 {
		t.Fatalf("the release: %d, %v", released, err)
	}
	if _, err := world.filer.ReleaseShare(ctx, world.confirmed(), shareId); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a second release: %v", err)
	}
}

// An accept is a person's confirmed command on an admin's device with the invite's code: an agent's, a member's, one
// with another code, or one on a device that could not write the share's signer claims and files nothing.
func TestAcceptRefusesWhoMayNotAccept(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	ctx := context.Background()
	code, _, shareId := world.invited(testBridgeShareTargets(32))
	if _, err := world.filer.AcceptInvite(ctx, world.mcp(), code); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("an agent's accept: %v", err)
	}
	if _, err := world.filer.AcceptInvite(ctx, world.confirmed(), code[:16]); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a short code: %v", err)
	}
	if _, err := world.filer.AcceptInvite(ctx, world.confirmed(), bytes.Repeat([]byte{0x01}, bridgeShareCodeByteCount)); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("another code: %v", err)
	}
	// a code of this share's hash that derives another key opens nothing: the server's row under a forged table
	forged := newTestBridgeShareServer(world.net.networkId)
	otherSeal, _ := NewBridgeShareSeal(bytes.Repeat([]byte{0x02}, bridgeShareCodeByteCount), world.other, nil)
	sealed, _ := otherSeal.Seal(BridgeShareLabelTargets, Id{}, 1, testBridgeShareTargets(32), mathrand.NewChaCha8([32]byte{0x24}))
	codeHash := sha256.Sum256(code)
	forged.invite(world.other, codeHash[:], sealed)
	world.filer.args.Share.Api = forged
	if _, err := world.filer.AcceptInvite(ctx, world.confirmed(), code); !errors.Is(err, ErrBridgeShareSeal) {
		t.Errorf("a table the code does not open: %v", err)
	}
	world.filer.args.Share.Api = world.server
	// no keyring
	world.filer.args.Share.Keys = nil
	if _, err := world.filer.AcceptInvite(ctx, world.confirmed(), code); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("no keyring: %v", err)
	}
	if world.api.postCount() != 0 || world.server.row(shareId).AcceptingNetworkId != (Id{}) || len(world.server.completions) != 0 {
		t.Fatal("a refused accept claimed or filed")
	}
	member := newTestBridgeShareWorld(t, false)
	memberCode, _, _ := member.invited(testBridgeShareTargets(32))
	if _, err := member.filer.AcceptInvite(ctx, member.confirmed(), memberCode); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a member's accept: %v", err)
	}
	if member.api.postCount() != 0 {
		t.Fatal("a member's accept filed")
	}
}

// D-BRIDGE-20's refusals: a target wider than the upper /17 can never fit and is refused too_large, a table with no
// room is refused no_space, each posted with a sealed shortfall the sharing network opens, and neither files an alias
// or makes a key.
func TestAcceptPostsItsRefusalWithItsShortfall(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		targets *bridge.BridgeShareTargets
		status  BridgeShareAcceptStatus
		reason  error
		index   uint32
	}{
		{name: "a /16", targets: testBridgeShareTargets(32, 16), status: BridgeShareAcceptStatusRefusedTooLarge, reason: ErrBridgeShareTooLarge, index: 1},
		{name: "two /17s", targets: testBridgeShareTargets(17, 17), status: BridgeShareAcceptStatusRefusedNoSpace, reason: ErrBridgeShareNoSpace, index: 1},
	} {
		code, seal, shareId := world.invited(c.targets)
		_, err := world.filer.AcceptInvite(ctx, world.confirmed(), code)
		refusal := (*BridgeShareRefusal)(nil)
		if !errors.Is(err, ErrBridgeFileRefused) || !errors.As(err, &refusal) || !errors.Is(err, c.reason) {
			t.Fatalf("%s: %v", c.name, err)
		}
		opened, err := OpenBridgeShareRow(seal, world.server.row(shareId), nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if opened.AcceptStatus != c.status || opened.Aliases != nil || len(opened.SharePublicKey) != 0 || opened.Shortfall.GetIndex() != c.index ||
			!proto.Equal(opened.Shortfall, refusal.Shortfall) {
			t.Errorf("%s: the sharing network opens %+v", c.name, opened)
		}
		if _, err := world.keys.keyring.PublicKey(ctx, shareId); !errors.Is(err, ErrBridgeShareKeyAbsent) {
			t.Errorf("%s: a refused share made a key: %v", c.name, err)
		}
		// a refusal is final
		if _, err := world.filer.AcceptInvite(ctx, world.confirmed(), code); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("%s: a second accept: %v", c.name, err)
		}
	}
	if world.api.postCount() != 0 {
		t.Fatalf("a refused accept filed %d statements", world.api.postCount())
	}
	if head, _ := world.heads.savedHead(); head != nil {
		t.Fatal("a refused accept wrote a head")
	}
}

// A concurrent accept (D-BRIDGE-20): another alias takes the planned block between this accept's plan and its filing,
// so its alias is void. It plans again on the ledger as it stands and reports active with the block it holds.
func TestAcceptPlansAgainWhenItsAliasIsVoid(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	ctx := context.Background()
	code, seal, shareId := world.invited(testBridgeShareTargets(24, 24))
	// lands after the accept read its state and before it files: the first /24 of the upper half
	world.heads.beforeRead = []func(){func() { world.competitor(0x8000, 24) }}
	accepted, err := world.filer.AcceptInvite(ctx, world.confirmed(), code)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Status != BridgeShareAcceptStatusActive || len(accepted.Aliases) != 2 {
		t.Fatalf("the accept: %+v", accepted)
	}
	held := world.aliases(shareId)
	if len(held) != 2 {
		t.Fatalf("%d aliases in force", len(held))
	}
	for _, alias := range accepted.Aliases {
		if alias.GetAliasHostBits() < 0x8100 {
			t.Errorf("an alias inside the block another accept holds: %x", alias.GetAliasHostBits())
		}
		if got := held[alias.GetIndex()].Body.GetAliasPrefix().GetAddress() & 0xffff; got != alias.GetAliasHostBits() {
			t.Errorf("the table says %x and the ledger %x", alias.GetAliasHostBits(), got)
		}
	}
	opened, err := OpenBridgeShareRow(seal, world.server.row(shareId), nil)
	if err != nil || !proto.Equal(opened.Aliases, &bridge.BridgeShareAliases{Aliases: accepted.Aliases}) {
		t.Fatalf("the posted table is not the ledger's: %v", err)
	}
}

// Three plans at most: an accept whose every plan loses its block releases what landed and refuses no_space.
func TestAcceptRefusesNoSpaceAfterThreePlans(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	ctx := context.Background()
	code, seal, shareId := world.invited(testBridgeShareTargets(24, 24))
	// each view the accept takes is followed by another accept's alias at the block it will plan first
	next := uint32(0x8000)
	take := func() {
		world.competitor(next, 24)
		next += 0x0200
	}
	world.heads.beforeRead = []func(){take}
	world.server.onComplete = nil
	hooked := &testBridgeShareVoidingConfig{testBridgeFileConfig: testBridgeFileConfig{net: world.net}, world: world, take: take}
	world.filer.args.Config = hooked
	_, err := world.filer.AcceptInvite(ctx, world.confirmed(), code)
	refusal := (*BridgeShareRefusal)(nil)
	if !errors.As(err, &refusal) || !errors.Is(err, ErrBridgeShareNoSpace) {
		t.Fatalf("an accept that lost three plans: %v", err)
	}
	if hooked.plans != 3 {
		t.Errorf("%d plans were filed", hooked.plans)
	}
	if held := world.aliases(shareId); len(held) != 0 {
		t.Errorf("%d aliases stayed in force", len(held))
	}
	opened, err := OpenBridgeShareRow(seal, world.server.row(shareId), nil)
	if err != nil || opened.AcceptStatus != BridgeShareAcceptStatusRefusedNoSpace || opened.Shortfall == nil {
		t.Fatalf("the refusal the sharing network opens: %+v, %v", opened, err)
	}
}

// A config whose state, read right after a plan's aliases applied, is followed by another accept's alias: the next
// plan's first block is taken before it files.
type testBridgeShareVoidingConfig struct {
	testBridgeFileConfig
	world *testBridgeShareWorld
	take  func()
	plans int
}

func (self *testBridgeShareVoidingConfig) WaitFor(ctx context.Context, n uint64) (*ConfigState, error) {
	state, err := self.testBridgeFileConfig.WaitFor(ctx, n)
	// a wait follows each filing: count the plans by the aliases in force after it, and void the next plan's block
	if len(self.world.aliases(testConfigId("share 0"))) != 0 {
		self.plans += 1
		self.world.heads.stateLock.Lock()
		self.world.heads.beforeRead = append(self.world.heads.beforeRead, nil, self.take)
		self.world.heads.stateLock.Unlock()
	}
	return state, err
}

// A kill between the completion's post and its answer: the bytes were kept first, so the accept run again posts the
// same bytes and files no alias a second time.
func TestAcceptPostsTheSameCompletionAfterAKill(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	ctx := context.Background()
	code, _, shareId := world.invited(testBridgeShareTargets(32, 26))
	world.server.completeErr = errors.New("the answer was lost")
	if _, err := world.filer.AcceptInvite(ctx, world.confirmed(), code); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("an unanswered completion: %v", err)
	}
	if names, _ := world.filer.recordNames(bridgeFileShareAcceptPrefix); len(names) != 1 {
		t.Fatalf("the completion's record: %v", names)
	}
	posts := world.api.postCount()
	_, saves := world.heads.savedHead()
	accepted, err := world.filer.AcceptInvite(ctx, world.confirmed(), code)
	if err != nil || accepted.Status != BridgeShareAcceptStatusActive {
		t.Fatalf("the accept run again: %+v, %v", accepted, err)
	}
	if len(world.server.completions) != 2 || !bytes.Equal(world.server.completions[0], world.server.completions[1]) {
		t.Fatal("the second completion is not the first's bytes")
	}
	if _, again := world.heads.savedHead(); world.api.postCount() != posts || again != saves {
		t.Fatal("the accept run again filed or wrote a head")
	}
	if world.server.row(shareId).AcceptStatus != BridgeShareAcceptStatusActive {
		t.Fatal("the share is not active")
	}
}

// §17.9's invite: the target table carries each host's identity key from this network's own state, sealed under the
// code's key at version 1 with the code's hash; the key is kept for the activation and the code is kept nowhere. An
// agent, a member, and a target that is no admitted sidecar are refused before anything is posted.
func TestInviteSealsItsTargetsAndKeepsItsKey(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	ctx := context.Background()
	request := &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
		{Host: world.hostId, Prefix: netip.MustParsePrefix("192.168.7.0/24")},
		{Host: world.hostId, Prefix: netip.MustParsePrefix("10.1.2.3/32"), Protocol: 6, Ports: []*bridge.BridgePortRange{{First: 443, Last: 443}}},
	}}
	invite, err := world.filer.Invite(ctx, world.confirmed(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(invite.Code) != bridgeShareCodeByteCount || bytes.Contains([]byte(fmt.Sprintf("%v %+v %#v", invite, *invite, invite)), []byte(fmt.Sprintf("%x", invite.Code[:6]))) {
		t.Fatal("the invite's code is short or prints")
	}
	row := world.server.row(invite.ShareId)
	seal, err := NewBridgeShareSeal(invite.Code, world.net.networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenBridgeShareRow(seal, row, nil)
	if err != nil {
		t.Fatal(err)
	}
	if row.TargetTableVersion != 1 || len(opened.Targets.GetTargets()) != 2 {
		t.Fatalf("the table: %+v", opened.Targets)
	}
	identityKey := world.sidecar.currentIdentity().IdentityPublicKey
	for index, target := range opened.Targets.GetTargets() {
		if target.GetIndex() != uint32(index) || !bytes.Equal(target.GetHostSidecarId(), world.hostId.Bytes()) || !bytes.Equal(target.GetHostIdentityPublicKey(), identityKey) {
			t.Errorf("target %d: %+v", index, target)
		}
	}
	codeHash := sha256.Sum256(invite.Code)
	if world.server.codes[codeHash] != invite.ShareId {
		t.Error("the invite is not stored under its code's hash")
	}
	record, err := world.filer.shareInvite(invite.ShareId)
	if err != nil || !bytes.Equal(record.TableKey, seal.TableKey()) || !bytes.Equal(record.TargetTableSha256, BridgeShareTableSha256(row.TargetTable)) {
		t.Fatalf("the invite's record: %v", err)
	}
	for name, file := range world.store.files {
		if bytes.Contains(file, invite.Code) || bytes.Contains(file, []byte(fmt.Sprintf("%x", invite.Code))) {
			t.Errorf("%s holds the code", name)
		}
	}
	shares := len(world.server.rows)
	for name, refused := range map[string]func() error{
		"an agent's invite": func() error { _, err := world.filer.Invite(ctx, world.mcp(), request); return err },
		"no target": func() error {
			_, err := world.filer.Invite(ctx, world.confirmed(), &BridgeShareInviteRequest{})
			return err
		},
		"a target that is no sidecar of this network": func() error {
			_, err := world.filer.Invite(ctx, world.confirmed(), &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
				{Host: testConfigId("no such host"), Prefix: netip.MustParsePrefix("192.168.7.0/24")},
			}})
			return err
		},
		"an IPv6 target": func() error {
			_, err := world.filer.Invite(ctx, world.confirmed(), &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
				{Host: world.hostId, Prefix: netip.MustParsePrefix("fd00::/64")},
			}})
			return err
		},
	} {
		if err := refused(); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	member := newTestBridgeShareWorld(t, false)
	if _, err := member.filer.Invite(ctx, member.confirmed(), &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
		{Host: member.hostId, Prefix: netip.MustParsePrefix("192.168.7.0/24")},
	}}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a member's invite: %v", err)
	}
	if len(world.server.rows) != shares || len(member.server.rows) != 0 {
		t.Fatal("a refused invite was posted")
	}
}

// Adds the requests rule a share's inbound grant is asked under: any network's reach to a member's devices, which an
// admin approves; and has the world's gate approve as the owner.
func (self *testBridgeShareWorld) withSharesRule() {
	self.t.Helper()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
			RuleId:        testConfigId("bridge share rule").Bytes(),
			SrcAtoms:      [][]byte{aclNetworkWildcardAtom().Bytes()},
			Targets:       []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)},
			Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
			ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN).Bytes()},
		})
	})
	// the rows changed the head the base names
	self.testBridgeFileWorld.heads.reader = newTestConfigHeadReader(self.net)
	self.install()
	self.gate.approver = self.net.ownerMemberId
}

// The other network's completion of an invite of the world's, made by hand under the invite's code: aliases at blocks,
// a ShareKey, status active.
func (self *testBridgeShareWorld) completed(invite *BridgeShareInvite, blocks ...uint32) (sharePublicKey []byte) {
	self.t.Helper()
	seal, err := NewBridgeShareSeal(invite.Code, self.net.networkId, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	row := self.server.row(invite.ShareId)
	opened, err := OpenBridgeShareRow(seal, row, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	aliases := &bridge.BridgeShareAliases{}
	for index, target := range opened.Targets.GetTargets() {
		aliases.Aliases = append(aliases.Aliases, &bridge.BridgeShareAlias{Index: target.GetIndex(), AliasHostBits: blocks[index], Length: target.GetPrefix().GetLength()})
	}
	sharePublicKey = bytes.Repeat([]byte{0x5c}, 32)
	random := mathrand.NewChaCha8([32]byte{0x25})
	sealedAliases, err := seal.Seal(BridgeShareLabelAliases, self.other, 1, aliases, random)
	if err != nil {
		self.t.Fatal(err)
	}
	sealedKey, err := seal.Seal(BridgeShareLabelShareKey, self.other, 1, &bridge.BridgeShareKeyBody{SharePublicKey: sharePublicKey}, random)
	if err != nil {
		self.t.Fatal(err)
	}
	accept, _ := proto.Marshal(&bridge.BridgeShareAccept{Aliases: sealedAliases, ShareKey: sealedKey})
	self.server.stateLock.Lock()
	defer self.server.stateLock.Unlock()
	stored := self.server.rows[invite.ShareId]
	stored.AcceptingNetworkId, stored.AliasTable, stored.AliasTableVersion, stored.AcceptStatus = self.other, accept, 1, BridgeShareAcceptStatusActive
	return sharePublicKey
}

// §17.9's activation (QD-077, QD-670): the approving admin's device shows the accepting network, the targets and the
// aliases, and on that preview files the share's inbound grant through the gate and writes the pin file with the
// grant's id, the ShareKey, K, the accepting network and both tables' hashes and versions. A host opens the share
// only from tables that hash to the pins. A share that changed after it was shown is not activated.
func TestActivateWritesItsPinsWithItsGrant(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	world.withSharesRule()
	ctx := context.Background()
	invite, err := world.filer.Invite(ctx, world.confirmed(), &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
		{Host: world.hostId, Prefix: netip.MustParsePrefix("192.168.7.0/24")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// before the other network completed, there is nothing to activate
	pending, err := world.filer.PreviewShare(ctx, world.confirmed(), invite.ShareId)
	if err != nil || pending.Status != "" || len(pending.Targets) != 1 {
		t.Fatalf("the preview of an open invite: %+v, %v", pending, err)
	}
	if _, err := world.filer.ActivateShare(ctx, world.confirmed(), pending, 0); !errors.Is(err, ErrBridgeFileRefused) {
		t.Fatalf("an activation before the accept: %v", err)
	}
	sharePublicKey := world.completed(invite, 0x8100)
	preview, err := world.filer.PreviewShare(ctx, world.confirmed(), invite.ShareId)
	if err != nil {
		t.Fatal(err)
	}
	if preview.AcceptingNetworkId != world.other || preview.Status != BridgeShareAcceptStatusActive || len(preview.Aliases) != 1 ||
		preview.Aliases[0].GetAliasHostBits() != 0x8100 || !bytes.Equal(preview.SharePublicKey, sharePublicKey) {
		t.Fatalf("the preview: %+v", preview)
	}
	if _, err := world.filer.PreviewShare(ctx, world.mcp(), invite.ShareId); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("an agent's preview: %v", err)
	}
	if _, err := world.filer.ActivateShare(ctx, world.mcp(), preview, 0); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("an agent's activation: %v", err)
	}
	// a preview of another ShareKey than the row's is not what was shown
	shown := *preview
	shown.SharePublicKey = bytes.Repeat([]byte{0x11}, 32)
	if _, err := world.filer.ActivateShare(ctx, world.confirmed(), &shown, 0); !errors.Is(err, ErrBridgeShareTableMismatch) {
		t.Errorf("an activation of another key than the one shown: %v", err)
	}
	if head, _ := world.heads.savedHead(); head != nil || world.api.postCount() != 0 {
		t.Fatal("a refused activation filed or wrote a head")
	}

	filing, err := world.filer.ActivateShare(ctx, world.confirmed(), preview, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(filing.GrantId) == 0 || filing.ApprovalId == (Id{}) {
		t.Fatalf("the filing: %+v", filing)
	}
	if got := world.api.postedTypes(t); len(got) != 1 || got[0] != bridge.SignedType_SIGNED_GRANT_ACTIVATE {
		t.Fatalf("the activation posted %v", got)
	}
	calls := world.gate.seen()
	if last := calls[len(calls)-1]; last.kind != SidecarActionForward {
		t.Fatalf("the gate saw a %v", last.kind)
	}
	head, saves := world.heads.savedHead()
	pins := ReadBridgeShareGrants(head)
	if len(pins) != 1 {
		t.Fatalf("%d pin files", len(pins))
	}
	pin := pins[0]
	record, _ := world.filer.shareInvite(invite.ShareId)
	row := world.server.row(invite.ShareId)
	if !bytes.Equal(pin.GetShareId(), invite.ShareId.Bytes()) || !bytes.Equal(pin.GetGrantId(), filing.GrantId) ||
		!bytes.Equal(pin.GetSharePublicKey(), sharePublicKey) || !bytes.Equal(pin.GetTableKey(), record.TableKey) ||
		!bytes.Equal(pin.GetAcceptingNetworkId(), world.other.Bytes()) ||
		!bytes.Equal(pin.GetTargetTableSha256(), BridgeShareTableSha256(row.TargetTable)) ||
		!bytes.Equal(pin.GetAliasTableSha256(), BridgeShareTableSha256(row.AliasTable)) ||
		pin.GetTargetTableVersion() != 1 || pin.GetAliasTableVersion() != 1 {
		t.Fatalf("the pin file: %+v", pin)
	}
	// a host compiles from the pinned tables alone
	opened, err := OpenBridgeShareTables(pin, world.net.networkId, row, nil, nil)
	if err != nil || len(opened.Targets.GetTargets()) != 1 || opened.Aliases.GetAliases()[0].GetAliasHostBits() != 0x8100 {
		t.Fatalf("a host's opening of the pinned tables: %v", err)
	}
	// calling again, once the host's follower installed the grant's entry, finds the grant and the file and does
	// neither twice
	world.install()
	again, err := world.filer.ActivateShare(ctx, world.confirmed(), preview, 0)
	if _, after := world.heads.savedHead(); err != nil || !bytes.Equal(again.GrantId, filing.GrantId) || after != saves || world.api.postCount() != 1 {
		t.Fatalf("a second activation: %v", err)
	}
	// a device that holds no invite for the share activates nothing
	other := newTestBridgeShareWorld(t, true)
	other.filer.args.Share.Api = world.server
	if _, err := other.filer.ActivateShare(ctx, other.confirmed(), preview, 0); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("an activation with no invite: %v", err)
	}

	// the revocation ends the grant its pin names
	revoked, err := world.filer.RevokeShare(ctx, world.confirmed(), invite.ShareId)
	if err != nil || !bytes.Equal(revoked.GrantId, filing.GrantId) {
		t.Fatalf("the revocation: %v", err)
	}
	if got := world.api.postedTypes(t); len(got) != 2 || got[1] != bridge.SignedType_SIGNED_GRANT_REVOKE {
		t.Fatalf("the revocation posted %v", got)
	}
	if _, err := world.filer.RevokeShare(ctx, world.confirmed(), testConfigId("no such share")); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a revocation of no share: %v", err)
	}
}

// A host compiles a share only from tables that hash to its pins (QD-670): a table the server changed, a table of
// another version, a row of another accepting network, and a pin of another share each open nothing.
func TestAShareCompilesOnlyFromPinnedTables(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	world.withSharesRule()
	ctx := context.Background()
	invite, err := world.filer.Invite(ctx, world.confirmed(), &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
		{Host: world.hostId, Prefix: netip.MustParsePrefix("192.168.7.0/24")},
		{Host: world.hostId, Prefix: netip.MustParsePrefix("192.168.9.9/32")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	world.completed(invite, 0x8100, 0x8001)
	preview, err := world.filer.PreviewShare(ctx, world.confirmed(), invite.ShareId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.filer.ActivateShare(ctx, world.confirmed(), preview, 0); err != nil {
		t.Fatal(err)
	}
	head, _ := world.heads.savedHead()
	pin := ReadBridgeShareGrants(head)[0]
	row := world.server.row(invite.ShareId)
	if _, err := OpenBridgeShareTables(pin, world.net.networkId, row, nil, nil); err != nil {
		t.Fatal(err)
	}
	// the accepting network, or the server, swaps the alias table after the activation: one re-sealed under K itself
	seal, _ := NewBridgeShareSealOfKey(pin.GetTableKey(), world.net.networkId, nil)
	random := mathrand.NewChaCha8([32]byte{0x26})
	moved, _ := seal.Seal(BridgeShareLabelAliases, world.other, 1, &bridge.BridgeShareAliases{Aliases: []*bridge.BridgeShareAlias{
		{Index: 0, AliasHostBits: 0x9000, Length: 24}, {Index: 1, AliasHostBits: 0x8001, Length: 32},
	}}, random)
	key, _ := seal.Seal(BridgeShareLabelShareKey, world.other, 1, &bridge.BridgeShareKeyBody{SharePublicKey: bytes.Repeat([]byte{0x66}, 32)}, random)
	swapped, _ := proto.Marshal(&bridge.BridgeShareAccept{Aliases: moved, ShareKey: key})
	for name, edit := range map[string]func(row *BridgeShareRow){
		"an alias table swapped after the activation": func(row *BridgeShareRow) { row.AliasTable = swapped },
		"a target table changed":                      func(row *BridgeShareRow) { row.TargetTable = append(bytes.Clone(row.TargetTable), 0) },
		"an alias table of another version":           func(row *BridgeShareRow) { row.AliasTableVersion = 2 },
		"a target table of another version":           func(row *BridgeShareRow) { row.TargetTableVersion = 2 },
		"another accepting network":                   func(row *BridgeShareRow) { row.AcceptingNetworkId = testConfigId("a third network") },
		"another share's row":                         func(row *BridgeShareRow) { row.ShareId = testConfigId("another share") },
		"a share no longer active":                    func(row *BridgeShareRow) { row.AcceptStatus = BridgeShareAcceptStatusRefusedNoSpace },
	} {
		edited := testBridgeShareRowCopy(row)
		edit(edited)
		if _, err := OpenBridgeShareTables(pin, world.net.networkId, edited, nil, nil); err == nil {
			t.Errorf("%s opened", name)
		}
	}
	if _, err := OpenBridgeShareTables(pin, testConfigId("a third network"), row, nil, nil); err == nil {
		t.Error("another sharing network's host opened the tables")
	}
	// the view a host compiles from keeps the row the server answered, and the pins judge it
	view, err := NewBridgeShareTableView(world.server, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Refresh(ctx, []Id{invite.ShareId}); err != nil {
		t.Fatal(err)
	}
	if kept := view.Row(invite.ShareId); kept == nil || !bytes.Equal(kept.AliasTable, row.AliasTable) {
		t.Fatal("the view did not keep the share's row")
	}
	if view.Row(testConfigId("another share")) != nil || len(view.Rows()) != 1 {
		t.Fatal("the view holds a row it did not fetch")
	}
}
