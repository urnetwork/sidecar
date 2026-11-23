//go:build !ios_extension && !sidecar_http && !js

// QD-1205's remaining parts (owner decision 698) on T2's fake api, with sidecartest's in-memory config ref and real
// ConfigClients, ConfigWriters and ConfigLogs, and on the follower world's hosted Sidecars:
//
//	carry   every reader of a base holds the bridge block's record its head carries from the base where a head first
//	        held it under a standing signer, whoever's bases carried it since; so once the owner's first device, which
//	        drew and signed the block at the bootstrap, is revoked, a Network admin's head, which cannot sign it again,
//	        strands nothing: the owner's desktop's next head signs it again, which a reader holding none takes
//	attack  a record the revoked device's key signs after its revocation, filed in a head by a Network admin's
//	        writer, is one no reader holds, which the desktop's next head leaves as it is: no admin chose it
//	flow    a hosted Sidecar whose host gives a ref for confirmed saves alone, as ur daemon's does, runs no general
//	        writer; its own revocation of the device that signed the block, and its own removal of the member whose
//	        device signed it, each save a head that signs the block again before the call returns
//
// Every wait is on a client's log or a call's return; api's clock never moves, so no fold loop publishes on its own.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The network the carry tests share: the owner's first device bootstraps it, drawing the block from the owner's
// stream; it admits the owner's desktop, which revokes it as lost and admits a Network admin's member and laptop, which
// the desktop's AdminSet raises: a config writer whose own block every reader refuses.
type testCarryNet struct {
	world *testWriterWorld
	want  *bridge.BridgeIpv4Prefix
	// the bootstrap's bridge/block record, the revoked first device's
	record        []byte
	desktop       testWriterDevice
	networkLaptop testWriterDevice
}

func newTestCarryNet(t *testing.T) *testCarryNet {
	t.Helper()
	world := newTestWriterWorld(t)
	result, err := testBlockBootstrap(world, world.owner, testBlockRandom("owner"))
	if err != nil || !result.Won {
		t.Fatalf("bootstrap: %v", err)
	}
	world.genesis = result
	net := &testCarryNet{
		world:   world,
		want:    testBlockDrawn(t, "owner"),
		record:  result.Push.Head.File(sidecar.ConfigHeadBridgeBlockPath),
		desktop: testWriterDeviceOf("owner desktop", world.owner.memberId),
	}
	if len(net.record) == 0 {
		t.Fatal("the bootstrap drew no block")
	}
	testRevokedSignerAdmit(world, world.owner, net.desktop)
	testRevokedSignerRevoke(world, net.desktop, world.owner)
	memberId := testWriterId("network admin member")
	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(net.desktop, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: world.header(), MemberId: memberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("the Network admin's member: %v", err)
	}
	net.networkLaptop = testWriterDeviceOf("network admin laptop", memberId)
	testRevokedSignerAdmit(world, net.desktop, net.networkLaptop)
	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(net.desktop, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: world.header(), Owners: [][]byte{world.owner.memberId.Bytes()}, NetworkAdmins: [][]byte{memberId.Bytes()},
	})); err != nil {
		t.Fatalf("the AdminSet raising the Network admin: %v", err)
	}
	return net
}

// A writer of device's on a reader of its own caught up to api's tip, as the follower composes it.
func (self *testCarryNet) writer(device testWriterDevice) (*sidecar.ConfigClient, *sidecar.ConfigWriter) {
	self.world.t.Helper()
	client := self.world.client()
	if state := self.world.caughtUp(client); !state.IsConfigWriter(device.sidecarId) {
		self.world.t.Fatalf("%s writes no config head", device.sidecarId)
	}
	return client, testBlockWriter(self.world, device, client, nil, testBlockNoDraw())
}

// Fails unless the readers of state's base hold record as the network's bridge block.
func testCarryHolds(t *testing.T, label string, state *sidecar.ConfigState, record []byte) {
	t.Helper()
	recordSha256 := sha256.Sum256(record)
	if !bytes.Equal(state.BridgeBlockRecordSha256ForTest(), recordSha256[:]) {
		t.Fatalf("%s: the readers of the base at %d hold %x, want the record %x", label, state.Base().GetVersion(), state.BridgeBlockRecordSha256ForTest(), recordSha256)
	}
}

// After the first device's revocation a Network admin's writer saves a head, which carries the first device's record as
// every head does: its own signature would not carry the block, so it signs nothing, and a reader holding no block
// refuses the record, while every reader of that base still holds it and the filer's view takes it. The owner's
// desktop's next head then signs the same block again, which a reader holding none takes from that base on, as does a
// new reader. On the code before, the desktop's writer judged the record at the newest base, the Network admin's, where
// its signer no longer stood, and left it to an admin's `ur bridge block`.
func TestANetworkAdminsBaseInBetweenStrandsNoBridgeBlock(t *testing.T) {
	net := newTestCarryNet(t)
	world := net.world
	networkClient, networkWriter := net.writer(net.networkLaptop)
	if _, err := networkWriter.SaveHead(world.ctx, testBlockPolicy("{}")); err != nil {
		t.Fatalf("the Network admin's head: %v", err)
	}
	state := world.caughtUp(networkClient)
	head := testBlockHead(t, world, state)
	if !bytes.Equal(head.File(sidecar.ConfigHeadBridgeBlockPath), net.record) || string(head.File(sidecar.ConfigHeadPolicyPath)) != "{}" {
		t.Fatal("the Network admin's head does not carry the first device's record beside its edit")
	}
	testCarryHolds(t, "the Network admin's base", state, net.record)
	if _, err := sidecar.ReadBridgeBlock(head, state, nil); !errors.Is(err, sidecar.ErrBridgeBlockRefused) {
		t.Fatalf("a reader holding no block judges the revoked device's record: %v", err)
	}
	if block, err := sidecar.ReadBridgeBlockInForceForTest(head, state); err != nil || !proto.Equal(block.GetIpv4Prefix(), net.want) {
		t.Fatalf("the filer's view of the block every reader holds: %v, %v", block, err)
	}

	desktopClient, desktopWriter := net.writer(net.desktop)
	if _, err := desktopWriter.SaveHead(world.ctx, testBlockPolicy(`{"grants": []}`)); err != nil {
		t.Fatalf("the desktop's head: %v", err)
	}
	state = world.caughtUp(desktopClient)
	head = testBlockHead(t, world, state)
	held := testBlockAt(t, world, state)
	if held == nil || !proto.Equal(held.GetIpv4Prefix(), net.want) || held.GetPreviousPrefix() != nil || held.GetDrainUntil() != 0 ||
		testBlockSigner(t, head) != net.desktop.sidecarId {
		t.Fatalf("the desktop's head holds the block %v, want %v signed again by the desktop", held, net.want)
	}
	testCarryHolds(t, "the desktop's base", state, head.File(sidecar.ConfigHeadBridgeBlockPath))
	if held := testBlockAt(t, world, world.caughtUp(world.client())); held == nil || !proto.Equal(held.GetIpv4Prefix(), net.want) {
		t.Fatalf("a new reader holds %v", held)
	}
}

// After the first device's revocation its key, a stolen one, signs another block, which a Network admin's writer files
// in a head: every reader judges it where that head first holds it and refuses it, holding the first block's record
// still, so a reader holding none and the filer's view hold no block from that head. The desktop's next head leaves the
// stolen record as it is, signing nothing: no admin chose that block, and signing it would put it in force.
func TestAWritersNextHeadLeavesARecordTheRevokedDeviceSignedAfter(t *testing.T) {
	net := newTestCarryNet(t)
	world := net.world
	other := &bridge.BridgeIpv4Prefix{Address: 100<<24 | 90<<16, Length: 16}
	if proto.Equal(other, net.want) {
		other.Address = 100<<24 | 91<<16
	}
	stolen := world.statement(world.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, &bridge.BridgeBlock{Ipv4Prefix: other})
	networkClient, networkWriter := net.writer(net.networkLaptop)
	if _, err := networkWriter.SaveHead(world.ctx, func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadBridgeBlockPath, stolen)
	}); err != nil {
		t.Fatalf("the Network admin's head: %v", err)
	}
	state := world.caughtUp(networkClient)
	head := testBlockHead(t, world, state)
	if !bytes.Equal(head.File(sidecar.ConfigHeadBridgeBlockPath), stolen) {
		t.Fatal("the Network admin's head does not hold the stolen record")
	}
	testCarryHolds(t, "the stolen record's base", state, net.record)
	if _, err := sidecar.ReadBridgeBlock(head, state, nil); !errors.Is(err, sidecar.ErrBridgeBlockRefused) {
		t.Fatalf("a reader holding no block took the stolen record: %v", err)
	}
	if block, err := sidecar.ReadBridgeBlockInForceForTest(head, state); !errors.Is(err, sidecar.ErrBridgeBlockRefused) {
		t.Fatalf("the filer's view took the stolen record: %v, %v", block, err)
	}

	desktopClient, desktopWriter := net.writer(net.desktop)
	if _, err := desktopWriter.SaveHead(world.ctx, testBlockPolicy(`{"grants": []}`)); err != nil {
		t.Fatalf("the desktop's head: %v", err)
	}
	state = world.caughtUp(desktopClient)
	head = testBlockHead(t, world, state)
	if !bytes.Equal(head.File(sidecar.ConfigHeadBridgeBlockPath), stolen) {
		t.Fatalf("the desktop's head signed the stolen block again, now %s's", testBlockSigner(t, head))
	}
	testCarryHolds(t, "the desktop's base", state, net.record)
}

// ur daemon's shape over the follower world: a head reader that is no ConfigHeadRef, so the follower runs no general
// writer, and gives a ref for confirmed saves alone, the network's in-memory ref signed by the hosted Sidecar.
type testCarryConfirmedHeads struct {
	sidecar.ConfigHeadReader
	ref sidecar.ConfigHeadRef
}

func (self *testCarryConfirmedHeads) ConfirmedAclConfigRef() sidecar.ConfigHeadRef {
	return self.ref
}

// A follower world of one network whose hosted Sidecars follow over testCarryConfirmedHeads.
func newTestCarryFollowWorld(t *testing.T) *configFollowWorld {
	t.Helper()
	world := newConfigFollowWorld(t, 1, nil)
	world.wrapHeads = func(running *sidecar.Sidecar, heads sidecar.ConfigHeadReader) sidecar.ConfigHeadReader {
		return &testCarryConfirmedHeads{ConfigHeadReader: heads, ref: &testBlockFollowHeads{ConfigHeadReader: heads, world: world, running: running}}
	}
	return world
}

// The head state's base names in network's config repo.
func testCarryBaseHead(t *testing.T, world *configFollowWorld, network *sidecartest.AdmissionNet, state *sidecar.ConfigState) *sidecar.ConfigHead {
	t.Helper()
	base := state.Base()
	head, err := network.Heads().ReadConfigHead(world.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		t.Fatalf("the head of the base at %d: %v", base.GetVersion(), err)
	}
	return head
}

// Fails unless the hosted Sidecar's follower runs ur daemon's one writer, the one for confirmed saves.
func testCarryConfirmedOnly(t *testing.T, client *sidecar.ConfigClient) {
	t.Helper()
	if client.Writer() != nil || client.ConfirmedWriter() == nil {
		t.Fatalf("the follower's writers: general %v, for confirmed saves %v", client.Writer(), client.ConfirmedWriter())
	}
}

// In ur daemon's shape, where nothing but a person's confirmed save writes a head, the owner's hosted device revokes
// the owner's first device, which drew and signed the network's block at the bootstrap, as lost. Before RevokeDevice
// returns, its own flow has saved a head through the writer for confirmed saves: the base after the revocation names a
// head carrying the same block signed again by the hosted device, which a reader holding none, a new device's, takes,
// and no general writer was installed for it. On the code before, no head came, and such a reader held no block until
// the next `ur acl push`.
func TestARevocationInUrDaemonsShapeReSignsTheBlockAtOnce(t *testing.T) {
	world := newTestCarryFollowWorld(t)
	network := world.networks[0]
	running := world.host(network, nil)
	client := world.standing(running, network)
	testCarryConfirmedOnly(t, client)
	head := testCarryBaseHead(t, world, network, client.State())
	first, err := sidecar.ReadBridgeBlock(head, client.State(), nil)
	if err != nil || first == nil || testBlockSigner(t, head) != network.Owner().SidecarId {
		t.Fatalf("the network's first block %v, by the owner's first device: %v", first, err)
	}

	ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
	defer cancel()
	plan, err := running.PreviewDeviceRevoke(ctx, network.Owner().SidecarId, sidecar.DeviceRevokeLost, time.Time{}, 0)
	if err != nil || plan.Signatures != 1 {
		t.Fatalf("the revocation's plan %+v: %v", plan, err)
	}
	entry, proposalId, err := running.RevokeDevice(ctx, plan.PlanId, nil, nil)
	if err != nil || entry == nil || proposalId != nil {
		t.Fatalf("the revocation: %v %x %v", entry, proposalId, err)
	}
	state := client.State()
	if base := state.Base(); base == nil || base.GetVersion() <= entry.GetVersion() {
		t.Fatalf("no base after the revocation at %d: %v", entry.GetVersion(), base)
	}
	head = testCarryBaseHead(t, world, network, state)
	block, err := sidecar.ReadBridgeBlock(head, state, nil)
	if err != nil || !proto.Equal(block, first) || testBlockSigner(t, head) != running.Identity().SidecarId {
		t.Fatalf("the block after the revocation %v, signed by %s: %v; want %v signed again by the hosted device", block, testBlockSigner(t, head), err, first)
	}
	testCarryHolds(t, "the base after the revocation", state, head.File(sidecar.ConfigHeadBridgeBlockPath))
	testCarryConfirmedOnly(t, client)
}

// In ur daemon's shape, an Admin's laptop has set the network's block; the owner's hosted device removes that Admin
// member, whose devices the removal revokes. Before SignMemberRevoke returns, its own flow has saved a head through
// the writer for confirmed saves, carrying the Admin's block signed again by the hosted device, which a reader holding
// none takes.
func TestAMemberRemovalInUrDaemonsShapeReSignsTheBlockAtOnce(t *testing.T) {
	world := newTestCarryFollowWorld(t)
	network := world.networks[0]
	adminMember := network.AdmitMember(network.Owner(), "carry admin", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	network.MustLand(network.Sign(network.Owner(), bridge.SignedType_SIGNED_ADMIN_SET, network.AdminSet([]sidecar.Id{network.Owner().MemberId}, []sidecar.Id{adminMember}, 0)))
	adminLaptop := network.Device("carry admin laptop", adminMember)
	network.AdmitDevice(network.Owner(), adminLaptop, 0)
	set := &bridge.BridgeBlock{Ipv4Prefix: &bridge.BridgeIpv4Prefix{Address: 100<<24 | 90<<16, Length: 16}}
	record := network.Sign(adminLaptop, bridge.SignedType_SIGNED_BRIDGE_BLOCK, set)
	network.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadBridgeBlockPath, record)
	})
	running := world.host(network, nil)
	client := world.standing(running, network)
	testCarryConfirmedOnly(t, client)
	if block, err := sidecar.ReadBridgeBlock(testCarryBaseHead(t, world, network, client.State()), client.State(), nil); err != nil || !proto.Equal(block, set) {
		t.Fatalf("the Admin's block %v: %v", block, err)
	}
	testCarryHolds(t, "the Admin's base", client.State(), record)

	ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
	defer cancel()
	removal, err := running.SignMemberRevoke(ctx, adminMember, sidecar.SidecarActConfirmed, nil)
	if err != nil || removal.Entry == nil || removal.ProposalId != nil {
		t.Fatalf("the removal: %+v, %v", removal, err)
	}
	state := client.State()
	if base := state.Base(); base == nil || base.GetVersion() <= removal.Entry.GetVersion() {
		t.Fatalf("no base after the removal at %d: %v", removal.Entry.GetVersion(), base)
	}
	head := testCarryBaseHead(t, world, network, state)
	block, err := sidecar.ReadBridgeBlock(head, state, nil)
	if err != nil || !proto.Equal(block, set) || testBlockSigner(t, head) != running.Identity().SidecarId {
		t.Fatalf("the block after the removal %v, signed by %s: %v; want the Admin's signed again by the hosted device", block, testBlockSigner(t, head), err)
	}
}

// A desktop writer whose ref answers as busy says, for SaveBridgeBlock's tries: no wait between them, and at most
// attempts of them.
func (self *testCarryNet) busyWriter(busy *testCarryBusyRef, attempts int) (*sidecar.ConfigClient, *sidecar.ConfigWriter) {
	world := self.world
	world.t.Helper()
	client := world.client()
	world.caughtUp(client)
	settings := sidecar.DefaultConfigWriterSettings()
	settings.Clock = sidecartest.NewFakeClock(world.clock.Now())
	settings.Random = func() float64 { return 0 }
	settings.BridgeBlockRandom = testBlockNoDraw()
	settings.BridgeBlockRetryWait = 0
	settings.BridgeBlockAttemptCount = attempts
	settings.Log = sidecar.NewNoopLogger()
	busy.ConfigHeadRef = world.heads.For(self.desktop.sidecarId, self.desktop.key)
	writer, err := sidecar.NewConfigWriter(world.ctx, &sidecar.ConfigWriterArgs{
		SidecarId:   self.desktop.sidecarId,
		Sign:        self.desktop.sign(),
		Client:      client,
		Heads:       busy,
		Publisher:   world.publisher(),
		Settings:    settings,
		BridgeBlock: sidecar.WithBridgeBlock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	world.t.Cleanup(writer.Close)
	return client, writer
}

// The desktop's ref, which answers its first prepares with gkm's 503, as gkm does while its gate has not loaded the
// revocation, and its first commits with a conflict, as when another writer's head landed first, counting each.
type testCarryBusyRef struct {
	sidecar.ConfigHeadRef
	unavailable int
	conflicts   int
	prepares    int
}

func (self *testCarryBusyRef) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	self.prepares += 1
	if 0 < self.unavailable {
		self.unavailable -= 1
		return nil, fmt.Errorf("the config repo's key: %w", &sidecar.GkmError{Status: http.StatusServiceUnavailable})
	}
	return self.ConfigHeadRef.PrepareConfigHead(ctx, head, version)
}

func (self *testCarryBusyRef) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	if 0 < self.conflicts {
		self.conflicts -= 1
		return fmt.Errorf("%w: another head landed first", sidecar.ErrConfigHeadConflict)
	}
	return self.ConfigHeadRef.CommitConfigHead(ctx, push)
}

// SaveBridgeBlock saves a head for the block alone: the desktop's signs the revoked first device's block again, its
// policy file as it was, and a second call, with a statement past the base's fold, saves nothing and publishes no
// base, where a fold then publishes one. Its tries come again after gkm's 503 and a conflict at the ref, and stop at
// the bound with the last answer.
func TestSaveBridgeBlockSavesOnlyForTheBlockAndTriesAgain(t *testing.T) {
	net := newTestCarryNet(t)
	world := net.world
	busy := &testCarryBusyRef{unavailable: 1, conflicts: 1}
	client, writer := net.busyWriter(busy, 3)
	before := testBlockHead(t, world, client.State())
	pin, err := writer.SaveBridgeBlock(world.ctx)
	if err != nil || pin == nil || busy.prepares != 3 {
		t.Fatalf("the block's save: %v, %v, after %d prepares", pin, err, busy.prepares)
	}
	state := world.caughtUp(client)
	head := testBlockHead(t, world, state)
	if held := testBlockAt(t, world, state); !proto.Equal(held.GetIpv4Prefix(), net.want) || testBlockSigner(t, head) != net.desktop.sidecarId ||
		!bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), before.File(sidecar.ConfigHeadPolicyPath)) {
		t.Fatalf("the block's head holds %v, signed by %s", held, testBlockSigner(t, head))
	}

	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(net.desktop, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: world.header(), MemberId: testWriterId("past the fold").Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	})); err != nil {
		t.Fatal(err)
	}
	tip := world.caughtUp(client).Pin()
	if pin, err := writer.SaveBridgeBlock(world.ctx); err != nil || pin != nil {
		t.Fatalf("a save with nothing for the block: %v, %v", pin, err)
	}
	if after, err := world.api.Tip(world.ctx, world.networkId); err != nil || !proto.Equal(after, tip) {
		t.Fatalf("a save with nothing for the block published at %v: %v", after, err)
	}
	// the fold it left was there to publish
	if folded, err := writer.PublishBase(world.ctx, true); err != nil || folded.GetVersion() != tip.GetVersion()+1 {
		t.Fatalf("the fold after: %v, %v", folded, err)
	}

	stuck := newTestCarryNet(t)
	stuckBusy := &testCarryBusyRef{unavailable: 5}
	_, stuckWriter := stuck.busyWriter(stuckBusy, 2)
	if pin, err := stuckWriter.SaveBridgeBlock(stuck.world.ctx); !sidecar.IsGkmStatus(err, http.StatusServiceUnavailable) || pin != nil || stuckBusy.prepares != 2 {
		t.Fatalf("a save gkm keeps refusing: %v, %v, after %d prepares", pin, err, stuckBusy.prepares)
	}
}
