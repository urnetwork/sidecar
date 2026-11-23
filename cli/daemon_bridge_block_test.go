// QD-1205's ur daemon parts (bridge-block-resign-carry; owner decision 698). ur daemon's follower runs no general config
// writer: its head reader over evs is no ConfigHeadRef, and gives an exact-head ref for confirmed saves alone
// (ConfirmedAclConfigRef), whose writer only a person's confirmed save selects (ConfigClient.ConfirmedWriter).
//
//	block    `ur bridge block` on ur daemon's bridge saves the network's block through that writer, where it refused
//	         with "no config writer runs" before: over the follow world, its head reader in ur daemon's shape
//	revoke   a revocation on ur daemon saves a head at once that signs the network's block again once its signer, the
//	         revoked device, no longer stands, so a reader holding no block, a new device's, holds it: over the real
//	         engines and ur daemon's own head reader over evs, the push exact-head
//
// Every wait is on a call's return or a client's log, bounded by a real-time guard only a broken wiring reaches.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// The daemon's head reader in ur daemon's shape over the follow world: running's network's config repo read as
// testUrConfigHeads reads it, no ConfigHeadRef, and a ref for confirmed saves alone, the network's in-memory ref
// signed by running, as urNetworkConfigHeads gives its exact-head ref over evs.
type testUrConfirmedConfigHeads struct {
	*testUrConfigHeads
}

func (self *testUrConfirmedConfigHeads) ConfirmedAclConfigRef() sidecar.ConfigHeadRef {
	return &testUrConfirmedConfigRef{heads: self.testUrConfigHeads}
}

// running's ref on its network's config repo, found at each call, since the follower is built before the identity
// names the network.
type testUrConfirmedConfigRef struct {
	heads *testUrConfigHeads
}

func (self *testUrConfirmedConfigRef) ref() (*sidecartest.FakeConfigHeadRef, error) {
	running := self.heads.running
	networkId, identity := running.NetworkId(), running.Identity()
	if networkId == nil || identity == nil {
		return nil, sidecar.ErrConfigHeadUnavailable
	}
	for _, network := range self.heads.world.networks {
		if network.NetworkId() == *networkId {
			return network.Heads().ForSigner(identity.SidecarId, func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
				return running.Sign(purpose, signedType, body, nil)
			}), nil
		}
	}
	return nil, sidecar.ErrConfigHeadUnavailable
}

func (self *testUrConfirmedConfigRef) CurrentConfigHead(ctx context.Context) (*sidecar.ConfigHead, uint64, [sha256.Size]byte, error) {
	ref, err := self.ref()
	if err != nil {
		return nil, 0, [sha256.Size]byte{}, err
	}
	return ref.CurrentConfigHead(ctx)
}

func (self *testUrConfirmedConfigRef) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	ref, err := self.ref()
	if err != nil {
		return nil, err
	}
	return ref.PrepareConfigHead(ctx, head, version)
}

func (self *testUrConfirmedConfigRef) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	ref, err := self.ref()
	if err != nil {
		return err
	}
	return ref.CommitConfigHead(ctx, push)
}

func (self *testUrConfirmedConfigRef) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	ref, err := self.ref()
	if err != nil {
		return nil, err
	}
	return ref.ConfigHeadPushes(ctx, after, through)
}

// The sidecar that signed head's bridge/block.
func testUrBlockSigner(t *testing.T, head *sidecar.ConfigHead) sidecar.Id {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(head.File(sidecar.ConfigHeadBridgeBlockPath), signed); err != nil {
		t.Fatal(err)
	}
	signerId, err := sidecar.IdFromBytes(signed.GetSignerId())
	if err != nil {
		t.Fatal(err)
	}
	return signerId
}

// `ur bridge block` on ur daemon's bridge, over a follower in ur daemon's shape: its client runs no general writer, only
// the one for confirmed saves, and a person's confirmed bridge.block saves a head through it, which the network's next
// base names: the chosen /16 signed by the hosted device, the bootstrap's block draining behind it, which every reader
// takes. No general writer comes of it. On the code before, the filer took the general writer alone and refused.
func TestUrBridgeBlockSetsTheBlockInUrDaemon(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	urDaemonConfigHeads = func(running *sidecar.Sidecar) sidecar.ConfigHeadReader {
		return &testUrConfirmedConfigHeads{testUrConfigHeads: &testUrConfigHeads{world: world, running: running}}
	}
	network := world.networks[0]
	running := world.host(network, nil)
	world.standing(running, network)
	client := running.ConfigFollower().Client()
	if client.Writer() != nil || client.ConfirmedWriter() == nil {
		t.Fatal("the follower runs a general writer, or none for confirmed saves")
	}
	readBlock := func(state *sidecar.ConfigState) (*sidecar.ConfigHead, *bridge.BridgeBlock) {
		t.Helper()
		head, err := network.Heads().ReadConfigHead(world.ctx, state.Base().GetConfigVersion(), state.Base().GetConfigHeadSha256())
		if err != nil {
			t.Fatal(err)
		}
		block, err := sidecar.ReadBridgeBlock(head, state, nil)
		if err != nil || block == nil {
			t.Fatalf("the block at %d: %v, %v", state.Base().GetVersion(), block, err)
		}
		return head, block
	}
	_, first := readBlock(client.State())

	backends := &urBridgeBackends{bridges: world.bridges, networkIdBackends: map[sidecar.Id]*urBridgeBackend{}}
	defer backends.close()
	backend, err := backends.backend(world.ctx, network.NetworkId(), running)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(world.ctx, urTestTimeout)
	defer cancel()
	chosen := netip.MustParsePrefix("10.20.0.0/16")
	set, err := backend.SetBlock(ctx, &sidecar.BridgeFileOrigin{Act: sidecar.SidecarActConfirmed}, &sidecar.BridgeBlockRequest{Prefix: chosen})
	if err != nil {
		t.Fatalf("ur bridge block in ur daemon: %v", err)
	}
	state := client.State()
	head, held := readBlock(state)
	if !proto.Equal(held, set) || held.GetIpv4Prefix().GetAddress() != 10<<24|20<<16 || !proto.Equal(held.GetPreviousPrefix(), first.GetIpv4Prefix()) ||
		held.GetDrainUntil() <= network.Clock().Now().UnixMilli() || testUrBlockSigner(t, head) != running.Identity().SidecarId {
		t.Fatalf("the network's block %v, set %v, want %s signed by the hosted device with %v draining", held, set, chosen, first.GetIpv4Prefix())
	}
	if client.Writer() != nil {
		t.Fatal("ur bridge block installed a general writer")
	}
}

// A second device of the owner, enrolled on the same engines and joined to the network as TestDaemonsSecondDeviceJoinsOverEvs
// joins one, standing on its follower over ur daemon's head reader.
func testUrJoinSecondOwnerDevice(t *testing.T, ctx context.Context, net *sidecartest.Net, engines *enginenet.Engines, first *sidecar.Sidecar, result *enginenet.BootstrapResult) (*sidecar.Sidecar, *sidecar.ConfigClient) {
	t.Helper()
	networkId := first.Identity().NetworkId
	ownerMemberId, err := sidecar.IdFromBytes(result.Bootstrap.State.Genesis().GetOwnerMemberId())
	if err != nil {
		t.Fatal(err)
	}
	instance, err := net.StartInstance("second", &sidecartest.TestInstanceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	second, err := instance.AddSidecarIn(networkId, &sidecar.SidecarEnrollAnchor{GenesisSha256: result.Bootstrap.GenesisChain[:]})
	if err != nil {
		t.Fatal(err)
	}
	identity := second.Identity()
	pin, err := engines.PostStatement(ctx, first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, func(header *bridge.StatementHeader) proto.Message {
		return &protocol.SidecarAdmit{
			Header:            header,
			NetworkId:         networkId.Bytes(),
			SidecarId:         identity.SidecarId.Bytes(),
			IdentityPublicKey: identity.IdentityPublicKey,
			IdentityAlg:       "ed25519",
			MemberId:          ownerMemberId.Bytes(),
		}
	})
	if err != nil {
		t.Fatalf("the second device's admission: %v", err)
	}
	if startUrConfigFollower(second, sidecar.NewNoopLogger()) == nil {
		t.Fatal("no follower started on the second device")
	}
	secondClients := testUrClientsOf(second)
	if secondClients == nil {
		t.Fatal("the second device's clients are not built")
	}
	select {
	case <-secondClients.groupBuilt():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	upkeep := secondClients.upkeep
	for {
		_, changed := upkeep.Passes()
		state, repoId, confirmed := secondClients.gkm.joiningState()
		if state != nil && (confirmed || repoId == result.ConfigRepoId) && state.Pin().GetVersion() >= pin.GetVersion() &&
			state.SidecarRow(identity.SidecarId) != nil && len(upkeep.CurrentReaderKeySha256()) != 0 {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("the admitted device has no ReaderKey at its joining state: %v", second.ConfigFollower().Status())
		}
	}
	if err := first.ConfigFollower().Client().CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if err := testUrClientsOf(first).builtGroup().DeliverFirstWrap(ctx, result.ConfigRepoId, identity.SidecarId); err != nil {
		t.Fatalf("the first device's delivery: %v", err)
	}
	if err := secondClients.builtGroup().SyncRepo(ctx, result.ConfigRepoId); err != nil {
		t.Fatalf("the second device's first wrap: %v", err)
	}
	standCtx, standCancel := context.WithTimeout(ctx, urTestTimeout)
	defer standCancel()
	client, err := second.ConfigFollower().WaitStanding(standCtx)
	if err != nil {
		t.Fatalf("the second device's follower: %v (%+v)", err, second.ConfigFollower().Status())
	}
	return second, client
}

// On the real engines and ur daemon's own head reader over evs: the owner's first device bootstraps the network,
// drawing and signing its block, and its second device joins and revokes it as lost. Before RevokeDevice returns, the
// second device's own flow has saved a head through ur daemon's one writer, the one for confirmed saves, its push signed
// exact-head: the base after the revocation names a head carrying the same block signed again by the second device,
// which a reader holding no block, a new device's, takes, and the second device's follower runs no general writer still.
// On the code before, no head came, and such a reader held no block until the next `ur acl push`.
func TestUrDaemonsRevocationReSignsTheBridgeBlockAtOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	first, _, result := bootstrapTestDaemonOwner(t, ctx, net, engines)
	if startUrConfigFollower(first, sidecar.NewNoopLogger()) == nil {
		t.Fatal("no follower started on the first device")
	}
	if _, err := first.ConfigFollower().WaitStanding(ctx); err != nil {
		t.Fatal(err)
	}
	second, client := testUrJoinSecondOwnerDevice(t, ctx, net, engines, first, result)
	if client.Writer() != nil || client.ConfirmedWriter() == nil {
		t.Fatal("the stock follower runs a general writer, or none for confirmed saves")
	}
	headOf := func(state *sidecar.ConfigState) *sidecar.ConfigHead {
		t.Helper()
		head, err := second.ConfigFollower().Heads().ReadConfigHead(ctx, state.Base().GetConfigVersion(), state.Base().GetConfigHeadSha256())
		if err != nil {
			t.Fatalf("the head of the base at %d: %v", state.Base().GetVersion(), err)
		}
		return head
	}
	head := headOf(client.State())
	drawn, err := sidecar.ReadBridgeBlock(head, client.State(), nil)
	if err != nil || drawn == nil || testUrBlockSigner(t, head) != first.Identity().SidecarId {
		t.Fatalf("the network's first block %v: %v", drawn, err)
	}

	// the gates load each statement a device posts before its post answers, as api's {acl_} hint has them load it in
	// moments, which this world does not send: gkm judges the rotation the revocation's save needs by the revocation
	api := engines.Api()
	networkId := first.Identity().NetworkId
	api.RouteConfigDelta(networkId, func(ctx context.Context, signedBytes []byte) (*bridge.AuthPin, error) {
		pin, err := api.AppendStatement(ctx, networkId, signedBytes)
		if err != nil {
			return nil, err
		}
		if err := engines.Sync(ctx, networkId); err != nil {
			return nil, err
		}
		return pin, nil
	})
	t.Cleanup(func() { api.RouteConfigDelta(networkId, nil) })
	revokeCtx, revokeCancel := context.WithTimeout(ctx, urTestTimeout)
	defer revokeCancel()
	plan, err := second.PreviewDeviceRevoke(revokeCtx, first.Identity().SidecarId, sidecar.DeviceRevokeLost, time.Time{}, 0)
	if err != nil || plan.Signatures != 1 {
		t.Fatalf("the revocation's plan %+v: %v", plan, err)
	}
	entry, proposalId, err := second.RevokeDevice(revokeCtx, plan.PlanId, nil, nil)
	if err != nil || entry == nil || proposalId != nil {
		t.Fatalf("the revocation: %v %x %v", entry, proposalId, err)
	}
	state := client.State()
	if base := state.Base(); base == nil || base.GetVersion() <= entry.GetVersion() {
		t.Fatalf("no base after the revocation at %d: %v", entry.GetVersion(), base)
	}
	head = headOf(state)
	held, err := sidecar.ReadBridgeBlock(head, state, nil)
	if err != nil || !proto.Equal(held, drawn) || testUrBlockSigner(t, head) != second.Identity().SidecarId {
		t.Fatalf("the block after the revocation %v: %v; want %v signed again by the second device", held, err, drawn)
	}
	if client.Writer() != nil {
		t.Fatal("the revocation's save installed a general writer")
	}
	// the push the base names, exact-head as ur daemon signs a confirmed save's
	evs, err := testUrClientsOf(second).evsClient()
	if err != nil {
		t.Fatal(err)
	}
	version := state.Base().GetConfigVersion()
	walk, err := evs.Verifier().Walk(ctx, result.ConfigRepoId, result.MainRefId, 1, result.Chain, version)
	if err != nil || uint64(len(walk)) != version-1 {
		t.Fatalf("the config pushes through %d: %d, %v", version, len(walk), err)
	}
	last := walk[len(walk)-1].Statement.Push
	if last.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD) == 0 || !bytes.Equal(last.GetSignerSidecarId(), second.Identity().SidecarId.Bytes()) {
		t.Fatalf("the re-signing push: flags %d, signed by %x", last.GetFlags(), last.GetSignerSidecarId())
	}
}
