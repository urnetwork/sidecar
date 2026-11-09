// C-02's run of TestKillAfterCheckRepostsSameBytes on the fake api: a real Sidecar, admitted in a real log the fake
// api sequences and verifies, approves its member's new device; the delta's answer is lost, the SidecarAdmit stays
// pending, and the next start posts the very same bytes, which api answers with the entry it already holds, so the log
// carries it once.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestKillAfterCheckRepostsSameBytesOnTheFakeApi(t *testing.T) {
	net := newTestNet(t)
	ctx := coreScheduleContext(t)
	laptop := addCoreSidecar(t, net, "laptop")
	record := coreNetworkRecord(t, laptop)
	api := laptop.Api
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}

	// the network's genesis and base 1, its owner's first device another device, and the laptop admitted under the
	// owner by that device
	env := newConfigLogSuiteEnv(ctx, cluster, func(sidecar.Clock, sidecar.BlobCluster) ConfigLogSequencer { return api })
	env.clock = net.Clock()
	env.networkId = record.NetworkId
	env.signedGenesis = env.genesis(env.owner, env.configRepo)
	genesisChain := bridge.GenesisChain(env.signedGenesis)
	env.tip = &bridge.AuthPin{Version: 0, Chain: genesisChain[:]}
	rows := env.baseOneRows(env.owner)
	pin, err := api.AppendBase(ctx, env.networkId, env.base(env.owner, env.tip, rows, 0, 1), rows, env.signedGenesis, env.configRepo.pushes(0, 1))
	if err != nil {
		t.Fatal(err)
	}
	env.tip = pin
	identity := laptop.Sidecar().Identity()
	admit := env.sign(env.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header:            env.header(),
		NetworkId:         env.networkId.Bytes(),
		SidecarId:         identity.SidecarId.Bytes(),
		IdentityPublicKey: identity.IdentityPublicKey,
		IdentityAlg:       "ed25519",
		MemberId:          env.ownerMemberId.Bytes(),
	})
	pin, err = api.AppendStatement(ctx, env.networkId, admit)
	if err != nil {
		t.Fatal(err)
	}

	// the verified state as the laptop reads it: admitted under the owner, consented
	authority := NewFakeAuthority()
	authority.SetPin(pin)
	authority.AdmitSidecar(&FakeAuthorityAdmission{SidecarId: identity.SidecarId, MemberId: env.ownerMemberId, IdentityPublicKey: identity.IdentityPublicKey})
	authority.SetConsented(identity.SidecarId, env.ownerMemberId, true)
	defer laptop.Sidecar().InstallAuthority(authority)()

	newDevice := env.device(env.ownerMemberId)
	approvalId, err := laptop.Sidecar().OpenAdmission(&sidecar.SidecarAdmissionRequest{
		SidecarId:         newDevice.sidecarId,
		MemberId:          env.ownerMemberId,
		IdentityPublicKey: newDevice.key.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := net.Faults().Add(&FaultPlan{Op: FaultOpHttp, KeyPrefix: "/network/config/delta", Result: ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	err = laptop.Sidecar().DecideApproval(ctx, approvalId, sidecar.SidecarDecisionApprove, sidecar.SidecarActConfirmed, nil)
	if !errors.Is(err, sidecar.ErrSidecarActPending) {
		t.Fatalf("a lost answer: %v", err)
	}
	afterLoss, err := api.Tip(ctx, env.networkId)
	if err != nil || afterLoss.GetVersion() != pin.GetVersion()+1 {
		t.Fatalf("the lost post did not land once: %v %v", afterLoss, err)
	}

	// the next start posts what is pending, the same bytes, and api answers the entry it holds
	if err := laptop.Sidecar().PostPendingStatements(ctx); err != nil {
		t.Fatal(err)
	}
	tip, err := api.Tip(ctx, env.networkId)
	if err != nil || tip.GetVersion() != afterLoss.GetVersion() {
		t.Fatalf("the retry appended again: %v %v", tip, err)
	}
	read, err := api.ReadProjection(context.Background(), env.networkId, pin.GetVersion(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Entries) != 1 {
		t.Fatalf("%d entries after the admission", len(read.Entries))
	}
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(read.Entries[0], entry); err != nil {
		t.Fatal(err)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		t.Fatal(err)
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_SIDECAR_ADMIT || !bytes.Equal(signed.GetSignerId(), identity.SidecarId.Bytes()) {
		t.Errorf("the entry is not the laptop's admission: %+v", signed)
	}
	items, err := laptop.Sidecar().PendingApprovals()
	if err != nil || len(items) != 0 {
		t.Errorf("still pending: %+v %v", items, err)
	}
}
