// FS-98's main path on the fake api (CORE-M3-02, CORE-M3-03): a real Sidecar, admitted in a real log the fake api
// sequences and verifies, lists its member's devices, previews the revocation of another of them as lost and signs
// it; api's verifier takes the SidecarRevoke at the tip, so the log carries it once, signed by the laptop, and the
// laptop's effects run from its entry.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a landed revocation handed on.
type coreRevokeEffects struct {
	committed []sidecar.Id
	tracked   []uint64
}

func (self *coreRevokeEffects) CommitRevocation(ctx context.Context, sidecarId sidecar.Id, entry *bridge.AuthPin) error {
	self.committed = append(self.committed, sidecarId)
	return nil
}

func (self *coreRevokeEffects) TrackRevocation(position uint64) {
	self.tracked = append(self.tracked, position)
}

func TestRevokeDeviceLandsOnTheFakeApi(t *testing.T) {
	net := newTestNet(t)
	ctx := coreScheduleContext(t)
	laptop := addCoreSidecar(t, net, "laptop")
	record := coreNetworkRecord(t, laptop)
	api := laptop.Api
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}

	// the network's genesis and base 1, then the laptop and a phone admitted under the owner by its first device
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
	phone := env.device(env.ownerMemberId)
	authority := NewFakeAuthority()
	admit := func(sidecarId sidecar.Id, identityPublicKey []byte) {
		t.Helper()
		signed := env.sign(env.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
			Header:            env.header(),
			NetworkId:         env.networkId.Bytes(),
			SidecarId:         sidecarId.Bytes(),
			IdentityPublicKey: identityPublicKey,
			IdentityAlg:       "ed25519",
			MemberId:          env.ownerMemberId.Bytes(),
		})
		authority.AdmitSidecar(&FakeAuthorityAdmission{SidecarId: sidecarId, MemberId: env.ownerMemberId, IdentityPublicKey: identityPublicKey})
		pin, err = api.AppendStatement(ctx, env.networkId, signed)
		if err != nil {
			t.Fatal(err)
		}
		env.tip = pin
		authority.Apply(&sidecar.SidecarAuthorityEntry{Pin: pin, TimeMs: net.Clock().Now().UnixMilli(), Applied: true})
	}
	authority.SetPin(pin)
	admit(identity.SidecarId, identity.IdentityPublicKey)
	admit(phone.sidecarId, phone.key.Public().(ed25519.PublicKey))
	authority.SetConsented(identity.SidecarId, env.ownerMemberId, true)
	defer laptop.Sidecar().InstallAuthority(authority)()
	effects := &coreRevokeEffects{}
	defer laptop.Sidecar().InstallRevokeEffects(effects)()

	devices, err := laptop.Sidecar().Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 || !devices[0].This || devices[0].SidecarId != identity.SidecarId || devices[1].SidecarId != phone.sidecarId ||
		devices[1].State != sidecar.MemberDeviceLive || devices[1].AdmittedAt.IsZero() {
		t.Fatalf("the devices: %+v", devices)
	}
	if _, err := laptop.Sidecar().PreviewDeviceRevoke(ctx, identity.SidecarId, sidecar.DeviceRevokeLost, time.Time{}, 0); err == nil {
		t.Fatal("this sidecar previewed its own revocation")
	}
	plan, err := laptop.Sidecar().PreviewDeviceRevoke(ctx, phone.sidecarId, sidecar.DeviceRevokeLost, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SidecarId != phone.sidecarId || plan.Signatures != 1 || plan.Presence || plan.SinceN != 0 {
		t.Fatalf("the plan: %+v", plan)
	}
	entry, proposalId, err := laptop.Sidecar().RevokeDevice(ctx, plan.PlanId, nil, nil)
	if err != nil || entry == nil || proposalId != nil {
		t.Fatalf("the revocation: %v %x %v", entry, proposalId, err)
	}
	tip, err := api.Tip(ctx, env.networkId)
	if err != nil || tip.GetVersion() != pin.GetVersion()+1 || entry.GetVersion() != tip.GetVersion() || !bytes.Equal(entry.GetChain(), tip.GetChain()) {
		t.Fatalf("the revocation did not land once at the tip: %v %v %v", entry, tip, err)
	}
	read, err := api.ReadProjection(context.Background(), env.networkId, pin.GetVersion(), false)
	if err != nil || len(read.Entries) != 1 {
		t.Fatalf("the entries after the admissions: %v", err)
	}
	logEntry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(read.Entries[0], logEntry); err != nil {
		t.Fatal(err)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(logEntry.GetBody(), signed); err != nil {
		t.Fatal(err)
	}
	revoke := &bridge.SidecarRevoke{}
	if err := proto.Unmarshal(signed.GetBody(), revoke); err != nil {
		t.Fatal(err)
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE || !bytes.Equal(signed.GetSignerId(), identity.SidecarId.Bytes()) ||
		!bytes.Equal(revoke.GetSidecarId(), phone.sidecarId.Bytes()) || revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST {
		t.Errorf("the entry is not the laptop's revocation of the phone: %+v", revoke)
	}
	if len(effects.committed) != 1 || effects.committed[0] != phone.sidecarId || len(effects.tracked) != 1 || effects.tracked[0] != entry.GetVersion() {
		t.Errorf("the effects: %+v", effects)
	}
	// the plan is spent, and one never previewed is stale
	var revokeError *sidecar.DeviceRevokeError
	if _, _, err := laptop.Sidecar().RevokeDevice(ctx, plan.PlanId, nil, nil); !errors.As(err, &revokeError) || revokeError.Code != sidecar.DeviceRevokeCodeStale {
		t.Errorf("a spent plan: %v", err)
	}
}
