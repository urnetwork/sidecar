//go:build !sidecar_http

// KF1 split at a network's bootstrap (QD-824) on the fake gkm: DraftGroup draws the config group's id and RK_1 before
// base 1 and keeps them, a kill drawing nothing new; CreateGroup at the genesis state still refuses GenRotate_1, whose
// auth pin must be past position 0, and sends nothing; past it, CreateGroup signs gen/1 over the drafted RK_1, so the
// C_1 a push sealed under the draft named is gen/1's, H(repo_id, 1, RK_1); and the drafted id is never drawn again.

package sidecar_test

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A state at the genesis, position 0, with the rows of the view it wraps: what a network's first device holds before
// base 1, the only state there is then.
type gkmGenesisView struct {
	*sidecartest.FakeGkmAuthView
}

func (self gkmGenesisView) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: 0, Chain: bytes.Repeat([]byte{0xa0}, 32)}
}

func (self gkmGenesisView) At(pin *bridge.AuthPin) (sidecar.GkmAuthView, error) {
	if pin.GetVersion() == 0 && bytes.Equal(pin.GetChain(), self.Pin().GetChain()) {
		return self, nil
	}
	return nil, sidecar.ErrGkmAuthAhead
}

// A client of the device over its keychain that holds view as its newest state and no other, as the network's first
// device's holds the genesis state before base 1.
func (self *gkmFlowDevice) clientAt(view sidecar.GkmAuthView) *sidecar.GkmGroupClient {
	self.world.t.Helper()
	world := self.world
	client, err := sidecar.NewGkmGroupClient(&sidecar.GkmGroupClientArgs{
		SidecarId: self.id,
		Api:       self.api,
		Sign:      self.signer.Sign,
		Secrets:   self.secrets,
		Mls:       self.mls,
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			return nil, sidecar.ErrGkmKeyMissing
		},
		RecoveryKey: func(memberId sidecar.Id) (*sidecar.GkmRecoveryKey, error) {
			return world.recoveryKeys[memberId], nil
		},
		Jitter: func(max time.Duration) time.Duration { return 0 },
		Clock:  world.clock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	client.AuthAdvanced(view)
	return client
}

// The bootstrap draft survives a kill: a restart over the same keychain drafts the same group and the same RK_1, and
// nothing reaches gkm before base 1. Past base 1, CreateGroup forms the group under the drafted id, gen/1 naming the
// drafted C_1, which is SHA-256("UR evs 1.0 commit" || repo_id || u64be(1) || RK_1) of the drafted RK_1, signed at the
// state's pin; the draft goes, and a later draft answers the generation 1 held.
func TestDraftGroupResumesWithTheSameIdAndKeyAfterAKill(t *testing.T) {
	world := newGkmBareFlowWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	a := world.flows[world.a]
	drafted, err := a.client.DraftGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	if drafted.Generation() != 1 || drafted.GroupId() == (sidecar.Id{}) || drafted.RepoId() != world.repoId ||
		!bytes.Equal(drafted.Commitment(), drafted.TestCommitmentOfKey()) || !drafted.HoldsFirst() {
		t.Fatalf("the drafted key: generation %d, group %s", drafted.Generation(), drafted.GroupId())
	}
	if kept, signed, err := a.client.TestCreateDraft(world.repoId); err != nil || !kept || signed {
		t.Fatalf("the keychain's draft before base 1: kept %t, signed %t, %v", kept, signed, err)
	}
	if world.store.callCount("CreateGroup") != 0 || len(world.store.groupOwnerRepoIds) != 0 {
		t.Fatal("a draft reached gkm")
	}
	manifest, err := drafted.DeriveKey(sidecar.EvsKeyPurposeManifest, nil)
	if err != nil {
		t.Fatal(err)
	}

	// a kill: the same keychain, nothing else kept
	a.restart()
	again, err := a.client.DraftGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	againManifest, err := again.DeriveKey(sidecar.EvsKeyPurposeManifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.GroupId() != drafted.GroupId() || !bytes.Equal(again.TestCommitmentOfKey(), drafted.TestCommitmentOfKey()) ||
		!bytes.Equal(againManifest, manifest) {
		t.Fatal("the draft after a kill holds another group or RK_1")
	}

	formed, err := a.client.CreateGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	world.groupId = formed.GroupId()
	tip := world.log.Tip()
	first := world.storedGeneration(tip, 1)
	if formed.GroupId() != drafted.GroupId() || world.store.groupOwnerRepoIds[drafted.GroupId()] != world.repoId {
		t.Fatalf("the group formed is not the drafted one")
	}
	if !bytes.Equal(first.Rotate.GetCommitment(), drafted.TestCommitmentOfKey()) || !bytes.Equal(formed.Commitment(), drafted.Commitment()) {
		t.Fatal("gen/1's C_1 is not H(repo_id, 1, RK_1) of the drafted RK_1")
	}
	if auth := first.Rotate.GetAuth(); auth.GetVersion() != tip.Pin().GetVersion() || auth.GetVersion() == 0 || first.SignerId != world.a.id {
		t.Fatalf("gen/1 signed at %d by %s", auth.GetVersion(), first.SignerId)
	}
	if verdict := world.memberAccepts(tip, 1, nil); !verdict.Passed() {
		t.Errorf("a member's check of gen/1: %+v", verdict)
	}
	if kept, _, err := a.client.TestCreateDraft(world.repoId); err != nil || kept {
		t.Errorf("the draft outlived the group's deliveries: %v", err)
	}
	if held, err := a.client.DraftGroup(world.ctx, world.createArgs()); err != nil || held.GroupId() != drafted.GroupId() ||
		!bytes.Equal(held.Commitment(), drafted.Commitment()) || held.Auth().GetVersion() != tip.Pin().GetVersion() {
		t.Errorf("a draft once the group stands: %v", err)
	}
}

// GenRotate_1 at the genesis state's pin {0, A_0} is refused as KEYS's floor has it, nothing sent to gkm, and the
// draft kept unsigned; at a state past base 1 the same client forms the group over the same draft, taking the MLS group
// the refused attempt made at epoch 0 rather than making another under the drafted id.
func TestCreateGroupAtTheGenesisStateStillRefusesGenRotateOne(t *testing.T) {
	world := newGkmBareFlowWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	a := world.flows[world.a]
	client := a.clientAt(gkmGenesisView{FakeGkmAuthView: world.log.Tip()})
	drafted, err := client.DraftGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateGroup(world.ctx, world.createArgs())
	if !errors.Is(err, sidecar.ErrGkmMalformed) || !strings.Contains(err.Error(), "auth pin") {
		t.Fatalf("KF1 at the genesis state: %v", err)
	}
	if world.store.callCount("CreateGroup") != 0 || len(world.store.groupOwnerRepoIds) != 0 {
		t.Fatal("a refused GenRotate_1 reached gkm")
	}
	if kept, signed, err := client.TestCreateDraft(world.repoId); err != nil || !kept || signed {
		t.Fatalf("the draft after the refusal: kept %t, signed %t, %v", kept, signed, err)
	}

	client.AuthAdvanced(world.log.Tip())
	formed, err := client.CreateGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatalf("KF1 past base 1: %v", err)
	}
	world.groupId = formed.GroupId()
	if formed.GroupId() != drafted.GroupId() || !bytes.Equal(world.storedGeneration(world.log.Tip(), 1).Rotate.GetCommitment(), drafted.TestCommitmentOfKey()) {
		t.Fatal("the group formed past base 1 is not the drafted one")
	}
	if group, err := a.mls.LoadGroup(drafted.GroupId()); err != nil || group.Epoch() != 0 {
		t.Fatalf("the creator's MLS group: %v", err)
	}
}

// A 409 for the config group's drafted id ends the creation with ErrGkmDraftTaken and draws no other, since a push
// base 1 names is sealed under it: the draft stays, and the next creation posts the same group.
func TestTheConfigGroupsDraftedIdIsNeverDrawnAgain(t *testing.T) {
	world := newGkmBareFlowWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	a := world.flows[world.a]
	drafted, err := a.client.DraftGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	world.store.refuseOnce("CreateGroup", http.StatusConflict)
	if _, err := a.client.CreateGroup(world.ctx, world.createArgs()); !errors.Is(err, sidecar.ErrGkmDraftTaken) {
		t.Fatalf("a 409 on the drafted id: %v", err)
	}
	if kept, signed, err := a.client.TestCreateDraft(world.repoId); err != nil || !kept || !signed {
		t.Fatalf("the draft after the 409: kept %t, signed %t, %v", kept, signed, err)
	}
	formed, err := a.client.CreateGroup(world.ctx, world.createArgs())
	if err != nil || formed.GroupId() != drafted.GroupId() || world.store.callCount("CreateGroup") != 2 {
		t.Fatalf("the creation after the 409: %v", err)
	}
}

// Only the config repo's group is drafted, by a sidecar that holds a leaf, in the process that holds the network's
// state.
func TestDraftGroupRefusesWhatIsNoBootstrap(t *testing.T) {
	world, agent := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	a := world.flows[world.a]
	general := &sidecar.GkmCreateGroupArgs{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL}
	if _, err := a.client.DraftGroup(world.ctx, general); !errors.Is(err, sidecar.ErrGkmMalformed) {
		t.Errorf("a draft of a general repo's group: %v", err)
	}
	if _, err := world.flows[agent].client.DraftGroup(world.ctx, world.createArgs()); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("a draft by a sidecar with no leaf: %v", err)
	}
	a.stateless = true
	if _, err := a.client.DraftGroup(world.ctx, world.createArgs()); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("a draft in a process without the network's state: %v", err)
	}
	if kept, _, err := a.client.TestCreateDraft(world.repoId); err != nil || kept {
		t.Errorf("a refused draft was kept: %v", err)
	}
}
