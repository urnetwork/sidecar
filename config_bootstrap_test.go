//go:build !sidecar_http && !js

// BootstrapNetwork's order with the first head on evs's seams (QD-824), on T2's fake api with sidecartest's in-memory
// ref standing in for evs's prepare and commit: KF1's draft, the head's prepare at the genesis state, base 1, the
// device's own S(1) handed on, the repo with its group, and the push sent, in that order; a bootstrap cut short before
// base 1 leaves nothing after the prepare, and its retry runs the whole order again; and the seams' args are held.

package sidecar_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A publisher whose every base is lost before api takes it: a bootstrap cut short before base 1.
type testBootstrapLostPublisher struct{}

func (self testBootstrapLostPublisher) PublishConfigBase(ctx context.Context, base *sidecar.ConfigBasePublish) (*bridge.AuthPin, error) {
	return nil, errors.New("the base never reached api")
}

// What the first head's seams saw, in order.
type testBootstrapSeams struct {
	t     *testing.T
	world *testWriterWorld
	steps []string
	// the state BaseLanded was handed
	landed *sidecar.ConfigState
}

// First's seams over the world's in-memory ref for device, each step recorded: the draft a generation-1 key of the
// config repo, the prepare the ref's at version 0 held to the genesis state, the commit the ref's.
func (self *testBootstrapSeams) args(device testWriterDevice, publisher sidecar.ConfigBasePublisher) *sidecar.ConfigBootstrapArgs {
	world := self.world
	ref := world.heads.For(device.sidecarId, device.key)
	return &sidecar.ConfigBootstrapArgs{
		NetworkId:         world.networkId,
		OwnerMemberId:     device.memberId,
		SidecarId:         device.sidecarId,
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		Sign:              device.sign(),
		ConfigRepoId:      world.repoId,
		First: &sidecar.ConfigFirstHead{
			Draft: func(ctx context.Context, genesis *sidecar.ConfigState) (*sidecar.EvsRepoKey, error) {
				self.steps = append(self.steps, "draft")
				if genesis.Pin().GetVersion() != 0 || !genesis.IsConfigWriter(device.sidecarId) {
					self.t.Errorf("the draft's state: %v", genesis.Pin())
				}
				key, _, err := sidecar.NewGkmFirstGeneration(world.repoId, testWriterId("config group"), &sidecar.GkmGenerationArgs{
					Cause: sidecar.GkmCauseRequest, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)}, Time: time.UnixMilli(1),
					HoldersSha256: make([]byte, 32),
				})
				return key, err
			},
			Prepare: func(ctx context.Context, key *sidecar.EvsRepoKey, genesis *sidecar.ConfigState, head *sidecar.ConfigHead) (*sidecar.ConfigHeadPush, error) {
				self.steps = append(self.steps, "prepare")
				if key == nil || key.RepoId() != world.repoId || genesis.Pin().GetVersion() != 0 ||
					!slices.Equal(genesis.Genesis().GetConfigRepoId(), world.repoId.Bytes()) {
					self.t.Errorf("the prepare's key or state")
				}
				return ref.PrepareConfigHead(ctx, head, 0)
			},
			Commit: func(ctx context.Context, push *sidecar.ConfigHeadPush) error {
				self.steps = append(self.steps, "commit")
				return ref.CommitConfigHead(ctx, push)
			},
		},
		Publisher:  publisher,
		Projection: world.reader(),
		BaseLanded: func(ctx context.Context, state *sidecar.ConfigState) error {
			self.steps = append(self.steps, "base 1")
			self.landed = state
			return nil
		},
		CreateRepo: func(ctx context.Context) error {
			self.steps = append(self.steps, "repo")
			return nil
		},
		Clock: world.clock,
	}
}

// The first head on evs's seams: draft, prepare at the genesis state, base 1 naming the prepared (1, C_1), the device's
// own S(1) at api's pin with the device a config writer there, the repo, then the push; a reader's catch-up checks
// base 1 over the head the ref holds.
func TestBootstrapNetworkDraftsAndPreparesBeforeBaseOne(t *testing.T) {
	world := newTestWriterWorld(t)
	seams := &testBootstrapSeams{t: t, world: world}
	result, err := sidecar.BootstrapNetwork(world.ctx, seams.args(world.owner, world.publisher()))
	if err != nil || !result.Won {
		t.Fatalf("bootstrap: %v", err)
	}
	if want := []string{"draft", "prepare", "base 1", "repo", "commit"}; !slices.Equal(seams.steps, want) {
		t.Fatalf("the steps %v, want %v", seams.steps, want)
	}
	if result.Pin.GetVersion() != 1 || result.Push == nil || result.Push.Version != 1 || result.State != seams.landed {
		t.Fatalf("the result: pin %v", result.Pin)
	}
	if pin := seams.landed.Pin(); pin.GetVersion() != 1 || !slices.Equal(pin.GetChain(), result.Pin.GetChain()) ||
		!seams.landed.IsConfigWriter(world.owner.sidecarId) || !slices.Equal(seams.landed.Base().GetConfigHeadSha256(), result.Push.Chain[:]) {
		t.Fatalf("the device's own S(1): %v", pin)
	}
	world.genesis = result
	client := world.client()
	if err := client.CatchUp(world.ctx); err != nil || client.Pin().GetVersion() != 1 {
		t.Fatalf("a reader's catch-up to base 1: %v", err)
	}
}

// A bootstrap cut short before base 1 runs nothing past the prepare; its retry drafts and prepares again and lands.
func TestBootstrapNetworkCutShortBeforeBaseOneRetries(t *testing.T) {
	world := newTestWriterWorld(t)
	seams := &testBootstrapSeams{t: t, world: world}
	if _, err := sidecar.BootstrapNetwork(world.ctx, seams.args(world.owner, testBootstrapLostPublisher{})); err == nil {
		t.Fatal("a bootstrap whose base never landed answered")
	}
	if want := []string{"draft", "prepare"}; !slices.Equal(seams.steps, want) {
		t.Fatalf("the steps of a bootstrap cut short %v, want %v", seams.steps, want)
	}
	seams.steps = nil
	result, err := sidecar.BootstrapNetwork(world.ctx, seams.args(world.owner, world.publisher()))
	if err != nil || !result.Won {
		t.Fatalf("the retry: %v", err)
	}
	if want := []string{"draft", "prepare", "base 1", "repo", "commit"}; !slices.Equal(seams.steps, want) {
		t.Fatalf("the retry's steps %v, want %v", seams.steps, want)
	}
}

// The first head goes through evs's seams or a ref, exactly one, and the seams come whole.
func TestBootstrapNetworkHoldsItsFirstHeadSeams(t *testing.T) {
	world := newTestWriterWorld(t)
	seams := &testBootstrapSeams{t: t, world: world}
	both := seams.args(world.owner, world.publisher())
	both.Heads = world.heads.For(world.owner.sidecarId, world.owner.key)
	neither := seams.args(world.owner, world.publisher())
	neither.First = nil
	partial := seams.args(world.owner, world.publisher())
	partial.First.Commit = nil
	for name, args := range map[string]*sidecar.ConfigBootstrapArgs{"both": both, "neither": neither, "no commit": partial} {
		if _, err := sidecar.BootstrapNetwork(world.ctx, args); err == nil {
			t.Errorf("%s: a bootstrap ran", name)
		}
	}
	if len(seams.steps) != 0 {
		t.Errorf("refused args ran %v", seams.steps)
	}
	if tip, err := world.api.Tip(world.ctx, world.networkId); err != nil || tip != nil {
		t.Errorf("a refused bootstrap reached api: %v %v", tip, err)
	}
}
