//go:build !ios_extension && !sidecar_http && !js

// Exercises the forwarding setup the real standing follower installs, including after the daemon reopens its store.
package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The group is already established. Its forwarding writes complete against the network fixture.
type configForwardingKeys struct {
	*configJoinTestKeys
	key *sidecar.EvsRepoKey
}

func (self *configForwardingKeys) UploadDelegationKey(context.Context, []byte, []byte) error {
	return nil
}

func (self *configForwardingKeys) DeliverDelegationWraps(context.Context, []byte) error {
	return nil
}

func (self *configForwardingKeys) EnsureWritable(context.Context, sidecar.Id) (*sidecar.EvsRepoKey, error) {
	return self.key, nil
}

func (self *configForwardingKeys) RepoKey(context.Context, sidecar.Id, uint64) (*sidecar.EvsRepoKey, error) {
	return self.key, nil
}

func TestStandingConfigFollowerInstallsForwardingOnFirstOpenAndRestart(t *testing.T) {
	world := newConfigFollowWorld(t, 1, nil)
	network := world.networks[0]
	key, _, err := sidecar.NewGkmFirstGeneration(network.ConfigRepoId(), sidecar.NewId(), &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: network.Tip(), Time: world.net.Clock().Now(), HoldersSha256: make([]byte, sha256.Size),
	})
	if err != nil {
		t.Fatal(err)
	}
	world.keys = func(running *sidecar.Sidecar) sidecar.GkmClient {
		keys := newConfigJoinTestKeys()
		keys.held = true
		keys.observe(running)
		return &configForwardingKeys{configJoinTestKeys: keys, key: key}
	}
	first := world.host(network, nil)
	world.standing(first, network)
	check := func(running *sidecar.Sidecar, due sidecar.ForwardingSetupReason) {
		t.Helper()
		witness, err := running.ForwardingWitness(network.NetworkId())
		if err != nil || witness.SetupDue != due || witness.Pin == nil {
			t.Fatalf("standing follower's forwarding witness %+v, %v", witness, err)
		}
		if _, err := running.ForwardingSetupDue(sidecar.NewId()); !errors.Is(err, sidecar.ErrForwardingSetupUnavailable) {
			t.Fatalf("a second network's forwarding setup became available: %v", err)
		}
	}
	check(first, sidecar.ForwardingSetupNoneLive)
	component := &bridge.ForwardingKeys{
		KeySetId: sidecar.NewId().Bytes(), ForwardPublicKey: bytes.Repeat([]byte{1}, 32),
		ClientPublicKey: bytes.Repeat([]byte{2}, 32), ReaderXwingPublicKey: bytes.Repeat([]byte{3}, 1216),
	}
	handOff, err := first.SetUpForwarding(world.ctx, network.NetworkId(), component)
	if err != nil || len(handOff.GetSignedDelegation()) == 0 || handOff.GetStrictExpMs() <= world.net.Clock().Now().UnixMilli() {
		t.Fatalf("first signed hand-off: %v", err)
	}
	network.Sync()
	if err := world.instance.Restart(); err != nil {
		t.Fatal(err)
	}
	reopened := world.instance.Sidecar(network.NetworkId())
	world.standing(reopened, network)
	check(reopened, sidecar.ForwardingSetupNotDue)
	renewed, err := reopened.SetUpForwarding(world.ctx, network.NetworkId(), component)
	if err != nil || !bytes.Equal(renewed.GetSignedDelegation(), handOff.GetSignedDelegation()) || renewed.GetForwardClientJwt() == handOff.GetForwardClientJwt() {
		t.Fatalf("renewal against the original delegation after restart: %v", err)
	}
	if _, err := first.ForwardingSetupDue(network.NetworkId()); !errors.Is(err, sidecar.ErrForwardingSetupUnavailable) {
		t.Fatalf("the stopped follower retained its setup sources: %v", err)
	}
	network.Sync()
	network.MustLand(network.Sign(network.Owner(), bridge.SignedType_SIGNED_DELEGATION_REVOKE, &protocol.DelegationRevoke{
		Header: network.Header(), DelegationId: handOff.GetPending().GetForwardDelegationId(),
	}))
	if err := world.instance.Restart(); err != nil {
		t.Fatal(err)
	}
	withdrawn := world.instance.Sidecar(network.NetworkId())
	world.standing(withdrawn, network)
	check(withdrawn, sidecar.ForwardingSetupForeignRevocation)
	if renewed, err := withdrawn.SetUpForwarding(world.ctx, network.NetworkId(), component); renewed != nil || !errors.Is(err, sidecar.ErrForwardingSetupNeedsConfirm) {
		t.Fatalf("a withdrawn delegation after restart: %v", err)
	}
	if err := withdrawn.ConfirmForwardingSetup(network.NetworkId()); err != nil {
		t.Fatal(err)
	}
	replaced, err := withdrawn.SetUpForwarding(world.ctx, network.NetworkId(), component)
	if err != nil || len(replaced.GetSignedDelegation()) == 0 || bytes.Equal(replaced.GetPending().GetForwardDelegationId(), handOff.GetPending().GetForwardDelegationId()) {
		t.Fatalf("confirmed replacement of an undelivered set: %v", err)
	}
}
