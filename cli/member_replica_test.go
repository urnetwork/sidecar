//go:build !ios_extension && !sidecar_http && !js

package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// A signed-in app opens a previously provisioned network through its stock replica.
// The config and application readers must both decrypt the real EVS head with the
// generation kept by the enrolled instance, including after a full process restart.
func TestMemberReplicaReadsTheEnrolledNetworksEncryptedHeadAfterRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	instance, err := net.StartInstance("member", &sidecartest.TestInstanceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	networkId := sidecar.NewId()
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	provisioned, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: running, Gkm: keys, OwnerMemberId: sidecar.NewId()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	open := func(running *sidecar.Sidecar) *sidecar.MemberReplica {
		t.Helper()
		replica, err := running.OpenMemberReplica(ctx)
		if err != nil {
			t.Fatal(err)
		}
		again, err := running.OpenMemberReplica(ctx)
		if err != nil || again != replica {
			t.Fatalf("the enrolled host opened a second replica: %v", err)
		}
		if _, err := running.ConfigFollower().WaitStanding(ctx); err != nil {
			t.Fatalf("the enrolled config head: %v (%+v)", err, running.ConfigFollower().Status())
		}
		config, evs := replica.Config(), replica.Evs()
		if config == nil || evs == nil || !bytes.Equal(config.Pin().GetChain(), provisioned.Bootstrap.Pin.GetChain()) {
			t.Fatal("the public clients did not open on the verified pin")
		}
		var content bytes.Buffer
		_, err = evs.Repo(provisioned.ConfigRepoId).ReadHead(ctx, &sidecar.EvsReadArgs{Path: sidecar.ConfigHeadGenesisPath}, &content)
		if err != nil || !bytes.Equal(content.Bytes(), provisioned.Bootstrap.SignedGenesis) {
			t.Fatalf("the public file read: %v", err)
		}
		return replica
	}
	first := open(running)
	if err := instance.Restart(); err != nil {
		t.Fatal(err)
	}
	if first.Config() != nil || first.Evs() != nil || running.MemberReplica() != nil {
		t.Fatal("the closed host still publishes the old replica")
	}
	open(instance.Sidecar(networkId))
}
